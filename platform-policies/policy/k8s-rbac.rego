# =============================================================================
# Conftest Rego Policy: Kubernetes RBAC Security
# Part of Track 1 — DevSecOps Assessment
#
# These OPA/Rego policies enforce least-privilege RBAC by catching:
#   K8S-001: ClusterRoleBinding to cluster-admin for non-system principals
#   K8S-002: Wildcard ClusterRoles (* verbs + * resources + * apiGroups)
#   K8S-003: ClusterRoleBinding subjects using default ServiceAccounts
#   K8S-007: Over-broad Role definitions (wildcard resources)
#   K8S-008: Over-broad RoleBindings to default or over-privileged SAs
#
# Policies are consumed by Conftest in CI (see 02-pipeline-supply-chain/).
# =============================================================================

package main

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# DENY: ClusterRoleBinding to cluster-admin for non-system principals
# K8S-001 trigger incident
# ---------------------------------------------------------------------------
# Fails if a ClusterRoleBinding references the built-in "cluster-admin" ClusterRole
# and the subject name does NOT start with "system:"
#
# Severity: CRITICAL

cluster_admin_binding_deny[msg] {
    binding := input.kind == "ClusterRoleBinding"
    binding_role_ref := input.roleRef.name == "cluster-admin"
    input.roleRef.kind == "ClusterRole"
    input.roleRef.apiGroup == "rbac.authorization.k8s.io"

    some subject in input.subjects
    not startswith(subject.name, "system:")

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-001]: ClusterRoleBinding '%s' binds cluster-admin to non-system subject '%s/%s'. This is the trigger incident pattern.",
            [input.metadata.name, subject.kind, subject.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-001",
        "category": "rbac",
    }
}

# ---------------------------------------------------------------------------
# DENY: Wildcard ClusterRole (all verbs, all resources, all apiGroups)
# K8S-002 — Helm pwnchart anti-pattern
# ---------------------------------------------------------------------------
# A ClusterRole with * on apiGroups, resources, AND verbs is effectively
# cluster-admin-equivalent regardless of binding context.
#
# Severity: CRITICAL

wildcard_cluster_role_deny[msg] {
    input.kind == "ClusterRole"

    some rule in input.rules
    contains(rule.verbs[_], "*")
    contains(rule.resources[_], "*")
    contains(rule.apiGroups[_], "*")

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-002]: ClusterRole '%s' uses wildcard (*) on apiGroups, resources, AND verbs. This is cluster-admin-equivalent.",
            [input.metadata.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-002",
        "category": "rbac",
    }
}

# ---------------------------------------------------------------------------
# DENY: ClusterRoleBinding to default ServiceAccount
# K8S-003 — default SA escalation
# ---------------------------------------------------------------------------
# Binds a ClusterRole to "default" SA in any namespace — any pod in that
# namespace without an explicit SA inherits these elevated privileges.
#
# Severity: CRITICAL

default_sa_clusterrole_binding_deny[msg] {
    input.kind == "ClusterRoleBinding"
    input.roleRef.kind == "ClusterRole"

    some subject in input.subjects
    subject.kind == "ServiceAccount"
    subject.name == "default"

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-003]: ClusterRoleBinding '%s' binds ClusterRole '%s' to default ServiceAccount in namespace '%s'. Any pod without explicit SA inherits this.",
            [input.metadata.name, input.roleRef.name, subject.namespace]
        ),
        "severity": "CRITICAL",
        "id": "K8S-003",
        "category": "rbac",
    }
}

# ---------------------------------------------------------------------------
# DENY: ClusterRole in kube-system from non-system components
# K8S-001 variant — SAs that shouldn't live in kube-system
# ---------------------------------------------------------------------------
# Warns if a custom (non-system) ServiceAccount is placed in kube-system.
#
# Severity: HIGH

custom_sa_in_kube_system_warn[msg] {
    input.kind == "ServiceAccount"
    input.metadata.namespace == "kube-system"
    not startswith(input.metadata.name, "system:")

    msg := {
        "msg": sprintf(
            "HIGH [K8S-001]: ServiceAccount '%s' in kube-system namespace. Custom SAs should not be placed in kube-system.",
            [input.metadata.name]
        ),
        "severity": "HIGH",
        "id": "K8S-001",
        "category": "rbac",
    }
}

# ---------------------------------------------------------------------------
# DENY: Role with wildcard resources (over-broad read)
# K8S-007 — secret-reader pattern
# ---------------------------------------------------------------------------
# A Role with resources: ["*"] exposes all namespace resources including
# all Secrets. Should be scoped to only the specific resources needed.
#
# Severity: HIGH

wildcard_role_resources_deny[msg] {
    input.kind == "Role"

    some rule in input.rules
    contains(rule.resources[_], "*")
    contains(rule.verbs[_], "get")

    msg := {
        "msg": sprintf(
            "HIGH [K8S-007]: Role '%s' grants 'get' on all resources ('*'). This exposes all namespace Secrets and resource metadata. Scope to specific resource types.",
            [input.metadata.name]
        ),
        "severity": "HIGH",
        "id": "K8S-007",
        "category": "rbac",
    }
}

# ---------------------------------------------------------------------------
# DENY: RoleBinding to default SA in non-system namespaces
# K8S-008 variant — broader default SA binding pattern
# ---------------------------------------------------------------------------
# Binds a Role/RoleBinding to "default" SA — unintended privilege inheritance.
#
# Severity: HIGH

default_sa_role_binding_deny[msg] {
    input.kind == "RoleBinding"

    some subject in input.subjects
    subject.kind == "ServiceAccount"
    subject.name == "default"
    # Exclude kube-system and system-managed namespaces
    subject.namespace != "kube-system"
    not startswith(subject.namespace, "kube-")

    msg := {
        "msg": sprintf(
            "HIGH [K8S-008]: RoleBinding '%s' binds to default ServiceAccount. Use an explicit, purpose-specific ServiceAccount instead.",
            [input.metadata.name]
        ),
        "severity": "HIGH",
        "id": "K8S-008",
        "category": "rbac",
    }
}

# ---------------------------------------------------------------------------
# WARN: ClusterRoleBinding with Subject cross-namespace
# K8S-001/003 — cross-namespace binding check
# ---------------------------------------------------------------------------
# A ClusterRoleBinding where subject.namespace != "" and the subject is
# a ServiceAccount outside the binding namespace is often unintentional.
#
# Severity: MEDIUM

cross_namespace_clusterrole_binding_warn[msg] {
    input.kind == "ClusterRoleBinding"

    some subject in input.subjects
    subject.kind == "ServiceAccount"
    subject.namespace != ""
    subject.namespace != input.metadata.namespace

    msg := {
        "msg": sprintf(
            "MEDIUM: ClusterRoleBinding '%s' binds a ServiceAccount from namespace '%s'. Verify this cross-namespace binding is intentional.",
            [input.metadata.name, subject.namespace]
        ),
        "severity": "MEDIUM",
        "id": "K8S-001",
        "category": "rbac",
    }
}

# ---------------------------------------------------------------------------
# DENY: ClusterRoleBinding to CI/pipeline type service accounts
# K8S-001 — CI-related binding detection
# ---------------------------------------------------------------------------
# Pipeline/runners service accounts should never get ClusterRoleBindings.
# Look for common CI SA naming patterns.
#
# Severity: CRITICAL

ci_sa_clusterrole_binding_deny[msg] {
    input.kind == "ClusterRoleBinding"

    some subject in input.subjects
    subject.kind == "ServiceAccount"
    contains(lower(subject.name), "ci-")
    # CI SA should not have ClusterRole binding

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-001]: ClusterRoleBinding '%s' binds ClusterRole '%s' to CI service account '%s/%s'. CI identities must NOT have ClusterRole bindings.",
            [input.metadata.name, input.roleRef.name, subject.namespace, subject.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-001",
        "category": "rbac",
    }
}

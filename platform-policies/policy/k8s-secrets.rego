package main

import future.keywords.if
import future.keywords.in

# =============================================================================
# Conftest Rego Policy: Kubernetes Secrets Anti-Patterns
# Part of Track 1 — DevSecOps Assessment
#
# Catches:
#   K8S-009: Inline base64 secret data in manifests
#   K8S-010: Secret values injected as environment variables
#   K8S-016: NodePort service type
# =============================================================================

# ---------------------------------------------------------------------------
# DENY: Inline Secret manifests (base64 data or stringData)
# K8S-009
# ---------------------------------------------------------------------------
# Secrets should use External Secrets Operator references, not inline values.
# Severity: HIGH

inline_secret_data_deny[msg] {
    input.kind == "Secret"

    # Has base64-encoded data
    count(input.data) > 0
    # Exclude service-account-token type Secrets (K8s-managed)
    input.type != "kubernetes.io/service-account-token"
    input.type != "kubernetes.io/dockercfg"
    input.type != "kubernetes.io/dockerconfigjson"
    input.type != "kubernetes.io/basic-auth"
    input.type != "kubernetes.io/ssh-auth"
    input.type != "kubernetes.io/tls"

    msg := {
        "msg": sprintf(
            "HIGH [K8S-009]: Secret '%s' in '%s' has inline data. Use External Secrets Operator instead of committing secret values to Git.",
            [input.metadata.name, input.metadata.namespace]
        ),
        "severity": "HIGH",
        "id": "K8S-009",
        "category": "secrets",
    }
}

inline_secret_stringdata_deny[msg] {
    input.kind == "Secret"
    count(input.stringData) > 0
    input.type != "kubernetes.io/service-account-token"
    input.type != "kubernetes.io/dockercfg"
    input.type != "kubernetes.io/dockerconfigjson"
    input.type != "kubernetes.io/basic-auth"
    input.type != "kubernetes.io/ssh-auth"
    input.type != "kubernetes.io/tls"

    msg := {
        "msg": sprintf(
            "HIGH [K8S-009]: Secret '%s' in '%s' has inline stringData. Use External Secrets Operator.",
            [input.metadata.name, input.metadata.namespace]
        ),
        "severity": "HIGH",
        "id": "K8S-009",
        "category": "secrets",
    }
}

# ---------------------------------------------------------------------------
# DENY: Secret via environment variable (valueFrom.secretKeyRef)
# K8S-010
# ---------------------------------------------------------------------------
# Secrets should be mounted as projected volumes, not environment variables.
# Env vars leak via process inspection, crash dumps, and debug endpoints.
#
# Severity: HIGH

secret_env_var_deny[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]
    env := container.env[_]
    env.valueFrom.secretKeyRef

    msg := {
        "msg": sprintf(
            "HIGH [K8S-010]: Container '%s' in %s '%s' injects secret '%s' via environment variable '%s'. Use projected secret volume mount instead.",
            [container.name, input.kind, input.metadata.name, env.valueFrom.secretKeyRef.name, env.name]
        ),
        "severity": "HIGH",
        "id": "K8S-010",
        "category": "secrets",
    }
}

# Also check init containers
secret_env_var_init_deny[msg] {
    containers := [c | c = input.spec.template.spec.initContainers[_]]
    container := containers[_]
    env := container.env[_]
    env.valueFrom.secretKeyRef

    msg := {
        "msg": sprintf(
            "HIGH [K8S-010]: Init container '%s' in %s '%s' injects secret '%s' via environment variable.",
            [container.name, input.kind, input.metadata.name, env.valueFrom.secretKeyRef.name]
        ),
        "severity": "HIGH",
        "id": "K8S-010",
        "category": "secrets",
    }
}

# ---------------------------------------------------------------------------
# DENY: NodePort service type
# K8S-016
# ---------------------------------------------------------------------------
# NodePort bypasses ingress governance and exposes services on every node IP.
# Use ClusterIP + Ingress/ALB instead.
#
# Severity: HIGH

nodeport_service_deny[msg] {
    input.kind == "Service"
    input.spec.type == "NodePort"

    msg := {
        "msg": sprintf(
            "HIGH [K8S-016]: Service '%s' in '%s' uses NodePort type. Use ClusterIP + Ingress/ALB instead.",
            [input.metadata.name, input.metadata.namespace]
        ),
        "severity": "HIGH",
        "id": "K8S-016",
        "category": "secrets",
    }
}

# ---------------------------------------------------------------------------
# WARN: envFrom with secretRef
# K8S-010 variant — bulk secret injection as env vars
# ---------------------------------------------------------------------------
# Severity: HIGH

env_from_secret_warn[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]
    env_from := container.envFrom[_]
    env_from.secretRef

    msg := {
        "msg": sprintf(
            "HIGH [K8S-010]: Container '%s' in %s '%s' uses envFrom with secretRef. This bulk-injects all secret keys as environment variables.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "HIGH",
        "id": "K8S-010",
        "category": "secrets",
    }
}

# ---------------------------------------------------------------------------
# INFO: Secret with default automount
# K8S-012 companion — detect SAs without automount disabled
# ---------------------------------------------------------------------------
# Severity: INFO

automount_sa_token_info[msg] {
    input.kind == "ServiceAccount"
    input.metadata.namespace != "kube-system"
    object.get(input, "automountServiceAccountToken", true) == true

    msg := {
        "msg": sprintf(
            "INFO [K8S-012]: ServiceAccount '%s' in '%s' has automountServiceAccountToken implicitly enabled. Disable unless the pod needs API access.",
            [input.metadata.name, input.metadata.namespace]
        ),
        "severity": "INFO",
        "id": "K8S-012",
        "category": "secrets",
    }
}

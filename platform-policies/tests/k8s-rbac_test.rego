package main

# =============================================================================
# Unit tests for k8s-rbac.rego
# Run: conftest verify --policy ../policy/
# =============================================================================

import future.keywords.if
import future.keywords.in

# --- K8S-001 tests ---

test_cluster_admin_binding_deny {
    # A ClusterRoleBinding binding cluster-admin to a non-system SA should be denied
    r := cluster_admin_binding_deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "superadmin"},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "cluster-admin"
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": "superadmin",
            "namespace": "kube-system"
        }]
    }

    count(r) > 0
    r[0].severity == "CRITICAL"
    r[0].id == "K8S-001"
}

test_cluster_admin_system_binding_allowed {
    # A ClusterRoleBinding binding cluster-admin to a system: prefix SA should NOT be denied
    r := cluster_admin_binding_deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "system-controller"},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "cluster-admin"
        },
        "subjects": [{
            "kind": "User",
            "name": "system:kube-controller-manager"
        }]
    }

    count(r) == 0
}

# --- K8S-002 tests ---

test_wildcard_cluster_role_deny {
    r := wildcard_cluster_role_deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "all-your-base"},
        "rules": [{
            "apiGroups": ["*"],
            "resources": ["*"],
            "verbs": ["*"]
        }]
    }

    count(r) > 0
    r[0].severity == "CRITICAL"
    r[0].id == "K8S-002"
}

test_narrow_cluster_role_allowed {
    # A ClusterRole with specific resources should NOT be denied
    r := wildcard_cluster_role_deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "namespace-reader"},
        "rules": [{
            "apiGroups": [""],
            "resources": ["pods", "services"],
            "verbs": ["get", "list", "watch"]
        }]
    }

    count(r) == 0
}

# --- K8S-003 tests ---

test_default_sa_clusterrole_binding_deny {
    r := default_sa_clusterrole_binding_deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "belong-to-us"},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "cluster-admin"
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": "default",
            "namespace": "default"
        }]
    }

    count(r) > 0
    r[0].severity == "CRITICAL"
    r[0].id == "K8S-003"
}

# --- K8S-007 tests ---

test_wildcard_role_resources_deny {
    r := wildcard_role_resources_deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "secret-reader"},
        "rules": [{
            "apiGroups": [""],
            "resources": ["*"],
            "verbs": ["get", "list", "watch"]
        }]
    }

    count(r) > 0
    r[0].id == "K8S-007"
}

# --- K8S-008 tests ---

test_default_sa_role_binding_deny {
    r := default_sa_role_binding_deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "secret-reader-binding"},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "secret-reader"
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": "default",
            "namespace": "citizen-frontend"
        }]
    }

    count(r) > 0
    r[0].id == "K8S-008"
}

test_default_sa_role_binding_kube_system_allowed {
    # kube-system default SA bindings are typically system-managed and should be allowed
    r := default_sa_role_binding_deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "system-role-binding"},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "extension-apiserver-authentication-reader"
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": "default",
            "namespace": "kube-system"
        }]
    }

    count(r) == 0
}

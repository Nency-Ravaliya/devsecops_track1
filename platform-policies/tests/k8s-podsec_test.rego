package main

# =============================================================================
# Unit tests for k8s-podsec.rego
# Run: conftest verify --policy ../policy/
# =============================================================================

# --- K8S-004 tests ---

test_privileged_container_deny {
    r := privileged_container_deny with input as {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "system-monitor"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "monitor",
                        "image": "busybox:1.36",
                        "securityContext": {"privileged": true}
                    }]
                }
            }
        }
    }

    count(r) > 0
    r[0].severity == "CRITICAL"
    r[0].id == "K8S-004"
}

test_host_pid_ipc_deny {
    r := host_pid_ipc_deny with input as {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "system-monitor"},
        "spec": {
            "template": {
                "spec": {
                    "hostPID": true,
                    "containers": [{"name": "monitor", "image": "busybox:1.36"}]
                }
            }
        }
    }

    count(r) > 0
    r[0].id == "K8S-004"
}

test_dangerous_host_path_deny {
    r := dangerous_host_path_deny with input as {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "system-monitor"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "monitor", "image": "busybox:1.36"}],
                    "volumes": [{
                        "name": "host-root",
                        "hostPath": {"path": "/"}
                    }]
                }
            }
        }
    }

    count(r) > 0
}

# --- K8S-005 tests ---

test_runtime_socket_host_path_deny_docker {
    r := runtime_socket_host_path_deny with input as {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "health-check"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "checker", "image": "busybox:1.36"}],
                    "volumes": [{
                        "name": "docker-sock",
                        "hostPath": {"path": "/var/run/docker.sock"}
                    }]
                }
            }
        }
    }

    count(r) > 0
    r[0].id == "K8S-005"
}

# --- K8S-013/014 tests ---

test_latest_tag_deny {
    r := latest_tag_deny with input as {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "frontend"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "web",
                        "image": "nginx:latest"
                    }]
                }
            }
        }
    }

    count(r) > 0
    r[0].id == "K8S-014"
}

test_pinned_image_allowed {
    r := latest_tag_deny with input as {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "frontend"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "web",
                        "image": "nginx:1.25.3"
                    }]
                }
            }
        }
    }

    count(r) == 0
}

test_digest_image_allowed {
    r := unpinned_image_deny with input as {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "frontend"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "web",
                        "image": "nginx@sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b"
                    }]
                }
            }
        }
    }

    count(r) == 0
}

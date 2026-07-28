# =============================================================================
# Conftest Rego Policy: Kubernetes Pod Security
# Part of Track 1 — DevSecOps Assessment
#
# These policies enforce pod security standards by catching:
#   K8S-004: Privileged containers with host namespaces and host root mounts
#   K8S-005: Container runtime socket mounts (Docker/containerd)
#   K8S-006: DaemonSets with hostNetwork + privileged
#   K8S-013: Unpinned image tags (no digest/version)
#   K8S-014: :latest tag usage
#   K8S-021: Missing runAsNonRoot
#   K8S-022: Missing seccomp profile
#
# Policies align with Pod Security Standards (PSS) Restricted profile.
# =============================================================================

package main

import future.keywords.if
import future.keywords.in

# Approved registry list — only images from these registries are allowed.
# Configured via data.json in the same policy directory.
#
# NOTE: In tests, these values are provided by data.approved_registries.
# The pipeline provides actual data via `conftest test --data data.json`.
#
# For unit testing, use:
#   data.approved_registries = ["docker.io/library", "registry.example.com"]

# ---------------------------------------------------------------------------
# DENY: Privileged container
# K8S-004, K8S-005, K8S-006
# ---------------------------------------------------------------------------
# Severity: CRITICAL

privileged_container_deny[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]
    container.securityContext.privileged == true

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-004/005/006]: Container '%s' in %s '%s' runs as privileged. This is a direct node compromise path.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-004",
        "category": "pod-security",
    }
}

# Also check Pod specs that aren't wrapped in a controller
privileged_pod_deny[msg] {
    input.kind == "Pod"
    input.spec.containers[_].securityContext.privileged == true

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-004]: Pod '%s' runs as privileged.",
            [input.metadata.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-004",
        "category": "pod-security",
    }
}

# ---------------------------------------------------------------------------
# DENY: hostPID or hostIPC
# K8S-004
# ---------------------------------------------------------------------------
# Severity: CRITICAL

host_pid_ipc_deny[msg] {
    input.spec.template.spec.hostPID == true

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-004]: %s '%s' has hostPID: true. Container can see all host processes.",
            [input.kind, input.metadata.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-004",
        "category": "pod-security",
    }
}

host_pid_ipc_deny[msg] {
    input.spec.template.spec.hostIPC == true

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-004]: %s '%s' has hostIPC: true. Container can access host IPC resources.",
            [input.kind, input.metadata.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-004",
        "category": "pod-security",
    }
}

host_pid_ipc_pod_deny[msg] {
    input.kind == "Pod"
    input.spec.hostPID == true

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-004]: Pod '%s' has hostPID: true.",
            [input.metadata.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-004",
        "category": "pod-security",
    }
}

# ---------------------------------------------------------------------------
# DENY: hostPath to root filesystem or runtime sockets
# K8S-004 (host root), K8S-005 (runtime sockets)
# ---------------------------------------------------------------------------
# Severity: CRITICAL

dangerous_host_path_deny[msg] {
    volumes := [v | v = input.spec.template.spec.volumes[_]]
    volume := volumes[_]
    volume.hostPath.path == "/"

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-004]: %s '%s' mounts host root filesystem via hostPath '/'. This enables host-level compromise.",
            [input.kind, input.metadata.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-004",
        "category": "pod-security",
    }
}

runtime_socket_host_path_deny[msg] {
    volumes := [v | v = input.spec.template.spec.volumes[_]]
    volume := volumes[_]

    volume.hostPath.path == "/var/run/docker.sock"

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-005]: %s '%s' mounts Docker socket. This is a container escape path.",
            [input.kind, input.metadata.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-005",
        "category": "pod-security",
    }
}

runtime_socket_host_path_deny[msg] {
    volumes := [v | v = input.spec.template.spec.volumes[_]]
    volume := volumes[_]

    contains(volume.hostPath.path, "containerd.sock")

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-005]: %s '%s' mounts containerd socket. This is a container escape path.",
            [input.kind, input.metadata.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-005",
        "category": "pod-security",
    }
}

# ---------------------------------------------------------------------------
# DENY: hostNetwork combined with privileged
# K8S-006 — DaemonSet anti-pattern
# ---------------------------------------------------------------------------
# hostNetwork bypasses NetworkPolicy; combined with privileged it's
# a cluster-wide compromise vector.
#
# Severity: CRITICAL

host_network_privileged_deny[msg] {
    input.spec.template.spec.hostNetwork == true
    containers := [c | c = input.spec.template.spec.containers[_]]
    containers[_].securityContext.privileged == true

    msg := {
        "msg": sprintf(
            "CRITICAL [K8S-006]: %s '%s' has hostNetwork: true AND privileged containers. This bypasses all NetworkPolicy controls.",
            [input.kind, input.metadata.name]
        ),
        "severity": "CRITICAL",
        "id": "K8S-006",
        "category": "pod-security",
    }
}

# ---------------------------------------------------------------------------
# DENY: allowPrivilegeEscalation
# K8S-004, K8S-005
# ---------------------------------------------------------------------------
# Severity: HIGH

privilege_escalation_deny[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]
    container.securityContext.allowPrivilegeEscalation == true

    msg := {
        "msg": sprintf(
            "HIGH [K8S-004]: Container '%s' in %s '%s' has allowPrivilegeEscalation: true. Process can gain additional privileges.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "HIGH",
        "id": "K8S-004",
        "category": "pod-security",
    }
}

# ---------------------------------------------------------------------------
# WARN: Missing runAsNonRoot
# K8S-021
# ---------------------------------------------------------------------------
# Severity: MEDIUM

missing_run_as_non_root_warn[msg] {
    input.spec.template.spec.securityContext.runAsNonRoot != true
    # Skip init containers and system namespaces
    not startswith(input.metadata.namespace, "kube-")
    input.metadata.namespace != "kube-system"

    msg := {
        "msg": sprintf(
            "MEDIUM [K8S-021]: %s '%s' does not set runAsNonRoot: true at Pod securityContext. Container may run as root.",
            [input.kind, input.metadata.name]
        ),
        "severity": "MEDIUM",
        "id": "K8S-021",
        "category": "pod-security",
    }
}

# Container-level runAsNonRoot check (warn if Pod-level is missing AND container-level is also missing)
missing_run_as_non_root_warn[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]
    input.spec.template.spec.securityContext.runAsNonRoot != true
    object.get(container.securityContext, "runAsNonRoot", true) != true

    not startswith(input.metadata.namespace, "kube-")
    input.metadata.namespace != "kube-system"

    msg := {
        "msg": sprintf(
            "MEDIUM [K8S-021]: Container '%s' in %s '%s' does not set runAsNonRoot: true. May run as root.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "MEDIUM",
        "id": "K8S-021",
        "category": "pod-security",
    }
}

# ---------------------------------------------------------------------------
# WARN: Missing seccomp profile
# K8S-022
# ---------------------------------------------------------------------------
# Severity: MEDIUM

missing_seccomp_warn[msg] {
    input.spec.template.spec.securityContext.seccompProfile.type == "Unconfined"

    msg := {
        "msg": sprintf(
            "MEDIUM [K8S-022]: %s '%s' has seccomp 'Unconfined'. Kernel syscall surface is unrestricted.",
            [input.kind, input.metadata.name]
        ),
        "severity": "MEDIUM",
        "id": "K8S-022",
        "category": "pod-security",
    }
}

missing_seccomp_warn[msg] {
    input.spec.template.spec.securityContext.seccompProfile == ""
}

missing_seccomp_warn[msg] {
    # Pod-level seccomp is completely absent
    not input.spec.template.spec.securityContext.seccompProfile
    not input.spec.template.spec.securityContext.seccompProfile == null

    # Check container-level too
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]
    not container.securityContext.seccompProfile
    not container.securityContext.seccompProfile == null

    not startswith(input.metadata.namespace, "kube-")
    input.metadata.namespace != "kube-system"

    msg := {
        "msg": sprintf(
            "MEDIUM [K8S-022]: %s '%s' has no seccomp profile set. Set seccompProfile.type: RuntimeDefault as a minimum.",
            [input.kind, input.metadata.name]
        ),
        "severity": "MEDIUM",
        "id": "K8S-022",
        "category": "pod-security",
    }
}

# ---------------------------------------------------------------------------
# DENY: Unpinned image tag (no digest, no versioned tag)
# K8S-013
# ---------------------------------------------------------------------------
# Severity: HIGH

unpinned_image_deny[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]
    image := container.image

    # Check that image uses either a digest or a versioned tag (not just "latest" or bare)
    not contains(image, "@sha256:")
    # Has a tag but check if it looks versioned
    tag_found := regex.match(":[0-9a-zA-Z._-]+$", image)

    not tag_found
    # Bare image reference without any tag or digest

    msg := {
        "msg": sprintf(
            "HIGH [K8S-013]: Container '%s' in %s '%s' uses unpinned image '%s'. Pin by digest or versioned tag.",
            [container.name, input.kind, input.metadata.name, image]
        ),
        "severity": "HIGH",
        "id": "K8S-013",
        "category": "pod-security",
    }
}

unpinned_image_deny[msg] {
    init_containers := [c | c = input.spec.template.spec.initContainers[_]]
    container := init_containers[_]
    image := container.image

    not contains(image, "@sha256:")
    tag_found := regex.match(":[0-9a-zA-Z._-]+$", image)
    not tag_found

    msg := {
        "msg": sprintf(
            "HIGH [K8S-013]: Init container '%s' in %s '%s' uses unpinned image '%s'. Pin by digest or versioned tag.",
            [container.name, input.kind, input.metadata.name, image]
        ),
        "severity": "HIGH",
        "id": "K8S-013",
        "category": "pod-security",
    }
}

# ---------------------------------------------------------------------------
# DENY: :latest tag usage
# K8S-014
# ---------------------------------------------------------------------------
# Severity: HIGH

latest_tag_deny[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]
    endswith(container.image, ":latest")

    msg := {
        "msg": sprintf(
            "HIGH [K8S-014]: Container '%s' in %s '%s' uses ':latest' tag (image: %s). Pin to a specific version.",
            [container.name, input.kind, input.metadata.name, container.image]
        ),
        "severity": "HIGH",
        "id": "K8S-014",
        "category": "pod-security",
    }
}

latest_tag_deny[msg] {
    init_containers := [c | c = input.spec.template.spec.initContainers[_]]
    container := init_containers[_]
    endswith(container.image, ":latest")

    msg := {
        "msg": sprintf(
            "HIGH [K8S-014]: Init container '%s' in %s '%s' uses ':latest' tag.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "HIGH",
        "id": "K8S-014",
        "category": "pod-security",
    }
}

# ---------------------------------------------------------------------------
# WARN: Missing capability drops
# K8S-021 companion — not all caps are dropped
# ---------------------------------------------------------------------------
# Severity: LOW (informational)

missing_capability_drop_warn[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]

    # Check if securityContext exists but capabilities.drop doesn't include ALL
    container.securityContext.capabilities
    not contains(container.securityContext.capabilities.drop[_], "ALL")

    msg := {
        "msg": sprintf(
            "INFO [K8S-021]: Container '%s' in %s '%s' does not drop ALL capabilities. Consider dropping ALL and adding back only needed capabilities.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "INFO",
        "id": "K8S-021",
        "category": "pod-security",
    }
}

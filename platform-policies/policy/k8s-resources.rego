package main

import future.keywords.if
import future.keywords.in

# =============================================================================
# Conftest Rego Policy: Resource Governance
# Part of Track 1 — DevSecOps Assessment
#
# Catches:
#   K8S-023: Containers missing CPU/memory requests
#   K8S-024: Containers missing CPU/memory limits
# =============================================================================

# ---------------------------------------------------------------------------
# WARN: Missing resource requests
# K8S-023
# ---------------------------------------------------------------------------
# Without requests, the scheduler lacks data for optimal placement.
# Severity: MEDIUM

missing_resource_requests_warn[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]

    # Check if requests block exists
    not container.resources.requests

    not startswith(input.metadata.namespace, "kube-")
    input.metadata.namespace != "kube-system"

    msg := {
        "msg": sprintf(
            "MEDIUM [K8S-023]: Container '%s' in %s '%s' has no resource requests. This can cause noisy-neighbour issues and poor scheduler placement.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "MEDIUM",
        "id": "K8S-023",
        "category": "resources",
    }
}

missing_resource_requests_warn[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]

    # Requests block exists but is missing CPU and/or memory
    container.resources.requests
    not container.resources.requests.cpu

    not startswith(input.metadata.namespace, "kube-")
    input.metadata.namespace != "kube-system"

    msg := {
        "msg": sprintf(
            "MEDIUM [K8S-023]: Container '%s' in %s '%s' has resource requests but is missing CPU request.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "MEDIUM",
        "id": "K8S-023",
        "category": "resources",
    }
}

missing_resource_requests_warn[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]

    container.resources.requests
    not container.resources.requests.memory

    not startswith(input.metadata.namespace, "kube-")
    input.metadata.namespace != "kube-system"

    msg := {
        "msg": sprintf(
            "MEDIUM [K8S-023]: Container '%s' in %s '%s' has resource requests but is missing memory request.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "MEDIUM",
        "id": "K8S-023",
        "category": "resources",
    }
}

# ---------------------------------------------------------------------------
# WARN: Missing resource limits
# K8S-024
# ---------------------------------------------------------------------------
# Without limits, a single workload can starve node resources.
# Severity: MEDIUM

missing_resource_limits_warn[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]

    # No limits block at all
    not container.resources.limits

    not startswith(input.metadata.namespace, "kube-")
    input.metadata.namespace != "kube-system"

    msg := {
        "msg": sprintf(
            "MEDIUM [K8S-024]: Container '%s' in %s '%s' has no resource limits. This can starve other workloads during traffic spikes.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "MEDIUM",
        "id": "K8S-024",
        "category": "resources",
    }
}

missing_resource_limits_warn[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]

    # Limits block exists but is missing CPU and/or memory
    container.resources.limits
    not container.resources.limits.cpu

    not startswith(input.metadata.namespace, "kube-")
    input.metadata.namespace != "kube-system"

    msg := {
        "msg": sprintf(
            "MEDIUM [K8S-024]: Container '%s' in %s '%s' has resource limits but is missing CPU limit.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "MEDIUM",
        "id": "K8S-024",
        "category": "resources",
    }
}

missing_resource_limits_warn[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]

    container.resources.limits
    not container.resources.limits.memory

    not startswith(input.metadata.namespace, "kube-")
    input.metadata.namespace != "kube-system"

    msg := {
        "msg": sprintf(
            "MEDIUM [K8S-024]: Container '%s' in %s '%s' has resource limits but is missing memory limit.",
            [container.name, input.kind, input.metadata.name]
        ),
        "severity": "MEDIUM",
        "id": "K8S-024",
        "category": "resources",
    }
}

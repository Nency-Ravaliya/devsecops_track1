# Module 6 — Remediation Summary

## Purpose
This file summarizes the remediation advisory for the highest-severity findings and the practical fixes delivered in the repo.

## Focus findings
- **K8S-001**: `superadmin` ServiceAccount bound to `cluster-admin`.
- **K8S-002 / K8S-003**: Wildcard ClusterRole and default ServiceAccount binding from Helm `pwnchart`.
- **K8S-004**: Privileged `system-monitor` workload with host root mount and host namespace access.
- **K8S-005**: Container runtime socket mount and privileged health-check.
- **K8S-006**: DaemonSet with hostNetwork and privileged access.

## Remediation approach
- Remove cluster-admin and wildcard RBAC bindings.
- Replace or harden privileged host-level workloads.
- Move secret handling to a managed store.
- Enforce least privilege in all new manifests.
- Document compensating controls where vendor constraints remain.

## Delivered artifacts
- `06-remediation/fixed-manifests/k8s-001-fixed-superadmin.yaml`
- `06-remediation/compensating-controls.md`
- `06-remediation/remediation-advisory.md`

## What to demo
- Show the fix manifest for K8S-001.
- Explain the difference between a cluster-scoped `ClusterRoleBinding` and a namespace-scoped `RoleBinding`.
- Point to the compensating controls file for the COTS vendor exception.

## Use this file to generate slides on:
- Critical remediation actions.
- Evidence required to close the top findings.
- The distinction between remediation and compensated acceptance.

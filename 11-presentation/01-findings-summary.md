# Module 1 — Findings Summary

## Purpose
This file summarizes the core security findings from the kubernetes-goat reference estate and maps them to the highest-priority remediation actions.

## Executive summary
- The assessment found **28 findings** across the estate.
- **6 Critical**, **12 High**, **7 Medium**, and **1 Low**.
- The most urgent finding is **K8S-001**: a `ClusterRoleBinding` granting `cluster-admin` to a non-system ServiceAccount.
- Other critical issues include wildcard ClusterRoles, privileged workloads with host access, runtime socket mounts, and secrets in manifests.

## Key critical findings
- **K8S-001**: `superadmin` ServiceAccount bound to `cluster-admin`.
- **K8S-002**: Helm `pwnchart` creates a wildcard `ClusterRole` with full cluster privileges.
- **K8S-003**: `pwnchart` binds that role to the `default` ServiceAccount.
- **K8S-004**: `system-monitor` privileged pod with `hostPID`, host root mount, and host-level access.
- **K8S-005**: `health-check` container mounts container runtime socket and runs privileged.
- **K8S-006**: DaemonSet with `hostNetwork`, privileged mode, and runtime socket mounts.

## High-priority themes
- RBAC over-privilege and cluster-admin patterns.
- Pod security violations: privileged containers, hostPath mounts, host namespace access.
- Secrets exposure: secrets committed in YAML and env vars.
- Image supply chain issues: unpinned tags, `latest`, and COTS vendor image constraints.
- Network posture gaps: no NetworkPolicy and NodePort exposure.
- Lack of audit and runtime detection controls.

## Why this matters
- K8S-001 is the **direct trigger incident pattern**: non-system workload identity with cluster-admin privileges.
- These findings enable **cluster-wide compromise**, secret exfiltration, and lateral movement.
- They also expose the lack of both **shift-left CI controls** and **runtime detection**.

## Suggested remediation priorities
1. Remove cluster-admin bindings and replace with least-privilege Roles.
2. Block wildcard ClusterRoles and default SA cluster-admin bindings in CI.
3. Harden or remove privileged host-level workloads.
4. Move secrets out of Git and into a managed secrets store.
5. Enforce image pinning, signature verification, and NetworkPolicy.
6. Deploy audit and runtime detection tooling.

## Use this file to generate slides on:
- Risk posture and finding distribution.
- Top 6 critical findings and business impact.
- Why K8S-001 is the trigger incident.
- Remediation priority list.

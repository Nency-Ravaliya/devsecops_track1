# Module 4 — Network Mesh & Zero-Trust Summary

## Purpose
This document summarises the zero-trust networking design for the assessed estate.

## Current state
- Default AWS VPC CNI with no NetworkPolicy enforcement.
- Any pod can talk to any workload across namespaces.
- NodePort exposure exists and access scripts bind port forwarding to 0.0.0.0.

## Target state
- **Cilium 1.16.x** replaces the CNI to enforce NetworkPolicy and provide observability.
- Every production namespace starts with **default-deny ingress and egress**.
- Approved flows are opened explicitly with CiliumNetworkPolicy.
- Internal NodePort services are replaced with ClusterIP + ingress.
- Egress is controlled through an **egress proxy** for external access.

## Why Cilium
- Native cross-cloud portability to EKS, AKS, and GKE.
- Transparent mTLS via WireGuard without sidecars.
- Hubble flow observability for policy authoring.
- Easier operational footprint than a full Istio mesh for 18 workloads.

## Key design decisions
- **Default-deny baseline** by namespace.
- **Cilium over Istio** for network enforcement without sidecar complexity.
- **Ingress/WAF** on the edge and **NetworkPolicy enforcement** inside the cluster.
- **NodePort ban** with Kyverno admission policy.

## Rollout plan
1. Deploy Cilium and Hubble in observation mode.
2. Generate policies from actual flow data.
3. Enable default-deny policies one namespace at a time.
4. Add egress lockdown and egress proxy controls.
5. Extend the same design to AKS and GKE.

## Use this file to generate slides on:
- Network posture gap and default-deny rationale.
- Why Cilium is the preferred cross-cloud CNI.
- How network policy enforcement contains compromised workloads.
- The phased rollout plan to avoid outages.

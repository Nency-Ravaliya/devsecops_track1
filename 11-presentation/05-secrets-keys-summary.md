# Module 5 — Secrets & Key Management Summary

## Purpose
This file summarises the secrets management architecture and the chosen solution for the assessed estate.

## Current state
- Secrets are committed as base64 data in Kubernetes manifests.
- Secrets are injected via environment variables.
- There is no evidence of etcd encryption or workload identity isolation.

## Selected approach
- **External Secrets Operator (ESO)** as the runtime sync mechanism.
- **Cloud Secrets Manager** for the source-of-truth store:
  - AWS Secrets Manager on EKS.
  - Azure Key Vault on AKS.
  - GCP Secret Manager on GKE.
- **IRSA / workload identity** to restrict each pod to its own secrets path.
- **Projected volume mounts** for runtime secret access.

## Why ESO over Vault
- Same Kubernetes CRD across clouds.
- Lower operational complexity for the programme.
- Native cloud KMS root of trust and simpler rotation.
- Vault is only recommended later if dynamic secrets are required.

## Key controls
- Path-scoped IAM access for each workload.
- Secrets never stored in Git.
- Secret rotation via the cloud provider and weekly validation.
- Defense-in-depth with etcd encryption and workload identity.

## Use this file to generate slides on:
- The current secrets risk and why Git is wrong.
- ESO architecture and multi-cloud portability.
- Secret rotation flow and key hierarchy.
- How this fix addresses K8S-009, K8S-010, K8S-011, and K8S-012.

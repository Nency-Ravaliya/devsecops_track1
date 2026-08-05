# Module 7 — Threat Model Summary

## Purpose
This file summarizes the threat modelling work for the `hunger-check` workload and the broader estate.

## Approach
- Used **STRIDE** to identify threats across Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
- Mapped the threats back to the highest-severity findings.
- Identified the one partially mitigated residual risk: secrets in Git and environment variables.

## Key threats
- **T7**: CI job service account/token compromise applying cluster-admin (trigger incident pattern).
- **T6**: Compromised workload reads all namespace secrets via over-broad Role.
- **T4**: Secrets leaked in Git and env vars.
- **T3**: Secret or RBAC access without audit evidence.
- **T5**: Resource exhaustion due to missing requests/limits.
- **T9**: Default ServiceAccount auto-mount granting unintended API access.

## Why this matter
- Shows how the assessment findings translate into attacker-capable scenarios.
- Demonstrates the need for both policy enforcement and runtime detection.
- Provides a clear residual risk statement for the panel.

## Use this file to generate slides on:
- The `hunger-check` threat model and STRIDE categories.
- The most dangerous exploitation paths.
- How the proposed controls disrupt the attacker kill chain.
- The remaining residual risk and acceptance criteria.

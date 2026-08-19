# Module 9 — Architecture Summary

## Purpose
This file summarizes the high-level and low-level architecture design for the assessed estate.

## High-level design
- Defence-in-depth with WAF, admission control, zero-trust network, and runtime detection.
- Secrets are sourced from cloud-managed store and mounted at runtime.
- Image signing and admission verification integrate the pipeline with runtime controls.
- The COTS workload is isolated with dedicated network and identity boundaries.

## Low-level request path
- Citizen request enters via ALB + WAF.
- Frontend pod receives secrets from ESO-synced Kubernetes Secret.
- Frontend communicates with backend through Cilium network policy.
- Backend connects to RDS over TLS.
- Pipeline and admission controls verify image provenance before deployment.

## Why this matters
- Shows the secure target-state architecture, not just the findings.
- Illustrates how the controls work together end to end.
- Makes the assessment concrete for an architecture-focused audience.

## Use this file to generate slides on:
- The system-wide security architecture.
- The request flow and control points.
- How the architecture prevents the trigger incident from surfacing again.
- The decision to use Cilium instead of a heavier service mesh.

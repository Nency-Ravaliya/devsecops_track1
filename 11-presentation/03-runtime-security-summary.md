# Module 3 — Runtime Detection & Incident Response Summary

## Purpose
This file summarizes the runtime security strategy and incident response design for the assessed estate.

## Current state
- No runtime detection tooling deployed across the assessed estate.
- Critical findings would not generate alerts today.
- The architecture lacks a detection layer for container escape, RBAC abuse, and secret access.

## Selected tools
- **Falco 0.38.x** as the runtime detection engine.
- **falcosidekick** to route alerts to PagerDuty, Slack, and SIEM.
- **CloudWatch Logs / SIEM** to centralize alert telemetry.

## Key rule categories
- **P1 Critical**: cluster role binding creation from a pod, privileged container start, container escape indicators, secret token access.
- **P2 High**: binary drift, host network access, shell spawn, unexpected network connections.
- **P3 Medium**: run-as-root in non-system namespace, missing seccomp, automount token usage.

## Incident response flow
1. Detect P1 alert in PagerDuty.
2. Triage by security on-call.
3. Cordon the compromised node.
4. Isolate the pod via NetworkPolicy or quarantine security group.
5. Capture forensic evidence before pod termination.
6. Kill and replace the workload after evidence capture.

## Why this matters
- Provides the detection layer missing from the existing estate.
- Ensures a compromised pod does not silently escalate to cluster-wide compromise.
- Enables the programme to prove it can detect and respond to real exploitation patterns.

## Use this file to generate slides on:
- Runtime detection gaps and why they matter.
- Falco rule priorities and alert routing.
- The incident response playbook for a container escape scenario.
- How runtime detection complements CI gates.

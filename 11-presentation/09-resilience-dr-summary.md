# Module 10 — Resilience & DR Summary

## Purpose
This file summarizes the resilience, backup, and disaster recovery strategy for the assessed estate.

## Key design points
- **Velero** for cluster state and volume backup.
- **RDS automated snapshots** for database recovery.
- **Quarterly restore drills** to validate RTO and procedures.
- **Cross-region backups** for full regional disaster recovery.
- **Immutable backup storage** with S3 Object Lock.

## RTO / RPO
- **RPO:** 24 hours for application state.
- **RTO:** 4 hours for cluster rebuild and recovery.
- The biggest recovery dependency is the database.

## What to demo
- The backup architecture diagram.
- The difference between GitOps recoverable resources and data backup recoverable resources.
- The quarterly restore drill cadence.

## Use this file to generate slides on:
- DR strategy and evidence requirements.
- Backup responsibilities and control points.
- The difference between infrastructure-as-code recovery and data recovery.
- The operational assumptions for the programme.

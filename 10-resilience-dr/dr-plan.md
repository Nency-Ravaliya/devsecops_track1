# Resilience, Backup & Disaster Recovery Plan

## 1. Scope

This plan covers the resilience and disaster recovery strategy for the ~18 EKS workloads running citizen-facing services. It addresses: etcd/control-plane backup, stateful workload backup, RTO/RPO targets, and full cluster rebuild recovery.

## 2. Backup Strategy

### 2.1 EKS Control-Plane (etcd) Backup

AWS EKS manages the control plane including etcd. EKS automatically backs up etcd daily and retains backups for 14 days. However, this is an AWS-managed backup with limited customer control over timing and retention.

**Programme-enhanced control-plane backup:**

| Component | Method | Frequency | Retention | Encryption |
|---|---|---|---|---|
| **EKS cluster state** (namespaces, RBAC, Deployments, Services, ConfigMaps, Secrets) | Velero 1.14.x scheduled backup of cluster resources | Daily at 02:00 UTC | 30 days | Encrypted at rest via S3 server-side encryption (SSE-KMS, programme KMS key) |
| **EKS cluster state** (for disaster recovery) | Velero full backup to cross-region S3 | Weekly (Sunday 03:00 UTC) | 90 days | SSE-KMS with cross-region replica |
| **etcd snapshots** (EKS-managed) | AWS-managed daily backup | Daily | 14 days | AWS-managed encryption |
| **Terraform state** | S3 backend with DynamoDB state locking | On every apply | Versioned (all versions retained) | SSE-KMS |

**Access control for backups:**

- S3 bucket has bucket policy: only the Velero IRSA role and a break-glass IAM user can access backups. No workload service account can read backup data.
- Velero IAM role: `VeleroBackupRole` with `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` on the Velero bucket only. No `s3:DeleteObject` — backups are immutable for 30 days via S3 Object Lock.
- Break-glass IAM user: stored in AWS Secrets Manager, used only in DR scenarios. MFA-protected, no programmatic access (console-only with MFA).

### 2.2 Stateful Workload Backup

The programme's stateful workloads include the `metadata-db` (PostgreSQL) and any COTS vendor databases.

**Velero Volume Snapshot Strategy:**

| Workload | Storage type | Velero backup method | Frequency | Retention | RPO |
|---|---|---|---|---|---|
| `metadata-db` | RDS PostgreSQL (Multi-AZ) | AWS-native: RDS automated daily snapshots + manual snapshots | Daily automated, weekly manual | 35 days (automated), 90 days (manual) | 24 hours (automated), 7 days (manual) |
| `metadata-db` (if running in-cluster on EBS) | EBS gp3 | Velero CSI volume snapshot (EBS snapshots) | Daily at 02:00 UTC | 30 days | 24 hours |
| COTS vendor DB | RDS or EBS | Same as above, per deployment | Daily at 02:00 UTC | 30 days | 24 hours |

**Why RDS over in-cluster PostgreSQL:** For the `metadata-db`, the programme should prefer RDS over in-cluster PostgreSQL because RDS provides automated backups, point-in-time recovery, and Multi-AZ failover without the programme managing backup infrastructure. If the database runs in-cluster (as the kubernetes-goat scenario suggests), Velero with CSI snapshots is the fallback.

### 2.3 Restore Testing Cadence

**Quarterly restore drills** — scheduled for the first week of January, April, July, and October.

**Why quarterly:** Monthly would be ideal but disproportionate for an 18-workload estate. Quarterly balances operational cost with confidence. The drill takes approximately 4 hours (setup → restore → validate → teardown) and requires coordination between the platform team and one workload team.

**Drill procedure:**

| Step | Action | Validation |
|---|---|---|
| 1 | Provision a temporary EKS cluster in a dedicated DR testing VPC | Cluster API is accessible |
| 2 | Install Velero on the temporary cluster | Velero server is running |
| 3 | Restore from the latest Velero backup | `kubectl get all --all-namespaces` shows expected resources |
| 4 | Restore stateful volumes from snapshots | Pods start successfully, database is accessible |
| 5 | Run application health checks | All citizen-facing endpoints return 200 OK |
| 6 | Measure time from restore start to service available | Record actual RTO vs target RTO |
| 7 | Document findings, teardown temporary cluster | Drill report filed in programme wiki |

**Drill output:** A report with actual RTO achieved, any failures encountered, and remediation actions. This report is presented to the ITSO-equivalent as evidence of DR capability.

### 2.4 Backup Monitoring

| Signal | Alert |
|---|---|
| Velero backup fails | PagerDuty P2 — investigate within 4 hours |
| Velero backup age > 48 hours (missed daily) | PagerDuty P1 — immediate investigation |
| RDS automated snapshot age > 48 hours | PagerDuty P1 — RDS health check |
| S3 Object Lock violation detected | PagerDuty P1 — potential tampering |

## 3. RTO/RPO Targets

### Representative Workload: `citizen-backend` (Citizen-Facing EKS Workload)

This workload serves citizens who are accessing government services. The target-state RTO/RPO is based on the impact of downtime on citizens:

| Metric | Target | Rationale |
|---|---|---|
| **RPO (Recovery Point Objective)** | 24 hours | The `citizen-backend` processes citizen requests that are idempotent (re-trying a request does not create duplicate state). The database is the primary state store. Losing 24 hours of database writes means citizens may need to re-submit some requests. This is acceptable for government services that are not real-time financial transactions. |
| **RTO (Recovery Time Objective)** | 4 hours | Citizens cannot access services for up to 4 hours before impact becomes significant (service level agreement with citizen-facing portal). This includes: cluster rebuild (1h), Velero restore (30m), application startup (15m), health check validation (15m), DNS propagation/load balancer reconfiguration (30m), buffer for unexpected issues (1h). |

### Architecture Choices Required to Meet These Targets

| Choice | How it supports RTO/RPO |
|---|---|
| **RDS Multi-AZ** | Automatic failover in <60 seconds if the primary database fails. RPO effectively zero for database failures (synchronous replication). |
| **Velero daily backups** | Ensures RPO ≤ 24 hours for cluster state. Cross-region backup ensures RPO is met even if the primary region is lost. |
| **GitOps (ArgoCD)** | All application manifests are in Git. A cluster rebuild can re-deploy all workloads from Git without manual intervention, reducing RTO. |
| **EKS managed node groups** | AWS provisions replacement nodes automatically. Node failures do not require manual intervention. |
| **Cilium as CNI** | NetworkPolicy definitions are in Git (Module 4). After cluster rebuild, Cilium policies are re-applied from Git — no manual NetworkPolicy recreation. |

## 4. Full Cluster Rebuild: What Is Recoverable from Git?

### GitOps-Recoverable (No Data Loss)

These resources are fully recoverable from Git repositories. A cluster rebuild re-applies them:

| Resource | Source | Recovery method |
|---|---|---|
| **Terraform infrastructure** (VPC, EKS cluster, node groups, IAM roles) | Git repo: `infrastructure/terraform/` | `terraform apply` |
| **Kubernetes manifests** (Deployments, Services, ConfigMaps, Ingresses) | Git repo: application repos | `kubectl apply` or ArgoCD sync |
| **NetworkPolicy definitions** | Git repo: `platform-policies/` | `kubectl apply` |
| **Cilium CNI configuration** | Git repo: `infrastructure/helm-values/` | `helm upgrade --install cilium` |
| **Kyverno admission policies** | Git repo: `platform-policies/` | `kubectl apply` |
| **Falco rules and configuration** | Git repo: `platform-policies/` | `helm upgrade --install falco` |
| **ESO ExternalSecret CRDs** | Git repo: application repos | `kubectl apply` |
| **Conftest OPA policies** | Git repo: `platform-policies/` | Already in Git |
| **CI/CD pipeline configuration** | Git repo: `.gitlab-ci.yml` | Already in Git |

### NOT GitOps-Recoverable (Data Loss Risk)

These resources require backup restoration or manual re-creation:

| Resource | Why not in Git | Recovery method | Risk |
|---|---|---|---|
| **Kubernetes Secrets** (synced by ESO) | Secrets are in AWS Secrets Manager, not Git (Module 5). ESO CRDs reference the path, not the value. | After cluster rebuild, ESO re-syncs from Secrets Manager. No data loss IF Secrets Manager is intact. | **Low** — Secrets Manager is a managed service with its own backup. |
| **RDS database data** | Database contents are not in Git. | Restore from RDS automated snapshot or Velero backup. | **RPO = 24h** (daily snapshot). Point-in-time recovery available within 35 days. |
| **EBS volume data** (if in-cluster databases) | Volume contents not in Git. | Restore from Velero CSI volume snapshots. | **RPO = 24h** (daily Velero backup). |
| **Pod ephemeral data** (in-memory caches, temp files) | Inherent in pod lifecycle. | Not recoverable. Applications must tolerate cold start. | **Acceptable** — stateless workloads rehydrate from database. |
| **IRSA role trust policies** | IAM roles are in Terraform (Git), but OIDC provider association requires cluster recreation order. | Terraform handles this — `terraform apply` recreates the OIDC provider and IRSA roles in the correct order. | **Low** — if Terraform is run correctly. |
| **Falco baseline** (30-day learning period) | Baseline is runtime state in Falco's memory. | After cluster rebuild, Falco restarts in audit-only mode. 30-day re-baseline needed. | **Medium** — alert tuning is lost. Falco runs with default rules during re-baseline. |
| **Cilium Hubble flow data** | Flow data is ephemeral. | Not recoverable. Hubble re-learns flows after cluster rebuild. | **Low** — Hubble is observability, not enforcement. NetworkPolicy enforcement is from Git. |

### Honest Assessment

**A full cluster rebuild is recoverable in approximately 2-4 hours** for the control plane and workloads, assuming Terraform and Git repositories are intact. The critical dependency is the **RDS database** — if RDS is intact, the application recovers with RPO ≤ 24 hours. If RDS is also lost (region-wide disaster), recovery requires cross-region RDS replica promotion and Velero cross-region restore, extending RTO to 6-8 hours.

**The biggest risk to DR is not the cluster — it's the database.** The programme should prioritise:
1. Cross-region RDS read replica for the critical citizen-facing databases
2. Regular restore testing (quarterly drills) to validate RTO assumptions
3. Monitoring of Velero backup health (§2.4)

## 5. Assumptions

- EKS version is 1.29+ with Amazon Linux 2 or Bottlerocket nodes (for Velero CSI snapshot compatibility).
- Velero 1.14.x is deployed with the AWS plugin for EBS snapshot support and the CSI plugin for volume snapshots.
- The programme uses a single EKS cluster for all 18 citizen-facing workloads. If the estate splits into multiple clusters, each cluster needs its own Velero configuration and backup schedule.
- Terraform state is stored in S3 with DynamoDB state locking (programme standard). Terraform state loss is a separate risk addressed by S3 versioning and cross-region replication.
- The 30-day Falco baseline loss on cluster rebuild is acceptable because Falco's default rules provide coverage during the re-baseline period. The risk of missed detections during re-baseline is accepted as a known operational gap.

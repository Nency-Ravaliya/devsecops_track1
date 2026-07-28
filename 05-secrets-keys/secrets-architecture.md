# Secrets & Key Management Architecture

## 1. Current State

The programme has **no centralised secrets management**. Module 1 found:
- **K8S-009:** Secrets committed as base64 data directly in manifests (High)
- **K8S-010:** Secrets injected as environment variables via `secretKeyRef` (High)
- **K8S-011:** No etcd encryption-at-rest configuration evidenced (High)
- **K8S-012:** No IRSA-equivalent workload identity boundary (High)
- **K8S-028:** API key baked into a Dockerfile ENV layer (High)

The current pattern is: a developer creates a `kind: Secret` YAML with base64-encoded values, commits it to Git, and the pipeline applies it to the cluster. The secret persists in Git history forever, sits unencrypted in etcd (or only Kubernetes-default encrypted), and has no rotation mechanism.

## 2. Comparison of Approaches

### 2.1 External Secrets Operator (ESO) + AWS Secrets Manager / Azure Key Vault / GCP Secret Manager

**How it works:** ESO is a Kubernetes operator that runs in-cluster and syncs secrets from an external cloud-native secrets manager into Kubernetes Secrets. Workload service accounts have cloud IAM permissions (IRSA on EKS) to fetch only their specific secrets.

| Aspect | Assessment |
|---|---|
| **Maturity** | ESO is CNCF Incubating (v0.10.x as of 2025). Battle-tested at scale. |
| **Operational complexity** | Low. ESO is a single Deployment + CRDs. No separate infrastructure to manage. |
| **Cloud integration** | Native: AWS Secrets Manager on EKS, Azure Key Vault on AKS, GCP Secret Manager on GKE. Same CRD (`ExternalSecret`) on all three clouds — only the `spec.refreshInterval` and `provider` block change. |
| **Secret rotation** | Cloud provider rotates secrets on their schedule. ESO polls at `refreshInterval` (configurable, default 1h) and updates the K8s Secret. Stakater Reloader can trigger pod restarts on change. |
| **Root of trust** | Cloud provider's KMS (AWS KMS, Azure Key Vault, GCP Cloud KMS). No additional key hierarchy to manage. |
| **Pricing** | ESO is open-source (Apache 2.0). Cloud secrets manager pricing is per-secret per-month (~$0.40/secret/month on AWS). |
| **Multi-cloud** | Excellent. Same CRD, different provider block. Secrets manager is the only cloud-specific component. |

### 2.2 HashiCorp Vault (with Vault Secrets Operator)

**How it works:** Vault is a standalone secrets management platform. It can run in-cluster or as a managed service (HashiCorp Cloud Platform). The Vault Secrets Operator (VSO) syncs Vault secrets into Kubernetes Secrets.

| Aspect | Assessment |
|---|---|
| **Maturity** | Vault is the industry standard for secrets management. CNCF Graduated. |
| **Operational complexity** | High. Vault requires: HA storage backend (Consul, Raft, or cloud storage), unsealing strategy, token management, policy authoring, and regular upgrades. Running Vault in HA on Kubernetes requires dedicated infrastructure (Raft storage nodes, separate namespace, PodDisruptionBudget). |
| **Cloud integration** | Vault supports AWS KMS, Azure Key Vault, GCP Cloud KMS as transit/backends, but it adds a layer of abstraction over them rather than using them natively. |
| **Secret rotation** | Vault has built-in dynamic secrets (generate short-lived DB credentials, AWS IAM keys). This is a genuine differentiator — ESO syncs static secrets, Vault generates ephemeral ones. |
| **Root of trust** | Vault's own unseal key hierarchy (Shamir's secret sharing or AWS KMS auto-unseal). An additional root of trust to manage on top of cloud KMS. |
| **Pricing** | Open-source (BSL license since 2023 — not pure open-source). Enterprise license for HA, namespaces, Sentinel policies. HCP Vault pricing starts at ~$1.58/hour. |
| **Multi-cloud** | Excellent — Vault is cloud-agnostic by design. But it requires running Vault infrastructure on each cloud or using HCP Vault as a central service. |

### 2.3 Sealed Secrets (Bitnami) / Mozilla SOPS

| Aspect | Assessment |
|---|---|
| **Maturity** | Sealed Secrets is stable but has limited activity. SOPS is mature for file-level encryption. |
| **Operational complexity** | Low for Sealed Secrets (single controller), moderate for SOPS (requires key management separately). |
| **Secret rotation** | Poor. Sealed Secrets rotation requires re-encrypting with the controller's key. No automated rotation — the secret is encrypted at rest in Git but not rotated. |
| **Dynamic secrets** | Not supported. Only static key-value secrets. |
| **Multi-cloud** | Good — both are Kubernetes-native or file-based, cloud-agnostic. |
| **Verdict** | Rejected for this programme. Sealed Secrets encrypts secrets for Git storage but does not solve rotation, dynamic secrets, or access control. It is a partial solution that adds complexity without addressing the core programme needs (rotation, cross-cloud portability, access control). |

### 2.4 Recommendation: ESO + Cloud Secrets Manager

**Trade-off call:** ESO is selected over Vault.

**Why ESO:**
1. **Multi-cloud portability is the primary constraint.** The programme is onboarding Azure and GCP within two quarters. ESO's `ExternalSecret` CRD is identical across all three clouds — only the provider configuration changes. Vault would require either running Vault infrastructure per cloud or adopting HCP Vault, adding cost and a new dependency.
2. **Operational maturity of the programme.** Module 1 found inconsistent RBAC, no NetworkPolicy, no runtime detection. Adding Vault's operational complexity (HA storage, unsealing, token lifecycle) on top of an immature security baseline is disproportionate.
3. **Cloud-native key hierarchy.** Using AWS KMS / Azure Key Vault / GCP Cloud KMS directly (via ESO) means the root of trust is the cloud provider's HSM-backed KMS, which already meets government compliance certifications (FIPS 140-2 Level 3). No additional key hierarchy to manage.

**When Vault becomes the right choice:** If the programme needs dynamic secrets (short-lived database credentials, auto-rotating AWS IAM keys) or cross-cloud secret sharing, Vault should be reconsidered. ESO handles static secrets; Vault handles dynamic ones. They are complementary, not mutually exclusive — Vault can be added later as the dynamic secrets layer while ESO remains the Kubernetes sync mechanism.

## 3. Architecture Design

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AWS Secrets Manager                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │ citizen- │  │ citizen- │  │ metadata │  │ COTS     │           │
│  │ frontend │  │ backend  │  │ db       │  │ vendor   │           │
│  │ /db-pass │  │ /api-key │  │ /vault   │  │ /license │           │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │
│         │              │              │              │               │
│    Encrypted with AWS KMS (FIPS 140-2 L3 HSM-backed)               │
└─────────────────────────┬───────────────────────────────────────────┘
                          │ IAM: IRSA per workload service account
                          │ (only reads its own secret path)
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    EKS Cluster (Cilium CNI)                         │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Namespace: external-secrets (dedicated)                       │  │
│  │ ┌──────────────────────────────────────────────────────────┐ │  │
│  │ │ External Secrets Operator (ESO) v0.10.x                  │ │  │
│  │ │ - Watches ExternalSecret CRDs across namespaces           │ │  │
│  │ │ - Syncs to native K8s Secret at refreshInterval (1h)     │ │  │
│  │ │ - IRSA role: ESO-external-secrets (read-only per path)   │ │  │
│  │ └──────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────────┐  ┌───────────────────────────────┐  │
│  │ Namespace: citizen-frontend│  │ Namespace: citizen-backend    │  │
│  │ ┌──────────────────────┐  │  │ ┌──────────────────────────┐ │  │
│  │ │ ExternalSecret CRD   │  │  │ │ ExternalSecret CRD       │ │  │
│  │ │ → K8s Secret (synced)│  │  │ │ → K8s Secret (synced)    │ │  │
│  │ └──────────┬───────────┘  │  │ └──────────┬───────────────┘ │  │
│  │            │ mounted as   │  │            │ mounted as       │  │
│  │            │ volume       │  │            │ volume           │  │
│  │ ┌──────────▼───────────┐  │  │ ┌──────────▼───────────────┐ │  │
│  │ │ frontend pods        │  │  │ │ backend pods             │ │  │
│  │ │ SA: frontend-sa      │  │  │ │ SA: backend-sa           │ │  │
│  │ │ IRSA: arn:aws:iam::  │  │  │ │ IRSA: arn:aws:iam::     │ │  │
│  │ │   :role/frontend-eso │  │  │ │   :role/backend-eso      │ │  │
│  │ └──────────────────────┘  │  │ └──────────────────────────┘ │  │
│  └───────────────────────────┘  └───────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## 4. Secret Rotation Strategy

### 4.1 Rotation Flow

```
Cloud Secrets Manager (source of truth)
  │  Auto-rotation policy enabled (90-day for API keys, 30-day for DB passwords)
  │
  ▼
ESO ExternalSecret (refreshInterval: 1h)
  │  ESO polls AWS Secrets Manager every hour
  │  Detects value change → updates K8s Secret
  │
  ▼
Kubernetes Secret (updated in-place)
  │
  ▼
Stakater Reloader (monitors K8s Secrets)
  │  Detects Secret change → triggers rolling restart of Deployment
  │  Pods get new secret value on next start
  │
  ▼
Application pod (new value)
```

### 4.2 Rotation Without Downtime

**Problem:** If a pod reads a secret at startup and never re-reads it, rotation requires a restart. Restarting all pods for a credential change causes downtime.

**Solutions by workload type:**

| Workload pattern | Rotation approach | Downtime |
|---|---|---|
| **Stateless HTTP services** (citizen-frontend, citizen-backend) | Stakater Reloader triggers rolling restart. With `maxSurge: 1, maxUnavailable: 0` on the Deployment, zero-downtime is achieved. | None (rolling update) |
| **Stateful workloads** (metadata-db) | Use a sidecar that watches the secret file and signals the main process (e.g. `SIGHUP` or custom reload endpoint). For PostgreSQL, `pg_reload_conf()` re-reads `pg_hba.conf` without restart. | None (hot reload) |
| **COTS vendor image** | The vendor image may not support hot reload. If it reads secrets at startup only, the rolling restart via Reloader is the only option. Document this as a known limitation — downtime is bounded by the pod's readiness probe timeout (~30s). | ~30s per pod |

### 4.3 Secret Refresh Intervals

| Secret type | Rotation interval | ESO refresh | Reloader action |
|---|---|---|---|
| Database passwords | 30 days (AWS Secrets Manager auto-rotation) | 1 hour | Rolling restart |
| API keys (external services) | 90 days (manual or provider-managed) | 1 hour | Rolling restart |
| TLS certificates | 90 days (AWS ACM or cert-manager) | 1 hour (or cert-manager handles) | Rolling restart |
| COTS vendor license | On vendor issuance (not auto-rotatable) | 1 hour | Rolling restart if changed |

## 5. Encryption Key Hierarchy

```
Cloud KMS (FIPS 140-2 Level 3 HSM-backed)
├── Root key (cloud-managed, never leaves HSM)
├── Data encryption key (DEK) — generated per secret version
│   ├── DEK encrypts the secret value in Secrets Manager
│   └── DEK itself encrypted by root key (envelope encryption)
│
├── IRSA role trust policy
│   ├── Root of trust: AWS IAM + OIDC provider for EKS
│   ├── Each workload SA gets an IAM role with minimal policy
│   │   ├── frontend-sa → arn:aws:iam::ACCOUNT:role/citizen-frontend-eso
│   │   │   └── Policy: Allow secretsmanager:GetSecretValue on arn:.../citizen/frontend/*
│   │   └── backend-sa → arn:aws:iam::ACCOUNT:role/citizen-backend-eso
│   │       └── Policy: Allow secretsmanager:GetSecretValue on arn:.../citizen/backend/*
│   └── No workload can read another workload's secrets (path-based IAM policy)
│
└── etcd encryption (defense-in-depth)
    ├── AWS: KMS envelope encryption enabled on EKS cluster creation
    ├── AKS: Azure Key Vault encryption provider
    └── GKE: Google-managed encryption (default) or CMEK
```

**Who/what can access the root of trust:**
- The cloud KMS root key is accessible only by cloud IAM principals with `kms:Decrypt` permission. No human has direct KMS access — it is mediated by IAM roles.
- ESO's IRSA role has `secretsmanager:GetSecretValue` only — no `kms:Decrypt` directly, no `secretsmanager:DeleteSecret`, no `secretsmanager:PutSecretValue`.
- Emergency break-glass access: a sealed envelope with KMS `kms:Decrypt` permission for a break-glass IAM user, stored in a physical safe. Used only if all IRSA roles are compromised.

## 6. Cross-Cloud Portability

| Component | AWS (EKS) | Azure (AKS) | GKE (Google) |
|---|---|---|---|
| **Secrets store** | AWS Secrets Manager | Azure Key Vault | GCP Secret Manager |
| **KMS** | AWS KMS | Azure Key Vault HSM | Cloud KMS |
| **Workload identity** | IRSA (IAM Roles for Service Accounts) | Azure Workload Identity | GKE Workload Identity |
| **ESO provider** | `secrets-manager` | `azurekv` | `gcpsm` |
| **ESO CRD** | `ExternalSecret` (identical) | `ExternalSecret` (identical) | `ExternalSecret` (identical) |
| **Secret format** | Key-value (JSON) | Key-value | Key-value |

**What changes per cloud:** Only the ESO `ExternalSecret` provider configuration and the cloud IAM role binding. The workload-side (K8s Secret mount, Reloader, pod spec) is identical across clouds. This is the core portability advantage of ESO over Vault — the Kubernetes-side interface never changes.

## 7. Existing Findings Remediation Traceability

| Module 1 Finding | How this architecture addresses it |
|---|---|
| **K8S-009** Secrets in manifests | Secrets are no longer in Git. ESO ExternalSecret CRDs reference the cloud secret path — the actual value is never in the repository. |
| **K8S-010** Secret as env var | Migrated to projected Secret volume mount. ESO syncs to K8s Secret, which is mounted as a volume with `defaultMode: 0400`. |
| **K8S-011** No etcd encryption | EKS cluster KMS encryption enabled (mandatory for new clusters; migration plan for existing clusters). AKS/GKE use their native encryption. |
| **K8S-012** No workload identity | IRSA for EKS, Azure Workload Identity for AKS, GKE Workload Identity for GKE. Each workload SA has a scoped IAM role. |
| **K8S-028** Secret in Dockerfile ENV | Removed from Dockerfile. Injected at runtime via projected volume mount from ESO-synced K8s Secret. |

## 8. Assumptions

- ESO v0.10.x is used because it supports all three cloud providers natively. Earlier versions may lack Azure or GCP support.
- Stakater Reloader 1.x is used for pod restart on secret change. It is a lightweight controller (~30MB memory) that watches K8s Secrets and triggers rolling restarts.
- AWS Secrets Manager auto-rotation uses Lambda-based rotation for database credentials. For API keys, rotation is manual (triggered by the provider or a cron job).
- The 1-hour ESO refresh interval is a balance between latency (how long until a rotated secret reaches the pod) and API call cost (polling Secrets Manager every minute would be expensive at 100+ workloads).
- etcd encryption is a defense-in-depth measure. If the attacker already has node-level access (K8S-004/005/006), etcd encryption does not prevent them from reading secrets via the API. The primary protection is workload identity and IAM scoping.

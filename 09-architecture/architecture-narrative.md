# Architecture Narrative

## HLD: High-Level Design — System Context

### Diagram Source
. . 
The HLD diagram is authored as Mermaid in `hld-diagram.mmd`. To render:

```bash
# Option 1: Mermaid CLI (npm install -g @mermaid-js/mermaid-cli)
mmdc -i hld-diagram.mmd -o hld-diagram.png -w 2400 -H 1600

# Option 2: Online editor
# Paste hld-diagram.mmd contents into https://mermaid.live
```

The `.mmd` source is the authoritative artifact. If rendering tooling is not available in the review environment, the Mermaid source is sufficient — a reviewer can view it at https://mermaid.live by pasting the file contents.

### Key Security Decisions Reflected in the Diagram

**1. Defence-in-depth: four independent security layers**

The diagram shows four distinct security mechanisms that each independently constrain what a workload can do:
- **Edge:** WAF + ALB — blocks known attack patterns before they reach the cluster (OWASP CRS 3.3)
- **Admission:** Kyverno — validates every pod specification at deploy time (image signature, security context, RBAC policies from Module 2)
- **Network:** Cilium NetworkPolicy — enforces default-deny between namespaces, blocks lateral movement (Module 4)
- **Runtime:** Falco — detects exploitation at runtime, triggers incident response (Module 3)

No single layer is sufficient. A vulnerability that bypasses the WAF is caught by admission policy. A policy violation that slips through admission is blocked by NetworkPolicy. A container that escapes NetworkPolicy is detected by Falco. This is the "assume breach" posture.

**2. Secrets never touch Git or container memory**

The diagram shows a direct path from AWS Secrets Manager → ESO → K8s Secret → pod volume mount. There is no arrow from Git to Secrets. This is the architectural guarantee behind K8S-009/010/028 remediation (Module 5): secrets flow from a managed store to the pod at runtime, never through the source repository or environment variables.

**3. Each workload has a unique identity and minimal access**

The diagram shows three separate IRSA roles (`frontend-eso`, `backend-eso`, `cots-vendor-eso`), each scoped to only the Secrets Manager path that workload needs. This is the architectural expression of K8S-012 remediation: no workload can read another workload's secrets, and no workload has cluster-wide API access.

**4. The COTS workload is isolated, not trusted**

The COTS namespace has its own SA, its own IRSA role, and a dedicated CiliumNetworkPolicy that restricts ingress to a single workload and egress to the egress proxy. The Kyverno admission policy only allows the COTS image by digest in that namespace. This is the architectural expression of Module 7's compensating controls.

**5. Pipeline security is a first-class component, not an afterthought**

The diagram includes the CI/CD pipeline (GitLab → Conftest → Trivy → Cosign) as a component with direct arrows to the cluster (Kyverno verifies signatures). This makes the supply chain security visible in the architecture, not hidden in a process document.

### Alternative HLD Approach Considered and Rejected

**Alternative: Centralised policy enforcement point (PEP) at ingress only**

An alternative design would place all security controls at the ingress layer — a single API gateway/WAF that handles authentication, authorization, rate limiting, and traffic inspection. Internal pod-to-pod traffic would be unrestricted.

**Why rejected:** This design has a single point of failure and does not address the trigger incident (K8S-001: a CI job with cluster-admin). A CI job does not go through the ingress layer — it talks directly to the API server. Centralised ingress security cannot prevent a compromised workload from reading Secrets in its own namespace (K8S-007) or modifying RBAC (K8S-001). The defence-in-depth approach in the selected HLD provides independent controls at every layer, ensuring that a failure at one layer does not leave the entire estate unprotected.

**Alternative: Service mesh (Istio) as the primary security layer**

An alternative would deploy Istio as the service mesh, using its mTLS, authorization policies, and telemetry as the primary security mechanism.

**Why rejected (Module 4 §2.3):** At 18 workloads, the operational cost of Istio's control plane and per-pod sidecars is disproportionate. Cilium provides equivalent mTLS (WireGuard), equivalent authorization (CiliumNetworkPolicy), and better observability (Hubble) without sidecar overhead. The programme can add Istio later if the workload count grows beyond 50.

---

## LLD: Low-Level Design — Citizen-Frontend → Citizen-Backend Request Path

### Diagram Source

The LLD diagram is authored as Mermaid in `lld-diagram.mmd`. Render using the same instructions as the HLD diagram. The `.mmd` source is the authoritative artifact.

### Scope

This LLD traces a single request from a citizen's browser through the full security stack to the backend data store, detailing every security control, identity, and encryption point along the path. It is the implementable detail behind the HLD's system-context view.

### Walkthrough: Request Path

**Step 1: Citizen → ALB (External)**

The citizen sends an HTTPS request to the application URL. AWS WAF v2 inspects the request against OWASP CRS 3.3 rules (SQL injection, XSS, SSRF, path traversal). Blocked requests never reach the cluster. Allowed requests pass to the ALB, which terminates TLS and forwards HTTP to the `citizen-frontend` namespace.

**Step 2: ALB → Frontend Pod (Ingress NetworkPolicy)**

Cilium NetworkPolicy in `citizen-frontend` allows ingress ONLY from the ALB node security group on TCP/443. All other ingress is denied by default. The ALB passes the request to a frontend pod selected by the Service endpoint.

**Step 3: Frontend Pod (Security Context)**

The frontend container runs with:
- `runAsNonRoot: true`, `runAsUser: 1000` — not root
- `readOnlyRootFilesystem: true` — filesystem is immutable
- `allowPrivilegeEscalation: false` — no capability escalation
- `capabilities.drop: [ALL]` — no Linux capabilities
- `seccompProfile: RuntimeDefault` — syscall filtering via kernel

The pod mounts secrets from the K8s Secret (synced by ESO from AWS Secrets Manager) as a projected volume at `/etc/secrets` with file permissions `0400`. The secret values are never in environment variables.

**Step 4: Frontend → Backend (Egress NetworkPolicy + Cilium mTLS)**

The frontend sends a gRPC request to the backend on TCP/8080. Cilium NetworkPolicy in `citizen-frontend` allows egress only to `citizen-backend` pods on TCP/8080. Cilium WireGuard provides transparent encryption for the in-transit data. The backend is identified by Cilium's SPIFFE-based pod identity — impersonation is not possible.

**Step 5: Backend Pod (Security Context + Secrets)**

The backend container runs with the same restricted security context as the frontend. It reads its database credentials from a projected volume mount (ESO → K8s Secret → `/etc/secrets/db-credentials`).

**Step 6: Backend → RDS (Egress NetworkPolicy + TLS)**

The backend connects to RDS PostgreSQL on TCP/5432. Cilium NetworkPolicy allows egress from `citizen-backend` to any IP in the VPC CIDR on TCP/5432 only. The RDS connection uses TLS (enforced by RDS parameter `rds.force_ssl = 1`). RDS data is encrypted at rest using AWS KMS envelope encryption. RDS runs in Multi-AZ for availability.

**Step 7: Secrets Flow (ESO → IRSA → Secrets Manager)**

At startup (and every 1 hour), ESO polls AWS Secrets Manager for the backend's database password. ESO authenticates to AWS via IRSA — the `backend-sa` ServiceAccount has an IAM role with `secretsmanager:GetSecretValue` permission scoped to `arn:aws:secretsmanager:eu-west-2:123:secret:citizen/backend/*` only. ESO writes the value to a K8s Secret. The backend pod reads it from the projected volume. The value is never in Git, never in environment variables, and never visible to other workloads.

**Step 8: Pipeline → Admission (Supply Chain Verification)**

Before the backend pod was deployed, the CI pipeline (Module 2) verified:
- Conftest OPA Rego: RBAC policy compliant (K8S-001/002/003 check)
- Conftest OPA Rego: Pod security compliant (K8S-004/005/006 check)
- Trivy: zero Critical CVEs with fix available
- Cosign: image signed with programme KMS key
- SBOM: CycloneDX attestation attached to image

At admission time, Kyverno verifies:
- Image signature matches the programme's Cosign public key
- Image is pinned by digest (not tag)
- Pod security context meets Restricted baseline
- ServiceAccount is explicitly specified (not default)

**Step 9: Runtime Monitoring**

Throughout the request lifecycle, Falco monitors the pods for:
- P1: Container escape indicators, RBAC mutations
- P2: Binary drift, unexpected network connections, shell spawns
- P3: Root execution in non-system namespace

Alerts flow to PagerDuty (P1), Slack (P2), and CloudWatch Logs (all). K8s audit logs capture all API server interactions.

### IAM Permission Detail

| IAM Role | Service Account | Policy | Permissions |
|---|---|---|---|
| `citizen-frontend-eso` | `frontend-sa` in `citizen-frontend` | Inline: `frontend-eso-policy` | `secretsmanager:GetSecretValue` on `arn:...:secret:citizen/frontend/*` only |
| `citizen-backend-eso` | `backend-sa` in `citizen-backend` | Inline: `backend-eso-policy` | `secretsmanager:GetSecretValue` on `arn:...:secret:citizen/backend/*` only |
| `cots-vendor-eso` | `cots-vendor-sa` in `cots-vendor` | Inline: `cots-vendor-eso-policy` | `secretsmanager:GetSecretValue` on `arn:...:secret:cots-vendor/*` only |
| `falco-detector` | `falco` in `falco-system` | AWS managed: `CloudWatchAgentServerPolicy` | `logs:PutLogEvents`, `logs:CreateLogGroup`, `logs:CreateLogStream` |

No workload can assume another workload's IAM role. No workload can read another workload's secrets. No workload has `kms:Decrypt` directly — KMS access is mediated by Secrets Manager.

### Port/Protocol Detail

| Source | Destination | Port | Protocol | Cilium Policy |
|---|---|---|---|---|
| Internet | ALB | 443 | TCP (HTTPS) | AWS SG (not Cilium) |
| ALB nodes | frontend pods | 443 | TCP | Ingress: ALB SG → frontend |
| frontend pods | backend pods | 8080 | TCP (gRPC) | Egress: frontend → backend TCP/8080 |
| backend pods | RDS | 5432 | TCP (PostgreSQL+TLS) | Egress: backend → VPC CIDR TCP/5432 |
| cots pods | backend pods | 8443 | TCP (HTTPS) | Ingress: backend → cots TCP/8443 only |
| cots pods | egress-proxy | 443 | TCP (HTTPS) | Egress: cots → egress-proxy TCP/443 only |
| All pods | kube-dns | 53 | UDP+TCP | Egress: all → kube-system DNS |

### Encryption Points

| Data state | Where | Mechanism |
|---|---|---|
| In transit: citizen → ALB | Internet | TLS 1.2+ (AWS ACM certificate) |
| In transit: ALB → pod | VPC | HTTP (within VPC — private network, no public exposure) |
| In transit: pod → pod | Cluster | Cilium WireGuard (transparent, kernel-level) |
| In transit: pod → RDS | VPC | TLS 1.2+ (RDS enforced SSL) |
| At rest: Secrets Manager | AWS | AWS KMS envelope encryption (FIPS 140-2 L3) |
| At rest: etcd (K8s Secrets) | EKS | KMS envelope encryption (defense-in-depth) |
| At rest: RDS | AWS | KMS envelope encryption (AES-256) |
| At rest: container filesystem | Node | Read-only root filesystem (emptyDir for /tmp only) |

### Alternative LLD Approach Considered and Rejected

**Alternative: Mutual TLS via Istio sidecar proxy**

An alternative would inject Istio's Envoy sidecar into every pod, providing mTLS between all services and detailed L7 metrics.

**Why rejected:** The LLD shows that Cilium WireGuard provides the same in-transit encryption at the kernel level without sidecar overhead (no extra 50MB memory per pod, no additional latency hop). For L7 observability, Hubble provides sufficient flow-level visibility. If L7 metrics become needed (e.g. per-request latency for canary analysis), Istio can be added as a future enhancement without changing the existing NetworkPolicy or IAM architecture.

---

## LLD: Low-Level Design — Citizen-Frontend → Citizen-Backend Request Path

### Diagram Source

The LLD diagram is authored as Mermaid in `lld-diagram.mmd`. Render using the same instructions as the HLD diagram. The `.mmd` source is the authoritative artifact.

### Scope

This LLD traces a single request from a citizen's browser through the full security stack to the backend data store, detailing every security control, identity, and encryption point along the path. It is the implementable detail behind the HLD's system-context view.

### Walkthrough: Request Path

**Step 1: Citizen → ALB (External)**

The citizen sends an HTTPS request to the application URL. AWS WAF v2 inspects the request against OWASP CRS 3.3 rules (SQL injection, XSS, SSRF, path traversal). Blocked requests never reach the cluster. Allowed requests pass to the ALB, which terminates TLS and forwards HTTP to the `citizen-frontend` namespace.

**Step 2: ALB → Frontend Pod (Ingress NetworkPolicy)**

Cilium NetworkPolicy in `citizen-frontend` allows ingress ONLY from the ALB node security group on TCP/443. All other ingress is denied by default. The ALB passes the request to a frontend pod selected by the Service endpoint.

**Step 3: Frontend Pod (Security Context)**

The frontend container runs with:
- `runAsNonRoot: true`, `runAsUser: 1000` — not root
- `readOnlyRootFilesystem: true` — filesystem is immutable
- `allowPrivilegeEscalation: false` — no capability escalation
- `capabilities.drop: [ALL]` — no Linux capabilities
- `seccompProfile: RuntimeDefault` — syscall filtering via kernel

The pod mounts secrets from the K8s Secret (synced by ESO from AWS Secrets Manager) as a projected volume at `/etc/secrets` with file permissions `0400`. The secret values are never in environment variables.

**Step 4: Frontend → Backend (Egress NetworkPolicy + Cilium mTLS)**

The frontend sends a gRPC request to the backend on TCP/8080. Cilium NetworkPolicy in `citizen-frontend` allows egress only to `citizen-backend` pods on TCP/8080. Cilium WireGuard provides transparent encryption for the in-transit data. The backend is identified by Cilium's SPIFFE-based pod identity — impersonation is not possible.

**Step 5: Backend Pod (Security Context + Secrets)**

The backend container runs with the same restricted security context as the frontend. It reads its database credentials from a projected volume mount (ESO → K8s Secret → `/etc/secrets/db-credentials`).

**Step 6: Backend → RDS (Egress NetworkPolicy + TLS)**

The backend connects to RDS PostgreSQL on TCP/5432. Cilium NetworkPolicy allows egress from `citizen-backend` to any IP in the VPC CIDR on TCP/5432 only. The RDS connection uses TLS (enforced by RDS parameter `rds.force_ssl = 1`). RDS data is encrypted at rest using AWS KMS envelope encryption. RDS runs in Multi-AZ for availability.

**Step 7: Secrets Flow (ESO → IRSA → Secrets Manager)**

At startup (and every 1 hour), ESO polls AWS Secrets Manager for the backend's database password. ESO authenticates to AWS via IRSA — the `backend-sa` ServiceAccount has an IAM role with `secretsmanager:GetSecretValue` permission scoped to `arn:aws:secretsmanager:eu-west-2:123:secret:citizen/backend/*` only. ESO writes the value to a K8s Secret. The backend pod reads it from the projected volume. The value is never in Git, never in environment variables, and never visible to other workloads.

**Step 8: Pipeline → Admission (Supply Chain Verification)**

Before the backend pod was deployed, the CI pipeline (Module 2) verified:
- Conftest OPA Rego: RBAC policy compliant (K8S-001/002/003 check)
- Conftest OPA Rego: Pod security compliant (K8S-004/005/006 check)
- Trivy: zero Critical CVEs with fix available
- Cosign: image signed with programme KMS key
- SBOM: CycloneDX attestation attached to image

At admission time, Kyverno verifies:
- Image signature matches the programme's Cosign public key
- Image is pinned by digest (not tag)
- Pod security context meets Restricted baseline
- ServiceAccount is explicitly specified (not default)

**Step 9: Runtime Monitoring**

Throughout the request lifecycle, Falco monitors the pods for:
- P1: Container escape indicators, RBAC mutations
- P2: Binary drift, unexpected network connections, shell spawns
- P3: Root execution in non-system namespace

Alerts flow to PagerDuty (P1), Slack (P2), and CloudWatch Logs (all). K8s audit logs capture all API server interactions.

### IAM Permission Detail

| IAM Role | Service Account | Policy | Permissions |
|---|---|---|---|
| `citizen-frontend-eso` | `frontend-sa` in `citizen-frontend` | Inline: `frontend-eso-policy` | `secretsmanager:GetSecretValue` on `arn:...:secret:citizen/frontend/*` only |
| `citizen-backend-eso` | `backend-sa` in `citizen-backend` | Inline: `backend-eso-policy` | `secretsmanager:GetSecretValue` on `arn:...:secret:citizen/backend/*` only |
| `cots-vendor-eso` | `cots-vendor-sa` in `cots-vendor` | Inline: `cots-vendor-eso-policy` | `secretsmanager:GetSecretValue` on `arn:...:secret:cots-vendor/*` only |
| `falco-detector` | `falco` in `falco-system` | AWS managed: `CloudWatchAgentServerPolicy` | `logs:PutLogEvents`, `logs:CreateLogGroup`, `logs:CreateLogStream` |

No workload can assume another workload's IAM role. No workload can read another workload's secrets. No workload has `kms:Decrypt` directly — KMS access is mediated by Secrets Manager.

### Port/Protocol Detail

| Source | Destination | Port | Protocol | Cilium Policy |
|---|---|---|---|---|
| Internet | ALB | 443 | TCP (HTTPS) | AWS SG (not Cilium) |
| ALB nodes | frontend pods | 443 | TCP | Ingress: ALB SG → frontend |
| frontend pods | backend pods | 8080 | TCP (gRPC) | Egress: frontend → backend TCP/8080 |
| backend pods | RDS | 5432 | TCP (PostgreSQL+TLS) | Egress: backend → VPC CIDR TCP/5432 |
| cots pods | backend pods | 8443 | TCP (HTTPS) | Ingress: backend → cots TCP/8443 only |
| cots pods | egress-proxy | 443 | TCP (HTTPS) | Egress: cots → egress-proxy TCP/443 only |
| All pods | kube-dns | 53 | UDP+TCP | Egress: all → kube-system DNS |

### Encryption Points

| Data state | Where | Mechanism |
|---|---|---|
| In transit: citizen → ALB | Internet | TLS 1.2+ (AWS ACM certificate) |
| In transit: ALB → pod | VPC | HTTP (within VPC — private network, no public exposure) |
| In transit: pod → pod | Cluster | Cilium WireGuard (transparent, kernel-level) |
| In transit: pod → RDS | VPC | TLS 1.2+ (RDS enforced SSL) |
| At rest: Secrets Manager | AWS | AWS KMS envelope encryption (FIPS 140-2 L3) |
| At rest: etcd (K8s Secrets) | EKS | KMS envelope encryption (defense-in-depth) |
| At rest: RDS | AWS | KMS envelope encryption (AES-256) |
| At rest: container filesystem | Node | Read-only root filesystem (emptyDir for /tmp only) |

### Alternative LLD Approach Considered and Rejected

**Alternative: Mutual TLS via Istio sidecar proxy**

An alternative would inject Istio's Envoy sidecar into every pod, providing mTLS between all services and detailed L7 metrics.

**Why rejected:** The LLD shows that Cilium WireGuard provides the same in-transit encryption at the kernel level without sidecar overhead (no extra 50MB memory per pod, no additional latency hop). For L7 observability, Hubble provides sufficient flow-level visibility. If L7 metrics become needed (e.g. per-request latency for canary analysis), Istio can be added as a future enhancement without changing the existing NetworkPolicy or IAM architecture.

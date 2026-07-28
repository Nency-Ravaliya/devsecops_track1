# Zero-Trust Network Design

## 1. Current State

The programme runs the **default AWS VPC CNI** on EKS managed node groups with **no NetworkPolicy enforcement** (K8S-015). Any pod can communicate with any other pod across all namespaces. The only network controls are VPC-level security groups and subnet routing. This is the single largest unmitigated lateral-movement risk across the 18 EKS workloads.

Module 1 found:
- **K8S-015:** No NetworkPolicy resources exist anywhere (High)
- **K8S-016:** Internal service exposed as NodePort 30003 (High)
- **K8S-017:** Access scripts bind port-forwards to 0.0.0.0 (High)
- **K8S-006:** DaemonSet with hostNetwork bypasses any NetworkPolicy entirely (Critical)

## 2. Target-State Network Design

### 2.1 Default-Deny NetworkPolicy Baseline

Every namespace in the cluster starts with a default-deny policy that blocks all ingress and egress, then applications explicitly declare what they need:

```yaml
# Applied to every workload namespace via namespace label + Kyverno policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: citizen-frontend
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

**Exception process for development namespaces:**

| Namespace tier | Default policy | Exception process |
|---|---|---|
| `production-*` | Default-deny all | Exceptions require security team MR review (same CODEOWNERS as pipeline policy changes from Module 2) |
| `staging-*` | Default-deny all | Exceptions require platform team approval |
| `development-*` | Default-allow all (current state) | Logged in compliance tracker; migrated to default-deny on a 90-day rolling schedule as NetworkPolicies are authored per-workload |

**Why not default-deny everywhere from day one:** Blocking all traffic without ready-made policies for 18 workloads would cause outages. The rollout strategy is: instrument traffic with Cilium Hubble for 2 weeks to observe real flows, then generate NetworkPolicies from observed flows, then enforce default-deny.

### 2.2 CNI Decision: Cilium 1.16.x as EKS CNI Replacement

The programme currently uses the default AWS VPC CNI. To enforce NetworkPolicy, the CNI must be replaced or augmented. The choice:

**Selected: Cilium 1.16.x** (replacing AWS VPC CNI as the primary CNI on EKS).

| Option | Verdict |
|---|---|
| **Cilium 1.16.x** | Selected. Provides NetworkPolicy enforcement (eBPF-based, kernel 5.10+), Hubble for network flow observability, transparent mTLS (via Cilium's SPIFFE-based identity), and eBPF-based service mesh capabilities. EKS-optimized via the [Cilium on EKS via Helm](https://docs.cilium.io/en/stable/network/concepts/) documented path. Replaces AWS VPC CNI with Cilium's ENI mode to preserve VPC-native pod networking. |
| **Calico 3.28.x** | Strong NetworkPolicy enforcement, but lacks built-in flow observability and service mesh. Would need separate observability (e.g. Hubble alternative) and a separate mesh (Istio/Linkerd) if the programme decides mesh is needed. More operational overhead. |
| **Keep AWS VPC CNI + Calico add-on** | AWS offers Calico as an optional EKS add-on. Less disruption, but dual-CNI management adds complexity and performance overhead. Does not provide the observability (Hubble) needed for NetworkPolicy authoring. |
| **Tetragon only (no Cilium CNI)** | Tetragon is the enforcement/detection companion to Cilium. Without Cilium as CNI, Tetragon's network policy enforcement features are unavailable. |

**EKS-specific deployment:** Cilium is installed via Helm into the `kube-system` namespace with `--set eni.enabled=true --set ipam.mode=eni` for VPC-native networking. AWS VPC CNI is uninstalled after Cilium is confirmed healthy. This is a documented, supported EKS configuration.

**Multi-cloud portability:**
- **AKS:** Azure supports Cilium as the default CNI (Azure CNI Powered by Cilium). Drop-in replacement.
- **GKE:** GKE Dataplane V2 uses Cilium as the data plane. NetworkPolicy enforcement is native. Cilium Helm install is supported as an add-on.
- **Net:** Cilium is the most portable choice across all three cloud Kubernetes services.

### 2.3 Service Mesh Assessment: Honest For-And-Against

**Recommendation: Do NOT deploy a service mesh (Istio/Linkerd) at this time. Deploy Cilium's lightweight mTLS and policy engine instead.**

#### Against a full service mesh (Istio / Linkerd):

| Factor | Assessment |
|---|---|
| **Workload count** | 18 EKS workloads is too few to justify the operational cost of Istio's control plane (istiod + sidecar injection per pod). Each sidecar adds ~50MB memory and ~2ms p99 latency per hop. |
| **Traffic patterns** | Citizen-facing with unpredictable traffic means the mesh's traffic management features (canary routing, traffic splitting) are less valuable — these workloads aren't doing service-to-service retries at scale. |
| **Team maturity** | The programme has inconsistent RBAC (Module 1), no NetworkPolicy (K8S-015), and no runtime detection (Module 3 current state). Adding a service mesh on top of an immature security baseline multiplies operational risk without fixing the foundation. |
| **Upgrade burden** | Istio control-plane upgrades require careful rollout and have broken workloads in production for organisations with fewer than ~50 services. At 18 workloads, the upgrade cost per workload is disproportionately high. |
| **Multi-cloud** | Istio works on all three clouds, but each cloud's managed Kubernetes has its own mesh offering (EKS App Mesh is deprecated, AKS has Open Service Mesh add-on, GKE has Anthos Service Mesh). Istio avoids lock-in but adds self-management. |

#### What a mesh WOULD provide (and how Cilium covers it instead):

| Mesh capability | Cilium equivalent |
|---|---|
| **mTLS between services** | Cilium's WireGuard-based encryption (transparent, kernel-level, no sidecar) covers in-transit encryption. For mutual authentication, Cilium's SPIFFE-based identity provides service-to-service identity verification. |
| **Authorization policies** (allow pod A to call pod B) | Cilium's `CiliumNetworkPolicy` with `toServices` and L7 rules provides fine-grained access control without sidecars. |
| **Observability** (request-level metrics) | Hubble (bundled with Cilium) provides L3/L4/L7 flow visibility, request latency, and error rates. |

**When to revisit mesh:** If the programme grows to 50+ workloads or needs advanced traffic management (A/B testing, fine-grained canary), Istio or Linkerd should be reassessed. Cilium's architecture makes adding Istio later straightforward (Cilium can serve as Istio's CNI and dataplane).

### 2.4 Ingress and Egress Control

#### Ingress

| Component | Design |
|---|---|
| **AWS Load Balancer Controller** | Remains the primary ingress path for external traffic. Deploys ALBs per Ingress resource. |
| **WAF integration** | AWS WAF v2 attached to ALBs for citizen-facing workloads. OWASP Core Rule Set (CRS) 3.3 for SQL injection, XSS, and SSRF protection. |
| **Ingress NetworkPolicy** | Cilium `CiliumNetworkPolicy` allows ingress ONLY from the ALB node IP ranges to the workload pods on the application port. Blocks all other ingress. |
| **NodePort lockdown** | K8S-016 (NodePort 30003) remediated: NodePort services are banned via Kyverno admission policy (`ClusterPolicy/deny-nodeport`). Existing NodePort services converted to ClusterIP + ALB Ingress. |

#### Egress

| Component | Design |
|---|---|
| **Default-deny egress** | All production namespaces have `policyTypes: [Egress]` with no egress rules by default. |
| **Approved egress destinations** | Each workload namespace gets a Cilium `CiliumNetworkPolicy` allowing egress to only: (a) its own namespace (service-to-service), (b) kube-dns (`kube-system/kube-dns`), (c) approved external endpoints (database, API gateway, cloud services). |
| **Internet egress control** | Workloads that should NOT access the internet (internal services, backend APIs) get egress policies that only allow traffic to private CIDRs (VPC CIDR, peered VPCs). All other egress is blocked. |
| **Egress proxy** | For workloads that DO need internet access (e.g. external API calls for citizen-facing services), traffic routes through a dedicated egress proxy namespace (`egress-proxy`) with explicit allowlists. Squid or Envoy-based, running as a Deployment with restrictive NetworkPolicy. |

### 2.5 Port and Protocol Detail

| Flow | Allowed source → destination | Ports/protocols | Policy |
|---|---|---|---|
| External → citizen-frontend | ALB SG → pod | TCP/443 (HTTPS) | `CiliumNetworkPolicy` ingress + ALB listener |
| citizen-frontend → citizen-backend | Frontend pods → backend pods (same namespace) | TCP/8080 (gRPC) | Namespace-level egress within `citizen-frontend` |
| citizen-backend → postgres | Backend pods → RDS (VPC CIDR) | TCP/5432 (PostgreSQL) | Egress to VPC CIDR only, Cilium L4 |
| citizen-frontend → internet (external API) | Frontend pods → egress-proxy → internet | TCP/443 (HTTPS) | Egress to `egress-proxy` namespace only |
| kube-dns access | All pods → kube-system/kube-dns | UDP/53, TCP/53 | Egress to `kube-system` namespace |
| Everything else | — | — | **Denied by default** |

## 3. How This Design Changes Across Clouds

| Component | EKS (current) | AKS (Azure) | GKE (Google) |
|---|---|---|---|
| **CNI** | Cilium in ENI mode (replaces VPC CNI) | Azure CNI Powered by Cilium (native) | GKE Dataplane V2 (Cilium-based, native) |
| **NetworkPolicy enforcement** | Cilium eBPF | Azure CNI + Cilium (or Azure NetworkPolicy) | GKE Dataplane V2 native |
| **Ingress** | AWS Load Balancer Controller + ALB | Azure Application Gateway Ingress Controller + WAF | GKE Ingress + Cloud Armor WAF |
| **Egress proxy** | Squid on EC2 or EKS Deployment | Squid on AKS (same design) | Squid on GKE (same design) |
| **mTLS / encryption** | Cilium WireGuard | Cilium WireGuard (native on AKS) | Cilium WireGuard or GKE-managed |

**Net:** Cilium is the consistent networking layer across all three clouds. The NetworkPolicy definitions are identical. Only the ingress controller and WAF provider change per cloud.

## 4. Rollout Plan

| Phase | Timeframe | What happens |
|---|---|---|
| **Phase 1: Observability** | Week 1-2 | Deploy Cilium with Hubble in observation-only mode. Capture real traffic flows across all 18 workloads. No policies enforced yet. |
| **Phase 2: Policy authoring** | Week 3-4 | Generate NetworkPolicies from Hubble flow data. Review with workload teams. Test in staging. |
| **Phase 3: Production enforcement** | Week 5-6 | Enable default-deny on production namespaces, one at a time. Start with `citizen-frontend` (highest exposure), then backends. |
| **Phase 4: Egress lockdown** | Week 7-8 | Add egress policies. Deploy egress proxy for workloads needing internet access. |
| **Phase 5: NodePort and admission** | Week 9-10 | Enforce Kyverno `deny-nodeport` admission policy. Convert existing NodePort services. |
| **Phase 6: Multi-cloud** | Quarter 2+ | Deploy Cilium on AKS/GKE clusters using same policies. |

## 5. Assumptions

- EKS nodes run kernel 5.10+ (Amazon Linux 2 or Bottlerocket) for Cilium eBPF support. EKS 1.29+ with AL2023 or Bottlerocket satisfies this.
- Cilium ENI mode preserves VPC-native pod networking, so existing VPC flow logs, security groups, and VPC endpoints continue to work. This avoids a disruptive IP range change.
- The egress proxy is a single point of failure for internet-bound traffic. It should be deployed with at least 2 replicas across AZs, with PodDisruptionBudget minAvailable=1.
- The Kyverno `deny-nodeport` policy is a hard blocker for existing NodePort services. The programme must have a backlog item to convert K8S-016 before enabling this policy.

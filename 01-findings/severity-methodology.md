# Severity Rating Methodology

## Scope

This methodology is used for Module 1 findings against the cloned `reference-target/` copy of kubernetes-goat. Ratings are deliberately calibrated for the programme context: ~18 EKS workloads today, mostly citizen-facing, with no cluster-wide admission controller, inconsistent namespace RBAC, no centralised secrets management, default AWS VPC CNI without NetworkPolicy enforcement, and no runtime detection. Azure AKS and GKE onboarding is expected within two quarters, so the rubric avoids AWS-only assumptions unless the finding is specifically about the AWS KinD/CDK setup.

The register uses stable IDs in the form `K8S-NNN`. Later modules must reference these IDs exactly.

## Rating Model

Severity is a practitioner judgement based on **impact × likelihood**, with explicit modifiers for blast radius, exploit preconditions, detectability, and time-to-governance-sign-off.

### Impact Bands

| Impact | Definition in this programme |
|---|---|
| **Very High** | Plausible cluster-wide compromise, node takeover, access to secrets across namespaces, or ability to create persistent privileged access. This includes anything that can recreate the trigger incident: a non-system principal acquiring `cluster-admin` or equivalent. |
| **High** | Namespace compromise, host-level access on at least one node, material exposure of application secrets, or externally reachable workload weakness that could be chained to privilege escalation. |
| **Medium** | Weakening of baseline controls that increases exploitability or operational blast radius, but normally requires another bug/misconfiguration to cause material compromise. |
| **Low** | Hygiene issue, documentation/config drift, or weak default that should be fixed but is unlikely to drive compromise on its own before the next migration wave. |

### Likelihood Bands

| Likelihood | Definition in this programme |
|---|---|
| **Very High** | Directly exploitable from a pod, CI job, or reachable service with no special cluster knowledge; or likely to recur because there is no preventive control such as admission policy. |
| **High** | Exploitable by a compromised workload, developer pipeline, or namespace operator; uses common Kubernetes primitives and requires little specialist capability. |
| **Medium** | Requires a foothold, specific namespace access, or operational mistake; still realistic in a 100-workload estate. |
| **Low** | Requires privileged access already, lab-only paths, or unlikely deployment choices; mainly important as governance evidence. |

## Severity Definitions

| Severity | Criteria | Examples |
|---|---|---|
| **Critical** | Very High impact and High/Very High likelihood, especially where compromise crosses namespace boundaries or reaches the node/control plane. Must normally be remediated or formally risk-accepted before governance sign-off. | `cluster-admin` binding to a workload/CI service account; wildcard ClusterRole bound via ClusterRoleBinding; privileged pod with host root filesystem mounted read-write; container runtime socket mounted into a privileged container. |
| **High** | High or Very High impact with Medium likelihood, or Medium impact with Very High likelihood. Must have a funded remediation path before go-live. | Secrets in manifests, broad namespace read access to secrets, NodePort exposure, unpinned images in production manifests, no NetworkPolicy posture in an estate with citizen-facing workloads. |
| **Medium** | Medium impact and Medium/High likelihood. Fix through platform guardrails and backlog before broad migration, but may not block go-live if compensating controls exist. | Missing resource requests, missing seccomp on otherwise normal pods, outdated tooling used only in lab setup, broad egress from a lab EC2 host. |
| **Low** | Low impact or low likelihood. Track as hygiene, documentation, or baseline drift. Should not consume urgent migration capacity unless bundled with related work. | Hardcoded demo URLs, placeholder `.env` templates without real credentials. |

## One-Notch Rule

Every finding includes a one-line rationale explaining why the rating is not one notch higher or lower:

- **Why not higher:** what prevents immediate wider compromise, such as namespace scope, read-only mount, lab-only provisioning path, or need for an existing foothold.
- **Why not lower:** what makes the issue material in this environment, such as citizen-facing workloads, no admission control, no runtime detection, inconsistent RBAC, or a repeat pattern matching the trigger incident.

## Remediation Effort Scale

| Estimate | Meaning |
|---|---|
| **Hours** | Manifest/policy change with limited blast radius; can be reviewed and merged in a normal sprint. |
| **1-2 days** | Requires testing across one namespace/workload, pipeline update, or platform policy rollout. |
| **3-5 days** | Requires cluster-level control, staged rollout, exception handling, or coordination with platform teams. |
| **1-2 weeks** | Requires platform architecture change, multi-team adoption, or migration to a managed control-plane capability. |

## Tooling Assumptions for Later Modules

The target-state controls referenced in remediation will assume:

- **Policy as code:** Kyverno 1.13.x or OPA Gatekeeper 3.17.x; the assessment will prefer Kyverno for Kubernetes-native policy ergonomics unless Module 2/6 chooses otherwise.
- **Runtime detection:** Falco 0.38.x or equivalent eBPF runtime detection, with Kubernetes audit log enrichment where available.
- **Image provenance:** Cosign 2.4.x / Sigstore policy checks, SBOM via Syft 1.x, vulnerability scanning via Trivy 0.55+ or Grype 0.79+.
- **EKS baseline:** `aws-ia/terraform-aws-eks-blueprints` as the hardened AWS target-state pattern, with controls expressed so they can map to AKS/GKE without a redesign.

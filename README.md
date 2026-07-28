# DevSecOps Assessment — Track 1

## Executive Summary

### Overall Risk Posture: High — Remediable Before Go-Live

This submission presents a comprehensive security review and target-state design for the programme's ~100-workload Kubernetes estate (~18 on EKS). The assessment was conducted against a kubernetes-goat reference target and interpreted against the real programme context.

**Key findings:** 28 security findings identified — **6 Critical, 12 High, 7 Medium, 1 Low**. The most severe finding (K8S-001) directly mirrors the trigger incident: a `ClusterRoleBinding` granting `cluster-admin` to a CI job's ServiceAccount, enabling full cluster compromise from any workload.

**What's fixable before the migration wave (next quarter):**
- All 6 Critical findings (RBAC over-permissioning, privileged containers, host filesystem access) — estimated 2-3 weeks of focused remediation
- 8 of 12 High findings (secrets in manifests, unpinned images, missing admission controls) — achieved through the platform rollout described in the 30/60/90-day plan

**Accepted residual risk:**
- COTS vendor image with unpatched Critical CVEs and root execution — compensating controls (network isolation, runtime detection, admission restrictions, weekly scanning) reduce residual risk to Medium. Formal ITSO acceptance required before go-live.
- Full NetworkPolicy enforcement — requires Cilium CNI migration on EKS (6-week phased plan), with interim compensating controls via VPC security groups.

**Target-state architecture:** Defence-in-depth across four independent layers: edge (WAF + ALB), admission (Kyverno), network (Cilium NetworkPolicy + WireGuard mTLS), and runtime (Falco 0.38.x detection). Supply chain secured via Conftest OPA policies, Trivy scanning, Cosign image signing, and a 6-stage GitLab CI/CD pipeline with hard-fail gates on Critical/High findings. Secrets managed via External Secrets Operator + cloud-native secrets managers, portable across AWS/Azure/GCP.

**Recommendation:** Approve the 30/60/90-day implementation plan and COTS risk acceptance to proceed with the migration wave.

## Programme Context

Multi-cloud government programme running ~100 workloads on AWS (Terraform + GitLab CI/CD), split across two EKS landing zone tiers. Azure and GCP onboarding on the roadmap within two quarters. ~18 workloads on EKS run citizen-facing services with unpredictable traffic. The trigger incident was an audit finding: a `ClusterRoleBinding` granting `cluster-admin` to a CI job's service account.

## Reference Repository

**Chosen: [kubernetes-goat](https://github.com/madhuakula/kubernetes-goat)** (cloned, not forked — see note below)

### Why kubernetes-goat

| Criterion | kubernetes-goat | terragoat | eks-blueprints | kube-bench |
|-----------|-----------------|-----------|----------------|------------|
| **K8s workload focus** | ✅ Intentionally vulnerable K8s scenarios covering privilege escalation, secrets exposure, RBAC misconfig, supply-chain attacks | ❌ Terraform IaC vulns only — no K8s runtime context | ⚠️ Hardened baseline reference, no attack scenarios | ⚠️ CIS benchmark scanner — no attack lab |
| **Scenario coverage vs. trigger incident** | ✅ Directly replicates ClusterRoleBinding abuse, service-account token theft, container breakout | ❌ No K8s RBAC scenarios | ✅ Provides remediation target architecture | ❌ Reports posture but doesn't let you attack/fix |
| **Multi-cloud portability** | ⚠️ K8s-native, cloud-agnostic by nature (works on any K8s cluster) | ⚠️ AWS-only | ❌ AWS/EKS-specific | ✅ Cloud-agnostic |
| **Hands-on review suitability** | ✅ Designed for learning via exploitation — ideal for demonstrating find→exploit→fix | ❌ Not designed for runtime review | ✅ Good for "fix to this" baselines | ⚠️ Point-in-time scan only |
| **Familiarity risk** | Low — well-documented, actively maintained, MIT licensed | Low | Low | Low |

**Trade-off call:** kubernetes-goat is chosen because the assessment requires demonstrating both attack (finding the vulnerability) and remediation (fixing it). Terragoat would only cover the IaC layer. EKS Blueprints is referenced as the hardened target-state architecture (see `06-remediation/`) but doesn't provide the vulnerable scenarios needed for Modules 1, 3, and 7. kube-bench outputs inform the findings register but can't substitute for a hands-on lab. kubernetes-goat covers all three needs.

### Repo Note

> This repository contains a **clone** of kubernetes-goat under `reference-target/`, not a GitHub fork. To create a proper fork, go to https://github.com/madhuakula/kubernetes-goat and click "Fork", then replace the `reference-target/` directory with your forked copy. The clone was used here because no GitHub authentication is available in this environment.

### Secrets Notice for Reviewers

> kubernetes-goat is an **intentionally vulnerable** training repository. It deliberately contains fake/demo secrets, dummy credentials, and simulated misconfigurations for educational purposes. **None of the credentials found in `reference-target/` are real** — they are synthetic values designed to demonstrate security anti-patterns. Reviewers should not flag these as genuine credential exposures. A full scan was performed prior to initial commit and no real AWS keys, tokens, or private keys were found. Scan results are documented in the commit message.

## How This Repo Is Organised

| # | Module | Directory | Deliverable |
|---|--------|-----------|-------------|
| 0 | Reference Target | `reference-target/` | Cloned kubernetes-goat for hands-on review |
| 1 | Findings | `01-findings/` | `findings-register.md`, `severity-methodology.md` |
| 2 | Pipeline & Supply Chain | `02-pipeline-supply-chain/` | `pipeline-design.md`, `.gitlab-ci-example.yml` |
| 3 | Runtime Security | `03-runtime-security/` | `runtime-detection-ir-plan.md` |
| 4 | Network / Zero-Trust | `04-network-mesh/` | `zero-trust-design.md` |
| 5 | Secrets & Key Management | `05-secrets-keys/` | `secrets-architecture.md` |
| 6 | Remediation | `06-remediation/` | `remediation-advisory.md`, `compensating-controls.md`, `fixed-manifests/` |
| 7 | Threat Model | `07-threat-model/` | `threat-model.md` |
| 8 | Compliance | `08-compliance/` | `compliance-mapping.md` |
| 9 | Architecture | `09-architecture/` | `hld-diagram.md`, `lld-diagram.md`, `architecture-narrative.md` |
| 10 | Resilience & DR | `10-resilience-dr/` | `dr-plan.md` |
| 11 | Presentation | `11-presentation/` | `slides.pdf` (placeholder) |

## Hard Constraints

- **Vendor COTS image:** One workload ships as a container image the vendor won't rebuild without a paid support contract. This is an accepted residual risk with compensating controls documented in `06-remediation/compensating-controls.md`.
- **Governance deadline:** Formal sign-off required before next quarter's migration wave.
- **No real environment access:** All work targets the kubernetes-goat reference copy.

## Key References

- [aws-ia/terraform-aws-eks-blueprints](https://github.com/aws-ia/terraform-aws-eks-blueprints) — hardened target-state architecture
- [CIS Kubernetes Benchmark v1.8](https://www.cisecurity.org/benchmark/kubernetes) — compliance baseline
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/) — threat modelling framework

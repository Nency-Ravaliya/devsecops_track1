# Pipeline & Supply Chain Security Design

## 1. Purpose and Scope

This document defines a GitLab CI/CD pipeline architecture that would have **prevented the trigger incident** (K8S-001: CI service account bound to `cluster-admin`) before merge, and systematically catches the finding classes identified in Module 1 (K8S-001 through K8S-028). It treats the full software supply chain as in-scope: source code, IaC manifests, container images, runtime configuration, and deployment artefacts.

The pipeline is designed for the programme's self-managed GitLab CI/CD estate (~100 workloads, ~18 on EKS) and must generalise to AKS/GKE without a rebuild when Azure and GCP onboard next quarter.

### Relationship to Module 1 Findings

Every gate in this pipeline maps to at least one Module 1 finding class. The mapping is explicit in [Section 4](#4-gate-to-finding-mapping) and annotated in the companion `.gitlab-ci-example.yml`.

## 2. Pipeline Stages

```
┌──────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  Lint &   │──▶│   Policy &   │──▶│  Build &     │──▶│  Sign &      │──▶│  Staging     │──▶│  Production  │
│  Validate │   │  Security    │   │  Scan        │   │  Attest      │   │  Deploy      │   │  Deploy      │
│           │   │  Gates       │   │              │   │              │   │              │   │  (approval)  │
└──────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
     MR only         MR only         Post-merge          Post-build        Auto on main      Protected env
                                    + MR (scan)                                               manual gate
```

### Stage 1 — Lint & Validate

**Runs on:** every MR commit and every push to `main`/`release/*`.

| Job | Tool & version | What it checks | Hard-fail / Soft-fail |
|---|---|---|---|
| `yaml-lint` | yamllint 1.35.x | YAML syntax validity across all manifests | **Hard-fail.** Broken YAML blocks every downstream gate. |
| `helm-lint` | Helm 3.16.x `helm lint` | Helm chart structure, template rendering with default values | **Hard-fail.** Untemplatable charts cannot be scanned. |
| `terraform-validate` | Terraform 1.9.x `terraform validate` + `terraform fmt -check` | HCL syntax, provider schema validation, formatting | **Hard-fail.** Invalid Terraform cannot be planned. |
| `dockerfile-lint` | Hadolint 2.12.x | Dockerfile best practices: pinned base images, no `ADD` for URLs, no root USER instructions | **Soft-fail (warn).** Some base image choices are constrained by the COTS vendor image (see Hard Constraints). Warnings are surfaced as MR comments. |

### Stage 2 — Policy & Security Gates

**Runs on:** every MR (blocks merge on failure); also runs on `main` as a post-merge guardrail.

This is the stage that **would have caught the trigger incident**.

| Job | Tool & version | What it checks | Hard-fail / Soft-fail | Key Module 1 findings addressed |
|---|---|---|---|---|
| `conftest-k8s-rbac` | Conftest 0.56.x with custom OPA Rego policies | **RBAC policy violations:** ClusterRoleBinding to non-system principals, wildcard verbs/resources/apiGroups in ClusterRoles, `default` ServiceAccount in binding subjects, ClusterRole bindings to CI/pipeline identities | **Hard-fail on Critical RBAC.** Any manifest creating a ClusterRoleBinding with `cluster-admin` or wildcard ClusterRole fails the pipeline. | K8S-001, K8S-002, K8S-003, K8S-007, K8S-008 |
| `conftest-k8s-podsec` | Conftest 0.56.x with custom OPA Rego policies | **Pod security violations:** `privileged: true`, `hostPID`, `hostIPC`, `hostNetwork`, `hostPath` to `/` or runtime sockets, `allowPrivilegeEscalation: true`, missing `runAsNonRoot`, missing `seccompProfile`, missing `capabilities.drop: ["ALL"]` | **Hard-fail on Critical/High.** Privileged containers, host namespace access, and runtime socket mounts fail immediately. Missing `runAsNonRoot` or seccomp is a **soft-fail (warn)** until Pod Security Admission is cluster-wide. | K8S-004, K8S-005, K8S-006, K8S-021, K8S-022 |
| `conftest-k8s-secrets` | Conftest 0.56.x with custom OPA Rego policies | **Secrets anti-patterns:** `kind: Secret` with inline `data`/`stringData` in manifests (should use External Secrets Operator references), env var `valueFrom.secretKeyRef` without approved secret store annotation, NodePort service type | **Hard-fail on High.** Inline Secret manifests and NodePort services block merge. | K8S-009, K8S-010, K8S-016 |
| `conftest-k8s-resources` | Conftest 0.56.x with custom OPA Rego policies | **Resource governance:** containers missing `resources.requests` or `resources.limits` | **Soft-fail (warn).** Reported as MR comment but does not block merge. Becomes hard-fail once LimitRange/ResourceQuota is cluster-wide. | K8S-023, K8S-024 |
| `checkov-iac` | Checkov 3.2.x | Terraform and CDK IaC scanning: security group egress rules, AMI age, IAM wildcard policies, EKS logging/encryption, IRSA configuration | **Hard-fail on High+.** Checkov `--hard-fail-on HIGH,CRITICAL`. | K8S-011, K8S-012, K8S-025, K8S-026 |
| `kube-score` | kube-score 1.18.x | Kubernetes manifest best-practice scoring: missing probes, no resource limits, `latest` tag, no network policy | **Soft-fail (warn).** kube-score provides broad coverage but overlaps with Conftest; used for defence-in-depth and developer education, not as a gate. | K8S-013, K8S-014, K8S-023 |
| `gitleaks` | Gitleaks 8.21.x | Secrets detection in source/config committed to Git: AWS keys, API tokens, private keys, high-entropy strings | **Hard-fail.** Any detected secret blocks merge. | K8S-009, K8S-028 |

#### Why Conftest over kube-linter or Datree

Conftest evaluates arbitrary OPA Rego policies against _any_ structured data (YAML, JSON, HCL). This matters because:

1. The RBAC rules needed to catch K8S-001/002/003 are custom — no off-the-shelf tool ships a policy that says "fail if a ClusterRoleBinding binds cluster-admin to a non-`system:` principal." Conftest lets us write that exact rule.
2. The same Rego policy bundle works for Kubernetes YAML, Helm rendered output, and Terraform plan JSON, which means one policy language across the estate.
3. Conftest policies version-controlled alongside application code make policy-as-code auditable for governance.

kube-score is retained as a soft-fail defence-in-depth layer because it catches a broader set of hygiene issues with zero configuration.

### Stage 3 — Build & Scan

**Runs on:** post-merge to `main` and `release/*` branches (image build only happens for merged code); vulnerability scan also runs on MR for Dockerfiles that changed, using the existing image if available.

| Job | Tool & version | What it checks | Hard-fail / Soft-fail |
|---|---|---|---|
| `docker-build` | Docker BuildKit (or kaniko 1.23.x in unprivileged runners) | OCI image build from Dockerfile | **Hard-fail on build errors.** |
| `trivy-image-scan` | Trivy 0.55.x | Image CVE scan against NVD + GitHub Advisory DB. Scans OS packages, language dependencies, and Dockerfile misconfigurations. | **Hard-fail on Critical CVEs with a fix available.** High CVEs with fix available are **soft-fail (warn)** with a 14-day SLA to remediate or accept. Unfixable CVEs are logged for Module 6 compensating controls (e.g. the COTS vendor image). |
| `trivy-sbom-gen` | Trivy 0.55.x `--format cyclonedx` | Generates CycloneDX SBOM from built image. | **Hard-fail if SBOM generation fails** (indicates unparseable image layers). Never soft-fail — SBOM is a governance requirement. |
| `syft-sbom-gen` | Syft 1.14.x `--output spdx-json` | Generates SPDX SBOM as a secondary format for consumers that require it (e.g. some government procurement frameworks). | **Soft-fail.** Syft is a secondary generator; Trivy CycloneDX is primary. |
| `grype-cross-check` | Grype 0.82.x | Second-opinion CVE scan against the SBOM, using Grype's own vulnerability DB to catch scanner blind spots. | **Soft-fail (warn).** Discrepancies between Trivy and Grype are flagged for security team review, not auto-blocked. |
| `hadolint-dockerfile` | Hadolint 2.12.x (re-run on built context) | Catches `ENV` with secrets (K8S-028), unpinned `FROM` (K8S-014), `USER root` patterns | **Hard-fail** on DL3000-series (secrets) and DL3006 (unpinned tag). |

#### SBOM Storage and Consumption

- **Primary SBOM:** CycloneDX JSON, attached to the OCI image as an in-toto attestation via `cosign attach sbom` (stored in the same OCI registry alongside the image).
- **Secondary SBOM:** SPDX JSON, uploaded to the GitLab Package Registry as a versioned artefact for procurement/audit retrieval.
- **Consumption:** The admission controller (Kyverno, see Stage 5) can optionally verify SBOM attestation presence before admitting an image. The security team's vulnerability dashboard (Dependency-Track 4.x or GitLab Ultimate's dependency scanning dashboard if licensed) ingests SBOMs via API push after each build.

### Stage 4 — Sign & Attest

**Runs on:** after successful build and scan on `main`/`release/*`.

| Job | Tool & version | What it does |
|---|---|---|
| `cosign-sign` | Cosign 2.4.x | Signs the OCI image digest with a keyless (Fulcio + Rekor) or KMS-backed key. For this programme, use **AWS KMS-backed signing** (`cosign sign --key awskms:///arn:aws:kms:...`) because keyless requires Sigstore infrastructure that may not meet sovereign data residency requirements. When AKS/GKE onboards, swap to Azure Key Vault or GCP KMS URIs — same Cosign CLI, different `--key` URI. |
| `cosign-attest-sbom` | Cosign 2.4.x `cosign attest` | Attaches the CycloneDX SBOM as a signed in-toto attestation. |
| `cosign-attest-vuln` | Cosign 2.4.x `cosign attest` | Attaches the Trivy scan result as a signed vulnerability attestation (predicate type `cosign.sigstore.dev/attestation/vuln/v1`). |
| `slsa-provenance` | SLSA GitHub/GitLab generator or manual in-toto provenance statement | Generates SLSA v1.0 provenance attestation. See [Section 5](#5-slsa-provenance-assessment) for proportionality assessment. |

### Stage 5 — Staging Deploy

**Runs on:** automatically after sign+attest on `main`.

| Job | Tool & version | What it does |
|---|---|---|
| `deploy-staging` | `kubectl apply` / Helm 3.16.x / ArgoCD 2.12.x sync | Deploys to a staging EKS cluster (or AKS/GKE staging). |
| `smoke-tests` | Application-specific test suite | Basic connectivity, health endpoints, canary assertions. |
| `admission-verify` | Kyverno 1.13.x `ClusterPolicy` in `Enforce` mode | **In-cluster gate.** Kyverno policies verify: (a) image signature via `verifyImages` against the programme's Cosign public key / KMS key, (b) SBOM attestation exists, (c) no Critical unpatched CVEs in the vulnerability attestation, (d) Pod Security Standards Restricted baseline. This is the _runtime_ counterpart to the CI policy gates. |

#### Why Kyverno over OPA Gatekeeper for Admission

Module 1's severity methodology already flagged this choice. The trade-off:

- **Kyverno 1.13.x** supports native `verifyImages` with Cosign/Notary, SBOM attestation checks, and Kubernetes-native `ClusterPolicy` CRDs. Policy authors write YAML, not Rego. This matters in a programme where platform engineers maintain policies — lower barrier to contribution and review.
- **OPA Gatekeeper 3.17.x** is stronger for complex cross-resource logic and has broader multi-cloud governance ecosystem support. However, image signature verification requires an external webhook (Ratify or Connaisseur), adding another moving part.
- **Decision:** Use **Kyverno** for admission-time image verification and pod security. Retain **Conftest** (OPA Rego) for CI-time policy scanning where the policy language is richer and the execution context is a pipeline, not a webhook. This gives the programme OPA for shift-left and Kyverno for shift-right, with policy intent mapped between them rather than duplicated verbatim.

### Stage 6 — Production Deploy (Protected Environment)

**Runs on:** manual trigger only, requires approval from at least one member of the `security-reviewers` group in GitLab.

| Job | Tool & version | What it does |
|---|---|---|
| `security-approval` | GitLab Protected Environments + manual job | A manual gate job assigned to the `security-reviewers` protected environment group. The approver sees the Trivy/Grype scan summary, SBOM link, Conftest results, and any soft-fail warnings before clicking "Play." This is the security sign-off step required by governance. |
| `deploy-production` | Same tooling as staging | Deploys only images that passed all hard-fail gates and carry a valid Cosign signature. |
| `post-deploy-verify` | Kyverno audit report + Falco alert baseline | After deployment, verify no Kyverno `Fail` audit events fired and Falco (Module 3) baselines are clean for 10 minutes. |

#### Protected Environment Configuration

```yaml
# GitLab project settings (not in .gitlab-ci.yml — configured via UI or Terraform)
# Protected environment: production
# Required approvals: 1
# Allowed to deploy: @security-reviewers group
# Allowed to approve: @security-reviewers group (distinct from deployer for SoD)
```

For **separation of duties**: the engineer who merges the MR cannot be the same person who approves the production deploy. GitLab's protected environment "required approvals" enforces this when the approver group excludes the MR author.

## 3. Hard-Fail vs Soft-Fail Decision Framework

The split follows Module 1's severity methodology directly:

| Severity (Module 1) | Pipeline behaviour | Rationale |
|---|---|---|
| **Critical** | **Hard-fail, blocks merge.** No exceptions without a documented risk acceptance signed by the security lead and logged in `06-remediation/compensating-controls.md`. | Critical findings (K8S-001–006) represent cluster-wide or node-level compromise. Allowing merge means the control-plane is at risk before any runtime detection can act. |
| **High** | **Hard-fail on most, soft-fail on a defined subset.** Hard: inline secrets (K8S-009), NodePort (K8S-016), gitleaks hits, Critical CVEs. Soft: missing resource requests (K8S-023/024), kube-score hygiene. | High findings need a funded fix before go-live but some (e.g. resource tuning) are better handled by platform guardrails than by blocking every MR. |
| **Medium** | **Soft-fail (warn via MR comment).** Tracked in pipeline artefacts. | Medium findings (K8S-021–026) are backlog items; blocking developers on every MR creates fatigue-driven gate bypasses. |
| **Low** | **Informational.** Logged in pipeline output, not surfaced as MR comments. | Low findings (K8S-027) are hygiene; developer attention should not be consumed. |

### The COTS Vendor Image Exception

The programme has one container image the vendor won't rebuild (Hard Constraint in README.md). The pipeline handles this as:

1. `trivy-image-scan` runs on the vendor image but its findings are routed to a **separate allowlist policy** in Conftest (`policy/vendor-cots-exceptions.rego`).
2. Known unfixable CVEs in the vendor image are listed by CVE ID in the policy. New CVEs fail the pipeline and trigger a review — the team must either add the CVE to the allowlist (with a compensating control documented in `06-remediation/compensating-controls.md`) or escalate to the vendor.
3. Kyverno admission allows the vendor image by digest, not by tag, and only in the namespace where the COTS workload runs.

## 4. Gate-to-Finding Mapping

| Module 1 Finding | Pipeline gate(s) that would catch it | Fail mode |
|---|---|---|
| **K8S-001** ClusterRoleBinding to cluster-admin | `conftest-k8s-rbac`: denies ClusterRoleBinding with roleRef `cluster-admin` to non-`system:` subjects | Hard-fail |
| **K8S-002** Wildcard ClusterRole | `conftest-k8s-rbac`: denies ClusterRole rules with `*` verbs + `*` resources + `*` apiGroups | Hard-fail |
| **K8S-003** ClusterRoleBinding to default SA | `conftest-k8s-rbac`: denies ClusterRoleBinding subjects where SA name is `default` | Hard-fail |
| **K8S-004** Privileged + hostPID + host root mount | `conftest-k8s-podsec`: denies `privileged: true`, `hostPID`, hostPath `/` | Hard-fail |
| **K8S-005** Container runtime socket mount | `conftest-k8s-podsec`: denies hostPath containing `docker.sock` or `containerd.sock` | Hard-fail |
| **K8S-006** DaemonSet with hostNetwork + privileged | `conftest-k8s-podsec`: denies `hostNetwork: true` combined with `privileged: true` | Hard-fail |
| **K8S-007/008** Over-broad Role/RoleBinding | `conftest-k8s-rbac`: warns on wildcard `resources` in Roles; hard-fails if combined with verbs beyond `get` | Warn/Hard-fail |
| **K8S-009** Secrets in manifests | `conftest-k8s-secrets` + `gitleaks`: denies `kind: Secret` with inline data; gitleaks detects high-entropy strings | Hard-fail |
| **K8S-010** Secret via env var | `conftest-k8s-secrets`: warns on `secretKeyRef` without approved annotation | Warn |
| **K8S-011** No etcd encryption | `checkov-iac`: CKV_AWS_58 (EKS secrets encryption) | Hard-fail |
| **K8S-012** No IRSA/workload identity | `checkov-iac`: CKV_AWS_138 (EKS IRSA), custom check for SA annotation | Warn |
| **K8S-013** Unpinned image tags | `conftest-k8s-podsec` + `kube-score`: denies images without digest or specific version tag | Hard-fail |
| **K8S-014** `:latest` tag | `conftest-k8s-podsec`: denies `:latest` tag in deployment manifests; `hadolint`: DL3007 | Hard-fail |
| **K8S-015** No NetworkPolicy | `kube-score`: warns on namespaces without NetworkPolicy | Warn |
| **K8S-016** NodePort service | `conftest-k8s-secrets`: denies `type: NodePort` outside approved namespaces | Hard-fail |
| **K8S-017** Port-forward to 0.0.0.0 | `gitleaks` pattern + custom Conftest shell script policy | Warn |
| **K8S-018** Insecure TLS skip | `gitleaks` pattern for `--insecure-skip-tls-verify` in scripts | Warn |
| **K8S-019** No audit logging | `checkov-iac`: CKV_AWS_37/38/39 (EKS logging types) | Hard-fail |
| **K8S-020** No admission controller | Not catchable in CI — this is a platform-level control. Tracked as a deployment prerequisite. | N/A |
| **K8S-021** Missing runAsNonRoot | `conftest-k8s-podsec`: warns on missing `runAsNonRoot` | Warn |
| **K8S-022** Missing seccomp | `conftest-k8s-podsec`: warns on missing `seccompProfile` | Warn |
| **K8S-023/024** Missing resource requests/limits | `conftest-k8s-resources` + `kube-score` | Warn |
| **K8S-025** EOL AMI | `checkov-iac`: custom check for AMI age / Ubuntu version | Warn |
| **K8S-026** Broad egress SG | `checkov-iac`: CKV_AWS_382 or custom check for `allow_all_outbound` | Warn |
| **K8S-027** Hardcoded URLs | Not scanned — Low severity, tracked as backlog hygiene | N/A |
| **K8S-028** Secret baked in Dockerfile ENV | `hadolint`: DL3000-series + `gitleaks` on Dockerfile | Hard-fail |

## 5. SLSA Provenance Assessment

### Is SLSA Provenance Proportionate?

**Trade-off call: implement SLSA Build L2 now; defer L3 to post-go-live.**

| SLSA Level | What it adds | Proportionate for this programme? |
|---|---|---|
| **L0** (no provenance) | Nothing | Current state. Unacceptable for governance. |
| **L1** (provenance exists) | A signed statement saying "this image was built from this commit by this pipeline." Achieved by Cosign attestation + GitLab CI metadata. | **Yes.** Minimal effort — the cosign-attest jobs already produce this. |
| **L2** (hosted build, signed provenance) | Build runs on a hosted platform (GitLab CI runners) with tamper-evident provenance. Proves the build was not run on a developer laptop. | **Yes.** The programme already uses self-managed GitLab runners. Adding `--type slsaprovenance` to `cosign attest` with the build metadata from `CI_*` environment variables achieves L2 with ~2 hours of work. |
| **L3** (hardened builds, non-falsifiable provenance) | Runners are hardened, ephemeral, and isolated per build. Provenance is generated by the platform, not the build script (i.e. the build cannot forge its own provenance). | **Not yet.** Requires ephemeral runners with attestation generated outside the build job, which means GitLab Runner infrastructure changes. Worth pursuing post-go-live. |

**What L2 adds concretely:** If a compromised developer account pushes a malicious image tag, the provenance attestation lets the security team verify whether the image was actually built by the CI system from reviewed source, or built elsewhere and tagged to look legitimate. This is directly relevant to K8S-013/014 (unpinned/mutable images).

### SLSA Provenance Implementation

```bash
# In the cosign-attest job, after image signing:
cosign attest --key awskms:///arn:aws:kms:... \
  --type slsaprovenance \
  --predicate provenance.json \
  ${CI_REGISTRY_IMAGE}@${IMAGE_DIGEST}
```

The `provenance.json` is assembled from GitLab CI environment variables (`CI_COMMIT_SHA`, `CI_PIPELINE_ID`, `CI_RUNNER_ID`, `CI_PROJECT_URL`, etc.) in a SLSA v1.0 provenance predicate format.

## 6. Multi-Cloud Portability (AKS / GKE)

### What Changes

| Pipeline component | AWS (current) | AKS (Azure) | GKE (Google) |
|---|---|---|---|
| **Image registry** | ECR | ACR | Artifact Registry |
| **Cosign signing key** | AWS KMS `awskms:///` | Azure Key Vault `azurekms://` | GCP KMS `gcpkms://` |
| **IaC scanner (Checkov)** | AWS-specific CKV checks | Azure-specific CKV checks | GCP-specific CKV checks |
| **Workload identity check** | IRSA annotation | Azure Workload Identity annotation | GKE Workload Identity annotation |
| **Admission controller** | Kyverno on EKS | Kyverno on AKS (or Azure Policy add-on) | Kyverno on GKE (or GKE Policy Controller) |
| **Runner infrastructure** | EC2-based GitLab runners | AKS-based or VM-based runners | GKE-based or VM-based runners |

### What Does NOT Change

- **Conftest policies** — OPA Rego evaluates Kubernetes YAML regardless of cloud provider. The same RBAC, pod security, and secrets policies apply on EKS, AKS, and GKE.
- **Trivy/Grype image scanning** — scans OCI images, not cloud-specific artefacts.
- **Syft/SBOM generation** — cloud-agnostic.
- **Cosign CLI** — same binary, different `--key` URI per provider.
- **Kyverno policies** — Kubernetes-native, no cloud-specific fields.
- **GitLab CI pipeline structure** — stages, jobs, and gate logic are identical. Only CI variables change per environment.

### Implementation Approach

Use GitLab CI variables scoped to environments:

```yaml
# In GitLab project settings (per-environment variables):
# COSIGN_KEY = awskms:///arn:aws:kms:eu-west-2:...:key/...  (for AWS)
# COSIGN_KEY = azurekms://mykeyvault.vault.azure.net/keys/cosign  (for Azure)
# COSIGN_KEY = gcpkms://projects/.../locations/.../keyRings/.../cryptoKeys/cosign  (for GCP)
```

The `.gitlab-ci-example.yml` references `$COSIGN_KEY` so the same pipeline works across clouds.

## 7. Policy Repository Structure

Conftest policies should live in a dedicated Git repository (`platform-policies`) and be consumed by application repos via Git submodule or CI `include`. This ensures:

1. **Central governance** — security team owns and reviews policy changes.
2. **Versioning** — application repos pin a policy version; policy updates roll out deliberately.
3. **Auditability** — every policy change has a Git log entry, reviewable by the governance panel.

```
platform-policies/
├── policy/
│   ├── k8s-rbac.rego              # K8S-001, 002, 003, 007, 008
│   ├── k8s-podsec.rego            # K8S-004, 005, 006, 013, 014, 021, 022
│   ├── k8s-secrets.rego           # K8S-009, 010, 016
│   ├── k8s-resources.rego         # K8S-023, 024
│   ├── vendor-cots-exceptions.rego # COTS vendor image CVE allowlist
│   └── data.json                  # Approved registries, SA names, namespace exceptions
├── tests/
│   ├── k8s-rbac_test.rego
│   ├── k8s-podsec_test.rego
│   └── ...
└── README.md
```

## 8. Pipeline Security Hardening

The pipeline itself must be hardened to prevent bypass:

| Control | Implementation |
|---|---|
| **Runner isolation** | Use ephemeral Docker-in-Docker or Kubernetes pod runners that are destroyed after each job. Do not reuse runner state between jobs or pipelines. |
| **CI variable protection** | `COSIGN_KEY`, registry credentials, and cluster kubeconfigs are protected variables scoped to `main`/`release/*` branches only. MR branches cannot access production secrets. |
| **Branch protection** | `main` and `release/*` require MR with at least 1 approval, passing CI, and no unresolved threads. Direct push disabled for all users including maintainers. |
| **Pipeline tampering** | `.gitlab-ci.yml` changes require CODEOWNERS approval from `@platform-security`. An MR that modifies pipeline configuration and application code in the same commit triggers an additional review requirement. |
| **Audit trail** | All pipeline runs, approvals, and gate overrides are logged via GitLab Audit Events and forwarded to the programme SIEM. |

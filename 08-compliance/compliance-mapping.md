# Compliance Mapping

## 1. Methodology

This document demonstrates the compliance mapping methodology that would be applied to any finding in the estate. The methodology is reusable: for each finding, we identify which compliance domain(s) it falls under, what evidence must be gathered to demonstrate compliance or justify a documented exception, and what the current status is.

### Compliance Domains

| Domain | Definition | Applicable frameworks (representative) |
|---|---|---|
| **Access Control** | Who/what can access which resources, and how access is granted, revoked, and audited | CIS Kubernetes Benchmark 5.x, NIST 800-53 AC-2/AC-3/AC-6, SOC 2 CC6.1 |
| **Encryption** | Data at rest and in transit is encrypted using approved algorithms and key management | CIS Kubernetes Benchmark 5.4, NIST 800-53 SC-8/SC-12/SC-13, SOC 2 CC6.7 |
| **Logging & Monitoring** | Security-relevant events are logged, retained, monitored, and alerting is in place | CIS Kubernetes Benchmark 3.2, NIST 800-53 AU-2/AU-3/AU-6, SOC 2 CC7.2 |
| **Configuration Baseline** | Systems are configured to a hardened baseline, deviations are tracked and exceptions approved | CIS Kubernetes Benchmark (all), NIST 800-53 CM-2/CM-6/CM-7, SOC 2 CC6.1 |
| **Secure Development Lifecycle** | Security is integrated into the development and deployment process, not bolted on after | NIST 800-53 SA-3/SA-10/SA-11, SOC 2 CC8.1, OWASP SAMM |

### Mapping Process (Reusable)

For any finding:
1. Identify the **affected resource type** (RBAC, Secret, Pod, Network, etc.)
2. Map to **which compliance domains** the resource type falls under
3. Define **specific evidence** required to demonstrate compliance or document an exception
4. Record the **current status** (compliant, non-compliant, exception pending)
5. Assign an **evidence owner** (role, not name) and a **collection deadline**

---

## 2. Finding Mappings

### K8S-001: `superadmin` ServiceAccount Bound to `cluster-admin`

**Severity:** Critical | **Domain from Module 1:** RBAC

| Compliance domain | Applicability | Mapping rationale |
|---|---|---|
| **Access Control** | Primary | A non-system principal with cluster-admin violates the principle of least privilege (CIS 5.1.1: "Ensure that the cluster-admin role is only used where required"). |
| **Logging & Monitoring** | Secondary | The binding should have been detected by audit log monitoring — its existence indicates a gap in detection (CIS 3.1.2: audit policy should log RBAC changes). |

**Evidence to demonstrate compliance (after fix):**

| Evidence | Source | Owner | Deadline |
|---|---|---|---|
| `kubectl get clusterrolebindings -o wide` output showing no `superadmin` binding | kubectl command, screenshot or script output | Platform team | Before go-live |
| Git commit deleting the binding, with security review approval | GitLab MR history | Development team | Before go-live |
| Conftest policy test output: `conftest test --policy k8s-rbac.rego` passing with zero CRITICAL/HIGH violations | CI pipeline artefact (Module 2) | Platform team | Ongoing (every pipeline run) |
| Kubernetes audit log entries for the past 90 days showing no unauthorized ClusterRoleBinding creation events | CloudWatch Logs / SIEM query | Security team | Quarterly review |

**Evidence for documented exception (if not yet fixed):**

| Evidence | Format | Authority |
|---|---|---|
| Signed risk acceptance form documenting: finding ID (K8S-001), risk description, compensating controls in place, acceptance expiry date, ITSO signature | PDF/signed document in programme risk register | ITSO-equivalent / Accreditor |

---

### K8S-009: Secrets Committed as Base64 Data in Manifests

**Severity:** High | **Domain from Module 1:** Secrets

| Compliance domain | Applicability | Mapping rationale |
|---|---|---|
| **Encryption** | Primary | Secrets in Git are not encrypted at rest (base64 is encoding, not encryption). Violates requirements for encryption of sensitive data at rest (NIST 800-53 SC-28). |
| **Access Control** | Secondary | Anyone with Git repository read access can view the secrets — access is not scoped to the workload that uses them (SOC 2 CC6.1: logical access security). |
| **Secure Development Lifecycle** | Secondary | The pipeline should have caught secrets before merge (Module 2 gitleaks gate). Absence of this gate indicates a gap in the SDLC. |

**Evidence to demonstrate compliance (after fix):**

| Evidence | Source | Owner | Deadline |
|---|---|---|---|
| Trivy/gitleaks scan output: zero secrets detected in manifests | CI pipeline artefact (Module 2) | Platform team | Ongoing |
| `kubectl get secrets --all-namespaces` showing no secrets with names matching application API key patterns | kubectl output | Platform team | Before go-live |
| External Secrets Operator `ExternalSecret` CRD manifest showing the secret path in cloud Secrets Manager (no values in manifest) | Git repository | Development team | Before go-live |
| Git history scan (BFG Repo-Cleaner or git-secrets): confirming no secrets remain in historical commits | Git audit tool output | Security team | Before go-live |
| Cloud Secrets Manager access log showing the secret was accessed by the workload's IRSA role (not a human) | CloudTrail / Azure Activity Log | Security team | Monthly review |

**Evidence for documented exception (if not yet fixed):**

| Evidence | Format | Authority |
|---|---|---|
| Risk acceptance form: finding ID (K8S-009), secret values confirmed as synthetic/demo (if kubernetes-goat context), rotation plan documented, acceptance expiry | PDF/signed document | ITSO-equivalent / Accreditor |

---

### K8S-019: No Audit Policy, Audit Log Destination, or Runtime Detection

**Severity:** High | **Domain from Module 1:** Logging / Detection

| Compliance domain | Applicability | Mapping rationale |
|---|---|---|
| **Logging & Monitoring** | Primary | No audit policy means security-relevant events (RBAC changes, Secret access, pod exec) are not logged. Violates requirements for audit logging of security events (CIS 3.2.1: "Ensure that advanced audit logging is configured", NIST 800-53 AU-2). |
| **Access Control** | Secondary | Without audit logs, access control violations (like K8S-001) cannot be detected or investigated (SOC 2 CC7.2: monitoring of controls). |

**Evidence to demonstrate compliance (after fix):**

| Evidence | Source | Owner | Deadline |
|---|---|---|---|
| EKS cluster logging configuration showing `audit`, `api`, `authenticator`, `controllerManager`, `scheduler` log types enabled | Terraform output / AWS Console screenshot | Platform team | Before go-live |
| Falco DaemonSet running on all nodes: `kubectl get ds falco -n falco-system -o jsonpath='{.status.numberReady}'` matching desired count | kubectl output | Platform team | Before go-live |
| Sample audit log entry in CloudWatch Logs / SIEM showing a Kubernetes API event (e.g. pod creation) with full metadata | SIEM query screenshot | Security team | Before go-live |
| Falco alert test: deploy a test pod with `privileged: true` and confirm a P1 alert fires in Slack/PagerDuty within 5 minutes | Test output / Slack screenshot | Security team | Before go-live |
| SIEM dashboard showing 30-day rolling alert volume, with P1 alerts < 1/week after tuning period | Dashboard screenshot | Security team | Monthly review |

**Evidence for documented exception:**

| Evidence | Format | Authority |
|---|---|---|
| Risk acceptance form: finding ID (K8S-019), compensating controls (e.g. network-level logging via VPC Flow Logs), timeline for full audit log deployment, ITSO signature | PDF/signed document | ITSO-equivalent / Accreditor |

---

### K8S-015: No Kubernetes NetworkPolicy Resources Exist

**Severity:** High | **Domain from Module 1:** Network

| Compliance domain | Applicability | Mapping rationale |
|---|---|---|
| **Configuration Baseline** | Primary | No NetworkPolicy means the cluster operates without network segmentation. Violates the principle of least-privilege network access (CIS 5.3.2: "Ensure that all Namespaces have Network Policies defined"). |
| **Access Control** | Secondary | Without NetworkPolicy, any pod can communicate with any other pod — lateral movement is unrestricted (NIST 800-53 SC-7: boundary protection). |

**Evidence to demonstrate compliance (after fix):**

| Evidence | Source | Owner | Deadline |
|---|---|---|---|
| `kubectl get networkpolicies --all-namespaces` showing at least one default-deny policy per production namespace | kubectl output | Platform team | Before go-live |
| Cilium Hubble flow visualization showing default-deny enforcement (red for blocked, green for allowed) | Hubble UI screenshot or CLI output | Platform team | Before go-live |
| Conftest policy test: `conftest test --policy k8s-network.rego` passing with zero violations for production manifests | CI pipeline artefact | Platform team | Ongoing |
| Penetration test result: attempt lateral movement from a compromised pod to another namespace — blocked by NetworkPolicy | Pentest report excerpt | Security team | Before go-live |

**Evidence for documented exception:**

| Evidence | Format | Authority |
|---|---|---|
| Risk acceptance form: finding ID (K8S-015), compensating controls (VPC-level security groups, security group for pods), timeline for NetworkPolicy rollout (from Module 4 §5), ITSO signature | PDF/signed document | ITSO-equivalent / Accreditor |

---

### K8S-013: Workload Images Are Unpinned or Implicitly `latest`

**Severity:** High | **Domain from Module 1:** Image Supply Chain

| Compliance domain | Applicability | Mapping rationale |
|---|---|---|
| **Secure Development Lifecycle** | Primary | Unpinned images mean deployments are not reproducible — a redeploy can pull different code. Violates supply chain integrity requirements (NIST 800-53 SA-10: developer configuration management, OWASP SAMM verification). |
| **Configuration Baseline** | Secondary | Mutable tags violate the principle of immutable infrastructure (CIS Docker Benchmark 4.1: "Ensure that a user for the container has been created" — assumes known, tested image). |

**Evidence to demonstrate compliance (after fix):**

| Evidence | Source | Owner | Deadline |
|---|---|---|---|
| `kubectl get deployments --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.containers[*].image}{"\n"}{end}'` showing all images pinned to specific digests or versioned tags (no `:latest`, no tagless) | kubectl output | Platform team | Before go-live |
| Cosign signature verification: `cosign verify --key <pubkey> <image>@sha256:<digest>` returns `Verified OK` for every production image | Cosign CLI output | Security team | Before go-live |
| Trivy SBOM attestation present on every production image: `cosign verify-attestation --type slsaprovenance <image>@sha256:<digest>` | Cosign CLI output | Security team | Before go-live |
| Conftest policy test: `conftest test --policy k8s-podsec.rego` passing with zero violations for image tag policy | CI pipeline artefact | Platform team | Ongoing |

**Evidence for documented exception (COTS vendor image):**

| Evidence | Format | Authority |
|---|---|---|
| Risk acceptance form: finding ID (K8S-013), COTS image pinned by digest (not tag), vendor exception documented, compensating controls from `06-remediation/compensating-controls.md` confirmed operational, ITSO signature | PDF/signed document | ITSO-equivalent / Accreditor |

---

## 3. Reusable Mapping Template

For any future finding, apply this template:

```markdown
### [FINDING-ID]: [Title]

**Severity:** [from Module 1] | **Domain from Module 1:** [RBAC/Secrets/etc.]

| Compliance domain | Applicability | Mapping rationale |
|---|---|---|
| [Domain] | Primary/Secondary | [Why this finding maps here, with framework reference] |

**Evidence to demonstrate compliance (after fix):**

| Evidence | Source | Owner | Deadline |
|---|---|---|---|
| [Specific output/screenshot/artefact] | [Where to find it] | [Role] | [When] |

**Evidence for documented exception (if not yet fixed):**

| Evidence | Format | Authority |
|---|---|---|
| Risk acceptance form: finding ID, risk description, compensating controls, acceptance expiry, ITSO signature | PDF/signed document | ITSO-equivalent / Accreditor |
```

## 4. Assumptions

- The programme's compliance framework is not publicly available (government programme). The frameworks cited here (CIS Kubernetes Benchmark, NIST 800-53, SOC 2) are representative of the types of controls that would apply. The actual internal compliance clauses should be mapped using the same methodology when they become available.
- Evidence collection is a continuous process, not a one-time event. The "Owner" and "Deadline" columns ensure evidence is assigned and tracked.
- The ITSO-equivalent / Accreditor role is the formal risk acceptance authority. If this role is not yet filled, the programme director assumes this responsibility.

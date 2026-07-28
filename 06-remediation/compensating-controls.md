# Compensating Controls for COTS Vendor Image Constraint

## 1. The Gap Being Worked Around

The programme ships one Commercial-Off-The-Shelf (COTS) product as a container image that **the vendor will not rebuild without a paid support contract**. The specific assumed gap:

**The COTS image is based on Ubuntu 20.04 with known Critical CVEs in its base OS packages (e.g. `libc6` CVE-2023-6246, `openssl` CVE-2024-0727) that cannot be patched because the vendor has locked the image to their build pipeline.** The image also runs all processes as root (UID 0) because the vendor's application requires it and the startup script assumes root permissions.

These are the two most common COTS constraints in government programmes:
1. **Unpatched base image** — the vendor's release cycle doesn't align with vulnerability disclosure timelines
2. **Runs as root** — the vendor's application was written without non-root support

Both are **accepted residual risk** until the vendor provides a fix or the programme migrates to an alternative product.

## 2. Compensating Controls

The following controls are designed to reduce the risk of the COTS image to an acceptable level while the gap remains open. Each control draws from a specific module's design:

### Control 1: Network Isolation via Cilium NetworkPolicy (from Module 4)

**What it does:** The COTS workload is deployed in a dedicated namespace (`cots-vendor`) with a restrictive Cilium `CiliumNetworkPolicy` that:

- **Allows ingress only from the specific workload(s) that need the COTS service** — not from the entire cluster. For example, if only `citizen-backend` calls the COTS API, the policy allows ingress from `citizen-backend` pods only on TCP/8443.
- **Allows egress only to approved destinations** — the COTS workload can reach its database (if needed) and the egress proxy for license validation, but nothing else. No lateral movement possible.
- **Denies all other ingress and egress** — default-deny baseline from Module 4 applies.

**Why this compensates:** An attacker who compromises the COTS container (via an unpatched CVE or root access) is confined to the `cots-vendor` namespace with no ability to reach other workloads, exfiltrate data to the internet, or scan the cluster laterally.

**Implementation:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cots-vendor-restrictive
  namespace: cots-vendor
spec:
  endpointSelector:
    matchLabels:
      app: cots-vendor
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: citizen-backend
            io.cilium.k8s.namespace.labels.name: citizen-backend
      toPorts:
        - ports:
            - port: "8443"
              protocol: TCP
  egress:
    - toEndpoints:
        - matchLabels:
            io.cilium.k8s.namespace.labels.name: egress-proxy
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
    # No other egress allowed
```

**Module 4 reference:** Default-deny NetworkPolicy baseline (§2.1), egress proxy design (§2.4).

### Control 2: Falco Runtime Detection with COTS-Specific Rules (from Module 3)

**What it does:** Deploy dedicated Falco rules for the COTS workload that detect anomalous behaviour specific to the known risk profile (root process, unpatched image):

| Rule | What it detects | Priority |
|---|---|---|
| `COTS Container Spawning Shell` | Any `sh`, `bash`, or `python` process spawned inside the COTS container (indicates exploitation of an unpatched CVE leading to code execution) | P1 Critical |
| `COTS Container Accessing /etc/shadow` | Any process reading the shadow file (credential harvesting by an attacker who has root inside the container) | P1 Critical |
| `COTS Container Unexpected Network Connection` | The COTS container making a network connection to an IP not in the approved destination list (C2 callback or lateral movement) | P2 High |
| `COTS Container Reading Kubernetes Service Account Token` | The COTS container reading its service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token` outside of normal application startup (attempting to use the K8s API to escalate) | P2 High |

**Why this compensates:** Even though the COTS container runs as root and has unpatched CVEs, Falco provides runtime visibility into exploitation. If an attacker uses a CVE to execute code inside the container, the shell-spawn alert fires within seconds, triggering the incident response process from Module 3 (§3).

**Implementation:** Falco rules deployed via the platform-policies repo (Module 2), version-controlled, with the same CODEOWNERS approval process. The COTS namespace has a Falco exception profile that records baseline behaviour for the first 30 days before enforcing.

**Module 3 reference:** P1/P2 alert routing (§2.3), incident response procedure (§3).

### Control 3: Kyverno Admission Policy Bounding COTS Workload Identity (from Module 2/Module 5)

**What it does:** A Kyverno `ClusterPolicy` restricts the COTS workload's Kubernetes identity:

- **Blocks the COTS ServiceAccount from creating any Kubernetes resources** (no `create`, `update`, `patch`, or `delete` on any resource type). The COTS container can use its ServiceAccount token only for the specific API calls its application needs (e.g. reading a ConfigMap for configuration).
- **Blocks the COTS ServiceAccount from being used as a subject in any ClusterRoleBinding or RoleBinding** — prevents an attacker from granting the COTS identity additional permissions after initial deployment.
- **Restricts the COTS pod to its designated namespace** via Kyverno `validate pod security` policy that only allows the COTS image (by digest) in the `cots-vendor` namespace.

**Why this compensates:** Even with root inside the container, the attacker is constrained by Kubernetes RBAC. The COTS ServiceAccount has no permissions to read Secrets (K8S-009/010), no permissions to modify RBAC (K8S-001/002), and the Kyverno policy prevents the attacker from deploying a new pod with higher privileges.

**Implementation:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: cots-vendor-restrictions
spec:
  validationFailureAction: Enforce
  background: false
  rules:
  - name: cots-no-rbac-modification
    match:
      any:
      - resources:
          kinds:
          - RoleBinding
          - ClusterRoleBinding
    deny:
      conditions:
        any:
        - key: "{{ request.object.subjects[?(@.name=='cots-vendor-sa')][] | length(@) }}"
          operator: GreaterThanOrEquals
          value: 1
  - name: cots-namespace-only
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "COTS vendor images may only run in the cots-vendor namespace."
      pattern:
        metadata:
          namespace: cots-vendor
        spec:
          containers:
          - image: "registry.example.com/cots-vendor/*@sha256:*"
```

**Module 2 reference:** Conftest policy gates (§4), COTS vendor exception handling (§8).
**Module 5 reference:** IRSA/workload identity scoping (§5), path-based IAM policies (§6).

### Control 4: Vulnerability Monitoring with Auto-Ticketing (from Module 2)

**What it does:** The programme runs Trivy against the COTS image on a weekly scheduled pipeline (not just at build time) to detect newly disclosed CVEs:

- A scheduled GitLab CI pipeline scans the COTS image digest weekly
- New Critical CVEs create an automated Jira ticket assigned to the programme's security lead
- The ticket includes: CVE ID, CVSS score, affected package, and whether the vendor has released a patch
- If the vendor releases a patch within 30 days, the image is updated and the compensating controls are re-evaluated
- If the vendor does NOT patch within 30 days, the risk acceptance is formally reviewed by the ITSO-equivalent

**Why this compensates:** The unpatched CVE gap is time-bounded. This control ensures new vulnerabilities are tracked, the vendor is held to a response SLA, and the programme doesn't lose visibility into the evolving risk profile.

**Module 2 reference:** Vendor COTS exception handling (§8 of pipeline-design.md).

## 3. Residual Risk Rating After Compensating Controls

| Factor | Before controls | After controls |
|---|---|---|
| **Likelihood of exploitation** | High — unpatched CVEs + root access = trivial exploitation | Medium — exploitation is still technically possible, but runtime detection (Control 2) and network isolation (Control 1) reduce the window and blast radius |
| **Impact if exploited** | Critical — full cluster compromise via lateral movement, RBAC escalation | High — confined to COTS namespace, no lateral movement, no RBAC modification (Control 3). Impact is limited to the COTS workload and its immediate dependencies. |
| **Residual risk rating** | Critical | **Medium** |

The compensating controls reduce the risk from **Critical** (full cluster compromise) to **Medium** (namespace-scoped impact with runtime detection and rapid containment). The residual risk is that the COTS container itself could be compromised and used for data exfiltration within its narrow network perimeter, but the attacker cannot escalate to cluster-wide access.

## 4. Risk Acceptance

**Who formally accepts the residual risk:** The programme's **ITSO-equivalent (Information Technology Security Officer) / Accreditor**, in consultation with the programme director.

**Acceptance conditions:**
1. All four compensating controls are deployed and verified operational
2. The risk acceptance is time-bound: **maximum 6 months** or until the vendor provides a patched image, whichever is earlier
3. The weekly vulnerability scan (Control 4) ensures ongoing visibility
4. The acceptance is documented in the programme's risk register with: risk description, compensating controls in place, residual rating, acceptance authority, review date, and escalation path

**Formal acceptance statement template:**

> "The programme accepts the residual risk (Medium) associated with running the [vendor name] COTS image v[version] with known CVEs and root execution, subject to the four compensating controls documented in `06-remediation/compensating-controls.md` being maintained and operational. This acceptance expires on [date, max 6 months from now] or upon vendor patch availability, whichever is earlier. Review authority: ITSO-equivalent / Accreditor."

## 5. Remediation Plan: Interim vs Target State

| Timeframe | State | What changes |
|---|---|---|
| **Now (before go-live)** | **Interim** | All four compensating controls deployed. COTS image scanned, CVE list documented. Risk acceptance signed. |
| **Month 1-2** | **Interim → Target** | Vendor engagement: escalate patch request via support contract. If vendor commits to a patched image within 90 days, interim controls remain. If vendor cannot commit, initiate alternative product evaluation. |
| **Month 3-4** | **Target (if vendor patches)** | Vendor releases patched image. Programme rebuilds and deploys new image. Trivy scan confirms zero Critical CVEs. Compensating controls 1-3 remain as defense-in-depth (they are good hygiene regardless). Control 4 (weekly scan) continues. |
| **Month 3-4** | **Interim (if vendor does NOT patch)** | Alternative product evaluation completes. If viable alternative exists, begin migration. If not, re-evaluate residual risk with ITSO and potentially extend acceptance for one additional quarter with enhanced monitoring. |
| **Month 6** | **Target** | COTS image is either patched, replaced, or formally decommissioned. Compensating controls may be relaxed if the underlying risk is eliminated. |

## 6. Assumptions

- The COTS product is a stateless API or web application. If it is stateful (e.g. a database), additional controls around data-at-rest encryption and backup would be needed.
- The vendor support contract includes a vulnerability disclosure SLA. If not, the programme should negotiate one as a condition of the support contract.
- The Kyverno admission controller (Module 2) is deployed cluster-wide before the COTS workload is onboarded. If not, the admission-based controls (Control 3) cannot be enforced.
- The ITSO-equivalent role exists in the programme's governance structure. If not, the programme director assumes this responsibility until the role is filled.

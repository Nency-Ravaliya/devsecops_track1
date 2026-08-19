# DevSecOps Track 1 — Solution and Demo Presentation Guide

## Purpose
This file captures the complete implemented solution for the assessment described in `task.txt`. It is designed to be the one source of truth for your live demo and interview explanation, showing what was delivered, how it was done, and how to present it from start to finish.

## What the task required
The assessment asked for a full Kubernetes and container security review of a vulnerable public reference repository, plus a delivery-ready remediation and CI/CD design. The expected deliverables included:

- Findings register for cluster and workload security issues.
- Shift-left pipeline design that catches weaknesses before merge.
- Runtime security, detection, and incident response design.
- Remediation advisory for critical findings.
- Compensating controls for COTS or legacy constraints.
- Threat modelling and compliance mapping.
- High-level and low-level architecture diagrams.
- Resilience, backup and DR design.
- Presentation-ready slides and documentation.

## What was implemented in this repository
This repo now contains the following concrete solution artifacts:

1. **Findings and remediation evidence**
   - `01-findings/findings-register.md` — the register of the key security findings, including K8S-001.
   - `06-remediation/fixed-manifests/k8s-001-fixed-superadmin.yaml` — the practical fix for the cluster-admin binding issue.
   - `08-compliance/evidence/conftest-rbac-gate-output.txt` — evidence of policy gate behavior.

2. **Automation and policy gate**
   - `scripts/run_policy_gate.sh` — renders Helm charts and runs Conftest against policy files.
   - `platform-policies/policy/k8s-rbac.rego` — RBAC policy that detects the trigger incident and related high-risk RBAC patterns.
   - `.github/workflows/policy-gate.yml` — GitHub Actions workflow to run the policy gate and security scans on push/PR.
   - `.gitlab-ci.yml` — GitLab CI equivalent with gitleaks, Conftest policy gate, and Trivy scan.

3. **Presentation and demo support**
   - `11-presentation/onepage.md` — a one-page executive summary and demo script.
   - `11-presentation/slides.pdf` — a ready-to-use PDF for the interview presentation.
   - `demo-presentation.md` (this file) — the full root-level explanation and A-Z demo script.

4. **Repository hygiene for presentation**
   - `scripts/archive_suggested.sh` — archival helper for non-essential demo folders.
   - `archive/` — moved candidate vulnerable demo content such as the `pwnchart` helm directory to keep the repo presentation-ready.

5. **Static report serving**
   - A local report server was started for `reference-target/guide/static/kics-report.html` at `http://127.0.0.1:8001/kics-report.html`.

## Root-level solution overview
The implementation approach followed these phases:

### 1. Review and identify the core risk
- The root cause finding is `K8S-001`: a `ClusterRoleBinding` granting `cluster-admin` to a non-system ServiceAccount.
- This is the exact trigger incident pattern the assessment describes, because it enables cluster-wide compromise from a workload identity.

### 2. Build a policy gate and fix pattern
- Added OPA/Conftest-based policy checks to detect dangerous RBAC patterns and insecure pod security settings.
- Created `scripts/run_policy_gate.sh` so the policy gate is reproducible locally and in CI.
- Added `.github/workflows/policy-gate.yml` so the same checks run automatically on GitHub push/PR.
- Kept `.gitlab-ci.yml` so the solution is repeatable in GitLab as well.

### 3. Apply remediation and verify
- Applied the fix manifest for K8S-001 locally: `06-remediation/fixed-manifests/k8s-001-fixed-superadmin.yaml`.
- Verified cluster role bindings and confirmed no non-system subject is bound to `cluster-admin`.

### 4. Prepare interview-ready output
- Created a one-page summary and a PDF slide deck.
- Built a demo script and local evidence paths so the presentation is concrete and traceable.

## Files you should use in the interview
Use these files as your demonstration anchors:

- `task.txt` — the original assessment brief.
- `demo-presentation.md` — this complete solution guide.
- `11-presentation/onepage.md` — quick executive demo script.
- `11-presentation/slides.pdf` — presentation-ready slide file.
- `.github/workflows/policy-gate.yml` — demonstrates the implementation of shift-left CI.
- `scripts/run_policy_gate.sh` — shows automation and policy gate tooling.
- `platform-policies/policy/k8s-rbac.rego` — the concrete policy engine rule set.
- `06-remediation/fixed-manifests/k8s-001-fixed-superadmin.yaml` — the remediation implementation.
- `08-compliance/evidence/conftest-rbac-gate-output.txt` — evidence of policy gate behavior.

## What the solution does end-to-end

### A. Problem explained
- The vulnerable repository contains intentionally insecure Kubernetes workloads.
- The highest-risk finding is a workload identity with `cluster-admin` privileges.
- This is a real cluster compromise pattern because it bypasses namespace isolation and enables RBAC abuse.

### B. The proposed pipeline
- The GitHub Actions workflow runs on push and PR.
- It installs Helm and Conftest, renders Helm charts, and evaluates them against policy.
- It also runs a secrets scan and a Trivy filesystem vulnerability scan.
- The policy gate produces artifact logs for review.

### C. The remediation path
- Remove the cluster-admin binding.
- Replace it with a namespace-scoped Role + RoleBinding.
- Enforce the same RBAC rule in CI so the weakness cannot reappear.

### D. The runtime story
- The repository now includes runtime security policy design notes and evidence paths.
- A local static report server was prepared for the KICS findings.
- The solution is not only about the fix, but also about the automated checks that prevent regression.

## How to demo it live
For a strong live interview, follow this sequence:

1. **Intro**: show `task.txt` and explain the problem context: multi-cloud DevSecOps, Kubernetes security, and the audit trigger incident.
2. **Findings**: open `01-findings/findings-register.md` and highlight K8S-001 plus the high-level risk categories.
3. **Policy**: show `.github/workflows/policy-gate.yml` and explain the shift-left design.
4. **Automation**: open `scripts/run_policy_gate.sh` and explain rendering Helm + Conftest testing.
5. **Run**: execute the policy gate locally or point to the GitHub Actions run, showing policy artifacts.
6. **Remediation**: show the fix manifest and explain why namespace-scoped roles are safer than cluster-admin.
7. **Evidence**: open `08-compliance/evidence/conftest-rbac-gate-output.txt` and the `kics-report.html` static scan.
8. **Presentation**: use `11-presentation/slides.pdf` as your structured slide deck.

## What to say in the interview

### Problem statement
"This solution reviews a vulnerable Kubernetes reference repository, identifies the critical RBAC and workload risks, and implements both a concrete remediation and a shift-left CI gate to prevent recurrence."

### Key message
"The strongest part of this solution is that it does not just fix one misconfiguration — it codifies the policy as code and automates the guardrail so the same issue is caught before merge."

### Why this matters
"A non-system workload identity with `cluster-admin` is equivalent to giving a malicious container full control of the cluster. In a government cloud programme, that is a direct path to data loss, destruction, and control-plane abuse."

### What was delivered
- Findings register with severity-driven prioritization.
- A CI/CD policy gate for RBAC and secrets.
- A remediation manifest for the live fix.
- A presentation-ready summary and slides.
- GitHub Actions and GitLab CI definitions for ongoing enforcement.

## Implementation details you can walk through

### Files and behaviours
- `scripts/run_policy_gate.sh`: renders Helm charts and runs Conftest, with local or Docker-based execution.
- `.github/workflows/policy-gate.yml`: automated GitHub workflow for the policy gate.
- `.gitlab-ci.yml`: equivalent pipeline for GitLab.
- `platform-policies/policy/k8s-rbac.rego`: policy rules that detect cluster-admin bindings and insecure bindings.
- `11-presentation/slides.pdf`: the final output you can show to panel members.

### Live demo commands
Copy and paste these in the demo terminal:

```bash
# Run the policy gate locally
./scripts/run_policy_gate.sh

# Show the static report
cd reference-target/guide/static && python3 -m http.server 8001
# then open http://127.0.0.1:8001/kics-report.html

# Apply the remediation fix
kubectl apply -f 06-remediation/fixed-manifests/k8s-001-fixed-superadmin.yaml

# Verify no risky binding remains
kubectl get clusterrolebindings -o wide | grep -E 'cluster-admin|superadmin|belong-to-us' || true
```

## Why this solution is strong for the interview
- It shows both hands-on remediation and automation.
- It connects the problem statement in `task.txt` to an actual codebase and CI implementation.
- It includes evidence files and a ready-to-use slide deck.
- It demonstrates a practical, repeatable DevSecOps workflow rather than a single-point fix.

## What to emphasize for each audience

### For technical interviewers
- The policy engine is infrastructure-as-code; it enforces RBAC rules before deployment.
- The solution uses both local scripts and GitHub Actions so it is repeatable.
- The remediation is minimal privilege and observable.

### For non-technical or governance audience
- This is a risk-control solution: bad changes are blocked before they reach production.
- The repo now has a documented review path and evidence for compliance.
- The slide deck and summary are designed to explain the finding without jargon.

## Next launch points
If you want a stronger final deliverable, I can also add:

- A `README.md` section summarizing the new demo and execution steps.
- A direct `demo.sh` script that launches the presentation environment, runs the gate, and starts the local report server.
- A second slide deck in a simple Markdown-to-PPTX format.

---

**Use this file as your interview anchor.** It is intentionally written as the narrative you can read from during the demo, with concrete file references and a step-by-step story from problem through policy, remediation, and evidence.

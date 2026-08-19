# Module 2 — Pipeline & Supply Chain Summary

## Purpose
This document summarizes the shift-left pipeline design that catches the assessment findings before deployment.

## Pipeline architecture
- The pipeline is built as a six-stage flow:
  1. Lint & validate.
  2. Policy & security gates.
  3. Build & scan.
  4. Sign & attest.
  5. Staging deploy.
  6. Production deploy with manual approval.

## Key controls
- **Conftest + OPA Rego** for custom RBAC and pod security policies.
- **Trivy + Grype** for container vulnerability scanning.
- **gitleaks** for secrets detection in Git.
- **Cosign** for image signing and SBOM attestation.
- **Kyverno** for admission verification of signatures and pod security.

## What it catches
- **K8S-001 / K8S-002 / K8S-003**: cluster-admin bindings and wildcard cluster roles.
- **K8S-004 / K8S-005 / K8S-006**: privileged containers, hostPath, runtime socket mounts.
- **K8S-009 / K8S-010**: secrets in manifests and env vars.
- **K8S-013 / K8S-014**: unpinned and `latest` image tags.
- **K8S-016**: NodePort services outside the approved namespace.

## Hard-fail vs soft-fail
- **Hard-fail**: Critical and high-risk findings, secrets detection, cluster-admin RBAC violations, unpinned images, unsigned images.
- **Soft-fail**: hygiene issues such as missing resource requests/limits and non-critical warning patterns.

## Why this design is strong
- Uses **policy-as-code** to enforce exact security requirements.
- Keeps the same policy intent across **CI and admission control**.
- Prevents the trigger incident by blocking dangerous manifest patterns before merge.
- Produces reusable artefacts: SBOMs, signed images, policy test output.

## What to demo
- `conftest test --policy platform-policies/policy` against a vulnerable manifest.
- gitleaks scan of the repository.
- Trivy scan or Triy docker action output.
- Cosign verify of a signed image.
- Kyverno admission policies enforcing the same controls at deploy time.

## Use this file to generate slides on:
- Pipeline stages and security gates.
- The shift-left control flow from repo to cluster.
- How the pipeline maps to the assessment findings.
- Hard-fail gating logic and evidence sources.

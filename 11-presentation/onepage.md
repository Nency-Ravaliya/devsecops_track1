# DevSecOps Track 1 — Executive One-Page

## Executive summary
- Repo: kubernetes-goat (reference-target) — intentionally-vulnerable demo.
- Trigger: `ClusterRoleBinding` granting `cluster-admin` to a non-system ServiceAccount (K8S-001). This is an immediate critical risk because any pod using that SA can control the cluster.

## Evidence
- `01-findings/findings-register.md` — findings and severity.
- `platform-policies/policy/k8s-rbac.rego` — policy that detects K8S-001.
- `08-compliance/evidence/conftest-rbac-gate-output.txt` — CI gate shows failing vulnerable manifest and passing remediation.

## Remediation (short)
1. Delete any ClusterRoleBinding binding `cluster-admin` to non-system principals.
2. Replace with a namespace-scoped `Role` + `RoleBinding` granting least privilege. See `06-remediation/fixed-manifests/k8s-001-fixed-superadmin.yaml`.
3. Enforce RBAC checks in CI using Conftest/OPA and deny on Critical findings.

## Presentation checklist (live demo)
- Recreate shown vulnerability (helm template + kubectl apply) in an isolated Kind cluster.
- Run the Conftest gate against the vulnerable manifest (show failing output).
- Apply remediation manifest and show gate passing (or show `kubectl get clusterrolebindings`).
- Show static KICS report page: `/reference-target/guide/static/kics-report.html` in browser.

## Key commands (copy-paste)
```bash
# Render helm chart and test
helm template pwnchart reference-target/infrastructure/helm-tiller/pwnchart > /tmp/pwnchart.yaml
conftest test --policy platform-policies/policy /tmp/pwnchart.yaml

# Apply remediation
kubectl delete clusterrolebinding superadmin || true
kubectl apply -f 06-remediation/fixed-manifests/k8s-001-fixed-superadmin.yaml

# Serve static report (local)
cd reference-target/guide/static && python3 -m http.server 8001
```

# Platform Policies — OPA Rego for Conftest

Centrally maintained Conftest policies consumed by application repos via `conftest pull` in CI.

> **Owner:** `@platform-security` team  
> **Versioning:** Application repos pin to a policy version (Git tag/commit SHA).  
> **Audit trail:** All policy changes are reviewed via MR before merge.

## Structure

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
│   └── k8s-podsec_test.rego
└── README.md
```

## Usage

### In CI (GitLab CI/CD)

```bash
# Pull policies from the central repo
conftest pull git::https://gitlab.example.com/platform/platform-policies.git//policy

# Test Kubernetes manifests
conftest test --policy policy/ manifests/*.yaml

# Test rendered Helm charts
helm template my-chart charts/ | conftest test --policy policy/ -
```

### Locally

```bash
# Clone the policies repo
git clone git@gitlab.example.com:platform/platform-policies.git

# Run tests
conftest verify --policy policy/

# Test a specific manifest
conftest test --policy policy/ --data policy/data.json my-deployment.yaml
```

## Policy Coverage → Module 1 Findings

| Policy file | Module 1 findings | Fail mode |
|---|---|---|
| `k8s-rbac.rego` | K8S-001, 002, 003, 007, 008 | Hard-fail on CRITICAL/HIGH |
| `k8s-podsec.rego` | K8S-004, 005, 006, 013, 014, 021, 022 | Hard-fail on CRITICAL/HIGH; warn on MEDIUM |
| `k8s-secrets.rego` | K8S-009, 010, 016 | Hard-fail on HIGH |
| `k8s-resources.rego` | K8S-023, 024 | Soft-fail (warn) |
| `vendor-cots-exceptions.rego` | COTS CVE allowlist | Hard-fail on NEW CVEs |

## Adding a New Policy

1. Write the Rego rule in the appropriate `.rego` file
2. Add a test in `tests/`
3. Run `conftest verify` to confirm tests pass
4. Open an MR with `@platform-security` as required reviewer
5. After merge, application pipelines pick up the update on their next `conftest pull`

## COTS Vendor Exception Process

To add a new accepted CVE to the COTS allowlist:

1. Document the CVE in `06-remediation/compensating-controls.md`
2. Get ITSO approval (risk acceptance form)
3. Add the CVE ID to `vendor-cots-exceptions.rego` `known_cve_allowlist`
4. MR with `@platform-security` approval

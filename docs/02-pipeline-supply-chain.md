# Pipeline & Supply Chain Security Design

## Overview

This document outlines the 6-stage GitLab CI/CD pipeline with security gates for the Kubernetes Goat assessment.

## Pipeline Stages

```
┌─────────────┐
│   Stage 1   │
│  Source     │──────┐
└─────────────┘      │
                     │
┌─────────────┐      │
│   Stage 2   │      │
│  SAST Scan  │──────┤
└─────────────┘      │
                     │
┌─────────────┐      │
│   Stage 3   │      │
│  Trivy Scan│──────┤
└─────────────┘      │
                     │
┌─────────────┐      │
│   Stage 4   │      │
│  SBOM Gen   │──────┤
└─────────────┘      │
                     │
┌─────────────┐      │
│   Stage 5   │      │
│  Cosign Sign│──────┤
└─────────────┘      │
                     │
┌─────────────┐      │
│   Stage 6   │      │
│  Deploy     │──────┘
└─────────────┘
```

## Stage 1: Source Code Analysis

### Tools:
- GitLab SAST (Static Application Security Testing)
- Bandit (Python security linter)
- Semgrep (Custom rules)

### Gates:
- Fail on all Critical and High severity findings
- Warning for Medium findings

## Stage 2: Dependency Scanning

### Tools:
- GitLab Dependency Scanning
- Snyk (optional integration)

### Gates:
- Fail on Critical vulnerabilities in dependencies
- Warning for High vulnerabilities

## Stage 3: Container Image Scanning

### Tools:
- **Trivy** - Comprehensive vulnerability scanner

### Commands:
```bash
# Scan image for vulnerabilities
trivy image --severity CRITICAL,HIGH --exit-code 1 $IMAGE_NAME

# Generate SBOM
trivy image --format cyclonedx --output sbom.json $IMAGE_NAME

# Scan for misconfigurations
trivy config $IMAGE_NAME
```

### Gates:
- Fail on Critical and High CVEs
- Fail on container misconfigurations (privileged containers, root user, etc.)

## Stage 4: Software Bill of Materials (SBOM)

### Tools:
- Syft for SBOM generation
- Trivy for SBOM validation

### Commands:
```bash
# Generate SBOM
syft $IMAGE_NAME -o cyclonedx-json > sbom.cyclonedx.json

# Validate SBOM
trivy sbom --format json sbom.cyclonedx.json
```

## Stage 5: Image Signing

### Tools:
- **Cosign** - Container image signing

### Commands:
```bash
# Generate key pair
cosign generate-key-pair

# Sign image
cosign sign --key cosign.key $IMAGE_NAME

# Verify signature
cosign verify --key cosign.pub $IMAGE_NAME
```

### Gates:
- Image must be signed before deployment
- Signature verification in deployment stage

## Stage 6: Deployment with Conftest

### Tools:
- **Conftest** - Policy testing
- **Kyverno** - Kubernetes admission controller

### Commands:
```bash
# Test Kubernetes manifests against policies
conftest test k8s-manifests/ --policy policies/

# Deploy with kubectl
kubectl apply -f k8s-manifests/
```

## Security Policies

### OPA Policies (via Conftest)

```rego
# policy/pod-security.rego
package kubernetes.admission

# Deny privileged containers
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Privileged container %v is not allowed", [container.name])
}

# Require non-root user
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.runAsNonRoot != true
    msg := sprintf("Container %v must run as non-root", [container.name])
}
```

### Kyverno Policies

```yaml
# policies/require-image-tag.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-tag
spec:
  validationFailureAction: enforce
  rules:
  - name: check-image-tag
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Images must have a tag"
      pattern:
        spec:
          containers:
          - image: "*:.*"
```

## GitLab CI/CD Example Configuration

```yaml
# .gitlab-ci.yml
stages:
  - source
  - scan
  - sbom
  - sign
  - deploy

variables:
  IMAGE_NAME: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

sast:
  stage: source
  script:
    - bandit -r . -f json -o bandit-report.json
  artifacts:
    reports:
      sast: bandit-report.json

trivy_scan:
  stage: scan
  script:
    - trivy image --severity CRITICAL,HIGH --exit-code 1 $IMAGE_NAME
    - trivy config --exit-code 1 $IMAGE_NAME
  only:
    - merge_requests
    - main

generate_sbom:
  stage: sbom
  script:
    - syft $IMAGE_NAME -o cyclonedx-json > sbom.json
    - trivy sbom --format json sbom.json
  artifacts:
    paths:
      - sbom.json

sign_image:
  stage: sign
  script:
    - cosign sign --key env://COSIGN_KEY $IMAGE_NAME
  only:
    - main

deploy:
  stage: deploy
  script:
    - conftest test k8s/ --policy policies/
    - kubectl apply -f k8s/
  environment:
    name: production
```

## Remediation Actions

1. **Immediate**: Block deployment of images with Critical vulnerabilities
2. **Short-term**: Implement full pipeline with all security gates
3. **Long-term**: Integrate with security dashboards and alerting
# DevSecOps Assessment Project

## Kubernetes Security, Shift-Left Pipeline, Runtime Protection

---

# Project Goal

- Review the Kubernetes environment
- Find the main security issues
- Design a safer and more secure setup
- Build security into the delivery process

---

# Key Findings

- 28 findings identified in total
- 6 Critical and 12 High issues found
- Biggest risk: Service Account with cluster-admin rights
- Risks were ranked by business impact and remediation priority

---

# Shift-Left DevSecOps Pipeline

- Policy validation before merge
- Secret scanning with Gitleaks
- Vulnerability scanning with Trivy and Grype
- Image signing with Cosign
- SBOM generation and security gates

---

# Runtime Protection

- Falco for runtime detection and alerting
- Cilium for network control and isolation
- Default-deny Network Policies
- External Secrets for secure secret management

---

# Architecture

- User traffic enters through secure entry points
- Frontend and backend are separated by network controls
- Security checks are enforced before deployment
- Runtime monitoring protects the cluster

---

# Final Summary

- Risks were identified and prioritized
- Shift-left controls were designed for the pipeline
- Runtime protections were added for monitoring and isolation
- The project provides a clear roadmap for enterprise use

### Closing
My objective was to build a practical, production-ready DevSecOps solution with security built into the whole process.

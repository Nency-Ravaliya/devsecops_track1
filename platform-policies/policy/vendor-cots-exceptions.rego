package main

import future.keywords.if
import future.keywords.in

# =============================================================================
# Conftest Rego Policy: COTS Vendor Image CVE Exception Allowlist
# Part of Track 1 — DevSecOps Assessment
#
# The programme has one COTS vendor image that cannot be rebuilt.
# This policy manages CVE exceptions for that specific image.
#
# Known unfixable CVEs are listed by ID and routed to compensating controls.
# New CVEs (not in the allowlist) cause a pipeline failure requiring review.
# =============================================================================

# Known and accepted CVEs for the COTS vendor image.
# These have compensating controls documented in 06-remediation/compensating-controls.md.
known_cve_allowlist = {
    "CVE-2023-6246",   # libc6 — no vendor patch available
    "CVE-2024-0727",   # openssl — no vendor patch available
    "CVE-2024-3094",   # xz/liblzma — see compensating controls
    "CVE-2023-5678",   # libssl — accepted risk with network isolation
    "CVE-2023-44487",  # HTTP/2 rapid reset — mitigated by WAF (Module 4)
}

# Image digest that is allowed to carry known CVEs
# This MUST be pinned to a specific digest, never a tag.
allowed_cots_digest = "cots-vendor@sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b"

# ---------------------------------------------------------------------------
# WARN: Known CVEs are logged but allowed
# ---------------------------------------------------------------------------
# These are accepted by the risk acceptance process.
# Severity: INFO — logged for visibility, not blocking.

known_cve_log[msg] {
    vulnerabilities := [v | v = input.results[_].vulnerabilities[_]]
    vuln := vulnerabilities[_]
    vuln.VulnerabilityID == known_cve_allowlist[_]

    msg := {
        "msg": sprintf(
            "INFO [COTS]: Known accepted CVE %s (%s) in package %s. Compensating controls documented in 06-remediation/compensating-controls.md.",
            [vuln.VulnerabilityID, vuln.PkgName, vuln.Severity]
        ),
        "severity": "INFO",
        "id": "COTS-ACCEPTED",
        "category": "vendor-cots",
    }
}

# ---------------------------------------------------------------------------
# DENY: Unknown CVEs in the COTS image
# ---------------------------------------------------------------------------
# Any CVE in the COTS image that is NOT in the allowlist MUST be reviewed.
# Severity: HIGH — blocks pipeline until reviewed.

unknown_cve_deny[msg] {
    vulnerabilities := [v | v = input.results[_].vulnerabilities[_]]
    vuln := vulnerabilities[_]
    not known_cve_allowlist[vuln.VulnerabilityID]

    msg := {
        "msg": sprintf(
            "HIGH [COTS-NEW]: Unknown/untracked CVE %s (%s) in COTS vendor image. Not in exception allowlist. Document in 06-remediation/compensating-controls.md or escalate to vendor.",
            [vuln.VulnerabilityID, vuln.PkgName]
        ),
        "severity": "HIGH",
        "id": "COTS-NEW",
        "category": "vendor-cots",
    }
}

# ---------------------------------------------------------------------------
# DENY: COTS image not pinned by digest
# ---------------------------------------------------------------------------
# The COTS image must be referenced by digest, NOT by tag.
# Severity: CRITICAL

cots_image_not_pinned_deny[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]

    contains(container.image, allowed_cots_digest)
    # If image CONTAINS the allowed digest, allow.
}

cots_image_not_pinned_deny[msg] {
    containers := [c | c = input.spec.template.spec.containers[_]]
    container := containers[_]

    # This is the COTS image context
    contains(container.image, "cots-vendor")
    not contains(container.image, "@sha256:")

    msg := {
        "msg": sprintf(
            "CRITICAL [COTS]: COTS vendor image '%s' is not pinned by digest. Use digest reference for supply chain integrity.",
            [container.image]
        ),
        "severity": "CRITICAL",
        "id": "COTS-PINNING",
        "category": "vendor-cots",
    }
}

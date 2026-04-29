from __future__ import annotations

from urllib.parse import urlparse

from ..models import Finding
from .base import PassiveCheck


class SecurityHeadersCheck(PassiveCheck):
    name = "headers"
    description = "Passive security header and cookie checks."
    max_requests_per_target = 1

    def supports(self, template):
        return template.method == "GET"

    async def run(self, template, client, baseline, config):
        if template.url.rstrip("/") != config.target_url.rstrip("/"):
            return []
        try:
            snapshot = await client.send(template, check_name=self.name)
        except Exception:
            return []
        headers = {k.lower(): v for k, v in snapshot.headers.items()}
        findings = []
        final_scheme = urlparse(snapshot.final_url or template.url).scheme
        required = [
            ("content-security-policy", "Content-Security-Policy", "Medium"),
            ("x-frame-options", "X-Frame-Options", "Low"),
            ("x-content-type-options", "X-Content-Type-Options", "Low"),
            ("referrer-policy", "Referrer-Policy", "Low"),
        ]
        if final_scheme == "https":
            required.append(("strict-transport-security", "Strict-Transport-Security", "Low"))
        for key, name, severity in required:
            if key not in headers:
                findings.append(Finding(
                    type=f"Missing Security Header: {name}",
                    title=f"Missing {name}",
                    severity=severity,
                    confidence="High",
                    url=snapshot.final_url or template.url,
                    method="GET",
                    evidence=f"{name} header was not present in the response.",
                    remediation=f"Set a defensive {name} policy appropriate for the application.",
                    source=self.name,
                    tags={"headers", "passive"},
                ))
        csp = headers.get("content-security-policy", "").lower()
        if csp and ("'unsafe-inline'" in csp or "*" in csp or "http:" in csp):
            findings.append(Finding(
                type="Weak Security Header: Content-Security-Policy",
                title="Weak Content-Security-Policy",
                severity="Low",
                confidence="Medium",
                url=snapshot.final_url or template.url,
                method="GET",
                evidence="CSP contains unsafe-inline, wildcard, or insecure http source.",
                remediation="Tighten CSP source lists and avoid unsafe-inline/unsafe-eval where possible.",
                source=self.name,
                tags={"headers", "passive"},
            ))
        return findings

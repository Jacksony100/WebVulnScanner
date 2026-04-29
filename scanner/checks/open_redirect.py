from __future__ import annotations

from urllib.parse import unquote, urljoin, urlparse

from ..models import Finding
from .base import ActiveCheck


MARKER_REDIRECT = "https://example.com/advscan"
REDIRECT_PARAM_NAMES = {
    "url", "redirect", "redirect_url", "next", "return", "return_url",
    "continue", "callback", "dest", "destination",
}


def is_external_redirect(location: str, base_host: str) -> bool:
    if not location:
        return False
    decoded = unquote(location).strip().replace("\\", "/")
    parsed = urlparse(decoded)
    if not parsed.netloc and decoded.startswith("//"):
        parsed = urlparse("https:" + decoded)
    if not parsed.netloc:
        return False
    host = (parsed.hostname or "").lower()
    base_host = (base_host or "").lower()
    return bool(host and host != base_host and not host.endswith(f".{base_host}"))


class OpenRedirectCheck(ActiveCheck):
    name = "open_redirect"
    description = "Checks redirect parameters using parsed Location host comparison."
    max_requests_per_target = 2

    def supports(self, template):
        names = [name.lower() for name in template.parameter_names()]
        return bool(REDIRECT_PARAM_NAMES & set(names))

    async def run(self, template, client, baseline, config):
        findings = []
        host = urlparse(config.target_url).hostname or ""
        for name in template.parameter_names()[:3]:
            if name.lower() not in REDIRECT_PARAM_NAMES:
                continue
            if not template.has_param(name) and not template.data:
                continue
            probe = template.with_param_payload(name, MARKER_REDIRECT) if template.has_param(name) else template.with_body_payload(name, MARKER_REDIRECT)
            try:
                snapshot = await client.send(probe, check_name=self.name)
            except Exception:
                continue
            location = snapshot.headers.get("Location") or snapshot.headers.get("location") or ""
            if 300 <= snapshot.status_code < 400 and is_external_redirect(location, host):
                findings.append(Finding(
                    type="Open Redirect",
                    title="Open Redirect",
                    severity="Medium",
                    confidence="High",
                    url=template.url,
                    method=template.method,
                    parameter=name,
                    evidence=f"Redirect Location points to external host: {location[:160]}",
                    request_summary={"parameter": name, "payload": MARKER_REDIRECT},
                    response_summary={"status": snapshot.status_code, "location": location},
                    remediation="Validate redirect destinations with parsed URL host allowlists and prefer relative redirects.",
                    source=self.name,
                    tags={"redirect", "active"},
                    cwe="CWE-601",
                ))
                break
        return findings

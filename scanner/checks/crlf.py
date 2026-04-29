from __future__ import annotations

from ..models import Finding
from .base import ActiveCheck


CRLF_PAYLOADS = ["%0d%0aX-Advscan-CRLF:%201", "\r\nX-Advscan-CRLF: 1"]


class CRLFCheck(ActiveCheck):
    name = "crlf"
    description = "Safe CRLF response splitting marker check."
    max_requests_per_target = 3

    def supports(self, template):
        return bool(template.parameter_names())

    async def run(self, template, client, baseline, config):
        for name in template.parameter_names()[:3]:
            for payload in CRLF_PAYLOADS:
                probe = template.with_param_payload(name, payload) if template.has_param(name) else template.with_body_payload(name, payload)
                try:
                    snapshot = await client.send(probe, check_name=self.name)
                except Exception:
                    continue
                headers = {k.lower(): v for k, v in snapshot.headers.items()}
                if "x-advscan-crlf" in headers or "x-advscan-crlf" in snapshot.text_sample.lower():
                    return [Finding(
                        type="CRLF Injection",
                        title="CRLF Injection",
                        severity="Medium",
                        confidence="High",
                        url=template.url,
                        method=template.method,
                        parameter=name,
                        evidence="Controlled CRLF marker appeared in response headers/body.",
                        request_summary={"parameter": name, "payload": payload},
                        response_summary={"status": snapshot.status_code},
                        remediation="Reject or encode CR/LF characters before using input in headers or redirects.",
                        source=self.name,
                        tags={"crlf", "active"},
                        cwe="CWE-93",
                    )]
        return []

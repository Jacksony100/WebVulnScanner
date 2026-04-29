from __future__ import annotations

from ..models import Finding
from .base import ActiveCheck


SSTI_PROBES = [("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49")]


class SSTICheck(ActiveCheck):
    name = "ssti"
    description = "Safe arithmetic template evaluation probes."
    max_requests_per_target = 4

    def supports(self, template):
        path = template.url.lower().split("?")[0]
        if path.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".pdf", ".zip")):
            return False
        return bool(template.parameter_names())

    async def run(self, template, client, baseline, config):
        try:
            base = await client.send(template, check_name=f"{self.name}:baseline")
        except Exception:
            base = None
        base_text = base.text_sample if base else ""
        for name in template.parameter_names()[:4]:
            for payload, expected in SSTI_PROBES:
                probe = template.with_param_payload(name, payload) if template.has_param(name) else template.with_body_payload(name, payload)
                try:
                    snapshot = await client.send(probe, check_name=self.name)
                except Exception:
                    continue
                if expected in snapshot.text_sample and expected not in base_text and payload not in snapshot.text_sample:
                    return [Finding(
                        type="Server-Side Template Injection",
                        title="Server-Side Template Injection",
                        severity="High",
                        confidence="High",
                        url=template.url,
                        method=template.method,
                        parameter=name,
                        evidence=f"Template expression evaluated to {expected}.",
                        request_summary={"parameter": name, "payload": payload},
                        response_summary={"status": snapshot.status_code, "length": snapshot.length},
                        remediation="Avoid rendering user input as templates; pass untrusted data only as escaped variables.",
                        source=self.name,
                        tags={"ssti", "active"},
                        cwe="CWE-1336",
                    )]
        return []

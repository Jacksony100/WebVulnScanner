from __future__ import annotations

import html

from ..models import Finding
from .base import ActiveCheck


XSS_PAYLOADS = [
    "<advscan-xss>",
    "\"><advscan-xss>",
    "<img src=x onerror=advscanXssMarker>",
    "<script>advscanXssMarker</script>",
]


class ReflectedXSSCheck(ActiveCheck):
    name = "xss"
    description = "Reflected input and potential XSS context checks."
    max_requests_per_target = 6

    def supports(self, template):
        path = template.url.lower().split("?")[0]
        if path.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".pdf", ".zip")):
            return False
        return bool(template.parameter_names())

    async def run(self, template, client, baseline, config):
        findings = []
        for name in template.parameter_names()[:4]:
            for payload in XSS_PAYLOADS:
                probe = template.with_param_payload(name, payload) if template.has_param(name) else template.with_body_payload(name, payload)
                try:
                    snapshot = await client.send(probe, check_name=self.name)
                except Exception:
                    continue
                evidence, severity, confidence, title = classify_reflection(snapshot.text_sample, payload)
                if evidence:
                    findings.append(Finding(
                        type=title,
                        title=title,
                        severity=severity,
                        confidence=confidence,
                        url=template.url,
                        method=template.method,
                        parameter=name,
                        evidence=evidence,
                        request_summary={"parameter": name, "payload": payload},
                        response_summary={"status": snapshot.status_code, "length": snapshot.length},
                        remediation="Encode output by context and validate/normalize untrusted input before rendering.",
                        source=self.name,
                        tags={"xss", "active"},
                        cwe="CWE-79",
                    ))
                    break
            if findings:
                break
        return findings


def classify_reflection(body: str, payload: str):
    lower = (body or "").lower()
    payload_lower = payload.lower()
    escaped = html.escape(payload).lower()
    if payload_lower not in lower and "advscanxssmarker" not in lower and "advscan-xss" not in lower:
        return None, "Info", "Low", "Reflected input"
    if payload_lower in lower and escaped not in lower and ("<script" in lower or "onerror=" in lower or "onload=" in lower):
        return "Payload reflected unescaped in executable-looking HTML context.", "Medium", "High", "Potential XSS"
    if payload_lower in lower and escaped not in lower:
        return "Raw payload reflected without HTML escaping; manual browser validation recommended.", "Low", "Medium", "Reflected input"
    return "Input marker reflected but appears escaped.", "Info", "Low", "Reflected input"

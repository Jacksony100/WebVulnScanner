from __future__ import annotations

from difflib import SequenceMatcher

from ..models import Finding
from .base import ActiveCheck


ERROR_SIGNATURES = [
    "sql syntax",
    "mysql",
    "postgresql",
    "sqlite",
    "ora-",
    "odbc",
    "unclosed quotation",
    "syntax error at or near",
]
ERROR_PAYLOADS = ["'", "\"", "'))", "`)"]
BOOLEAN_PAIRS = []
TIME_PAYLOADS = []


class SQLInjectionCheck(ActiveCheck):
    name = "sqli"
    description = "Safe SQL injection probes: error, boolean, and deep-only low-budget time checks."
    max_requests_per_target = 8

    def supports(self, template):
        path = template.url.lower().split("?")[0]
        if path.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".pdf", ".zip")):
            return False
        return bool(template.parameter_names())

    async def run(self, template, client, baseline, config):
        findings = []
        base_snapshot = None
        try:
            base_snapshot = await client.send(template, check_name=f"{self.name}:baseline")
        except Exception:
            pass
        base_text = base_snapshot.text_sample if base_snapshot else ""
        base_status = base_snapshot.status_code if base_snapshot else 0

        for name in template.parameter_names()[:4]:
            for payload in ERROR_PAYLOADS:
                probe = template.with_param_payload(name, payload) if template.has_param(name) else template.with_body_payload(name, payload)
                try:
                    snapshot = await client.send(probe, check_name=self.name)
                except Exception:
                    continue
                lower = snapshot.text_sample.lower()
                if any(signature in lower for signature in ERROR_SIGNATURES):
                    findings.append(_finding(template, name, payload, "database error signature in response", "High", "High", "SQL Injection (error-based)", snapshot))
                    break
                if snapshot.status_code >= 500 and base_status and base_status < 500:
                    findings.append(_finding(template, name, payload, f"HTTP {snapshot.status_code} after SQL probe; baseline HTTP {base_status}", "Medium", "Medium", "SQL Injection (server error)", snapshot))
                    break
            if findings:
                break

            for true_payload, false_payload in BOOLEAN_PAIRS:
                try:
                    true_response = await client.send(_payload(template, name, true_payload), check_name=self.name)
                    false_response = await client.send(_payload(template, name, false_payload), check_name=self.name)
                except Exception:
                    continue
                if _boolean_diff(base_text, true_response.text_sample, false_response.text_sample):
                    findings.append(_finding(template, name, f"{true_payload} / {false_payload}", "consistent true/false SQL differential", "Medium", "Medium", "SQL Injection (boolean differential)", true_response))
                    break
            if findings:
                break

            if config.mode == "deep":
                for payload in TIME_PAYLOADS[:1]:
                    try:
                        snapshot = await client.send(_payload(template, name, payload), check_name=self.name)
                    except Exception:
                        continue
                    baseline_ms = base_snapshot.elapsed_ms if base_snapshot else 0
                    if snapshot.elapsed_ms >= max(3000, baseline_ms + 2500):
                        findings.append(_finding(template, name, payload, f"response delayed {snapshot.elapsed_ms}ms; baseline {baseline_ms}ms", "Medium", "Medium", "SQL Injection (time-based)", snapshot))
                        break
        return findings


def _payload(template, name, value):
    return template.with_param_payload(name, value) if template.has_param(name) else template.with_body_payload(name, value)


def _boolean_diff(base: str, true_text: str, false_text: str) -> bool:
    if not true_text or not false_text:
        return False
    delta = abs(len(true_text) - len(false_text))
    if delta < max(80, int(max(len(true_text), len(false_text)) * 0.12)):
        return False
    true_base = SequenceMatcher(None, base[:5000], true_text[:5000]).ratio() if base else 1.0
    true_false = SequenceMatcher(None, true_text[:5000], false_text[:5000]).ratio()
    return true_base > 0.70 and true_false < 0.92


def _finding(template, name, payload, evidence, severity, confidence, title, snapshot):
    return Finding(
        type=title,
        title=title,
        severity=severity,
        confidence=confidence,
        url=template.url,
        method=template.method,
        parameter=name,
        evidence=evidence,
        request_summary={"parameter": name, "payload": payload},
        response_summary={"status": snapshot.status_code, "length": snapshot.length, "elapsed_ms": snapshot.elapsed_ms},
        remediation="Use parameterized queries/ORM binding and avoid string concatenation in database queries.",
        source="sqli",
        tags={"sqli", "active"},
        cwe="CWE-89",
    )

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import Finding, RequestTemplate
from .base import ActiveCheck


OBJECT_MARKERS = re.compile(r"(email|phone|address|invoice|order|user_id|role)\s*[:=]", re.I)
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)


class PotentialIDORCheck(ActiveCheck):
    name = "idor"
    description = "Potential object reference probing without claiming confirmed IDOR."
    max_requests_per_target = 2

    def supports(self, template):
        return bool(_candidate_params(template) or _numeric_path_segment(template.url))

    async def run(self, template, client, baseline, config):
        candidates = _candidate_params(template)
        findings = []
        try:
            baseline_snapshot = await client.send(template, check_name=f"{self.name}:baseline")
        except Exception:
            baseline_snapshot = None
        for name, value in candidates[:2]:
            mutated = _mutate_identifier(value)
            if mutated == value:
                continue
            probe = template.with_param_payload(name, mutated) if template.has_param(name) else template.with_body_payload(name, mutated)
            try:
                snapshot = await client.send(probe, check_name=self.name)
            except Exception:
                continue
            if _looks_like_object_reference_change(baseline_snapshot, snapshot):
                findings.append(Finding(
                    type="Potential IDOR/Object Reference",
                    title="Potential IDOR/Object Reference",
                    severity="Medium" if OBJECT_MARKERS.search(snapshot.text_sample or "") else "Low",
                    confidence="Low",
                    url=template.url,
                    method=template.method,
                    parameter=name,
                    evidence="Changing an object-like identifier returned a different object-shaped response. This is not confirmed without a second authorization context.",
                    request_summary={"parameter": name, "original": value, "mutated": mutated},
                    response_summary={"status": snapshot.status_code, "length": snapshot.length},
                    remediation="Verify object-level authorization server-side for every referenced resource. Confirm with two authorized test accounts before reporting as IDOR.",
                    source=self.name,
                    tags={"idor", "object-reference", "active"},
                    cwe="CWE-639",
                ))
                break
        return findings


def _candidate_params(template: RequestTemplate) -> list[tuple[str, str]]:
    values = []
    combined = dict(template.params)
    from urllib.parse import parse_qsl, urlparse
    combined.update({key: value for key, value in parse_qsl(urlparse(template.url).query, keep_blank_values=True)})
    combined.update(template.data or {})
    if isinstance(template.json_body, dict):
        combined.update({str(k): str(v) for k, v in template.json_body.items() if isinstance(v, (str, int))})
    for name, value in combined.items():
        lowered = name.lower()
        text = str(value)
        if "id" in lowered or "user" in lowered or "order" in lowered or text.isdigit() or UUID_RE.search(text):
            values.append((name, text))
    return values


def _numeric_path_segment(url: str) -> str | None:
    for part in urlparse(url).path.split("/"):
        if part.isdigit():
            return part
    return None


def _mutate_identifier(value: str) -> str:
    if value.isdigit():
        return str(int(value) + 1)
    if UUID_RE.search(value):
        return re.sub(r"[0-9a-f]$", "0" if value[-1].lower() != "0" else "1", value, flags=re.I)
    return value


def _looks_like_object_reference_change(baseline, snapshot) -> bool:
    if snapshot.status_code not in {200, 206, 401, 403, 404}:
        return False
    if baseline is None:
        return OBJECT_MARKERS.search(snapshot.text_sample or "") is not None
    if baseline.status_code != snapshot.status_code:
        return snapshot.status_code in {200, 401, 403, 404}
    if baseline.content_type != snapshot.content_type:
        return False
    length_delta = abs((baseline.length or 0) - (snapshot.length or 0))
    if length_delta < 20 and baseline.text_sample[:200] == snapshot.text_sample[:200]:
        return False
    return OBJECT_MARKERS.search(snapshot.text_sample or "") is not None or length_delta > 80

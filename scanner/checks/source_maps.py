from __future__ import annotations

import json
from urllib.parse import urljoin

from ..models import Finding, RequestTemplate
from .base import PassiveCheck


def is_valid_source_map(body: str) -> bool:
    try:
        data = json.loads(body or "{}")
    except json.JSONDecodeError:
        return False
    return (
        isinstance(data, dict)
        and data.get("version") is not None
        and isinstance(data.get("sources"), list)
        and "mappings" in data
        and isinstance(data.get("mappings"), str)
    )


class SourceMapCheck(PassiveCheck):
    name = "source_maps"
    description = "Validates exposed JavaScript source maps."
    max_requests_per_target = 1

    def supports(self, template):
        url = template.url.lower().split("?")[0]
        return url.endswith(".js") or url.endswith(".js.map") or "javascript" in template.tags

    async def run(self, template, client, baseline, config):
        candidates = [template.url] if template.url.lower().endswith(".map") else [f"{template.url.split('?')[0]}.map"]
        findings = []
        for candidate in candidates:
            probe = RequestTemplate(method="GET", url=urljoin(template.url, candidate), source=self.name, tags={"source-map"})
            try:
                snapshot = await client.send(probe, check_name=self.name)
            except Exception:
                continue
            if snapshot.status_code == 200 and is_valid_source_map(snapshot.text_sample):
                data = json.loads(snapshot.text_sample)
                sources = data.get("sources") or []
                findings.append(Finding(
                    type="Source Map Disclosure",
                    title="Public JavaScript source map",
                    severity="Low",
                    confidence="High",
                    url=probe.url,
                    method="GET",
                    evidence=f"Valid source map with {len(sources)} sources; sample: {', '.join(map(str, sources[:3]))}",
                    response_summary={"status": snapshot.status_code, "sources": len(sources)},
                    remediation="Avoid publishing production source maps or restrict them to authorized debugging workflows.",
                    source=self.name,
                    tags={"source-map", "passive"},
                ))
        return findings

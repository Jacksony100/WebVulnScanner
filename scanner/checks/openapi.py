from __future__ import annotations

import json

from ..models import Finding
from .base import PassiveCheck


class OpenAPIDocsCheck(PassiveCheck):
    name = "openapi"
    description = "Reports exposed OpenAPI/Swagger documents as attack-surface inventory."

    def supports(self, template):
        lowered = template.url.lower()
        return "openapi" in template.tags or lowered.endswith(("openapi.json", "swagger.json")) or "api-docs" in lowered

    async def run(self, template, client, baseline, config):
        try:
            snapshot = await client.send(template, check_name=self.name)
        except Exception:
            return []
        try:
            data = json.loads(snapshot.text_sample or "{}")
        except json.JSONDecodeError:
            return []
        paths = data.get("paths") or {}
        if not isinstance(paths, dict):
            return []
        sensitive_paths = [
            path for path in paths
            if any(marker in path.lower() for marker in ("admin", "internal", "debug", "secret", "token", "password"))
        ]
        if not sensitive_paths:
            return []
        return [Finding(
            type="OpenAPI sensitive endpoint disclosure",
            title="OpenAPI document exposes sensitive-looking paths",
            severity="Low",
            confidence="Medium",
            url=template.url,
            method="GET",
            evidence=f"API document contains sensitive-looking paths: {', '.join(sensitive_paths[:5])}",
            response_summary={"status": snapshot.status_code, "paths": len(paths), "sensitive_paths": sensitive_paths[:10]},
            remediation="Restrict API documentation when it reveals non-public endpoints or sensitive operational details.",
            source=self.name,
            tags={"openapi", "information-disclosure"},
        )]

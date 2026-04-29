from __future__ import annotations

from ..models import Finding, RequestTemplate
from .base import ActiveCheck


class CORSCheck(ActiveCheck):
    name = "cors"
    description = "Low-budget CORS origin reflection check."
    max_requests_per_target = 1

    def supports(self, template):
        return template.method == "GET" and template.depth == 0

    async def run(self, template, client, baseline, config):
        origin = "https://advscan.example"
        probe = RequestTemplate(method="GET", url=config.target_url, headers={"Origin": origin}, source=self.name)
        try:
            snapshot = await client.send(probe, check_name=self.name)
        except Exception:
            return []
        acao = snapshot.headers.get("Access-Control-Allow-Origin") or snapshot.headers.get("access-control-allow-origin") or ""
        acac = (snapshot.headers.get("Access-Control-Allow-Credentials") or snapshot.headers.get("access-control-allow-credentials") or "").lower()
        if acao == "*" or acao == origin:
            severity = "Medium" if acac == "true" and acao == origin else "Low"
            return [Finding(
                type="Permissive CORS",
                title="Permissive CORS policy",
                severity=severity,
                confidence="High",
                url=config.target_url,
                method="GET",
                evidence=f"Access-Control-Allow-Origin={acao}; credentials={acac or 'not set'}",
                response_summary={"status": snapshot.status_code, "acao": acao, "acac": acac},
                remediation="Use a strict Origin allowlist and include Vary: Origin when reflecting allowed origins.",
                source=self.name,
                tags={"cors", "active"},
            )]
        return []

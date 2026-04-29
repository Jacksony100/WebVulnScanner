from __future__ import annotations

import base64
import json
import re

from ..models import Finding
from .base import PassiveCheck


JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")


class JWTCheck(PassiveCheck):
    name = "jwt"
    description = "Passive JWT exposure and alg=none inspection without cracking."

    def supports(self, template):
        return template.method == "GET"

    async def run(self, template, client, baseline, config):
        if template.depth > 1:
            return []
        try:
            snapshot = await client.send(template, check_name=self.name)
        except Exception:
            return []
        findings = []
        for token in JWT_RE.findall(snapshot.text_sample or "")[:3]:
            alg = _jwt_alg(token)
            findings.append(Finding(
                type="JWT Exposed",
                title="JWT-like token in response",
                severity="Info" if alg != "none" else "Low",
                confidence="Medium",
                url=template.url,
                method=template.method,
                evidence=f"JWT-like token reflected in response; alg={alg or 'unknown'}",
                remediation="Avoid exposing tokens in cacheable pages and verify JWT algorithms server-side.",
                source=self.name,
                tags={"jwt", "passive"},
            ))
        return findings


def _jwt_alg(token: str) -> str | None:
    try:
        header = token.split(".", 1)[0]
        padded = header + "=" * (-len(header) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        return data.get("alg")
    except Exception:
        return None

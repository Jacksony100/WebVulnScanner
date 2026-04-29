from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CheckContext:
    check_name: str
    template_fingerprint: str


class BaseCheck:
    name = "base"
    description = ""
    modes = {"safe", "active", "deep"}
    risk_level = "passive"
    max_requests_per_target = 3
    needs_baseline = False

    def supports(self, template) -> bool:
        return True

    async def run(self, template, client, baseline, config):
        raise NotImplementedError


class PassiveCheck(BaseCheck):
    risk_level = "passive"


class ActiveCheck(BaseCheck):
    modes = {"active", "deep"}
    risk_level = "active"

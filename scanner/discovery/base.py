from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Asset, DiscoveryCandidate, HttpResponseSnapshot, RequestTemplate


@dataclass
class DiscoveryResult:
    templates: list[RequestTemplate] = field(default_factory=list)
    pages: list[tuple[str, str]] = field(default_factory=list)
    snapshots: list[HttpResponseSnapshot] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    candidates: list[DiscoveryCandidate] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class BaseDiscoverer:
    name = "base"

    async def discover(self, client, registry) -> DiscoveryResult:
        raise NotImplementedError

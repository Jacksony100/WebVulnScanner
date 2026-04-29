from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

from ..models import Asset, DiscoveryCandidate, RequestTemplate
from ..scope import absolute_url, is_in_scope
from .base import BaseDiscoverer, DiscoveryResult
from .graphql import graphql_candidates, validate_graphql_candidate
from .openapi import parse_openapi_document


SAFE_WELL_KNOWN_PATHS = [
    "/sitemap.xml",
    "/robots.txt",
    "/.well-known/security.txt",
    "/openapi.json",
    "/swagger.json",
]

ACTIVE_WELL_KNOWN_PATHS = SAFE_WELL_KNOWN_PATHS + [
    "/swagger/v1/swagger.json",
    "/v3/api-docs",
    "/api-docs",
]

DEEP_WELL_KNOWN_PATHS = ACTIVE_WELL_KNOWN_PATHS + [
    "/api",
    "/api/docs",
    "/docs",
    "/swagger-ui.html",
]


class WellKnownDiscoverer(BaseDiscoverer):
    name = "well-known"

    async def discover(self, client, registry) -> DiscoveryResult:
        result = DiscoveryResult()
        paths = _paths_for_mode(client.config.mode)[: client.config.max_common_candidates or 0]
        candidates = [
            RequestTemplate(method="GET", url=urljoin(client.config.target_url.rstrip("/") + "/", path.lstrip("/")), source=self.name, tags={"well-known"})
            for path in paths
        ]
        graphql_common = graphql_candidates(client.config.target_url, client.config.mode)
        result.candidates.extend(graphql_common)

        for template in candidates:
            if not is_in_scope(template.url, client.config):
                continue
            registry.add(template)
            try:
                snapshot = await client.send(template, check_name=self.name)
            except Exception as exc:
                result.warnings.append(f"well-known discovery failed for {template.url}: {exc}")
                continue
            if snapshot.status_code not in {200, 401, 403}:
                continue
            asset = self._asset_from_response(template, snapshot)
            if asset:
                result.assets.append(asset)
            generated = self._templates_from_response(template, snapshot)
            registry.extend(generated)
            result.templates.extend(generated)

        for candidate in graphql_common:
            if not is_in_scope(candidate.url, client.config):
                continue
            validated, asset, template = await validate_graphql_candidate(candidate, client)
            if asset:
                result.assets.append(asset)
            if template:
                registry.add(template)
                result.templates.append(template)
        return result

    def _asset_from_response(self, template: RequestTemplate, snapshot) -> Asset | None:
        body = snapshot.text_sample or ""
        path = template.url.lower()
        if path.endswith("robots.txt") and "user-agent" in body.lower():
            return Asset(type="robots", url=template.url, source=self.name, evidence="robots.txt contains User-agent directives", tags={"metadata"}, confidence="High")
        if path.endswith("sitemap.xml") and "<urlset" in body.lower():
            return Asset(type="sitemap", url=template.url, source=self.name, evidence="sitemap.xml contains urlset XML", tags={"metadata"}, confidence="High")
        if any(marker in body[:5000].lower() for marker in ['"openapi"', '"swagger"', '"paths"']):
            return Asset(type="openapi", url=template.url, source=self.name, evidence="OpenAPI/Swagger-like document responded from common path", tags={"api", "openapi"}, confidence="Medium")
        if snapshot.status_code in {401, 403}:
            return Asset(type="endpoint", url=template.url, source=self.name, evidence=f"Common path exists but is access-restricted (HTTP {snapshot.status_code})", tags={"interesting"}, confidence="Low")
        return None

    def _templates_from_response(self, template: RequestTemplate, snapshot) -> list[RequestTemplate]:
        path = template.url.lower()
        body = snapshot.text_sample or ""
        if path.endswith("sitemap.xml"):
            return _parse_sitemap(snapshot.final_url or template.url, body)
        if path.endswith("robots.txt"):
            return _parse_robots(snapshot.final_url or template.url, body)
        if any(marker in body[:5000].lower() for marker in ['"openapi"', '"swagger"', '"paths"']):
            return parse_openapi_document(snapshot.final_url or template.url, body, template.url)
        return []


def _parse_sitemap(url: str, body: str) -> list[RequestTemplate]:
    templates: list[RequestTemplate] = []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return templates
    for loc in root.findall(".//{*}loc"):
        absolute = absolute_url(url, loc.text or "")
        if absolute:
            templates.append(RequestTemplate(method="GET", url=absolute, source="sitemap", discovered_from=url, tags={"html", "sitemap"}))
    return templates


def _parse_robots(url: str, body: str) -> list[RequestTemplate]:
    templates = []
    for line in (body or "").splitlines():
        match = re.match(r"\s*(allow|disallow)\s*:\s*(\S+)", line, re.I)
        if not match:
            continue
        value = match.group(2).strip()
        if not value or value == "/":
            continue
        absolute = absolute_url(url, value)
        if absolute:
            templates.append(RequestTemplate(method="GET", url=absolute, source="robots", discovered_from=url, tags={"interesting", "robots"}))
    return templates


def _paths_for_mode(mode: str) -> list[str]:
    if mode == "deep":
        return DEEP_WELL_KNOWN_PATHS
    if mode == "active":
        return ACTIVE_WELL_KNOWN_PATHS
    return SAFE_WELL_KNOWN_PATHS

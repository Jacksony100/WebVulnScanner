from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..models import RequestTemplate
from ..scope import absolute_url, is_in_scope
from .base import BaseDiscoverer, DiscoveryResult


FETCH_RE = re.compile(r"\bfetch\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
AXIOS_RE = re.compile(r"\baxios\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
XHR_RE = re.compile(r"\.open\s*\(\s*['\"]([A-Z]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.I)
AJAX_URL_RE = re.compile(r"\burl\s*:\s*['\"]([^'\"]+)['\"]", re.I)
AJAX_METHOD_RE = re.compile(r"\b(?:method|type)\s*:\s*['\"]([A-Z]+)['\"]", re.I)
GENERIC_ENDPOINT_RE = re.compile(r"['\"]((?:/|\.\.?/)[A-Za-z0-9_./?=&:%-]*(?:api|v\d+|graphql|json)[A-Za-z0-9_./?=&:%-]*)['\"]", re.I)


def extract_js_endpoints(script_url: str, body: str) -> list[RequestTemplate]:
    templates: list[RequestTemplate] = []
    seen: set[tuple[str, str]] = set()
    seen_urls: set[str] = set()

    def add(method: str, raw_url: str, tags=None):
        absolute = absolute_url(script_url, raw_url)
        if not absolute:
            return
        key = (method.upper(), absolute)
        if key in seen or absolute in seen_urls:
            return
        seen.add(key)
        seen_urls.add(absolute)
        templates.append(RequestTemplate(
            method=method.upper(),
            url=absolute,
            source="javascript",
            discovered_from=script_url,
            tags={"api", "js-endpoint", *(tags or set())},
        ))

    for match in FETCH_RE.finditer(body or ""):
        add("GET", match.group(1))
    for match in AXIOS_RE.finditer(body or ""):
        add(match.group(1), match.group(2))
    for match in XHR_RE.finditer(body or ""):
        add(match.group(1), match.group(2))
    for match in AJAX_URL_RE.finditer(body or ""):
        nearby = body[max(0, match.start() - 120): match.end() + 120]
        method_match = AJAX_METHOD_RE.search(nearby)
        add(method_match.group(1) if method_match else "GET", match.group(1))
    for match in GENERIC_ENDPOINT_RE.finditer(body or ""):
        add("GET", match.group(1), {"route-string"})

    return templates


class JSDiscoverer(BaseDiscoverer):
    name = "javascript"

    async def discover(self, client, registry) -> DiscoveryResult:
        result = DiscoveryResult()
        scripts = [
            template for template in registry.prioritized()
            if "javascript" in template.tags or template.url.lower().split("?")[0].endswith(".js")
        ]
        for script in scripts[: client.config.max_js_files or 0]:
            if not is_in_scope(script.url, client.config):
                continue
            try:
                snapshot = await client.send(script, check_name=self.name)
            except Exception as exc:
                result.warnings.append(f"JS discovery failed for {script.url}: {exc}")
                continue
            content_type = (snapshot.content_type or "").lower()
            if "javascript" not in content_type and "text/plain" not in content_type and not script.url.endswith(".js"):
                continue
            body = (snapshot.text_sample or "")[: client.config.max_js_bytes or 0]
            endpoints = extract_js_endpoints(snapshot.final_url or script.url, body)
            result.templates.extend(endpoints)
            registry.extend(endpoints)
        return result

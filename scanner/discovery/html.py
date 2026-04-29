from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Comment

from ..models import RequestTemplate
from ..scope import absolute_url, is_in_scope, normalize_url_for_dedupe
from .base import BaseDiscoverer, DiscoveryResult
from .forms import extract_forms


class HTMLDiscoverer(BaseDiscoverer):
    name = "html"

    async def discover(self, client, registry) -> DiscoveryResult:
        result = DiscoveryResult()
        start = RequestTemplate(method="GET", url=client.config.target_url, source=self.name, tags={"html"}, depth=0)
        registry.add(start)
        queue = deque([start])
        visited: set[str] = set()
        attempted: set[str] = set()

        while queue and len(visited) < client.config.max_pages:
            template = queue.popleft()
            key = normalize_url_for_dedupe(template.url)
            if key in attempted:
                continue
            attempted.add(key)
            if not is_in_scope(template.url, client.config):
                continue
            try:
                snapshot = await client.send(template, check_name=self.name)
            except Exception as exc:
                result.warnings.append(f"HTML discovery failed for {template.url}: {exc}")
                continue

            if snapshot.status_code not in {200, 204, 301, 302, 303, 307, 308, 401, 403}:
                continue
            visited.add(key)
            result.snapshots.append(snapshot)
            result.pages.append((snapshot.final_url or template.url, snapshot.text_sample))
            content_type = (snapshot.content_type or "").lower()
            if snapshot.status_code != 200 or ("html" not in content_type and "<html" not in snapshot.text_sample.lower()):
                continue

            soup = BeautifulSoup(snapshot.text_sample, "html.parser")
            new_templates = self._extract_templates(snapshot.final_url or template.url, soup, template.depth)
            for discovered in new_templates:
                if not is_in_scope(discovered.url, client.config):
                    continue
                result.templates.append(discovered)
                added = registry.add(discovered)
                if added and "html" in discovered.tags and discovered.depth <= client.config.max_depth:
                    queue.append(discovered)

        return result

    def _extract_templates(self, page_url: str, soup: BeautifulSoup, depth: int) -> list[RequestTemplate]:
        templates: list[RequestTemplate] = []

        for selector, attr, tags in [
            ("a[href]", "href", {"html", "link"}),
            ("link[href]", "href", {"asset", "link"}),
            ("script[src]", "src", {"asset", "javascript"}),
            ("iframe[src]", "src", {"html", "iframe"}),
            ("img[src]", "src", {"asset", "image"}),
            ("link[rel='canonical'][href]", "href", {"html", "canonical"}),
            ("link[rel='alternate'][href]", "href", {"html", "alternate"}),
        ]:
            for tag in soup.select(selector):
                absolute = absolute_url(page_url, tag.get(attr, ""))
                if not absolute:
                    continue
                templates.append(RequestTemplate(
                    method="GET",
                    url=absolute,
                    source="html",
                    discovered_from=page_url,
                    tags=set(tags),
                    depth=depth + 1,
                ))

        for meta in soup.find_all("meta"):
            http_equiv = (meta.get("http-equiv") or "").lower()
            content = meta.get("content") or ""
            if http_equiv == "refresh" and "url=" in content.lower():
                refresh_url = re.split(r"url\s*=", content, flags=re.I, maxsplit=1)[-1].strip("'\" ")
                absolute = absolute_url(page_url, refresh_url)
                if absolute:
                    templates.append(RequestTemplate(method="GET", url=absolute, source="meta-refresh", discovered_from=page_url, tags={"html"}, depth=depth + 1))

        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            for match in re.finditer(r"(/[A-Za-z0-9_./?=&:%-]*(?:api|graphql|v\d+)[A-Za-z0-9_./?=&:%-]*)", str(comment), re.I):
                absolute = absolute_url(page_url, match.group(1))
                if absolute:
                    templates.append(RequestTemplate(method="GET", url=absolute, source="html-comment", discovered_from=page_url, tags={"api", "comment"}, depth=depth + 1))

        templates.extend(extract_forms(page_url, soup))
        return templates

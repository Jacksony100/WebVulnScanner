from __future__ import annotations

from collections import defaultdict

from .models import Finding, RequestTemplate


class RequestRegistry:
    def __init__(self, max_targets: int | None = None):
        self.max_targets = max_targets
        self._items: dict[str, RequestTemplate] = {}
        self.sources: dict[str, set[str]] = defaultdict(set)
        self.graph: dict[str, set[str]] = defaultdict(set)

    def add(self, template: RequestTemplate) -> bool:
        if self.max_targets is not None and len(self._items) >= self.max_targets:
            return False
        key = template.fingerprint()
        if key in self._items:
            self.sources[key].add(template.source)
            if template.discovered_from:
                self.graph[template.discovered_from].add(template.url)
            return False
        self._items[key] = template
        self.sources[key].add(template.source)
        if template.discovered_from:
            self.graph[template.discovered_from].add(template.url)
        return True

    def extend(self, templates) -> int:
        return sum(1 for template in templates if self.add(template))

    def __iter__(self):
        return iter(self.prioritized())

    def __len__(self):
        return len(self._items)

    def prioritized(self) -> list[RequestTemplate]:
        def score(template: RequestTemplate):
            value = 0
            if template.params:
                value += 40
            if template.data or template.json_body is not None:
                value += 35
            if "api" in template.tags or "/api/" in template.url:
                value += 30
            if "openapi" in template.tags:
                value += 25
            if "form" in template.tags:
                value += 20
            if "interesting" in template.tags:
                value += 10
            value -= template.depth
            return value

        return sorted(self._items.values(), key=lambda item: (-score(item), item.normalized_url(), item.method))


class FindingRegistry:
    def __init__(self):
        self._items: dict[str, Finding] = {}

    def add(self, finding: Finding) -> bool:
        key = finding.dedupe_key()
        existing = self._items.get(key)
        if existing:
            if finding.evidence and finding.evidence not in existing.evidence:
                existing.evidence = f"{existing.evidence}; {finding.evidence}" if existing.evidence else finding.evidence
            existing.tags.update(finding.tags)
            return False
        self._items[key] = finding
        return True

    def extend(self, findings) -> int:
        return sum(1 for finding in findings if self.add(finding))

    def all(self) -> list[Finding]:
        severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        confidence_rank = {"High": 0, "Medium": 1, "Low": 2}
        return sorted(
            self._items.values(),
            key=lambda item: (severity_rank.get(item.severity, 5), confidence_rank.get(item.confidence, 3), item.url),
        )

    def to_dicts(self) -> list[dict]:
        return [finding.to_dict() for finding in self.all()]

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
CONFIDENCES = ("High", "Medium", "Low")


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False, separators=(",", ":"))


def _normalize_dynamic_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _normalize_dynamic_value(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_normalize_dynamic_value(v) for v in value]
    text = str(value)
    text = re.sub(r"[0-9a-f]{32,}", "<hex>", text, flags=re.I)
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>", text, flags=re.I)
    text = re.sub(r"\b\d{10,13}\b", "<timestamp>", text)
    return text


@dataclass(frozen=True)
class RequestTemplate:
    method: str = "GET"
    url: str = ""
    params: dict[str, str] = field(default_factory=dict)
    data: dict[str, str] | None = None
    json_body: Any | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None
    source: str = "manual"
    discovered_from: str | None = None
    tags: set[str] = field(default_factory=set)
    depth: int = 0

    def __post_init__(self):
        object.__setattr__(self, "method", (self.method or "GET").upper())
        object.__setattr__(self, "params", {str(k): str(v) for k, v in (self.params or {}).items()})
        if self.data is not None:
            object.__setattr__(self, "data", {str(k): str(v) for k, v in self.data.items()})
        object.__setattr__(self, "headers", {str(k): str(v) for k, v in (self.headers or {}).items()})
        object.__setattr__(self, "cookies", {str(k): str(v) for k, v in (self.cookies or {}).items()})
        object.__setattr__(self, "tags", set(self.tags or set()))

    def normalized_url(self) -> str:
        parsed = urlparse(self.url)
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
        path = parsed.path or "/"
        return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))

    def fingerprint(self) -> str:
        body_shape = {
            "params": _normalize_dynamic_value(self.params),
            "data": _normalize_dynamic_value(self.data or {}),
            "json": _normalize_dynamic_value(self.json_body) if self.json_body is not None else None,
            "content_type": self.content_type,
        }
        raw = _stable_json({"method": self.method, "url": self.normalized_url(), "body": body_shape})
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def with_param_payload(self, name: str, payload: str) -> "RequestTemplate":
        params = dict(self.params)
        url = self.url
        query_items = parse_qsl(urlparse(self.url).query, keep_blank_values=True)
        if name in params:
            params[name] = payload
        elif any(key == name for key, _ in query_items):
            parsed = urlparse(self.url)
            replaced = [(key, payload if key == name else value) for key, value in query_items]
            url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(replaced, doseq=True), ""))
        else:
            params[name] = payload
        return RequestTemplate(
            method=self.method,
            url=url,
            params=params,
            data=self.data,
            json_body=self.json_body,
            headers=self.headers,
            cookies=self.cookies,
            content_type=self.content_type,
            source=self.source,
            discovered_from=self.discovered_from,
            tags=set(self.tags),
            depth=self.depth,
        )

    def with_body_payload(self, path_or_name: str, payload: str) -> "RequestTemplate":
        data = dict(self.data or {}) if self.data is not None else None
        json_body = json.loads(json.dumps(self.json_body)) if self.json_body is not None else None
        if data is not None:
            data[path_or_name] = payload
        elif json_body is not None:
            self._set_json_path(json_body, path_or_name, payload)
        else:
            data = {path_or_name: payload}
        return RequestTemplate(
            method=self.method,
            url=self.url,
            params=self.params,
            data=data,
            json_body=json_body,
            headers=self.headers,
            cookies=self.cookies,
            content_type=self.content_type,
            source=self.source,
            discovered_from=self.discovered_from,
            tags=set(self.tags),
            depth=self.depth,
        )

    def parameter_names(self) -> list[str]:
        names = [key for key, _ in parse_qsl(urlparse(self.url).query, keep_blank_values=True)]
        names.extend(self.params)
        if self.data:
            names.extend(self.data)
        if isinstance(self.json_body, dict):
            names.extend(str(k) for k in self.json_body)
        return list(dict.fromkeys(names))

    def has_param(self, name: str) -> bool:
        return name in self.params or any(key == name for key, _ in parse_qsl(urlparse(self.url).query, keep_blank_values=True))

    @staticmethod
    def _set_json_path(document: Any, path: str, payload: str):
        parts = [part for part in re.split(r"[.\[\]]+", path) if part]
        if not parts:
            return
        cur = document
        for part in parts[:-1]:
            if isinstance(cur, dict):
                cur = cur.setdefault(part, {})
            else:
                return
        if isinstance(cur, dict):
            cur[parts[-1]] = payload


@dataclass
class HttpResponseSnapshot:
    status_code: int
    final_url: str
    headers: dict[str, str]
    text_sample: str
    body_hash: str
    normalized_body_hash: str
    length: int
    word_count: int
    title: str | None
    elapsed_ms: int
    content_type: str | None


@dataclass
class Finding:
    type: str
    title: str
    severity: str
    confidence: str
    url: str
    method: str = "GET"
    parameter: str | None = None
    location: str | None = None
    evidence: str = ""
    request_summary: dict[str, Any] = field(default_factory=dict)
    response_summary: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    source: str = "scanner"
    tags: set[str] = field(default_factory=set)
    cwe: str | None = None
    owasp: str | None = None
    discovered_by: str | None = None
    id: str = ""

    def __post_init__(self):
        self.severity = self.severity if self.severity in SEVERITIES else "Info"
        self.confidence = self.confidence if self.confidence in CONFIDENCES else "Low"
        self.method = (self.method or "GET").upper()
        self.tags = set(self.tags or set())
        if not self.id:
            self.id = self.dedupe_key()[:16]

    def dedupe_key(self) -> str:
        raw = _stable_json({
            "type": self.type,
            "title": self.title,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "location": self.location,
            "source": self.source,
        })
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["tags"] = sorted(self.tags)
        data["payload"] = self.request_summary
        return data


@dataclass
class DiscoveryCandidate:
    url: str
    method: str = "GET"
    source: str = "unknown"
    reason: str = ""
    confidence: str = "Low"
    validated: bool = False
    validation_evidence: str | None = None
    tags: set[str] = field(default_factory=set)
    discovered_from: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["tags"] = sorted(self.tags)
        return data


@dataclass
class Asset:
    type: str
    url: str
    method: str = "GET"
    source: str = "unknown"
    evidence: str = ""
    tags: set[str] = field(default_factory=set)
    confidence: str = "Medium"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["tags"] = sorted(self.tags)
        return data


@dataclass
class ScanConfig:
    target_url: str
    scope_hosts: set[str] = field(default_factory=set)
    mode: str = "safe"
    max_depth: int | None = None
    max_pages: int | None = None
    max_requests_total: int | None = None
    max_duration_seconds: int | None = None
    max_discovery_requests: int | None = None
    max_active_requests: int | None = None
    max_common_candidates: int | None = None
    max_js_files: int | None = None
    max_js_bytes: int | None = None
    max_requests_per_target: int = 20
    max_concurrency: int | None = None
    rate_limit_per_host: float | None = None
    timeout: float = 8.0
    user_agent: str = "AdvancedScanner/6.0"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    auth: dict[str, str] = field(default_factory=dict)
    allow_private_ips: bool = False
    follow_redirects: bool = False
    verify_tls: bool = True
    enable_playwright: bool = False
    enable_external_tools: bool = False
    enable_graphql_introspection_probe: bool = False
    enabled_checks: set[str] = field(default_factory=set)
    disabled_checks: set[str] = field(default_factory=set)
    safe_methods: set[str] = field(default_factory=lambda: {"GET", "HEAD", "OPTIONS"})

    def __post_init__(self):
        from .scope import normalize_target_url

        self.target_url = normalize_target_url(self.target_url)
        self.mode = self.mode if self.mode in {"safe", "active", "deep"} else "safe"
        host = urlparse(self.target_url).hostname or ""
        if not self.scope_hosts and host:
            self.scope_hosts = {host.lower()}
        else:
            self.scope_hosts = {h.lower() for h in self.scope_hosts}
        defaults = {
            "safe": {
                "max_duration_seconds": 45,
                "max_requests_total": 40,
                "max_discovery_requests": 25,
                "max_active_requests": 0,
                "max_common_candidates": 10,
                "max_concurrency": 4,
                "max_depth": 1,
                "max_pages": 20,
                "max_js_files": 5,
                "max_js_bytes": 512_000,
                "rate_limit_per_host": 4.0,
            },
            "active": {
                "max_duration_seconds": 180,
                "max_requests_total": 250,
                "max_discovery_requests": 80,
                "max_active_requests": 150,
                "max_common_candidates": 25,
                "max_concurrency": 6,
                "max_depth": 2,
                "max_pages": 60,
                "max_js_files": 12,
                "max_js_bytes": 1_000_000,
                "rate_limit_per_host": 4.0,
            },
            "deep": {
                "max_duration_seconds": 600,
                "max_requests_total": 700,
                "max_discovery_requests": 220,
                "max_active_requests": 350,
                "max_common_candidates": 60,
                "max_concurrency": 8,
                "max_depth": 3,
                "max_pages": 160,
                "max_js_files": 30,
                "max_js_bytes": 2_000_000,
                "rate_limit_per_host": 4.0,
            },
        }[self.mode]
        for key, value in defaults.items():
            current = getattr(self, key)
            if current is None:
                setattr(self, key, value)
        if self.mode == "safe":
            self.enable_external_tools = False


@dataclass
class ScanState:
    status: str = "idle"
    progress: dict[str, Any] = field(default_factory=lambda: {"message": "Ожидание", "current": 0, "total": 1, "done": False})
    counters: dict[str, int] = field(default_factory=dict)
    cancellation_requested: bool = False
    started_at: float | None = None
    finished_at: float | None = None
    current_phase: str = "idle"
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def start(self):
        self.status = "running"
        self.started_at = time.time()
        self.finished_at = None

    def finish(self, status: str = "completed"):
        self.status = status
        self.finished_at = time.time()

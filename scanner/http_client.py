from __future__ import annotations

import asyncio
import hashlib
import re
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup

from .models import HttpResponseSnapshot, RequestTemplate, ScanConfig
from .scope import is_in_scope


SECRET_HEADER_RE = re.compile(r"(authorization|cookie|token|api[_-]?key|secret|password|session)", re.I)


def redact_value(key: str, value: Any) -> str:
    text = str(value)
    if SECRET_HEADER_RE.search(key):
        return "***redacted***"
    if len(text) > 160:
        return text[:80] + "...[truncated]"
    return text


def redact_mapping(values: dict[str, Any] | None) -> dict[str, str]:
    return {str(k): redact_value(str(k), v) for k, v in (values or {}).items()}


def normalize_body_for_hash(text: str) -> str:
    text = text or ""
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>", text, flags=re.I)
    text = re.sub(r"[0-9a-f]{24,}", "<hex>", text, flags=re.I)
    text = re.sub(r"\b\d{10,13}\b", "<timestamp>", text)
    text = re.sub(r"csrf[^'\"\s<>=:]*['\"\s:=]+[A-Za-z0-9._-]+", "csrf=<token>", text, flags=re.I)
    return text


def snapshot_from_text(status: int, final_url: str, headers: dict[str, str], text: str, elapsed_ms: int) -> HttpResponseSnapshot:
    soup = BeautifulSoup(text or "", "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else None
    normalized = normalize_body_for_hash(text)
    return HttpResponseSnapshot(
        status_code=status,
        final_url=final_url,
        headers=dict(headers),
        text_sample=(text or "")[:200_000],
        body_hash=hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest(),
        normalized_body_hash=hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest(),
        length=len(text or ""),
        word_count=len((text or "").split()),
        title=title,
        elapsed_ms=elapsed_ms,
        content_type=headers.get("Content-Type") or headers.get("content-type"),
    )


class RequestBudgetExceeded(RuntimeError):
    pass


class ScopeViolation(RuntimeError):
    pass


class ScanCancelled(RuntimeError):
    pass


class AsyncHTTPClient:
    def __init__(self, config: ScanConfig, cancel_cb=None):
        self.config = config
        self.cancel_cb = cancel_cb or (lambda: False)
        self._session: aiohttp.ClientSession | None = None
        self._lock = asyncio.Lock()
        self._host_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._last_request_at: dict[str, float] = defaultdict(float)
        self._requests_total = 0
        self._requests_per_target: dict[str, int] = defaultdict(int)
        self.request_log: list[dict[str, Any]] = []
        self.started_at = time.perf_counter()

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {"User-Agent": self.config.user_agent, **self.config.headers}
        connector = aiohttp.TCPConnector(ssl=self.config.verify_tls, limit=self.config.max_concurrency)
        self._session = aiohttp.ClientSession(headers=headers, cookies=self.config.cookies, timeout=timeout, connector=connector)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._session:
            await self._session.close()

    @property
    def requests_total(self) -> int:
        return self._requests_total

    async def send(self, template: RequestTemplate, check_name: str = "scanner") -> HttpResponseSnapshot:
        if self.cancel_cb():
            raise ScanCancelled("scan cancelled")
        if not is_in_scope(template.url, self.config):
            raise ScopeViolation(f"out of scope URL: {template.url}")
        if self._session is None:
            raise RuntimeError("AsyncHTTPClient must be used as an async context manager")

        parsed = urlparse(template.url)
        target_key = f"{template.method} {template.normalized_url()}"
        async with self._lock:
            if self.config.max_duration_seconds is not None and time.perf_counter() - self.started_at >= self.config.max_duration_seconds:
                raise RequestBudgetExceeded("scan deadline reached")
            if self._requests_total >= self.config.max_requests_total:
                raise RequestBudgetExceeded("total request budget exhausted")
            if self._requests_per_target[target_key] >= self.config.max_requests_per_target:
                raise RequestBudgetExceeded("per-target request budget exhausted")
            self._requests_total += 1
            self._requests_per_target[target_key] += 1

        await self._rate_limit(parsed.hostname or "")
        headers = {**template.headers}
        if template.content_type:
            headers.setdefault("Content-Type", template.content_type)
        started = time.perf_counter()
        log_entry = {
            "method": template.method,
            "url": template.normalized_url(),
            "params": redact_mapping(template.params),
            "headers": redact_mapping(headers),
            "source": template.source,
            "check": check_name,
            "status": None,
            "elapsed_ms": None,
        }
        self.request_log.append(log_entry)
        async with self._session.request(
            template.method,
            template.url,
            params=template.params or None,
            data=template.data,
            json=template.json_body,
            headers=headers or None,
            cookies=template.cookies or None,
            allow_redirects=self.config.follow_redirects,
            max_redirects=4,
        ) as response:
            raw = await response.content.read(512_000)
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            log_entry["status"] = response.status
            log_entry["elapsed_ms"] = elapsed_ms
            encoding = response.charset or "utf-8"
            text = raw.decode(encoding, errors="ignore")
            return snapshot_from_text(response.status, str(response.url), dict(response.headers), text, elapsed_ms)

    async def _rate_limit(self, host: str):
        if not host or self.config.rate_limit_per_host <= 0:
            return
        async with self._host_locks[host]:
            min_delay = 1.0 / self.config.rate_limit_per_host
            now = time.perf_counter()
            elapsed = now - self._last_request_at[host]
            if elapsed < min_delay:
                await asyncio.sleep(min_delay - elapsed)
            self._last_request_at[host] = time.perf_counter()

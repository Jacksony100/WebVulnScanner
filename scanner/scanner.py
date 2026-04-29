from __future__ import annotations

import asyncio
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .checks import default_checks
from .checkers import (
    CRLFInjectionChecker,
    HPPChecker,
    NoSQLChecker,
    OpenRedirectChecker,
    SQLIChecker,
    SSTIChecker,
    XSSChecker,
)
from .discovery import HTMLDiscoverer, JSDiscoverer, WellKnownDiscoverer
from .external_engines import ExternalEngineRunner
from .http_client import AsyncHTTPClient
from .legacy_compat import LegacyScannerMixin, VulnResult
from .models import Finding, RequestTemplate, ScanConfig
from .payloads import HEADERS
from .registry import FindingRegistry, RequestRegistry
from .scheduler import ScanScheduler
from .scope import is_in_scope, normalize_target_url
from .utils import detect_cms, get_cms_version


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VulnerabilityScanner(LegacyScannerMixin):
    """Thin authorized scanner orchestrator built around discovery, templates, and checks."""

    def __init__(
        self,
        base_url: str,
        progress_cb=None,
        threads: int = 10,
        scan_mode: str = "safe",
        cancel_cb=None,
        allow_private_ips: bool = False,
        enable_external_tools: bool = False,
        max_requests_total: int | None = None,
        max_duration_seconds: int | None = None,
        max_discovery_requests: int | None = None,
        max_active_requests: int | None = None,
        max_common_candidates: int | None = None,
        enable_graphql_introspection_probe: bool = False,
        rate_limit_per_host: float | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        enabled_checks: set[str] | None = None,
        disabled_checks: set[str] | None = None,
    ):
        self.base = normalize_target_url(base_url).rstrip("/")
        self.threads = threads
        self.scan_mode = scan_mode if scan_mode in {"safe", "active", "deep"} else "safe"
        self.active_enabled = self.scan_mode in {"active", "deep"}
        self.deep_scan = self.scan_mode == "deep"
        self.progress_cb = progress_cb or (lambda _: {})
        self.cancel_cb = cancel_cb or (lambda: False)
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.executor = ThreadPoolExecutor(max_workers=threads)
        self.vulns: list[VulnResult] = []
        self._seen_vulns: set[tuple[str, str, str, str]] = set()
        self.cms_info = {"cms": None, "version": None}
        self.scan_info: dict = {}
        self.total = 1
        self.config = ScanConfig(
            target_url=self.base,
            mode=self.scan_mode,
            max_depth=None,
            max_pages=None,
            max_requests_total=max_requests_total,
            max_duration_seconds=max_duration_seconds,
            max_discovery_requests=max_discovery_requests,
            max_active_requests=max_active_requests,
            max_common_candidates=max_common_candidates,
            max_requests_per_target=18 if self.deep_scan else 8,
            max_concurrency=max(1, min(threads, 12)) if threads else None,
            rate_limit_per_host=rate_limit_per_host,
            timeout=10.0 if self.deep_scan else 8.0,
            headers=headers or {},
            cookies=cookies or {},
            allow_private_ips=allow_private_ips,
            enable_external_tools=enable_external_tools,
            enable_graphql_introspection_probe=enable_graphql_introspection_probe,
            enabled_checks=enabled_checks or set(),
            disabled_checks=disabled_checks or set(),
        )
        self.checkers = []
        if self.active_enabled:
            self.checkers = [
                XSSChecker(self.session),
                SQLIChecker(self.session, include_time_based=self.deep_scan),
                SSTIChecker(self.session),
                NoSQLChecker(self.session),
                HPPChecker(self.session),
                OpenRedirectChecker(self.session),
                CRLFInjectionChecker(self.session),
            ]
        logger.info("Инициализирован новый scanner core для %s, режим: %s", self.base, self.scan_mode)

    async def run(self):
        started = time.perf_counter()
        try:
            self._validate_scope()
            registry = RequestRegistry(max_targets=self.config.max_pages * 6)
            findings = FindingRegistry()
            root_template = RequestTemplate(method="GET", url=self.base, source="manual", tags={"html"}, depth=0)
            registry.add(root_template)

            async with AsyncHTTPClient(self.config, cancel_cb=self._cancelled) as client:
                self._update("Discovery: HTML, forms, links...", 0, 5)
                html_result = await HTMLDiscoverer().discover(client, registry)
                self._raise_if_cancelled()

                self._update("Discovery: sitemap, robots, OpenAPI, GraphQL...", 1, 5)
                well_known_result = await WellKnownDiscoverer().discover(client, registry)
                self._raise_if_cancelled()

                self._update("Discovery: JavaScript endpoints...", 2, 5)
                js_result = await JSDiscoverer().discover(client, registry)
                self._raise_if_cancelled()

                external_summary = self._empty_external_summary()
                if self.config.enable_external_tools and self.active_enabled:
                    self._update("External engines: bounded discovery/checks...", 3, 5)
                    external_vulns, external_summary = await asyncio.to_thread(self._run_external_engines)
                    findings.extend(self._findings_from_legacy(external_vulns, source="external"))
                    self._feed_external_discovery(registry, external_summary, external_vulns)

                self._update("Checks: passive and authorized active probes...", 4, 5)
                scheduler = ScanScheduler(
                    self.config,
                    default_checks(),
                    progress_cb=lambda msg, cur, total: self._update(msg, cur, total),
                    cancel_cb=self._cancelled,
                )
                scheduled_findings = await scheduler.run(registry.prioritized(), client)
                findings.extend(scheduled_findings)
                scheduler_diagnostics = dict(scheduler.diagnostics)
                request_log = list(client.request_log)
                requests_total = client.requests_total

            self.vulns = [VulnResult(item) for item in findings.to_dicts()]
            self._collect_scan_metadata(
                registry=registry,
                html_result=html_result,
                discovery_results=[html_result, well_known_result, js_result],
                scheduler_diagnostics=scheduler_diagnostics,
                warnings=html_result.warnings + well_known_result.warnings + js_result.warnings,
                external_summary=external_summary,
                request_log=request_log,
                requests_total=requests_total,
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
            self._update("Сканирование завершено", self.total, self.total, done=True)
            return self.vulns
        except asyncio.CancelledError:
            return self._finish_cancelled(0, 1)
        finally:
            try:
                self.executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                self.executor.shutdown(wait=False)

    def cancel(self):
        self.cancel_cb = lambda: True

    def get_cms_info(self):
        return self.cms_info

    def get_scan_info(self):
        return self.scan_info

    def _validate_scope(self):
        if not is_in_scope(self.config.target_url, self.config):
            raise ValueError(
                "Target is outside allowed scope or resolves to private/internal IP. "
                "Enable lab/private target mode only for authorized CTF/lab/self-hosted targets."
            )

    def _run_external_engines(self):
        def progress(engine_name, status, meta=None):
            label = engine_name
            self._update(f"External: {label} - {status}", 3, 5)

        runner = ExternalEngineRunner(
            self.base,
            self.scan_mode,
            max_seconds=120 if self.deep_scan else 45,
            progress_cb=progress,
            cancel_cb=self._cancelled,
        )
        return runner.run()

    def _empty_external_summary(self):
        runner = ExternalEngineRunner(self.base, self.scan_mode)
        return {"mode": self.scan_mode, "engines": runner.engines, "results": {}, "errors": []}

    def _feed_external_discovery(self, registry: RequestRegistry, summary: dict, vulns: list[dict]):
        katana = (summary.get("results") or {}).get("katana") or {}
        for url in katana.get("urls_list") or katana.get("sample") or []:
            registry.add(RequestTemplate(method="GET", url=url, source="katana", discovered_from=self.base, tags={"external", "katana"}))
        for vuln in vulns or []:
            if vuln.get("payload", {}).get("engine") == "ffuf" and vuln.get("url"):
                registry.add(RequestTemplate(method="GET", url=vuln["url"], source="ffuf", discovered_from=self.base, tags={"external", "ffuf", "interesting"}))

    def _findings_from_legacy(self, vulns: list[dict], source: str) -> list[Finding]:
        normalized = []
        for vuln in vulns or []:
            normalized.append(Finding(
                type=vuln.get("type", "External finding"),
                title=vuln.get("type", "External finding"),
                severity=vuln.get("severity", "Info"),
                confidence=vuln.get("confidence", "Medium"),
                url=vuln.get("url", self.base),
                method=vuln.get("method", "GET"),
                parameter=vuln.get("parameter"),
                evidence=vuln.get("evidence", "external engine reported a finding"),
                request_summary=vuln.get("payload", {}),
                remediation=vuln.get("remediation", "Review and validate the external engine finding manually."),
                source=source,
                tags={"external"},
            ))
        return normalized

    def _collect_scan_metadata(self, registry, html_result, discovery_results, scheduler_diagnostics, warnings, external_summary, request_log, requests_total, duration_ms):
        root_snapshot = self._target_info_from_pages(html_result.pages, html_result.snapshots[0] if html_result.snapshots else None)
        self.cms_info = self._detect_cms_safe()
        templates = registry.prioritized()
        phase_count = 3 if self.deep_scan else 2 if self.active_enabled else 1
        self.total = max(len(templates) * phase_count, 1)
        assets = []
        candidates = []
        for result in discovery_results:
            assets.extend(asset.to_dict() for asset in getattr(result, "assets", []))
            candidates.extend(candidate.to_dict() for candidate in getattr(result, "candidates", []))
        if not any(template.parameter_names() for template in templates):
            warnings = [*warnings, "No active input points found; active checks skipped or limited to passive checks."]
            scheduler_diagnostics.setdefault("skipped_reasons", {})
            scheduler_diagnostics["skipped_reasons"]["no active input points found"] = scheduler_diagnostics["skipped_reasons"].get("no active input points found", 0) + 1
        slowest_requests = sorted(
            [entry for entry in request_log if entry.get("elapsed_ms") is not None],
            key=lambda entry: entry.get("elapsed_ms") or 0,
            reverse=True,
        )[:10]
        self.scan_info = {
            **root_snapshot,
            "target": self.base,
            "mode": self.scan_mode,
            "scope_hosts": sorted(self.config.scope_hosts),
            "allow_private_ips": self.config.allow_private_ips,
            "pages_crawled": len(html_result.pages),
            "forms_total": sum(1 for template in templates if "form" in template.tags),
            "query_urls_total": sum(1 for template in templates if template.params),
            "request_templates_total": len(templates),
            "request_count": requests_total,
            "request_budget": self.config.max_requests_total,
            "duration_ms": duration_ms,
            "warnings": warnings,
            "assets": assets,
            "discovery_candidates": candidates,
            "diagnostics": {
                **scheduler_diagnostics,
                "requests_total": requests_total,
                "requests_by_check": self._request_counts_by_check(request_log),
                "slowest_requests": slowest_requests,
                "budget_exhausted": requests_total >= self.config.max_requests_total,
                "deadline_seconds": self.config.max_duration_seconds,
            },
            "skipped_checks": [],
            "external_engines": external_summary,
            "request_log": request_log[-80:],
            "discovery_sources": self._source_counts(templates),
            "cms": self.cms_info,
        }

    def _target_info_from_pages(self, pages, snapshot=None):
        parsed = urlparse(self.base)
        info = {
            "hostname": parsed.hostname or "",
            "ip_addresses": [],
            "final_url": self.base,
            "status_code": None,
            "title": None,
            "server": None,
            "powered_by": None,
            "content_type": None,
            "response_time_ms": None,
            "technologies": [],
            "allowed_methods": [],
        }
        try:
            info["ip_addresses"] = sorted({item[4][0] for item in socket.getaddrinfo(parsed.hostname, None)})[:8] if parsed.hostname else []
        except Exception:
            info["ip_addresses"] = []
        if snapshot is not None:
            soup = BeautifulSoup(snapshot.text_sample or "", "html.parser")
            info["final_url"] = snapshot.final_url or self.base
            info["status_code"] = snapshot.status_code
            info["title"] = snapshot.title
            info["server"] = snapshot.headers.get("Server") or snapshot.headers.get("server")
            info["powered_by"] = snapshot.headers.get("X-Powered-By") or snapshot.headers.get("x-powered-by")
            info["content_type"] = snapshot.content_type
            info["response_time_ms"] = snapshot.elapsed_ms
            info["technologies"] = self._detect_technologies(SimpleNamespace(headers=snapshot.headers), snapshot.text_sample or "")
            if not info["title"] and soup.title and soup.title.string:
                info["title"] = soup.title.string.strip()
        elif pages:
            final_url, body = pages[0]
            soup = BeautifulSoup(body or "", "html.parser")
            info["final_url"] = final_url
            if soup.title and soup.title.string:
                info["title"] = soup.title.string.strip()
            fake_response = SimpleNamespace(headers={})
            info["technologies"] = self._detect_technologies(fake_response, body or "")
        return info

    def _request_counts_by_check(self, request_log):
        counts: dict[str, int] = {}
        for entry in request_log:
            check = entry.get("check") or "scanner"
            counts[check] = counts.get(check, 0) + 1
        return counts

    def _detect_cms_safe(self):
        try:
            cms = detect_cms(self.session, self.base)
            if cms:
                return {"cms": cms, "version": get_cms_version(self.session, self.base, cms) or "N/A"}
        except Exception:
            pass
        return {"cms": "Не определено", "version": "N/A"}

    def _source_counts(self, templates):
        counts: dict[str, int] = {}
        for template in templates:
            counts[template.source] = counts.get(template.source, 0) + 1
        return counts

    def _add_vulns(self, vulns):
        added = 0
        for vuln in vulns:
            if not vuln:
                continue
            key = (vuln.get("type", ""), vuln.get("url", ""), vuln.get("method", ""), str(vuln.get("payload", "")))
            if key in self._seen_vulns:
                continue
            self._seen_vulns.add(key)
            self.vulns.append(VulnResult(vuln))
            added += 1
        return added

    def _update(self, msg: str, cur: int, total: int, done: bool = False):
        self.progress_cb({"message": msg, "current": cur, "total": total or 1, "done": done})

    def _cancelled(self):
        try:
            return bool(self.cancel_cb())
        except Exception:
            return False

    def _raise_if_cancelled(self):
        if self._cancelled():
            raise asyncio.CancelledError()

    def _finish_cancelled(self, cur: int, total: int):
        self._update("Сканирование остановлено", cur, total or 1, done=True)
        return self.vulns

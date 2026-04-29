from __future__ import annotations

from collections import defaultdict
import time

from .checks.baseline import BaselineCollector
from .registry import FindingRegistry


class ScanScheduler:
    def __init__(self, config, checks, progress_cb=None, cancel_cb=None):
        self.config = config
        self.checks = checks
        self.progress_cb = progress_cb or (lambda message, current, total: None)
        self.cancel_cb = cancel_cb or (lambda: False)
        self.baseline = BaselineCollector()
        self.diagnostics = {
            "templates_checked": 0,
            "templates_skipped": 0,
            "skipped_reasons": {},
            "phase_durations": {},
        }

    async def run(self, templates, client):
        findings = FindingRegistry()
        templates = list(templates)
        phase_count = 3 if self.config.mode == "deep" else 2 if self.config.mode in {"active", "deep"} else 1
        total = min(len(templates) * phase_count, self.config.max_requests_total)
        processed_targets = 0
        per_target_counts = defaultdict(int)

        for phase in ("passive", "active", "deep"):
            if phase == "deep" and self.config.mode != "deep":
                continue
            phase_started = time.perf_counter()
            for template in templates:
                if self.cancel_cb():
                    break
                if processed_targets >= self.config.max_requests_total:
                    self._skip("budget exhausted")
                    break
                key = template.fingerprint()
                if per_target_counts[key] >= self.config.max_requests_per_target:
                    self._skip("per-target budget exhausted")
                    continue
                supported_checks = [
                    check for check in self._select_checks(template)
                    if getattr(check, "risk_level", "passive") == phase
                ]
                if not supported_checks:
                    self._skip(self._skip_reason(template, phase))
                    continue
                processed_targets += 1
                per_target_counts[key] += 1
                self.diagnostics["templates_checked"] += 1
                self.progress_cb(f"Проверки: {processed_targets}/{total}", processed_targets, total or 1)

                baseline = None
                if any(getattr(check, "needs_baseline", False) for check in supported_checks):
                    baseline = await self.baseline.collect(template, client)

                for check in supported_checks:
                    if self.cancel_cb():
                        break
                    try:
                        result = await check.run(template, client, baseline, self.config)
                    except Exception:
                        continue
                    findings.extend(result)
            self.diagnostics["phase_durations"][phase] = round(time.perf_counter() - phase_started, 3)
        return findings.all()

    def _select_checks(self, template):
        selected = []
        for check in self.checks:
            if self.config.enabled_checks and check.name not in self.config.enabled_checks:
                continue
            if check.name in self.config.disabled_checks:
                continue
            if self.config.mode not in check.modes:
                continue
            if template.method in {"PUT", "PATCH", "DELETE"} and self.config.mode != "deep":
                continue
            if "unsafe-method" in template.tags:
                continue
            try:
                if not check.supports(template):
                    continue
            except Exception:
                continue
            selected.append(check)
        return selected

    def _skip(self, reason: str):
        self.diagnostics["templates_skipped"] += 1
        reasons = self.diagnostics["skipped_reasons"]
        reasons[reason] = reasons.get(reason, 0) + 1

    def _skip_reason(self, template, phase: str) -> str:
        if phase in {"active", "deep"} and not template.parameter_names() and "validated" not in template.tags:
            return "no parameters"
        path = template.url.lower().split("?")[0]
        if path.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".pdf", ".zip")):
            return "static asset"
        if phase in {"active", "deep"} and self.config.mode == "safe":
            return "mode not allowed"
        return "unsupported template"

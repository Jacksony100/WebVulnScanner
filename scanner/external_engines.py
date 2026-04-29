# scanner/external_engines.py
# Optional integrations with installed security engines.

import json
import re
import requests
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

from .payloads import HEADERS


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORDLIST = PROJECT_ROOT / "wordlists" / "discovery-small.txt"

ENGINE_DEFINITIONS = [
    {
        "name": "nuclei",
        "label": "Nuclei",
        "category": "web active templates",
        "description": "CVE, misconfiguration, exposure and technology templates",
    },
    {
        "name": "katana",
        "label": "Katana",
        "category": "web crawler",
        "description": "Fast endpoint discovery for modern apps",
    },
    {
        "name": "ffuf",
        "label": "ffuf",
        "category": "web discovery",
        "description": "Directory and file discovery with bundled safe wordlist",
    },
    {
        "name": "sslyze",
        "label": "SSLyze",
        "category": "tls audit",
        "description": "TLS certificate and protocol audit",
    },
    {
        "name": "retire",
        "label": "Retire.js",
        "category": "javascript dependencies",
        "description": "Vulnerable frontend library detection",
    },
    {
        "name": "semgrep",
        "label": "Semgrep",
        "category": "project sast",
        "description": "Local source-code SAST engine",
    },
    {
        "name": "gitleaks",
        "label": "Gitleaks",
        "category": "project secrets",
        "description": "Local repository secret scanner",
    },
    {
        "name": "osv-scanner",
        "label": "OSV-Scanner",
        "category": "project dependencies",
        "description": "Local dependency vulnerability scanner",
    },
    {
        "name": "schemathesis",
        "label": "Schemathesis",
        "category": "api schema fuzzing",
        "description": "OpenAPI and GraphQL schema-aware testing",
    },
    {
        "name": "zap.sh",
        "label": "OWASP ZAP",
        "category": "web active proxy",
        "description": "Passive and active proxy scanner when ZAP is installed",
    },
]


def _resolve_tool(name: str, which_func=shutil.which):
    path = which_func(name)
    if path:
        return path
    for candidate in (
        PROJECT_ROOT / ".tools" / "node_modules" / ".bin" / name,
        PROJECT_ROOT / "node_modules" / ".bin" / name,
    ):
        if candidate.exists():
            return str(candidate)
    if name == "zap.sh":
        for candidate in (
            Path("/Applications/ZAP.app/Contents/MacOS/ZAP.sh"),
            Path("/Applications/ZAP.app/Contents/Java/zap.sh"),
        ):
            if candidate.exists():
                return str(candidate)
    return None


def detect_external_engines(which_func=shutil.which):
    """Returns JSON-serializable status for every supported optional engine."""
    engines = []
    for definition in ENGINE_DEFINITIONS:
        path = _resolve_tool(definition["name"], which_func=which_func)
        engines.append({
            **definition,
            "available": bool(path),
            "path": path,
        })
    return engines


def default_command_runner(command, timeout):
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


class ExternalEngineRunner:
    """Runs safe optional engines and converts their output into scanner findings."""

    def __init__(
        self,
        base_url: str,
        mode: str = "safe",
        command_runner=default_command_runner,
        which_func=shutil.which,
        wordlist_path: Path | None = None,
        max_seconds: float | None = None,
        progress_cb=None,
        cancel_cb=None,
        time_func=time.monotonic,
    ):
        self.base_url = base_url.rstrip("/")
        self.mode = mode if mode in {"safe", "active", "deep"} else "safe"
        self.command_runner = command_runner
        self.wordlist_path = Path(wordlist_path) if wordlist_path else DEFAULT_WORDLIST
        self.max_seconds = max_seconds if max_seconds is not None else self._default_budget(self.mode)
        self.progress_cb = progress_cb or (lambda engine, status, meta=None: None)
        self.cancel_cb = cancel_cb or (lambda: False)
        self.time_func = time_func
        self._deadline = None
        self.engines = {
            engine["name"]: engine
            for engine in detect_external_engines(which_func=which_func)
        }

    def run(self):
        self._deadline = self.time_func() + self.max_seconds if self.max_seconds else None
        summary = {
            "mode": self.mode,
            "profile": "quick" if self.mode == "active" else self.mode,
            "budget_seconds": self.max_seconds,
            "engines": self.engines,
            "results": {},
            "errors": [],
        }
        findings = []

        try:
            for engine_name, runner, include_findings in self._engine_plan():
                if include_findings:
                    self._record_result(summary, engine_name, runner, include_findings=True, findings=findings)
                else:
                    self._record_result(summary, engine_name, runner, include_findings=False)

            self._mark_profile_skips(summary)
            return findings, summary
        finally:
            self._deadline = None

    def _default_budget(self, mode: str):
        if mode == "active":
            return 45
        if mode == "deep":
            return 120
        return 0

    def _engine_plan(self):
        if self.mode == "safe":
            return []

        plan = [
            ("nuclei", self._run_nuclei, True),
            ("katana", self._run_katana, False),
        ]
        if self.mode == "deep":
            plan.extend([
                ("sslyze", self._run_sslyze, True),
                ("retire", self._run_retire, True),
                ("ffuf", self._run_ffuf, True),
            ])
        return plan

    def _mark_profile_skips(self, summary):
        if self.mode != "active":
            return
        for engine_name in ("sslyze", "retire", "ffuf"):
            summary["results"].setdefault(engine_name, {
                "status": "deep-only",
                "findings": 0,
                "reason": "runs only in Deep mode",
            })

    def _record_result(self, summary, engine_name, runner, include_findings=True, findings=None):
        if self._cancelled():
            summary["results"][engine_name] = {"status": "cancelled", "findings": 0}
            self._emit_progress(engine_name, "cancelled")
            return []
        if self._budget_exhausted():
            summary["results"][engine_name] = {
                "status": "skipped-budget",
                "findings": 0,
                "reason": "external engine budget exhausted",
            }
            self._emit_progress(engine_name, "skipped-budget")
            return []
        if not self._available(engine_name):
            summary["results"][engine_name] = {"status": "missing", "findings": 0}
            self._emit_progress(engine_name, "missing")
            return []
        started = self.time_func()
        self._emit_progress(engine_name, "running")
        try:
            engine_findings, meta = runner()
        except subprocess.TimeoutExpired:
            summary["results"][engine_name] = {"status": "timeout", "findings": 0}
            self._emit_progress(engine_name, "timeout")
            return []
        except Exception as exc:
            summary["results"][engine_name] = {"status": "error", "findings": 0, "error": str(exc)}
            summary["errors"].append({"engine": engine_name, "error": str(exc)})
            self._emit_progress(engine_name, "error", {"error": str(exc)})
            return []

        duration_ms = int(max(0, self.time_func() - started) * 1000)
        summary["results"][engine_name] = {
            "status": meta.get("status", "ok"),
            "findings": len(engine_findings),
            "duration_ms": meta.get("duration_ms", duration_ms),
            **{k: v for k, v in meta.items() if k != "status"},
        }
        self._emit_progress(engine_name, summary["results"][engine_name]["status"], summary["results"][engine_name])
        if include_findings and findings is not None:
            findings.extend(engine_findings)
            return []
        return engine_findings if include_findings else []

    def _available(self, engine_name: str):
        return bool(self.engines.get(engine_name, {}).get("available"))

    def _command(self, engine_name: str):
        return self.engines.get(engine_name, {}).get("path") or engine_name

    def _run(self, command, timeout=60):
        remaining = self._remaining_seconds()
        if remaining is not None:
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, 0)
            timeout = min(timeout, remaining)
        return self.command_runner(command, timeout)

    def _remaining_seconds(self):
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - self.time_func())

    def _budget_exhausted(self):
        remaining = self._remaining_seconds()
        return remaining is not None and remaining <= 0

    def _cancelled(self):
        try:
            return bool(self.cancel_cb())
        except Exception:
            return False

    def _emit_progress(self, engine_name: str, status: str, meta=None):
        try:
            self.progress_cb(engine_name, status, meta or {})
        except Exception:
            pass

    def _run_nuclei(self):
        command = [
            self._command("nuclei"),
            "-u",
            self.base_url,
            "-jsonl",
            "-silent",
            "-no-color",
            "-as",
            "-s",
            "low,medium,high,critical",
            "-etags",
            "intrusive,dos,fuzz,bruteforce",
            "-retries",
            "0",
            "-timeout",
            "3",
            "-c",
            "10",
            "-rl",
            "30",
        ]
        completed = self._run(command, timeout=45 if self.mode == "deep" else 25)
        findings = self._parse_nuclei_jsonl(completed.stdout)
        return findings, {
            "status": "ok" if completed.returncode == 0 else "error",
            "returncode": completed.returncode,
            "stderr": (completed.stderr or "")[-500:],
        }

    def _parse_nuclei_jsonl(self, output: str):
        findings = []
        for line in (output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info") or {}
            name = info.get("name") or item.get("template-id") or "Nuclei finding"
            matched = item.get("matched-at") or item.get("matched") or item.get("host") or self.base_url
            severity = self._normalize_severity(info.get("severity") or item.get("severity") or "Info")
            findings.append({
                "type": f"Nuclei: {name}",
                "url": matched,
                "method": "GET",
                "payload": {
                    "engine": "nuclei",
                    "template": item.get("template-id"),
                    "matcher": item.get("matcher-name"),
                    "severity": info.get("severity"),
                },
                "evidence": item.get("extracted-results") or info.get("description") or "nuclei template matched",
                "severity": severity,
            })
        return findings

    def _run_katana(self):
        command = [
            self._command("katana"),
            "-u",
            self.base_url,
            "-silent",
            "-jsonl",
            "-d",
            "2" if self.mode == "deep" else "1",
            "-c",
            "10",
            "-rl",
            "30",
            "-timeout",
            "8",
        ]
        completed = self._run(command, timeout=35 if self.mode == "deep" else 20)
        urls = self._parse_katana_urls(completed.stdout)
        return [], {
            "status": "ok" if completed.returncode == 0 else "error",
            "returncode": completed.returncode,
            "urls": len(urls),
            "sample": urls[:10],
            "urls_list": urls[:100],
            "stderr": (completed.stderr or "")[-500:],
        }

    def _parse_katana_urls(self, output: str):
        urls = []
        seen = set()
        for line in (output or "").splitlines():
            raw = line.strip()
            if not raw:
                continue
            url = raw
            if raw.startswith("{"):
                try:
                    item = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                request = item.get("request") or {}
                url = item.get("url") or item.get("endpoint") or request.get("endpoint") or request.get("url")
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
        return urls

    def _run_ffuf(self):
        if not self.wordlist_path.exists():
            return [], {"status": "missing-wordlist", "wordlist": str(self.wordlist_path)}

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_path = Path(tmp.name)

        try:
            command = [
                self._command("ffuf"),
                "-u",
                urljoin(self.base_url + "/", "FUZZ"),
                "-w",
                str(self.wordlist_path),
                "-of",
                "json",
                "-o",
                str(output_path),
                "-t",
                "20",
                "-rate",
                "60",
                "-mc",
                "200,204,301,302,307,401,403",
                "-s",
            ]
            completed = self._run(command, timeout=45)
            findings = self._parse_ffuf_json(output_path)
            return findings, {
                "status": "ok" if completed.returncode == 0 else "error",
                "returncode": completed.returncode,
                "wordlist": str(self.wordlist_path),
                "stderr": (completed.stderr or "")[-500:],
            }
        finally:
            output_path.unlink(missing_ok=True)

    def _parse_ffuf_json(self, output_path: Path):
        try:
            data = json.loads(output_path.read_text(encoding="utf-8") or "{}")
        except (OSError, json.JSONDecodeError):
            return []

        findings = []
        for item in data.get("results", [])[:30]:
            url = item.get("url") or self.base_url
            status = item.get("status")
            findings.append({
                "type": "FFUF Discovery",
                "url": url,
                "method": "GET",
                "payload": {
                    "engine": "ffuf",
                    "status": status,
                    "length": item.get("length"),
                    "words": item.get("words"),
                },
                "evidence": f"ffuf discovered path with HTTP {status}",
                "severity": "Low" if status in {200, 401, 403} else "Info",
            })
        return findings

    def _run_sslyze(self):
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            return [], {"status": "skipped", "reason": "target is not HTTPS"}
        command = [self._command("sslyze"), "--json_out", "-", parsed.hostname]
        completed = self._run(command, timeout=30)
        return self._parse_sslyze_output(completed.stdout), {
            "status": "ok" if completed.returncode == 0 else "error",
            "returncode": completed.returncode,
            "stderr": (completed.stderr or "")[-500:],
        }

    def _parse_sslyze_output(self, output: str):
        text = (output or "").lower()
        findings = []
        if "expired" in text:
            findings.append({
                "type": "SSLyze: Expired Certificate",
                "url": self.base_url,
                "method": "TLS",
                "payload": {"engine": "sslyze"},
                "evidence": "certificate output mentions expired certificate",
                "severity": "High",
            })
        if "heartbleed" in text and "true" in text:
            findings.append({
                "type": "SSLyze: Heartbleed",
                "url": self.base_url,
                "method": "TLS",
                "payload": {"engine": "sslyze"},
                "evidence": "heartbleed marker in SSLyze output",
                "severity": "Critical",
            })
        return findings

    def _run_retire(self):
        scripts = self._download_homepage_scripts()
        if not scripts:
            return [], {"status": "skipped", "reason": "no same-origin scripts found"}

        with tempfile.TemporaryDirectory(prefix="advscan-retire-") as tmpdir:
            tmp_path = Path(tmpdir)
            for filename, content in scripts.items():
                (tmp_path / filename).write_text(content, encoding="utf-8", errors="ignore")
            output_path = tmp_path / "retire.json"

            command = [
                self._command("retire"),
                "--path",
                str(tmp_path),
                "--outputformat",
                "json",
                "--outputpath",
                str(output_path),
                "--severity",
                "none",
            ]
            completed = self._run(command, timeout=25)
            output = ""
            if output_path.exists():
                output = output_path.read_text(encoding="utf-8", errors="ignore")
            elif completed.stdout:
                output = completed.stdout
            findings = self._parse_retire_json(output)
            return findings, {
                "status": "ok" if completed.returncode in {0, 13} else "error",
                "returncode": completed.returncode,
                "scripts": len(scripts),
                "stderr": (completed.stderr or "")[-500:],
            }

    def _download_homepage_scripts(self):
        headers = {**HEADERS, "Connection": "close"}
        try:
            with requests.Session() as session:
                response, html = self._fetch_text(session, self.base_url, headers, max_bytes=1_000_000)
                return self._extract_and_download_scripts(session, response.url or self.base_url, html, headers)
        except subprocess.TimeoutExpired:
            raise
        except Exception:
            return {}

    def _fetch_text(self, session, url, headers, max_bytes=512_000):
        remaining = self._remaining_seconds()
        if remaining is not None and remaining <= 0:
            raise subprocess.TimeoutExpired(["requests", url], 0)
        read_timeout = min(4, max(1, remaining)) if remaining is not None else 4
        response = session.get(
            url,
            headers=headers,
            timeout=(2, read_timeout),
            allow_redirects=True,
            stream=True,
        )
        chunks = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                if self._budget_exhausted():
                    raise subprocess.TimeoutExpired(["requests", url], self.max_seconds)
                remaining_bytes = max_bytes - total
                if remaining_bytes <= 0:
                    break
                chunks.append(chunk[:remaining_bytes])
                total += len(chunk[:remaining_bytes])
                if total >= max_bytes:
                    break
            encoding = response.encoding or "utf-8"
            return response, b"".join(chunks).decode(encoding, errors="ignore")
        finally:
            response.close()

    def _extract_and_download_scripts(self, session, page_url, html, headers):
        response_url = page_url or self.base_url
        if not html:
            return {}
        base_netloc = urlparse(response_url).netloc or urlparse(self.base_url).netloc
        script_urls = []
        seen = set()
        for match in re.finditer(r"<script[^>]+src=[\"']([^\"']+)[\"']", html or "", re.I):
            script_url = urljoin(response_url, match.group(1))
            parsed = urlparse(script_url)
            if parsed.scheme not in {"http", "https"} or parsed.netloc != base_netloc:
                continue
            normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))
            if normalized in seen:
                continue
            seen.add(normalized)
            script_urls.append(normalized)
            if len(script_urls) >= 6:
                break

        scripts = {}
        for index, script_url in enumerate(script_urls, start=1):
            if self._budget_exhausted():
                raise subprocess.TimeoutExpired(["requests", script_url], self.max_seconds)
            try:
                script_response, script_text = self._fetch_text(session, script_url, headers, max_bytes=512_000)
            except subprocess.TimeoutExpired:
                raise
            except Exception:
                continue
            if script_response.status_code != 200:
                continue
            content_type = script_response.headers.get("Content-Type", "").lower()
            if content_type and "javascript" not in content_type and "text/plain" not in content_type:
                continue
            filename = Path(urlparse(script_url).path).name or f"script-{index}.js"
            if not filename.endswith(".js"):
                filename = f"{filename}.js"
            scripts[f"{index:02d}-{filename}"] = script_text or ""
        return scripts

    def _parse_retire_json(self, output: str):
        try:
            data = json.loads(output or "[]")
        except json.JSONDecodeError:
            return []

        findings = []
        items = data if isinstance(data, list) else data.get("data", [])
        for item in items[:30]:
            component = item.get("component") or item.get("file") or "frontend dependency"
            vulns = item.get("vulnerabilities") or []
            if not vulns:
                continue
            first = vulns[0]
            findings.append({
                "type": f"Retire.js: {component}",
                "url": item.get("file") or self.base_url,
                "method": "GET",
                "payload": {
                    "engine": "retire",
                    "component": component,
                    "version": item.get("version"),
                    "count": len(vulns),
                },
                "evidence": first.get("summary") or first.get("identifiers", {}).get("summary") or "known vulnerable JS component",
                "severity": self._normalize_severity(first.get("severity", "Medium")),
            })
        return findings

    def _normalize_severity(self, value: str):
        normalized = (value or "Info").strip().lower()
        mapping = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "informational": "Info",
        }
        return mapping.get(normalized, "Info")

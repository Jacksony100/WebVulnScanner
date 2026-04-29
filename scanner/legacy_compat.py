# scanner/scanner.py
# Основной оркестратор для выполнения сканирования уязвимостей

import asyncio
import json
import requests
import re
import socket
import time
from urllib.parse import urljoin, parse_qs, urlparse, urlencode, urlunparse
from bs4 import BeautifulSoup
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import logging

from .crawler import Crawler
from .checkers import (
    XSSChecker,
    SQLIChecker,
    SSTIChecker,
    NoSQLChecker,
    CRLFInjectionChecker,
    LDAPInjectionChecker,
    XPathInjectionChecker,
    PrototypePollutionChecker,
    PathTraversalChecker,
    OSCommandChecker,
    SSRFChecker,
    LFIRFIChecker,
    HPPChecker,
    OpenRedirectChecker,
)
from .payloads import (HEADERS, ERROR_SIGS_SQL, ERROR_SIGS_PATH, ERROR_SIGS_LFI,
                      ERROR_SIGS_NOSQL, ERROR_SIGS_LDAP, ERROR_SIGS_XPATH,
                      FUZZ_PARAMS, HEADER_FUZZ_PAYLOADS, SEVERITY_MAP, COMMON_EXPOSURE_PATHS,
                      SENSITIVE_PATTERNS, GRAPHQL_PATHS, GRAPHQL_INTROSPECTION_QUERY,
                      SOURCE_MAP_CANDIDATES)
from .external_engines import ExternalEngineRunner
from .utils import rand_tag, detect_cms, get_cms_version, normalize_target_url

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnResult(dict):
    """Класс для представления результата уязвимости"""

    def __getattr__(self, key):
        return self.get(key)

class LegacyScannerMixin:
    """Основной класс для координации сканирования уязвимостей"""

    def __init__(self, base_url: str, progress_cb=None, threads: int = 10, scan_mode: str = "safe", cancel_cb=None):
        # Базовый URL для сканирования
        self.base = normalize_target_url(base_url).rstrip('/')
        self.threads = threads
        self.scan_mode = scan_mode if scan_mode in {"safe", "active", "deep"} else "safe"
        self.active_enabled = self.scan_mode in {"active", "deep"}
        self.deep_scan = self.scan_mode == "deep"
        # HTTP-сессия
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        # Callback для обновления прогресса
        self.progress_cb = progress_cb or (lambda _: {})
        self.cancel_cb = cancel_cb or (lambda: False)
        # Пул потоков для параллельного выполнения
        self.executor = ThreadPoolExecutor(max_workers=threads)
        # Список найденных уязвимостей
        self.vulns: list[VulnResult] = []
        self._seen_vulns: set[tuple[str, str, str, str]] = set()
        # Информация о CMS
        self.cms_info = {"cms": None, "version": None}
        self.scan_info = {}
        # Список проверок уязвимостей
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
            if self.deep_scan:
                self.checkers.extend([
                    LDAPInjectionChecker(self.session),
                    XPathInjectionChecker(self.session),
                    PrototypePollutionChecker(self.session),
                    PathTraversalChecker(self.session),
                    OSCommandChecker(self.session),
                    SSRFChecker(self.session),
                    LFIRFIChecker(self.session),
                ])
        logger.info(f"Инициализирован сканер для {self.base} с {threads} потоками, режим: {self.scan_mode}")

    async def run(self):
        """Основной метод для запуска сканирования"""
        try:
            self._update("Краулинг цели...", 0, 1)
            logger.info("Запуск краулинга")
            crawler = Crawler(self.base, max_pages=200 if self.deep_scan else 100, concurrent=min(self.threads, 20))
            pages = await crawler.crawl()
            logger.info(f"Краулинг завершен, найдено {len(pages)} страниц")
            if self._cancelled():
                return self._finish_cancelled(1, 1)

            # Детекция CMS
            self._update("Определение CMS и технологий...", 1, 4)
            logger.info("Детекция CMS")
            cms = detect_cms(self.session, self.base)
            if cms:
                version = get_cms_version(self.session, self.base, cms)
                self.cms_info = {"cms": cms, "version": version}
                logger.info(f"Обнаружен CMS: {cms} (версия: {version})")
            else:
                self.cms_info = {"cms": "Не определено", "version": "N/A"}
                logger.info("CMS не определен")

            self.scan_info = self._collect_target_info(pages)
            self.scan_info["cms"] = self.cms_info
            external_progress = {"current": 0, "total": 1}

            def external_progress_cb(engine_name, status, meta=None):
                label = external_runner.engines.get(engine_name, {}).get("label") or engine_name
                status_labels = {
                    "running": "запущен",
                    "ok": "готово",
                    "error": "ошибка",
                    "timeout": "таймаут",
                    "missing": "не установлен",
                    "skipped": "пропущен",
                    "deep-only": "только Deep",
                    "skipped-budget": "нет бюджета времени",
                    "cancelled": "остановлен",
                }
                readable = status_labels.get(status, status)
                self._update(
                    f"Внешние движки: {label} - {readable}",
                    external_progress["current"],
                    external_progress["total"],
                )

            external_runner = ExternalEngineRunner(
                self.base,
                self.scan_mode,
                max_seconds=120 if self.deep_scan else 45 if self.active_enabled else 0,
                progress_cb=external_progress_cb,
                cancel_cb=self._cancelled,
            )
            self.scan_info["external_engines"] = {
                "mode": self.scan_mode,
                "engines": external_runner.engines,
                "results": {},
                "errors": [],
            }

            logger.info("Пассивная проверка базовой конфигурации")
            passive_added = self._add_vulns(self._check_passive_baseline())
            logger.info(f"Добавлено пассивных находок: {passive_added}")
            if self._cancelled():
                return self._finish_cancelled(1, 4)

            forms_total = sum(len(s.find_all("form")) for _, s in pages)
            query_targets = self._collect_query_targets(pages)
            active_total = forms_total + len(query_targets)
            self.total = max(active_total + 4, 1)
            current = 2
            external_progress.update({"current": current, "total": self.total})
            logger.info(f"Найдено форм: {forms_total}, URL с параметрами: {len(query_targets)}")

            # Проверка CSRF остается пассивной: анализирует HTML форм.
            logger.info("Проверка CSRF")
            for url, soup in pages:
                csrf_vulns = self._check_csrf_forms(url, soup)
                self._add_vulns(csrf_vulns)
                if csrf_vulns:
                    logger.info(f"Обнаружены CSRF уязвимости: {len(csrf_vulns)}")

            script_secret_vulns = self._check_linked_script_secrets(pages)
            self._add_vulns(script_secret_vulns)
            if script_secret_vulns:
                logger.info(f"Найдены секреты в подключенных JS-файлах: {len(script_secret_vulns)}")

            if not self.active_enabled:
                _, external_summary = external_runner.run()
                self.scan_info["external_engines"] = external_summary
                if self._cancelled():
                    return self._finish_cancelled(self.total, self.total)
                self._update("Safe-сканирование завершено", self.total, self.total, done=True)
                logger.info(f"Safe-сканирование завершено, найдено {len(self.vulns)} находок")
                return self.vulns

            if self._cancelled():
                return self._finish_cancelled(current, self.total)

            cors_vulns = self._check_cors_origin_reflection()
            self._add_vulns(cors_vulns)
            if cors_vulns:
                logger.info(f"Обнаружены CORS проблемы: {len(cors_vulns)}")

            # Проверка IDOR активна: выполняет дополнительные запросы.
            logger.info("Проверка IDOR")
            idor_vulns = self._check_idor(pages)
            self._add_vulns(idor_vulns)
            if idor_vulns:
                logger.info(f"Обнаружены IDOR уязвимости: {len(idor_vulns)}")

            logger.info("Проверка распространенных открытых служебных файлов")
            exposure_vulns = self._check_common_exposures()
            self._add_vulns(exposure_vulns)
            if exposure_vulns:
                logger.info(f"Найдены открытые служебные файлы/эндпоинты: {len(exposure_vulns)}")

            if self.deep_scan:
                source_map_vulns = self._check_common_source_maps()
                self._add_vulns(source_map_vulns)
                if source_map_vulns:
                    logger.info(f"Найдены source map файлы: {len(source_map_vulns)}")

                graphql_vulns = self._check_graphql_introspection()
                self._add_vulns(graphql_vulns)
                if graphql_vulns:
                    logger.info(f"GraphQL introspection доступен: {len(graphql_vulns)}")

            if self.deep_scan:
                external_msg = "Внешние движки: nuclei/katana/ffuf/TLS/JS..."
            else:
                external_msg = "Внешние движки: nuclei/katana..."
            self._update(external_msg, current, self.total)
            external_vulns, external_summary = external_runner.run()
            self.scan_info["external_engines"] = external_summary
            if self._cancelled():
                return self._finish_cancelled(current, self.total)
            external_added = self._add_vulns(external_vulns)
            if external_added:
                logger.info(f"Внешние движки добавили находок: {external_added}")

            futures = []
            for url, soup in pages:
                for form in soup.find_all("form"):
                    futures.append(self.executor.submit(self._test_form, url, form, soup))
            for target, params in query_targets:
                futures.append(self.executor.submit(self._test_query_params, target, params))

            logger.info(f"Запущено активных задач: {len(futures)}")
            pending = set(futures)
            while pending:
                if self._cancelled():
                    for fut in pending:
                        fut.cancel()
                    return self._finish_cancelled(current, self.total)
                done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                if not done:
                    continue
                for fut in done:
                    try:
                        vulns = fut.result()
                        if vulns:
                            self._add_vulns(vulns)
                            logger.info(f"Обнаружены уязвимости: {len(vulns)}")
                    except Exception as e:
                        logger.error(f"Ошибка при активной проверке: {e}")
                    current += 1
                    self._update(f"Активные проверки: {current}/{self.total}", current, self.total)

            self._update("Сканирование завершено", self.total, self.total, done=True)
            logger.info(f"Сканирование завершено, найдено {len(self.vulns)} уязвимостей")
            return self.vulns
        finally:
            try:
                self.executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                self.executor.shutdown(wait=False)
    
    def get_cms_info(self):
        """Возвращает информацию о CMS"""
        return self.cms_info

    def get_scan_info(self):
        """Возвращает техническую информацию о цели."""
        return self.scan_info

    def _test_form(self, page_url: str, form, soup: BeautifulSoup):
        """Тестирование формы на уязвимости"""
        logger.debug(f"Проверка формы на {page_url}")
        action = form.get("action") or page_url
        method = (form.get("method") or "get").lower()
        target = urljoin(page_url, action)
        inputs = form.find_all(["input", "textarea", "select"])
        form_data = {i.get("name") or rand_tag(): "test" for i in inputs if i.get("name")}
        vulns: list[VulnResult] = []
        if not form_data:
            return vulns
        for chk in self.checkers:
            logger.debug(f"Check: {chk.__class__.__name__}")
            vulns.extend(chk.test(target, form_data, method))
        if self.deep_scan:
            vulns.extend(self._generic_fuzz(target, form_data, method))
            vulns.extend(self._context_aware_fuzz(target, form_data, method, soup))
        vulns.extend(self._header_fuzz(target, form_data, method))
        return vulns

    def _test_query_params(self, target: str, params: dict[str, str]):
        """Тестирует параметры URL на активные уязвимости."""
        vulns: list[VulnResult] = []
        if not params:
            return vulns
        for chk in self.checkers:
            logger.debug(f"Query check: {chk.__class__.__name__}")
            vulns.extend(chk.test(target, params, "get"))
        if self.deep_scan:
            vulns.extend(self._generic_fuzz(target, params, "get"))
        vulns.extend(self._header_fuzz(target, params, "get"))
        return vulns

    def _collect_query_targets(self, pages: list[tuple[str, BeautifulSoup]]):
        """Собирает URL с query-параметрами для SQL/XSS проверок."""
        targets = []
        seen = set()
        for page_url, _ in pages:
            parsed = urlparse(page_url)
            qs = parse_qs(parsed.query)
            if not qs:
                continue
            target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            params = {k: (vals[0] if vals else "test") for k, vals in qs.items()}
            key = (target, tuple(sorted(params)))
            if key not in seen:
                seen.add(key)
                targets.append((target, params))
        return targets

    def _collect_target_info(self, pages: list[tuple[str, BeautifulSoup]]):
        """Собирает техническую информацию для интерфейса и отчета."""
        parsed = urlparse(self.base)
        hostname = parsed.hostname or ""
        info = {
            "target": self.base,
            "mode": self.scan_mode,
            "hostname": hostname,
            "ip_addresses": [],
            "final_url": self.base,
            "status_code": None,
            "title": None,
            "server": None,
            "powered_by": None,
            "content_type": None,
            "response_time_ms": None,
            "pages_crawled": len(pages),
            "forms_total": sum(len(s.find_all("form")) for _, s in pages),
            "query_urls_total": len(self._collect_query_targets(pages)),
            "technologies": [],
            "allowed_methods": [],
        }

        try:
            ip_addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)}) if hostname else []
            info["ip_addresses"] = ip_addresses[:8]
        except Exception:
            info["ip_addresses"] = []

        try:
            started = time.perf_counter()
            response = self.session.get(self.base, headers=HEADERS, timeout=8, allow_redirects=True)
            info["response_time_ms"] = int((time.perf_counter() - started) * 1000)
            info["final_url"] = response.url
            info["status_code"] = response.status_code
            info["server"] = response.headers.get("Server")
            info["powered_by"] = response.headers.get("X-Powered-By")
            info["content_type"] = response.headers.get("Content-Type")
            soup = BeautifulSoup(response.text or "", "html.parser")
            if soup.title and soup.title.string:
                info["title"] = soup.title.string.strip()
            info["technologies"] = self._detect_technologies(response, response.text or "")
        except Exception as e:
            logger.warning(f"Не удалось собрать target info для {self.base}: {e}")

        return info

    def _detect_technologies(self, response, body: str):
        """Простая эвристика определения технологий по HTML и заголовкам."""
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        body_lower = body.lower()
        tech = set()

        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        for name in ["nginx", "apache", "cloudflare", "iis", "openresty"]:
            if name in server:
                tech.add(name.title())
        if "php" in powered_by or ".php" in body_lower:
            tech.add("PHP")
        if "asp.net" in powered_by or "aspnet" in body_lower:
            tech.add("ASP.NET")
        if "express" in powered_by:
            tech.add("Express")

        patterns = {
            "WordPress": ["wp-content", "wp-includes"],
            "Joomla": ["joomla", "com_content"],
            "Drupal": ["drupal.js", "drupal.settings"],
            "Magento": ["mage.", "magento"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "React": ["reactroot", "__next", "react-dom"],
            "Vue": ["vue.js", "__vue__"],
            "Laravel": ["laravel", "x-csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
        }
        for name, sigs in patterns.items():
            if any(sig in body_lower for sig in sigs):
                tech.add(name)
        return sorted(tech)

    def _add_vulns(self, vulns):
        """Добавляет находки без дублей."""
        added = 0
        for vuln in vulns:
            if not vuln:
                continue
            payload = json.dumps(vuln.get("payload", {}), sort_keys=True, default=str, ensure_ascii=False)
            key = (vuln.get("type", ""), vuln.get("url", ""), vuln.get("method", ""), payload)
            if key in self._seen_vulns:
                continue
            self._seen_vulns.add(key)
            self.vulns.append(vuln)
            added += 1
        return added

    def _check_passive_baseline(self):
        """Пассивные проверки, которые не отправляют вредные payload-ы."""
        vulns: list[VulnResult] = []
        try:
            r = self.session.get(self.base, headers=HEADERS, timeout=8, allow_redirects=True)
        except Exception as e:
            logger.warning(f"Не удалось выполнить пассивную проверку {self.base}: {e}")
            return vulns

        final_url = r.url or self.base
        final_scheme = urlparse(final_url).scheme
        headers = {k.lower(): v for k, v in r.headers.items()}
        body = r.text or ""

        if final_scheme == "http":
            vulns.append(VulnResult(
                type="Unencrypted connection",
                url=final_url,
                method="GET",
                payload={"scheme": "http", "evidence": "Цель доступна по незашифрованному HTTP"},
                severity=SEVERITY_MAP["Unencrypted connection"],
            ))

        checks = [
            ("content-security-policy", "Content-Security-Policy", "Medium",
             "Добавить CSP для снижения риска XSS и инъекций контента"),
            ("x-frame-options", "X-Frame-Options", "Medium",
             "Добавить DENY или SAMEORIGIN для защиты от clickjacking"),
            ("x-content-type-options", "X-Content-Type-Options", "Low",
             "Добавить nosniff для запрета MIME sniffing"),
            ("referrer-policy", "Referrer-Policy", "Low",
             "Ограничить утечки URL и параметров через Referer"),
        ]

        if final_scheme == "https":
            checks.append((
                "strict-transport-security",
                "Strict-Transport-Security",
                "Medium",
                "Добавить HSTS для принудительного HTTPS",
            ))

        for header_key, header_name, severity, recommendation in checks:
            if header_key not in headers:
                vulns.append(VulnResult(
                    type=f"Missing Security Header: {header_name}",
                    url=final_url,
                    method="GET",
                    payload={"header": header_name, "recommendation": recommendation},
                    severity=severity,
                ))

        vulns.extend(self._check_weak_security_headers(final_url, final_scheme, headers))

        if headers.get("server"):
            vulns.append(VulnResult(
                type="Information Disclosure: Server Header",
                url=final_url,
                method="GET",
                payload={"header": "Server", "value": headers.get("server")},
                severity=SEVERITY_MAP["Information Disclosure"],
            ))
        if headers.get("x-powered-by"):
            vulns.append(VulnResult(
                type="Information Disclosure: X-Powered-By",
                url=final_url,
                method="GET",
                payload={"header": "X-Powered-By", "value": headers.get("x-powered-by")},
                severity=SEVERITY_MAP["Information Disclosure"],
            ))

        vulns.extend(self._check_sensitive_patterns(final_url, body))

        acao = headers.get("access-control-allow-origin", "").strip()
        acac = headers.get("access-control-allow-credentials", "").strip().lower()
        if acao == "*" or (acao and acac == "true"):
            vulns.append(VulnResult(
                type="Permissive CORS",
                url=final_url,
                method="GET",
                payload={"access-control-allow-origin": acao, "access-control-allow-credentials": acac or "not set"},
                severity=SEVERITY_MAP["Permissive CORS"],
            ))

        for cookie in r.cookies:
            missing = []
            rest = {k.lower(): v for k, v in cookie._rest.items()}
            if final_scheme == "https" and not cookie.secure:
                missing.append("Secure")
            if "httponly" not in rest:
                missing.append("HttpOnly")
            if "samesite" not in rest:
                missing.append("SameSite")
            if missing:
                vulns.append(VulnResult(
                    type="Cookie Missing Security Flag",
                    url=final_url,
                    method="GET",
                    payload={"cookie": cookie.name, "missing": ", ".join(missing)},
                    severity=SEVERITY_MAP["Cookie Missing Security Flag"],
                ))

        soup = BeautifulSoup(body, "html.parser")
        title = soup.title.string.strip().lower() if soup.title and soup.title.string else ""
        if title.startswith("index of"):
            vulns.append(VulnResult(
                type="Directory Listing",
                url=final_url,
                method="GET",
                payload={"title": title},
                severity=SEVERITY_MAP["Directory Listing"],
            ))

        if final_scheme == "https":
            mixed = []
            for tag in soup.find_all(["script", "img", "link", "iframe"], src=True):
                if tag.get("src", "").startswith("http://"):
                    mixed.append(tag.get("src"))
            for tag in soup.find_all("link", href=True):
                if tag.get("href", "").startswith("http://"):
                    mixed.append(tag.get("href"))
            if mixed:
                vulns.append(VulnResult(
                    type="Mixed Content",
                    url=final_url,
                    method="GET",
                    payload={"examples": mixed[:5]},
                    severity=SEVERITY_MAP["Mixed Content"],
                ))

        method_vuln = self._check_http_methods()
        if method_vuln:
            vulns.append(method_vuln)

        return vulns

    def _check_weak_security_headers(self, url: str, scheme: str, headers: dict[str, str]):
        """Находит заголовки, которые есть, но настроены слишком мягко."""
        vulns: list[VulnResult] = []

        csp = headers.get("content-security-policy", "")
        csp_lower = csp.lower()
        if csp:
            issues = []
            if "'unsafe-inline'" in csp_lower:
                issues.append("unsafe-inline")
            if "'unsafe-eval'" in csp_lower:
                issues.append("unsafe-eval")
            if "http:" in csp_lower:
                issues.append("allows insecure http sources")
            if "*" in csp_lower:
                issues.append("wildcard source")
            if "default-src" not in csp_lower and "script-src" not in csp_lower:
                issues.append("no default-src/script-src")
            if issues:
                vulns.append(VulnResult(
                    type="Weak Security Header: Content-Security-Policy",
                    url=url,
                    method="GET",
                    payload={"header": "Content-Security-Policy", "issues": issues, "value": csp[:200]},
                    severity=SEVERITY_MAP["Weak Security Header"],
                ))

        if scheme == "https":
            hsts = headers.get("strict-transport-security", "")
            if hsts:
                max_age = self._parse_hsts_max_age(hsts)
                issues = []
                if max_age is not None and max_age < 15552000:
                    issues.append("max-age below 180 days")
                if "includesubdomains" not in hsts.lower():
                    issues.append("missing includeSubDomains")
                if issues:
                    vulns.append(VulnResult(
                        type="Weak Security Header: Strict-Transport-Security",
                        url=url,
                        method="GET",
                        payload={"header": "Strict-Transport-Security", "issues": issues, "value": hsts},
                        severity=SEVERITY_MAP["Weak Security Header"],
                    ))

        referrer = headers.get("referrer-policy", "").strip().lower()
        if referrer in {"unsafe-url", "origin-when-cross-origin"}:
            vulns.append(VulnResult(
                type="Weak Security Header: Referrer-Policy",
                url=url,
                method="GET",
                payload={"header": "Referrer-Policy", "value": referrer},
                severity=SEVERITY_MAP["Weak Security Header"],
            ))

        permissions = headers.get("permissions-policy", "").strip()
        if permissions and "*" in permissions:
            vulns.append(VulnResult(
                type="Weak Security Header: Permissions-Policy",
                url=url,
                method="GET",
                payload={"header": "Permissions-Policy", "value": permissions[:200]},
                severity=SEVERITY_MAP["Weak Security Header"],
            ))

        return vulns

    def _parse_hsts_max_age(self, hsts: str):
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if not match:
            return None
        try:
            return int(match.group(1))
        except ValueError:
            return None

    def _check_sensitive_patterns(self, url: str, body: str):
        """Ищет случайно опубликованные секреты в HTML/JS ответе."""
        vulns: list[VulnResult] = []
        if not body:
            return vulns

        for label, pattern in SENSITIVE_PATTERNS:
            match = re.search(pattern, body)
            if not match:
                continue
            value = match.group(0)
            vulns.append(VulnResult(
                type=f"Information Disclosure: {label}",
                url=url,
                method="GET",
                payload={
                    "secret_type": label,
                    "evidence": self._redact_secret(value),
                },
                severity=SEVERITY_MAP["Information Disclosure"],
            ))
        return vulns

    def _redact_secret(self, value: str):
        """Показывает короткий отпечаток секрета без утечки полного значения в отчет."""
        clean = value.strip()
        if len(clean) <= 12:
            return "***"
        return f"{clean[:6]}...{clean[-4:]}"

    def _check_common_exposures(self):
        """Проверяет типовые служебные пути без попыток эксплуатации содержимого."""
        vulns: list[VulnResult] = []
        baseline = None
        try:
            baseline = self.session.get(
                urljoin(self.base + "/", f"__advscan_missing_{rand_tag()}"),
                headers=HEADERS,
                timeout=6,
                allow_redirects=False,
            )
        except Exception:
            baseline = None

        for path in COMMON_EXPOSURE_PATHS:
            target = urljoin(self.base + "/", path.lstrip("/"))
            try:
                r = self.session.get(target, headers=HEADERS, timeout=6, allow_redirects=False)
            except Exception as e:
                logger.debug(f"Ошибка при проверке служебного пути {target}: {e}")
                continue
            if not self._looks_like_exposed_path(path, r, baseline):
                continue

            vuln_type = "Info" if path.endswith("security.txt") else "Sensitive File/Dir Found"
            vulns.append(VulnResult(
                type=vuln_type,
                url=target,
                method="GET",
                payload={
                    "path": path,
                    "status": r.status_code,
                    "evidence": self._exposure_evidence(path, r),
                },
                severity=SEVERITY_MAP[vuln_type],
            ))
        return vulns

    def _looks_like_exposed_path(self, path: str, response, baseline):
        if response.status_code in {401, 403}:
            return path not in {"/.well-known/security.txt"}
        if response.status_code != 200:
            return False
        if self._same_as_missing_response(response, baseline):
            return False

        lower_path = path.lower()
        body = (response.text or "")[:10000]
        lower_body = body.lower()
        content_type = response.headers.get("Content-Type", "").lower()

        signatures = {
            "/.env": ["app_key=", "database_url=", "secret", "password=", "aws_"],
            "/.git/config": ["[core]", "repositoryformatversion", "[remote "],
            "/config.php.bak": ["<?php", "db_password", "database"],
            "/config.php~": ["<?php", "db_password", "database"],
            "/settings.py": ["secret_key", "database", "installed_apps"],
            "/settings.py.bak": ["secret_key", "database", "installed_apps"],
            "/application.properties": ["spring.datasource", "server.port", "management.endpoints"],
            "/application.yml": ["spring:", "datasource:", "management:"],
            "/wp-config.php.bak": ["<?php", "db_password", "db_name", "wordpress"],
            "/wp-config.php~": ["<?php", "db_password", "db_name", "wordpress"],
            "/config.yaml": ["password:", "secret:", "database:", "api_key:"],
            "/config.yml": ["password:", "secret:", "database:", "api_key:"],
            "/docker-compose.yml": ["services:", "image:", "environment:"],
            "/.docker/config.json": ['"auths"', '"credsstore"', '"auth"'],
            "/.npmrc": ["_auth", "authToken", "registry="],
            "/composer.lock": ['"packages"', '"packages-dev"', '"content-hash"'],
            "/package-lock.json": ['"lockfileversion"', '"packages"', '"dependencies"'],
            "/backup.sql": ["create table", "insert into", "mysqldump"],
            "/db.sql": ["create table", "insert into", "mysqldump"],
            "/dump.sql": ["create table", "insert into", "mysqldump"],
            "/database.sql": ["create table", "insert into", "mysqldump"],
            "/mysql.sql": ["create table", "insert into", "mysqldump"],
            "/phpinfo.php": ["php version", "phpinfo()", "configuration file"],
            "/server-status": ["apache server status", "server uptime", "total accesses"],
            "/actuator/env": ["propertysources", "activeprofiles", "systemenvironment"],
            "/actuator/health": ['"status"', "diskspace", "components"],
            "/actuator/configprops": ["contexts", "beans", "prefix"],
            "/actuator/heapdump": [],
            "/swagger.json": ['"swagger"', '"openapi"', '"paths"'],
            "/openapi.json": ['"openapi"', '"paths"', '"components"'],
            "/api-docs": ['"swagger"', '"openapi"', '"paths"'],
            "/v2/api-docs": ['"swagger"', '"paths"'],
            "/v3/api-docs": ['"openapi"', '"paths"'],
            "/swagger-ui.html": ["swagger ui", "swagger-ui", "api-docs"],
            "/docs": ["swagger-ui", "redoc", "openapi"],
            "/redoc": ["redoc", "openapi", "__redoc_state"],
            "/debug": ["debug", "stack trace", "environment"],
            "/debug/default/view": ["debug toolbar", "yii", "application"],
            "/_profiler": ["symfony profiler", "profile token", "profiler"],
            "/.idea/workspace.xml": ["<project", "changemanager", "workspace"],
            "/.well-known/security.txt": ["contact:", "expires:", "preferred-languages:"],
        }

        if any(sig in lower_body for sig in signatures.get(lower_path, [])):
            return True
        if lower_path.endswith((".zip", ".tar", ".gz")) or lower_path == "/actuator/heapdump":
            try:
                content_length = int(response.headers.get("Content-Length", "1") or 1)
            except ValueError:
                content_length = 1
            return "text/html" not in content_type and content_length > 0
        return False

    def _same_as_missing_response(self, response, baseline):
        if baseline is None:
            return False
        if response.status_code != baseline.status_code:
            return False
        response_text = response.text or ""
        baseline_text = baseline.text or ""
        if not response_text or not baseline_text:
            return False
        if response_text[:500] == baseline_text[:500]:
            return True
        length_delta = abs(len(response_text) - len(baseline_text))
        return length_delta < 40 and response_text[:120] == baseline_text[:120]

    def _exposure_evidence(self, path: str, response):
        if response.status_code in {401, 403}:
            return "path exists but access is restricted"
        content_type = response.headers.get("Content-Type")
        if content_type:
            return f"matched known exposure signature, content-type: {content_type}"
        return "matched known exposure signature"

    def _check_linked_script_secrets(self, pages: list[tuple[str, BeautifulSoup]]):
        """Загружает same-origin JS-файлы из краулера и ищет в них секреты."""
        vulns: list[VulnResult] = []
        scripts = []
        seen = set()
        limit = 30 if self.deep_scan else 12
        base_netloc = urlparse(self.base).netloc

        for page_url, soup in pages:
            for tag in soup.find_all("script", src=True):
                script_url = urljoin(page_url, tag.get("src", ""))
                parsed = urlparse(script_url)
                if parsed.scheme not in {"http", "https"} or parsed.netloc != base_netloc:
                    continue
                normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))
                if normalized in seen:
                    continue
                seen.add(normalized)
                scripts.append(normalized)
                if len(scripts) >= limit:
                    break
            if len(scripts) >= limit:
                break

        for script_url in scripts:
            try:
                r = self.session.get(script_url, headers=HEADERS, timeout=6, allow_redirects=True)
            except Exception as e:
                logger.debug(f"Не удалось загрузить JS {script_url}: {e}")
                continue
            if r.status_code != 200:
                continue
            content_type = r.headers.get("Content-Type", "").lower()
            if content_type and "javascript" not in content_type and "text/plain" not in content_type:
                continue
            body = r.text or ""
            vulns.extend(self._check_sensitive_patterns(script_url, body))
            vulns.extend(self._check_source_maps_for_script(script_url, body))
        return vulns

    def _check_source_maps_for_script(self, script_url: str, body: str):
        """Ищет source map для конкретного JS-файла и сканирует map на секреты."""
        vulns: list[VulnResult] = []
        candidates = []
        seen = set()

        for match in re.finditer(r"sourceMappingURL\s*=\s*([^\s*]+)", body or "", re.I):
            raw = match.group(1).strip().strip("'\"")
            if raw.startswith("data:"):
                continue
            candidates.append(urljoin(script_url, raw))

        if script_url.endswith(".js"):
            candidates.append(f"{script_url}.map")

        for map_url in candidates:
            parsed = urlparse(map_url)
            if parsed.scheme not in {"http", "https"} or parsed.netloc != urlparse(self.base).netloc:
                continue
            normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))
            if normalized in seen:
                continue
            seen.add(normalized)
            source_map = self._fetch_source_map(normalized)
            if source_map is None:
                continue
            vulns.append(self._source_map_vuln(normalized, source_map))
            vulns.extend(self._check_sensitive_patterns(normalized, source_map))
        return vulns

    def _check_common_source_maps(self):
        """Проверяет типовые source map пути в deep режиме."""
        vulns: list[VulnResult] = []
        for path in SOURCE_MAP_CANDIDATES:
            target = urljoin(self.base + "/", path.lstrip("/"))
            source_map = self._fetch_source_map(target)
            if source_map is None:
                continue
            vulns.append(self._source_map_vuln(target, source_map))
            vulns.extend(self._check_sensitive_patterns(target, source_map))
        return vulns

    def _fetch_source_map(self, url: str):
        try:
            r = self.session.get(url, headers=HEADERS, timeout=6, allow_redirects=False)
        except Exception as e:
            logger.debug(f"Не удалось загрузить source map {url}: {e}")
            return None
        if r.status_code != 200:
            return None
        body = r.text or ""
        content_type = r.headers.get("Content-Type", "").lower()
        looks_like_map = (
            '"sources"' in body
            or '"sourcescontent"' in body.lower()
            or '"mappings"' in body
            or "webpack://" in body.lower()
        )
        if not looks_like_map and "json" not in content_type:
            return None
        if len(body) < 20:
            return None
        return body

    def _source_map_vuln(self, url: str, source_map: str):
        return VulnResult(
            type="Source Map Disclosure",
            url=url,
            method="GET",
            payload={
                "evidence": "source map is publicly accessible",
                "size": len(source_map),
            },
            severity=SEVERITY_MAP["Source Map Disclosure"],
        )

    def _check_cors_origin_reflection(self):
        """Проверяет отражение произвольного Origin с credentials."""
        origin = "https://advscan.example"
        try:
            headers = HEADERS.copy()
            headers["Origin"] = origin
            r = self.session.get(self.base, headers=headers, timeout=8, allow_redirects=False)
        except Exception:
            return []

        acao = r.headers.get("Access-Control-Allow-Origin", "").strip()
        acac = r.headers.get("Access-Control-Allow-Credentials", "").strip().lower()
        vary = r.headers.get("Vary", "")
        if acao != origin:
            return []

        issues = ["reflects arbitrary Origin"]
        if acac == "true":
            issues.append("credentials allowed")
        if "origin" not in vary.lower():
            issues.append("missing Vary: Origin")

        return [VulnResult(
            type="Permissive CORS",
            url=self.base,
            method="GET",
            payload={
                "origin": origin,
                "access-control-allow-origin": acao,
                "access-control-allow-credentials": acac or "not set",
                "issues": issues,
            },
            severity=SEVERITY_MAP["Permissive CORS"],
        )]

    def _check_graphql_introspection(self):
        """Проверяет доступность GraphQL introspection на типовых endpoint-ах."""
        vulns: list[VulnResult] = []
        for path in GRAPHQL_PATHS:
            target = urljoin(self.base + "/", path.lstrip("/"))
            try:
                r = self.session.post(
                    target,
                    json={"query": GRAPHQL_INTROSPECTION_QUERY},
                    headers={**HEADERS, "Content-Type": "application/json"},
                    timeout=8,
                    allow_redirects=False,
                )
            except Exception as e:
                logger.debug(f"GraphQL introspection check failed for {target}: {e}")
                continue
            body = r.text or ""
            body_lower = body.lower()
            if r.status_code == 200 and "__schema" in body_lower and "querytype" in body_lower:
                vulns.append(VulnResult(
                    type="GraphQL Introspection",
                    url=target,
                    method="POST",
                    payload={"query": "AdvscanIntrospection", "evidence": "__schema.queryType is accessible"},
                    severity=SEVERITY_MAP["GraphQL Introspection"],
                ))
                break
        return vulns

    def _check_http_methods(self):
        """Проверяет опасные HTTP-методы через OPTIONS."""
        try:
            r = self.session.options(self.base, headers=HEADERS, timeout=8, allow_redirects=False)
        except Exception:
            return None
        allow_header = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods") or ""
        methods = sorted({m.strip().upper() for m in allow_header.split(",") if m.strip()})
        if self.scan_info is not None:
            self.scan_info["allowed_methods"] = methods
        dangerous = [m for m in methods if m in {"PUT", "DELETE", "TRACE", "CONNECT"}]
        if dangerous:
            return VulnResult(
                type="Insecure HTTP Methods",
                url=self.base,
                method="OPTIONS",
                payload={"allowed": methods, "dangerous": dangerous},
                severity=SEVERITY_MAP["Insecure HTTP Methods"],
            )
        return None

    def _generic_fuzz(self, url: str, data: dict[str, str], method: str):
        """Общий фаззинг для поиска уязвимостей"""
        vulns: list[VulnResult] = []
        for p in data:
            for fz in FUZZ_PARAMS:
                mod = data.copy()
                mod[p] = fz
                r = None
                try:
                    if method == "post":
                        r = self.session.post(url, data=mod, headers=HEADERS, timeout=8)
                    else:
                        r = self.session.get(url, params=mod, headers=HEADERS, timeout=8)
                except Exception as e:
                    logger.error(f"Ошибка при фаззинге {url}: {e}")
                    continue
                if r is None:
                    continue
                t = r.text.lower()
                if any(s.lower() in t for s in ERROR_SIGS_SQL) and mod[p] != "test":
                    vulns.append(VulnResult(type="SQL Injection (fuzz)", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["SQL Injection (fuzz)"]))
                if any(s.lower() in t for s in ERROR_SIGS_NOSQL) and mod[p] != "test":
                    vulns.append(VulnResult(type="NoSQL Injection", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["NoSQL Injection"]))
                if any(s.lower() in t for s in ERROR_SIGS_LDAP) and mod[p] != "test":
                    vulns.append(VulnResult(type="LDAP Injection", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["LDAP Injection"]))
                if any(s.lower() in t for s in ERROR_SIGS_XPATH) and mod[p] != "test":
                    vulns.append(VulnResult(type="XPath Injection", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["XPath Injection"]))
                if any(s.lower() in t for s in ERROR_SIGS_PATH) and mod[p] != "test":
                    vulns.append(VulnResult(type="Path Traversal (fuzz)", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["Path Traversal (fuzz)"]))
                if "window.xssflag" in t and mod[p] != "test":
                    vulns.append(VulnResult(type="XSS (fuzz)", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["XSS"]))
                if "21993" in t and "7331" in str(mod[p]) and mod[p] != "test":
                    vulns.append(VulnResult(type="Server-Side Template Injection", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["Server-Side Template Injection"]))
                if "advscan_proto_polluted" in t and mod[p] != "test":
                    vulns.append(VulnResult(type="Prototype Pollution", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["Prototype Pollution"]))
                response_headers = {k.lower(): v for k, v in r.headers.items()}
                if ("x-advscan-crlf" in response_headers or "x-advscan-crlf" in t) and mod[p] != "test":
                    vulns.append(VulnResult(type="CRLF Injection", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["CRLF Injection"]))
                if self._looks_like_os_output(t) and mod[p] != "test":
                    vulns.append(VulnResult(type="OS Command Injection (fuzz)", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["OS Command Injection (fuzz)"]))
                if any(s.lower() in t for s in ERROR_SIGS_LFI) and mod[p] != "test":
                    vulns.append(VulnResult(type="LFI/RFI (fuzz)", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["LFI/RFI"]))
        return vulns

    def _looks_like_os_output(self, text: str):
        strong_sigs = [
            "advscan_cmd_marker", "uid=", "gid=", "bash:", "sh:", "cmd.exe",
            "powershell", "command not found", "executed successfully",
            "system command", "execution result", "output:",
        ]
        return any(sig in text for sig in strong_sigs)

    def _context_aware_fuzz(self, url: str, data: dict[str, str], method: str, soup: BeautifulSoup):
        """Контекстно-зависимый фаззинг для XSS"""
        vulns: list[VulnResult] = []
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr in ["href", "src", "action"]:
                    payload = "javascript:window.xssFlag=1"
                elif attr.startswith("on"):
                    payload = "window.xssFlag=1"
                else:
                    continue
                test_data = data.copy()
                for k in test_data:
                    test_data[k] = payload
                r = None
                try:
                    if method == "post":
                        r = self.session.post(url, data=test_data, headers=HEADERS, timeout=8)
                    else:
                        r = self.session.get(url, params=test_data, headers=HEADERS, timeout=8)
                except Exception as e:
                    logger.error(f"Ошибка при контекстном фаззинге {url}: {e}")
                    continue
                if r and "window.xssflag" in r.text.lower():
                    vulns.append(VulnResult(type="XSS (context-aware)", url=url, method=method.upper(),
                                            payload=test_data, severity=SEVERITY_MAP["XSS"]))
        return vulns

    def _header_fuzz(self, url: str, data: dict[str, str], method: str):
        """Фаззинг HTTP-заголовков"""
        vulns: list[VulnResult] = []
        for header in ["Referer", "Cookie"]:
            for payload in HEADER_FUZZ_PAYLOADS:
                mod_headers = HEADERS.copy()
                mod_headers[header] = payload
                r = None
                try:
                    if method == "post":
                        r = self.session.post(url, data=data, headers=mod_headers, timeout=8)
                    else:
                        r = self.session.get(url, params=data, headers=mod_headers, timeout=8)
                except Exception as e:
                    logger.error(f"Ошибка при фаззинге заголовков {url}: {e}")
                    continue
                if r is None:
                    continue
                t = r.text.lower()
                if "window.xssflag" in t and payload != "test":
                    vulns.append(VulnResult(type="XSS (header fuzz)", url=url, method=method.upper(),
                                            payload={header: payload}, severity=SEVERITY_MAP["XSS"]))
                if any(s.lower() in t for s in ERROR_SIGS_SQL) and payload != "test":
                    vulns.append(VulnResult(type="SQL Injection (header fuzz)", url=url, method=method.upper(),
                                            payload={header: payload}, severity=SEVERITY_MAP["SQL Injection (fuzz)"]))
                if any(s.lower() in t for s in ERROR_SIGS_LFI) and payload != "test":
                    vulns.append(VulnResult(type="LFI/RFI (header fuzz)", url=url, method=method.upper(),
                                            payload={header: payload}, severity=SEVERITY_MAP["LFI/RFI"]))
        return vulns

    def _check_csrf_forms(self, url: str, soup: BeautifulSoup):
        """Проверка форм на уязвимости CSRF"""
        vulns: list[VulnResult] = []
        forms = soup.find_all("form")
        for f in forms:
            method = (f.get("method") or "get").lower()
            if method == "get":
                continue
            action = f.get("action") or url
            target = urljoin(url, action)
            has_token = any(
                (i.get("type") == "hidden" and re.search(r"csrf|token", i.get("name", ""), re.I))
                for i in f.find_all("input")
            )
            if not has_token:
                vulns.append(VulnResult(type="CSRF", url=url, method=method.upper(),
                                        payload={"form_action": target, "issue": "missing CSRF token"},
                                        severity=SEVERITY_MAP["CSRF"]))
        return vulns

    def _check_idor(self, pages: list[tuple[str, BeautifulSoup]]):
        """Проверка на IDOR в параметрах URL"""
        vulns: list[VulnResult] = []
        for url, _ in pages:
            qs = parse_qs(urlparse(url).query)
            for param, vals in qs.items():
                val = vals[0]
                if val.isdigit():
                    new_val = str(int(val) + 1)
                    new_qs = qs.copy()
                    new_qs[param] = [new_val]
                    new_url = url.split("?")[0] + "?" + urlencode({k: v[0] for k, v in new_qs.items()})
                    try:
                        orig = self.session.get(url, headers=HEADERS, timeout=8)
                        mutated = self.session.get(new_url, headers=HEADERS, timeout=8)
                    except Exception as e:
                        logger.error(f"Ошибка при проверке IDOR {new_url}: {e}")
                        continue
                    if orig.status_code == mutated.status_code == 200 and orig.text != mutated.text:
                        vulns.append(VulnResult(type="IDOR", url=new_url, method="GET",
                                                payload={param: new_val}, severity=SEVERITY_MAP["IDOR"]))
        return vulns

    def _update(self, msg: str, cur: int, total: int, done: bool = False):
        """Обновление прогресса сканирования"""
        self.progress_cb({"message": msg, "current": cur, "total": total or 1, "done": done})

    def _cancelled(self):
        try:
            return bool(self.cancel_cb())
        except Exception:
            return False

    def _finish_cancelled(self, cur: int, total: int):
        self._update("Сканирование остановлено", cur, total or 1, done=True)
        return self.vulns

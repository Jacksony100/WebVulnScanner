# scanner/checkers.py
# Классы для проверки различных типов уязвимостей

import time
import requests
from urllib.parse import urlencode
from .payloads import (XSS_PAYLOADS, SQLI_PAYLOADS, PATH_TRAVERSAL_PAYLOADS, OS_CMD_PAYLOADS, SSRF_PAYLOADS,
                      LFI_RFI_PAYLOADS, HPP_PAYLOADS, OPEN_REDIRECT_PAYLOADS, ERROR_SIGS_SQL, ERROR_SIGS_PATH,
                      ERROR_SIGS_OS, ERROR_SIGS_LFI, HEADERS, SEVERITY_MAP)


class BaseChecker:
    """Базовый класс для проверок уязвимостей"""

    def __init__(self, session: requests.Session):
        self.session = session

    def submit(self, url: str, data: dict[str, str], method: str):
        """Отправка HTTP-запроса с данными"""
        try:
            if method == "post":
                return self.session.post(url, data=data, headers=HEADERS, timeout=10, allow_redirects=False)
            return self.session.get(url, params=data, headers=HEADERS, timeout=10, allow_redirects=False)
        except Exception:
            return None


class XSSChecker(BaseChecker):
    """Проверка на XSS-уязвимости"""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        for payload in XSS_PAYLOADS:
            test_data = {k: payload for k in data}
            r = self.submit(url, test_data, method)
            if not r:
                continue
            if payload in r.text or "window.xssFlag" in r.text:
                vulns.append({
                    "type": "XSS",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "severity": SEVERITY_MAP["XSS"]
                })
        return vulns


class SQLIChecker(BaseChecker):
    """Проверка на SQL-инъекции"""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        lower_err = [s.lower() for s in ERROR_SIGS_SQL]
        for payload in SQLI_PAYLOADS:
            test_data = {k: payload for k in data}
            start = time.perf_counter()
            r = self.submit(url, test_data, method)
            elapsed = time.perf_counter() - start
            if not r:
                continue
            t = r.text.lower()
            if any(sig in t for sig in lower_err):
                vulns.append({
                    "type": "SQL Injection",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "severity": SEVERITY_MAP["SQL Injection"]
                })
            elif elapsed > 4:
                vulns.append({
                    "type": "SQL Injection (time-based)",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "severity": SEVERITY_MAP["SQL Injection (time-based)"]
                })
        return vulns


class PathTraversalChecker(BaseChecker):
    """Проверка на уязвимости обхода пути"""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        lower_err = [s.lower() for s in ERROR_SIGS_PATH]
        for payload in PATH_TRAVERSAL_PAYLOADS:
            test_data = {k: payload for k in data}
            r = self.submit(url, test_data, method)
            if not r:
                continue
            if any(s in r.text.lower() for s in lower_err):
                vulns.append({
                    "type": "Path Traversal",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "severity": SEVERITY_MAP["Path Traversal"]
                })
        return vulns


class OSCommandChecker(BaseChecker):
    """Проверка на уязвимости инъекции команд ОС"""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        lower_err = [s.lower() for s in ERROR_SIGS_OS]
        for payload in OS_CMD_PAYLOADS:
            test_data = {k: payload for k in data}
            r = self.submit(url, test_data, method)
            if not r:
                continue
            if any(s in r.text.lower() for s in lower_err):
                vulns.append({
                    "type": "OS Command Injection",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "severity": SEVERITY_MAP["OS Command Injection"]
                })
        return vulns


class SSRFChecker(BaseChecker):
    """Проверка на уязвимости SSRF"""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        for payload in SSRF_PAYLOADS:
            test_data = {k: payload for k in data}
            r = self.submit(url, test_data, method)
            if not r:
                continue
            if "ami-id" in r.text or "instance-id" in r.text or "169.254.169.254" in r.text:
                vulns.append({
                    "type": "SSRF",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "severity": SEVERITY_MAP["SSRF"]
                })
        return vulns


class LFIRFIChecker(BaseChecker):
    """Проверка на уязвимости LFI/RFI"""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        lower_err = [s.lower() for s in ERROR_SIGS_LFI]
        for payload in LFI_RFI_PAYLOADS:
            test_data = {k: payload for k in data}
            r = self.submit(url, test_data, method)
            if not r:
                continue
            t = r.text.lower()
            if any(s in t for s in lower_err) or "php://filter" in t:
                vulns.append({
                    "type": "LFI/RFI",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "severity": SEVERITY_MAP["LFI/RFI"]
                })
        return vulns


class HPPChecker(BaseChecker):
    """Проверка на HTTP Parameter Pollution"""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        for param in data:
            for payload in HPP_PAYLOADS:
                # Дублируем параметр с полезной нагрузкой
                test_data = data.copy()
                test_data[param] = [data[param], payload]  # Множественные значения
                try:
                    if method == "post":
                        r = self.session.post(url, data=test_data, headers=HEADERS, timeout=10, allow_redirects=False)
                    else:
                        # Для GET формируем URL с дублированными параметрами
                        query = urlencode([(k, v) for k, v in test_data.items() for v in (v if isinstance(v, list) else [v])])
                        r = self.session.get(f"{url}?{query}", headers=HEADERS, timeout=10, allow_redirects=False)
                except Exception:
                    continue
                if not r:
                    continue
                if "polluted" in r.text.lower() or r.status_code == 500:  # Простая эвристика
                    vulns.append({
                        "type": "HTTP Parameter Pollution",
                        "url": url,
                        "method": method.upper(),
                        "payload": test_data,
                        "severity": SEVERITY_MAP["HTTP Parameter Pollution"]
                    })
        return vulns


class OpenRedirectChecker(BaseChecker):
    """Проверка на уязвимости Open Redirect"""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_data = {k: payload for k in data}
            try:
                r = self.submit(url, test_data, method)
                if not r:
                    continue
                # Проверяем редирект на внешний домен
                if r.status_code in (301, 302) and r.headers.get("Location", "").startswith(payload):
                    vulns.append({
                        "type": "Open Redirect",
                        "url": url,
                        "method": method.upper(),
                        "payload": test_data,
                        "severity": SEVERITY_MAP["Open Redirect"]
                    })
            except Exception:
                continue
        return vulns
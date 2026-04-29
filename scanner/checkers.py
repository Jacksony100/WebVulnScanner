# scanner/checkers.py
# Классы для проверки различных типов уязвимостей

import html
import time
import requests
from difflib import SequenceMatcher
from urllib.parse import unquote, urlencode, urlparse
from .payloads import (XSS_PAYLOADS, SQLI_PAYLOADS, PATH_TRAVERSAL_PAYLOADS, OS_CMD_PAYLOADS, SSRF_PAYLOADS,
                      LFI_RFI_PAYLOADS, HPP_PAYLOADS, OPEN_REDIRECT_PAYLOADS, ERROR_SIGS_SQL, ERROR_SIGS_PATH,
                      ERROR_SIGS_LFI, HEADERS, SEVERITY_MAP, SQLI_BOOLEAN_PAIRS,
                      SQLI_TIME_PAYLOADS, SSTI_PAYLOADS, NOSQL_PAYLOADS, ERROR_SIGS_NOSQL,
                      CRLF_PAYLOADS, LDAP_PAYLOADS, XPATH_PAYLOADS, PROTOTYPE_POLLUTION_PAYLOADS,
                      ERROR_SIGS_LDAP, ERROR_SIGS_XPATH)


class BaseChecker:
    """Базовый класс для проверок уязвимостей"""

    def __init__(self, session: requests.Session):
        self.session = session

    def submit(self, url: str, data: dict[str, str], method: str, timeout: int = 10):
        """Отправка HTTP-запроса с данными"""
        try:
            if method == "post":
                return self.session.post(url, data=data, headers=HEADERS, timeout=timeout, allow_redirects=False)
            return self.session.get(url, params=data, headers=HEADERS, timeout=timeout, allow_redirects=False)
        except Exception:
            return None


class XSSChecker(BaseChecker):
    """Проверка на XSS-уязвимости (с фильтрацией мусора и исключением дублей)"""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        if not data:
            return vulns

        for field in data:
            for payload in XSS_PAYLOADS:
                if not payload.strip():
                    continue
                original = data.copy()
                original[field] = payload

                r = self.submit(url, original, method)
                if r is None or not r.text:
                    continue

                evidence = self._get_xss_evidence(r.text, payload)
                if evidence:
                    vulns.append({
                        "type": "XSS",
                        "url": url,
                        "method": method.upper(),
                        "payload": {field: payload},
                        "evidence": evidence,
                        "parameter": field,
                        "severity": SEVERITY_MAP["XSS"]
                    })
                    break
        return vulns


    def _get_xss_evidence(self, html_text: str, payload: str) -> str | None:
        """Возвращает evidence, если payload отражен в потенциально исполняемом виде."""
        lower_html = html_text.lower()
        lower_payload = payload.lower()
        escaped_payload = html.escape(payload).lower()

        if "xssflag" in lower_html:
            if lower_payload in lower_html and escaped_payload not in lower_html:
                return "payload reflected without HTML escaping"
            if "<script" in lower_html or "onerror=" in lower_html or "onload=" in lower_html:
                return "xss marker reflected in executable-looking context"

        if lower_payload in lower_html and escaped_payload not in lower_html:
            return "raw payload reflected"

        return None

class SQLIChecker(BaseChecker):
    """Проверка на SQL-инъекции с комбинированными полями (username + password и т.д.)"""

    def __init__(self, session: requests.Session, include_time_based: bool = False):
        super().__init__(session)
        self.include_time_based = include_time_based

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        fields = list(data.keys())
        if not fields:
            return vulns

        lower_err = [s.lower() for s in ERROR_SIGS_SQL]
        baseline_start = time.perf_counter()
        baseline = self.submit(url, data, method)
        baseline_elapsed = time.perf_counter() - baseline_start
        baseline_text = baseline.text if baseline is not None and baseline.text else ""
        baseline_status = baseline.status_code if baseline is not None else None
        def check_response(test_data, label, field=None, payload=None, timeout=10):
            start = time.perf_counter()
            r = self.submit(url, test_data, method, timeout=timeout)
            elapsed = time.perf_counter() - start
            if r is None:
                return None
            t = r.text.lower()

            if any(sig in t for sig in lower_err):
                return {
                    "type": f"SQL Injection ({label})",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "parameter": field,
                    "evidence": "database error signature in response",
                    "severity": SEVERITY_MAP["SQL Injection"]
                }
            if r.status_code >= 500 and baseline_status and baseline_status < 500:
                return {
                    "type": f"SQL Injection (server error - {label})",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "parameter": field,
                    "evidence": f"HTTP {r.status_code} after SQL probe, baseline HTTP {baseline_status}",
                    "severity": SEVERITY_MAP["SQL Injection"]
                }
            if "login successful" in t or "успешный вход" in t:
                return {
                    "type": f"SQL Injection (logic bypass - {label})",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "parameter": field,
                    "evidence": "success marker appeared after SQL probe",
                    "severity": SEVERITY_MAP["SQL Injection"]
                }
            if payload in SQLI_TIME_PAYLOADS and elapsed >= max(3.5, baseline_elapsed + 3):
                return {
                    "type": f"SQL Injection (time-based - {label})",
                    "url": url,
                    "method": method.upper(),
                    "payload": test_data,
                    "parameter": field,
                    "evidence": f"response delayed {elapsed:.2f}s, baseline {baseline_elapsed:.2f}s",
                    "severity": SEVERITY_MAP["SQL Injection (time-based)"]
                }
            return None

        fields_with_error = set()
        for f in fields:
            for payload in SQLI_PAYLOADS:
                single_data = {k: data[k] for k in fields}
                single_data[f] = payload
                result = check_response(single_data, f"single:{f}", field=f, payload=payload)
                if result:
                    vulns.append(result)
                    fields_with_error.add(f)
                    break

        for true_payload, false_payload in SQLI_BOOLEAN_PAIRS:
            for f in fields:
                if f in fields_with_error:
                    continue
                true_data = {k: data[k] for k in fields}
                false_data = {k: data[k] for k in fields}
                true_data[f] = true_payload
                false_data[f] = false_payload
                true_response = self.submit(url, true_data, method)
                false_response = self.submit(url, false_data, method)
                if true_response is None or false_response is None:
                    continue
                if self._looks_boolean_injectable(baseline_text, true_response.text, false_response.text):
                    vulns.append({
                        "type": f"SQL Injection (boolean differential - {f})",
                        "url": url,
                        "method": method.upper(),
                        "payload": {f: f"{true_payload} / {false_payload}"},
                        "parameter": f,
                        "evidence": "true/false SQL probes produced meaningfully different responses",
                        "severity": SEVERITY_MAP["SQL Injection"],
                    })

        if self.include_time_based:
            for payload in SQLI_TIME_PAYLOADS:
                for f in fields:
                    if f in fields_with_error:
                        continue
                    test_data = {k: data[k] for k in fields}
                    test_data[f] = payload
                    result = check_response(test_data, f"time:{f}", field=f, payload=payload, timeout=8)
                    if result:
                        vulns.append(result)

        return vulns

    def _looks_boolean_injectable(self, baseline_text: str, true_text: str, false_text: str) -> bool:
        if not true_text or not false_text:
            return False
        true_false_delta = abs(len(true_text) - len(false_text))
        if true_false_delta < max(80, int(max(len(true_text), len(false_text)) * 0.12)):
            return False
        true_base_ratio = SequenceMatcher(None, baseline_text[:5000], true_text[:5000]).ratio()
        false_base_ratio = SequenceMatcher(None, baseline_text[:5000], false_text[:5000]).ratio()
        true_false_ratio = SequenceMatcher(None, true_text[:5000], false_text[:5000]).ratio()
        return true_base_ratio > 0.80 and false_base_ratio < 0.96 and true_false_ratio < 0.92


class SSTIChecker(BaseChecker):
    """Проверка Server-Side Template Injection по вычисляемым арифметическим маркерам."""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        if not data:
            return vulns

        baseline = self.submit(url, data, method)
        baseline_text = baseline.text if baseline is not None and baseline.text else ""

        for field in data:
            for payload, expected in SSTI_PAYLOADS:
                test_data = data.copy()
                test_data[field] = payload
                r = self.submit(url, test_data, method)
                if r is None or not r.text:
                    continue
                if expected in r.text and expected not in baseline_text and payload not in r.text:
                    vulns.append({
                        "type": "Server-Side Template Injection",
                        "url": url,
                        "method": method.upper(),
                        "payload": {field: payload},
                        "parameter": field,
                        "evidence": f"template expression evaluated to {expected}",
                        "severity": SEVERITY_MAP["Server-Side Template Injection"],
                    })
                    break
        return vulns


class NoSQLChecker(BaseChecker):
    """Проверка NoSQL-инъекций по ошибкам парсинга и простым bypass-маркерам."""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        if not data:
            return vulns

        lower_err = [s.lower() for s in ERROR_SIGS_NOSQL]
        baseline = self.submit(url, data, method)
        baseline_text = (baseline.text or "").lower() if baseline is not None else ""
        baseline_status = baseline.status_code if baseline is not None else None

        for field in data:
            for payload in NOSQL_PAYLOADS:
                test_data = data.copy()
                test_data[field] = payload
                r = self.submit(url, test_data, method)
                if r is None:
                    continue
                text = (r.text or "").lower()
                if any(sig in text for sig in lower_err) and text != baseline_text:
                    vulns.append({
                        "type": "NoSQL Injection",
                        "url": url,
                        "method": method.upper(),
                        "payload": {field: payload},
                        "parameter": field,
                        "evidence": "NoSQL parser/error signature in response",
                        "severity": SEVERITY_MAP["NoSQL Injection"],
                    })
                    break
                if r.status_code >= 500 and baseline_status and baseline_status < 500:
                    vulns.append({
                        "type": "NoSQL Injection",
                        "url": url,
                        "method": method.upper(),
                        "payload": {field: payload},
                        "parameter": field,
                        "evidence": f"HTTP {r.status_code} after NoSQL probe, baseline HTTP {baseline_status}",
                        "severity": SEVERITY_MAP["NoSQL Injection"],
                    })
                    break
                if "login successful" in text or "успешный вход" in text:
                    vulns.append({
                        "type": "NoSQL Injection",
                        "url": url,
                        "method": method.upper(),
                        "payload": {field: payload},
                        "parameter": field,
                        "evidence": "success marker appeared after NoSQL probe",
                        "severity": SEVERITY_MAP["NoSQL Injection"],
                    })
                    break
        return vulns


class CRLFInjectionChecker(BaseChecker):
    """Проверка response splitting / CRLF injection по контрольному заголовку."""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        if not data:
            return vulns

        for field in data:
            for payload in CRLF_PAYLOADS:
                test_data = data.copy()
                test_data[field] = payload
                r = self.submit(url, test_data, method)
                if r is None:
                    continue
                headers = {k.lower(): v for k, v in r.headers.items()}
                body = (r.text or "").lower()
                if "x-advscan-crlf" in headers or "x-advscan-crlf" in body:
                    vulns.append({
                        "type": "CRLF Injection",
                        "url": url,
                        "method": method.upper(),
                        "payload": {field: payload},
                        "parameter": field,
                        "evidence": "controlled CRLF marker appeared in response headers/body",
                        "severity": SEVERITY_MAP["CRLF Injection"],
                    })
                    break
        return vulns


class LDAPInjectionChecker(BaseChecker):
    """Проверка LDAP injection по ошибкам парсера и простым bypass-маркерам."""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        if not data:
            return vulns

        lower_err = [s.lower() for s in ERROR_SIGS_LDAP]
        baseline = self.submit(url, data, method)
        baseline_status = baseline.status_code if baseline is not None else None
        baseline_text = (baseline.text or "").lower() if baseline is not None else ""

        for field in data:
            for payload in LDAP_PAYLOADS:
                test_data = data.copy()
                test_data[field] = payload
                r = self.submit(url, test_data, method)
                if r is None:
                    continue
                text = (r.text or "").lower()
                if any(sig in text for sig in lower_err) and text != baseline_text:
                    vulns.append({
                        "type": "LDAP Injection",
                        "url": url,
                        "method": method.upper(),
                        "payload": {field: payload},
                        "parameter": field,
                        "evidence": "LDAP parser/error signature in response",
                        "severity": SEVERITY_MAP["LDAP Injection"],
                    })
                    break
                if r.status_code >= 500 and baseline_status and baseline_status < 500:
                    vulns.append({
                        "type": "LDAP Injection",
                        "url": url,
                        "method": method.upper(),
                        "payload": {field: payload},
                        "parameter": field,
                        "evidence": f"HTTP {r.status_code} after LDAP probe, baseline HTTP {baseline_status}",
                        "severity": SEVERITY_MAP["LDAP Injection"],
                    })
                    break
        return vulns


class XPathInjectionChecker(BaseChecker):
    """Проверка XPath injection по XML/XPath ошибкам и bypass-маркерам."""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        if not data:
            return vulns

        lower_err = [s.lower() for s in ERROR_SIGS_XPATH]
        baseline = self.submit(url, data, method)
        baseline_status = baseline.status_code if baseline is not None else None
        baseline_text = (baseline.text or "").lower() if baseline is not None else ""

        for field in data:
            for payload in XPATH_PAYLOADS:
                test_data = data.copy()
                test_data[field] = payload
                r = self.submit(url, test_data, method)
                if r is None:
                    continue
                text = (r.text or "").lower()
                if any(sig in text for sig in lower_err) and text != baseline_text:
                    vulns.append({
                        "type": "XPath Injection",
                        "url": url,
                        "method": method.upper(),
                        "payload": {field: payload},
                        "parameter": field,
                        "evidence": "XPath/XML parser error signature in response",
                        "severity": SEVERITY_MAP["XPath Injection"],
                    })
                    break
                if r.status_code >= 500 and baseline_status and baseline_status < 500:
                    vulns.append({
                        "type": "XPath Injection",
                        "url": url,
                        "method": method.upper(),
                        "payload": {field: payload},
                        "parameter": field,
                        "evidence": f"HTTP {r.status_code} after XPath probe, baseline HTTP {baseline_status}",
                        "severity": SEVERITY_MAP["XPath Injection"],
                    })
                    break
        return vulns


class PrototypePollutionChecker(BaseChecker):
    """Проверка prototype pollution по отраженному контрольному маркеру."""

    def test(self, url: str, data: dict[str, str], method: str):
        vulns = []
        if not data:
            return vulns

        baseline = self.submit(url, data, method)
        baseline_status = baseline.status_code if baseline is not None else None

        for key, value in PROTOTYPE_POLLUTION_PAYLOADS:
            test_data = data.copy()
            test_data[key] = value
            r = self.submit(url, test_data, method)
            if r is None:
                continue
            text = (r.text or "").lower()
            if "advscan_proto_polluted" in text:
                vulns.append({
                    "type": "Prototype Pollution",
                    "url": url,
                    "method": method.upper(),
                    "payload": {key: value},
                    "parameter": key,
                    "evidence": "prototype pollution marker appeared in response",
                    "severity": SEVERITY_MAP["Prototype Pollution"],
                })
                break
            if r.status_code >= 500 and baseline_status and baseline_status < 500:
                vulns.append({
                    "type": "Prototype Pollution",
                    "url": url,
                    "method": method.upper(),
                    "payload": {key: value},
                    "parameter": key,
                    "evidence": f"HTTP {r.status_code} after prototype pollution probe, baseline HTTP {baseline_status}",
                    "severity": SEVERITY_MAP["Prototype Pollution"],
                })
                break
        return vulns


class PathTraversalChecker(BaseChecker):
     def test(self, url: str, data: dict[str, str], method: str):
         vulns = []
         lower_err = [s.lower() for s in ERROR_SIGS_PATH]
         for payload in PATH_TRAVERSAL_PAYLOADS:
             test_data = {k: payload for k in data}
             r = self.submit(url, test_data, method)
             if r is None:
                 continue
             text = r.text.lower()
             if any(sig in text for sig in lower_err) or "/etc/passwd" in text or "[drivers]" in text:
                 vulns.append({
                     "type": "Path Traversal",
                     "url": url,
                     "method": method.upper(),
                     "payload": test_data,
                     "severity": SEVERITY_MAP["Path Traversal"]
                 })
         return vulns

class OSCommandChecker(BaseChecker):
     def test(self, url: str, data: dict[str, str], method: str):
         vulns = []
         strong_sigs = [
             "bash:", "sh:", "cmd.exe", "powershell", "command not found",
             "executed successfully", "system command", "execution result", "output:",
         ]
         for payload in OS_CMD_PAYLOADS:
             test_data = {k: payload for k in data}
             r = self.submit(url, test_data, method)
             if r is None:
                 continue
             text = r.text.lower()
             if (
                 "advscan_cmd_marker" in text
                 or ("uid=" in text and "gid=" in text)
                 or any(sig in text for sig in strong_sigs)
             ):
                 vulns.append({
                     "type": "OS Command Injection",
                     "url": url,
                     "method": method.upper(),
                     "payload": test_data,
                     "severity": SEVERITY_MAP["OS Command Injection"]
                 })
         return vulns

class SSRFChecker(BaseChecker):
     def test(self, url: str, data: dict[str, str], method: str):
         vulns = []
         for payload in SSRF_PAYLOADS:
             test_data = {k: payload for k in data}
             r = self.submit(url, test_data, method)
             if r is None:
                 continue
             text = r.text.lower()
             if "169.254.169.254" in text or "ami-id" in text or "instance-id" in text or "ec2" in text:
                 vulns.append({
                     "type": "SSRF",
                     "url": url,
                     "method": method.upper(),
                     "payload": test_data,
                     "severity": SEVERITY_MAP["SSRF"]
                 })
         return vulns

class LFIRFIChecker(BaseChecker):
     def test(self, url: str, data: dict[str, str], method: str):
         vulns = []
         lower_err = [s.lower() for s in ERROR_SIGS_LFI]
         for payload in LFI_RFI_PAYLOADS:
             test_data = {k: payload for k in data}
             r = self.submit(url, test_data, method)
             if r is None:
                 continue
             text = r.text.lower()
             if any(sig in text for sig in lower_err) or "/etc/passwd" in text or "root:x:" in text or "php://filter" in text:
                 vulns.append({
                     "type": "LFI/RFI",
                     "url": url,
                     "method": method.upper(),
                     "payload": test_data,
                     "severity": SEVERITY_MAP["LFI/RFI"]
                 })
         return vulns


class HPPChecker(BaseChecker):
     def test(self, url: str, data: dict[str, str], method: str):
         vulns = []
         for param in data:
             for payload in HPP_PAYLOADS:
                 test_data = data.copy()
                 test_data[param] = [data[param], payload]
                 try:
                     if method == "post":
                         r = self.session.post(url, data=test_data, headers=HEADERS, timeout=10, allow_redirects=False)
                     else:
                         query = urlencode([(k, v) for k, v in test_data.items() for v in (v if isinstance(v, list) else [v])])
                         r = self.session.get(f"{url}?{query}", headers=HEADERS, timeout=10, allow_redirects=False)
                 except Exception:
                     continue
                 if r is None:
                     continue
                 if "polluted" in r.text.lower() or r.status_code == 500:
                     vulns.append({
                         "type": "HTTP Parameter Pollution",
                         "url": url,
                         "method": method.upper(),
                         "payload": test_data,
                         "severity": SEVERITY_MAP["HTTP Parameter Pollution"]
                     })
         return vulns

class OpenRedirectChecker(BaseChecker):
     def test(self, url: str, data: dict[str, str], method: str):
         vulns = []
         for payload in OPEN_REDIRECT_PAYLOADS:
             test_data = {k: payload for k in data}
             r = self.submit(url, test_data, method)
             if r is None:
                 continue
             loc = r.headers.get("Location", "")
             if 300 <= r.status_code < 400 and self._looks_external_redirect(loc):
                 vulns.append({
                     "type": "Open Redirect",
                     "url": url,
                     "method": method.upper(),
                     "payload": test_data,
                     "severity": SEVERITY_MAP["Open Redirect"]
                 })
         return vulns

     def _looks_external_redirect(self, location: str):
         decoded = unquote(location or "").strip().lower()
         slash_normalized = decoded.replace("\\", "/")
         collapsed_slashes = slash_normalized
         while collapsed_slashes.startswith("///"):
             collapsed_slashes = collapsed_slashes[1:]
         candidates = [decoded, slash_normalized, collapsed_slashes]
         for candidate in candidates:
             if candidate.startswith("//"):
                 candidate = "https:" + candidate
             parsed = urlparse(candidate)
             if parsed.hostname == "example.com":
                 return True
         return False

# scanner/scanner.py
# Основной оркестратор для выполнения сканирования уязвимостей

import asyncio
import requests
import re
from urllib.parse import urljoin, parse_qs, urlparse, urlencode
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from .crawler import Crawler
from .checkers import (XSSChecker, SQLIChecker, PathTraversalChecker, OSCommandChecker, SSRFChecker,
                      LFIRFIChecker, HPPChecker, OpenRedirectChecker)
from .payloads import (HEADERS, ERROR_SIGS_SQL, ERROR_SIGS_PATH, ERROR_SIGS_OS, ERROR_SIGS_LFI,
                      FUZZ_PARAMS, HEADER_FUZZ_PAYLOADS, SEVERITY_MAP)
from .utils import rand_tag, detect_cms, get_cms_version

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnResult(dict):
    """Класс для представления результата уязвимости"""
    __getattr__ = dict.__getitem__

class VulnerabilityScanner:
    """Основной класс для координации сканирования уязвимостей"""

    def __init__(self, base_url: str, progress_cb=None, threads: int = 10):
        # Базовый URL для сканирования
        self.base = base_url.rstrip('/')
        # HTTP-сессия
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        # Callback для обновления прогресса
        self.progress_cb = progress_cb or (lambda _: {})
        # Пул потоков для параллельного выполнения
        self.executor = ThreadPoolExecutor(max_workers=threads)
        # Список найденных уязвимостей
        self.vulns: list[VulnResult] = []
        # Информация о CMS
        self.cms_info = {"cms": None, "version": None}
        # Список проверок уязвимостей
        self.checkers = [
            XSSChecker(self.session),
            SQLIChecker(self.session),
            PathTraversalChecker(self.session),
            OSCommandChecker(self.session),
            SSRFChecker(self.session),
            LFIRFIChecker(self.session),
            HPPChecker(self.session),
            OpenRedirectChecker(self.session),
        ]
        logger.info(f"Инициализирован сканер для {self.base} с {threads} потоками")

    async def run(self):
        """Основной метод для запуска сканирования"""
        self._update("🔍 Краулинг цели...", 0, 1)
        logger.info("Запуск краулинга")
        crawler = Crawler(self.base)
        pages = await crawler.crawl()
        logger.info(f"Краулинг завершен, найдено {len(pages)} страниц")

        # Детекция CMS
        self._update("🔎 Определение CMS...", 1, 2)
        logger.info("Детекция CMS")
        cms = detect_cms(self.session, self.base)
        if cms:
            version = get_cms_version(self.session, self.base, cms)
            self.cms_info = {"cms": cms, "version": version}
            logger.info(f"Обнаружен CMS: {cms} (версия: {version})")
        else:
            self.cms_info = {"cms": "Не определено", "version": "N/A"}
            logger.info("CMS не определен")

        forms_total = sum(len(s.find_all("form")) for _, s in pages)
        self.total = forms_total + 10  # Дополнительные задачи
        current = 0
        logger.info(f"Найдено {forms_total} форм для проверки")

        # Проверка форм
        futures = []
        for url, soup in pages:
            for form in soup.find_all("form"):
                futures.append(self.executor.submit(self._test_form, url, form, soup))
        logger.info(f"Запущено {len(futures)} задач для проверки форм")
        for fut in as_completed(futures):
            try:
                vulns = fut.result()
                if vulns:
                    self.vulns.extend([v for v in vulns if v['payload']])  # Исключаем пустые пейлоады
                    logger.info(f"Обнаружены уязвимости: {len(vulns)}")
            except Exception as e:
                logger.error(f"Ошибка при обработке формы: {e}")
            current += 1
            self._update(f"Проанализировано форм: {current}/{forms_total}", current, self.total)

        # Проверка CSRF
        logger.info("Проверка CSRF")
        for url, soup in pages:
            csrf_vulns = self._check_csrf_forms(url, soup)
            self.vulns.extend([v for v in csrf_vulns if v['payload']])
            if csrf_vulns:
                logger.info(f"Обнаружены CSRF уязвимости: {len(csrf_vulns)}")

        # Проверка IDOR
        logger.info("Проверка IDOR")
        idor_vulns = self._check_idor(pages)
        self.vulns.extend([v for v in idor_vulns if v['payload']])
        if idor_vulns:
            logger.info(f"Обнаружены IDOR уязвимости: {len(idor_vulns)}")

        self._update("✅ Сканирование завершено", self.total, self.total, done=True)
        logger.info(f"Сканирование завершено, найдено {len(self.vulns)} уязвимостей")
        return self.vulns

    def get_cms_info(self):
        """Возвращает информацию о CMS"""
        return self.cms_info

    def _test_form(self, page_url: str, form, soup: BeautifulSoup):
        """Тестирование формы на уязвимости"""
        logger.debug(f"Проверка формы на {page_url}")
        action = form.get("action") or page_url
        method = (form.get("method") or "get").lower()
        target = urljoin(page_url, action)
        inputs = form.find_all(["input", "textarea", "select"])
        form_data = {i.get("name") or rand_tag(): "test" for i in inputs if i.get("name")}
        vulns: list[VulnResult] = []
        for chk in self.checkers:
            vulns.extend(chk.test(target, form_data, method))
        vulns.extend(self._generic_fuzz(target, form_data, method))
        vulns.extend(self._context_aware_fuzz(target, form_data, method, soup))
        vulns.extend(self._header_fuzz(target, form_data, method))
        return [v for v in vulns if v['payload']]

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
                if not r:
                    continue
                t = r.text.lower()
                if any(s.lower() in t for s in ERROR_SIGS_SQL) and mod[p] != "test":
                    vulns.append(VulnResult(type="SQL Injection (fuzz)", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["SQL Injection (fuzz)"]))
                if any(s.lower() in t for s in ERROR_SIGS_PATH) and mod[p] != "test":
                    vulns.append(VulnResult(type="Path Traversal (fuzz)", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["Path Traversal (fuzz)"]))
                if "window.xssflag" in t and mod[p] != "test":
                    vulns.append(VulnResult(type="XSS (fuzz)", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["XSS"]))
                if any(s.lower() in t for s in ERROR_SIGS_OS) and mod[p] != "test":
                    vulns.append(VulnResult(type="OS Command Injection (fuzz)", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["OS Command Injection (fuzz)"]))
                if any(s.lower() in t for s in ERROR_SIGS_LFI) and mod[p] != "test":
                    vulns.append(VulnResult(type="LFI/RFI (fuzz)", url=url, method=method.upper(),
                                            payload=mod, severity=SEVERITY_MAP["LFI/RFI"]))
        return vulns

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
                if r and "window.xssFlag" in r.text.lower() and any(test_data.values()) != "test":
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
                if not r:
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
            has_token = any(
                (i.get("type") == "hidden" and re.search(r"csrf|token", i.get("name", ""), re.I))
                for i in f.find_all("input")
            )
            if not has_token:
                vulns.append(VulnResult(type="CSRF", url=url, method=method.upper(),
                                        payload={}, severity=SEVERITY_MAP["CSRF"]))
        return [v for v in vulns if v['payload']]

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
        return [v for v in vulns if v['payload']]

    def _update(self, msg: str, cur: int, total: int, done: bool = False):
        """Обновление прогресса сканирования"""
        self.progress_cb({"message": msg, "current": cur, "total": total or 1, "done": done})
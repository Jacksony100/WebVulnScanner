# scanner/crawler.py
# Логика асинхронного краулера для обнаружения страниц на сайте

import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
import logging

from .payloads import HEADERS

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Crawler:
    """Класс для асинхронного краулинга веб-сайта и сбора страниц"""

    def __init__(self, base_url: str, max_pages: int = 100, concurrent: int = 10):
        # Базовый URL сайта
        self.base = base_url.rstrip('/')
        # Максимальное количество страниц для краулинга
        self.max_pages = max_pages
        # Ограничение на количество одновременных запросов
        self.concurrent = concurrent
        # Множество посещенных URL
        self.visited: set[str] = set()
        # Очередь URL для посещения
        self.to_visit: set[str] = {self.base}
        # Список кортежей (URL, BeautifulSoup) для обработанных страниц
        self.pages: list[tuple[str, BeautifulSoup]] = []

    async def crawl(self):
        """Основной метод для асинхронного краулинга страниц"""
        logger.info(f"Начало краулинга: {self.base}")
        connector = aiohttp.TCPConnector(limit=self.concurrent)
        async with aiohttp.ClientSession(headers=HEADERS, connector=connector) as session:
            try:
                while self.to_visit and len(self.visited) < self.max_pages:
                    batch = self._next_batch()
                    if not batch:
                        logger.info("Очередь краулера пуста после фильтрации посещенных URL")
                        break
                    
                    # Выполняем задачи параллельно
                    tasks = [self._fetch_page(session, url) for url in batch]
                    logger.info(f"Запуск {len(tasks)} параллельных запросов")
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for item in results:
                        if isinstance(item, Exception):
                            logger.warning(f"Ошибка задачи краулера: {item}")
                            continue
                        url, result = item
                        if result is None:
                            logger.warning(f"Ошибка при загрузке {url}: пустой ответ")
                            continue
                        soup = BeautifulSoup(result, "html.parser")
                        self.pages.append((url, soup))
                        
                        # Собираем новые ссылки
                        for a in soup.find_all("a", href=True):
                            link = self._normalize_link(url, a["href"])
                            if (
                                link
                                and self._same_domain(link)
                                and link not in self.visited
                                and link not in self.to_visit
                            ):
                                self.to_visit.add(link)
                                logger.debug(f"Добавлен новый URL: {link}")
            finally:
                await session.close()
                logger.info("Сессия aiohttp закрыта")
        logger.info(f"Краулинг завершен, найдено {len(self.pages)} страниц")
        return self.pages

    def _next_batch(self):
        """Достает следующий batch URL и сразу помечает их посещенными."""
        batch = []
        while self.to_visit and len(batch) < self.concurrent and len(self.visited) < self.max_pages:
            url = self.to_visit.pop()
            if url in self.visited:
                continue
            self.visited.add(url)
            batch.append(url)
        return batch

    async def _fetch_page(self, session: aiohttp.ClientSession, url: str):
        """Асинхронная загрузка страницы"""
        try:
            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    logger.warning(f"Статус {response.status} для {url}")
                    return url, None
                text = await response.text()
                logger.debug(f"Успешно загружен {url}, размер: {len(text)}")
                return url, text
        except Exception as e:
            logger.error(f"Ошибка при запросе {url}: {e}")
            return url, None

    def _same_domain(self, url: str):
        """Проверяет, принадлежит ли URL тому же домену"""
        return urlparse(url).netloc == urlparse(self.base).netloc

    def _normalize_link(self, current_url: str, href: str):
        """Нормализует ссылку и отбрасывает не-HTTP переходы."""
        href = (href or "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            return None

        parsed = urlparse(urljoin(current_url, href))
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None

        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/")

        return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))

# scanner/crawler.py
# Логика асинхронного краулера для обнаружения страниц на сайте

import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse
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
                    # Ограничиваем количество одновременных задач
                    tasks = []
                    for url in list(self.to_visit)[:self.concurrent]:
                        if url not in self.visited:
                            tasks.append(self._fetch_page(session, url))
                    self.to_visit.difference_update([url for url in self.to_visit if url in self.visited])
                    
                    # Выполняем задачи параллельно
                    logger.info(f"Запуск {len(tasks)} параллельных запросов")
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for url, result in results:
                        if isinstance(result, Exception) or result is None:
                            logger.warning(f"Ошибка при загрузке {url}: {result}")
                            continue
                        self.visited.add(url)
                        soup = BeautifulSoup(result, "html.parser")
                        self.pages.append((url, soup))
                        
                        # Собираем новые ссылки
                        for a in soup.find_all("a", href=True):
                            link = urljoin(url, a["href"])
                            if self._same_domain(link) and link not in self.visited and link not in self.to_visit:
                                self.to_visit.add(link)
                                logger.debug(f"Добавлен новый URL: {link}")
            finally:
                await session.close()
                logger.info("Сессия aiohttp закрыта")
        logger.info(f"Краулинг завершен, найдено {len(self.pages)} страниц")
        return self.pages

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
# scanner/report.py
# Генерация HTML-отчета по результатам сканирования

import os
import datetime
import logging
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = PROJECT_ROOT / "templates"


def get_report_path() -> Path:
    """Возвращает стандартный путь HTML-отчета."""
    if os.environ.get('DOCKER'):
        return Path('/app/reports/report.html')
    return PROJECT_ROOT / 'reports' / 'report.html'


def generate_html_report(vulns, target_url, cms_info, scan_info=None):
    logger.debug("Начало генерации HTML-отчета")
    logger.debug(f"Входящие данные: vulns={vulns}, target_url={target_url}, cms_info={cms_info}")
    
    # Настройка Jinja2 для генерации HTML
    try:
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
        template = env.get_template('report.html')
        logger.debug("Шаблон report.html успешно загружен")
    except Exception as e:
        logger.error(f"Ошибка при загрузке шаблона: {str(e)}", exc_info=True)
        raise

    # Подготовка данных для отчета
    severity_counts = {}
    for v in vulns:
        severity = v.get('severity', 'Unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    logger.debug(f"Подсчитаны уровни серьезности: {severity_counts}")

    # Генерация HTML-файла
    try:
        html_content = template.render(
            target_url=target_url,
            cms_info=cms_info,
            scan_info=scan_info or {},
            vulns=vulns,
            severity_counts=severity_counts,
            now=datetime.datetime.now()
        )
        logger.debug("HTML-контент успешно сгенерирован")
    except Exception as e:
        logger.error(f"Ошибка при генерации HTML-контента: {str(e)}", exc_info=True)
        raise

    # Сохранение отчета
    report_path = get_report_path()
    logger.debug(f"Сохранение отчета в: {report_path}")
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Создана директория: {report_path.parent}")

        with report_path.open('w', encoding='utf-8') as f:
            f.write(html_content)
        logger.info(f"Отчет успешно сохранен в {report_path}")
        return str(report_path)
    except Exception as e:
        logger.error(f"Ошибка при сохранении отчета: {str(e)}", exc_info=True)
        raise

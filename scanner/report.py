# scanner/report.py
# Генерация HTML-отчета по результатам сканирования

import os
import datetime
import logging
from jinja2 import Environment, FileSystemLoader

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def generate_html_report(vulns, target_url, cms_info):
    logger.debug("Начало генерации HTML-отчета")
    logger.debug(f"Входящие данные: vulns={vulns}, target_url={target_url}, cms_info={cms_info}")
    
    # Настройка Jinja2 для генерации HTML
    try:
        env = Environment(loader=FileSystemLoader('templates'))
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
            vulns=vulns,
            severity_counts=severity_counts,
            now=datetime.datetime.now()
        )
        logger.debug("HTML-контент успешно сгенерирован")
    except Exception as e:
        logger.error(f"Ошибка при генерации HTML-контента: {str(e)}", exc_info=True)
        raise

    # Сохранение отчета
    report_path = 'report.html' if not os.environ.get('DOCKER') else '/app/reports/report.html'
    logger.debug(f"Сохранение отчета в: {report_path}")
    try:
        # Создаем директорию только если путь содержит поддиректории
        report_dir = os.path.dirname(report_path)
        if report_dir:  # Проверяем, что report_dir не пустой
            os.makedirs(report_dir, exist_ok=True)
            logger.debug(f"Создана директория: {report_dir}")
        else:
            logger.debug("Директория не требуется, сохранение в текущую директорию")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logger.info(f"Отчет успешно сохранен в {report_path}")
    except Exception as e:
        logger.error(f"Ошибка при сохранении отчета: {str(e)}", exc_info=True)
        raise
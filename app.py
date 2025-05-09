# app.py
# Главная точка входа для Flask-приложения и CLI-интерфейса

import argparse
import threading
import webbrowser
import asyncio
import json
import signal
import sys
import logging
import time
import os
from flask import Flask, request, jsonify, send_file

from scanner.scanner import VulnerabilityScanner
from scanner.report import generate_html_report

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")

# Глобальное состояние для отслеживания прогресса сканирования
scan_state = {
    "running": False,
    "progress": {"message": "Ожидание", "current": 0, "total": 1, "done": False},
    "results": [],
    "cms_info": {"cms": "Не определено", "version": "N/A"}
}

# Глобальная переменная для хранения потока сканирования
scan_thread = None

# Маршрут для главной страницы
@app.route('/')
def index():
    """Отображает главную страницу интерфейса"""
    from flask import render_template
    return render_template('index.html', version="5.1")

# Маршрут для запуска сканирования
@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Запускает сканирование указанного URL в отдельном потоке"""
    global scan_thread
    logger.info("Получен запрос на /start_scan")
    data = request.get_json(force=True)
    url = data.get('url')
    threads = data.get('threads', 10)  # Значение по умолчанию 10
    logger.info(f"Полученные данные: url={url}, threads={threads}")
    if not url:
        logger.error("Отсутствует URL в запросе")
        return jsonify({'error': 'Требуется URL'}), 400
    if not isinstance(threads, int) or threads < 1 or threads > 50:
        logger.error("Недопустимое количество потоков")
        return jsonify({'error': 'Количество потоков должно быть от 1 до 50'}), 400
    if scan_state['running']:
        logger.warning("Сканирование уже выполняется")
        return jsonify({'error': 'Сканирование уже выполняется'}), 409
    scan_state.update({
        'running': True,
        'progress': {'message': 'Запуск', 'current': 0, 'total': 1, 'done': False},
        'results': [],
        'cms_info': {"cms": "Не определено", "version": "N/A"}
    })

    def progress_cb(p):
        scan_state['progress'] = p
        logger.info(f"Обновлен прогресс: {p}")

    async def worker():
        try:
            start_time = time.time()
            logger.info(f"Запуск сканирования для URL: {url} с {threads} потоками")
            scanner = VulnerabilityScanner(url, progress_cb=progress_cb, threads=threads)
            res = await scanner.run()
            logger.info(f"Сканирование завершено, результаты: {len(res)} уязвимостей найдено")
            if not res:
                logger.warning("Список уязвимостей пуст")
            scan_state['results'] = [dict(r) for r in res]
            logger.info(f"Обновлено состояние результатов: {scan_state['results']}")
            scan_state['cms_info'] = scanner.get_cms_info()
            logger.info(f"CMS информация: {scan_state['cms_info']}")
            generate_html_report(res, url, scan_state['cms_info'])
            logger.info("Отчет успешно сгенерирован в /app/reports/report.html" if os.path.exists('/app/reports/report.html') else "Отчет НЕ сгенерирован")
        except Exception as e:
            logger.error(f"Ошибка в worker: {str(e)} с трассировкой: {str(e.__traceback__)}")
            scan_state['progress'] = {"message": f"Ошибка: {str(e)}", "current": 0, "total": 1, "done": True}
        finally:
            scan_state['running'] = False
            logger.info("Сканирование завершено или прервано")

    def run_async():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(worker())
        finally:
            loop.close()
            logger.info("Цикл событий закрыт")

    scan_thread = threading.Thread(target=run_async, daemon=True)
    scan_thread.start()
    logger.info("Поток сканирования запущен")
    return jsonify({'status': 'started'})

# Маршрут для получения прогресса сканирования
@app.route('/progress')
def progress():
    """Возвращает текущий прогресс сканирования"""
    progress_data = scan_state.get('progress', {"message": "Неизвестное состояние", "current": 0, "total": 1, "done": False})
    logger.info(f"Запрос /progress, возвращается: {progress_data}")
    return jsonify({'progress': progress_data})

# Маршрут для получения результатов сканирования
@app.route('/results')
def results():
    """Возвращает результаты сканирования"""
    logger.info(f"Запрос /results, возвращается: {scan_state['results']}")
    return jsonify({'results': scan_state['results'], 'cms_info': scan_state['cms_info']})

# Маршрут для скачивания HTML-отчета
@app.route('/download_html')
def dl_html():
    """Отправляет HTML-отчет для скачивания"""
    report_path = '/reports/report.html' if os.path.exists('/reports/report.html') else 'report.html'
    if not os.path.exists(report_path):
        logger.error(f"Отчет не найден по пути: {report_path}")
        return jsonify({'error': 'Отчет не найден. Сначала выполните сканирование.'}), 404
    logger.info(f"Отчет найден, отправка: {report_path}")
    return send_file(report_path, as_attachment=True)

# Обработчик сигнала для корректного завершения
def signal_handler(sig, frame):
    logger.info("Получен сигнал завершения (Ctrl+C)")
    global scan_thread
    if scan_state['running']:
        logger.info("Остановка сканирования...")
        scan_state['running'] = False
        if scan_thread:
            logger.info("Ожидание завершения потока сканирования")
    sys.exit(0)

# Точка входа для CLI
if __name__ == '__main__':
    # Регистрация обработчика сигнала
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='Сканер уязвимостей веб-приложений v5.1')
    parser.add_argument('target', nargs='?', help='URL для сканирования')
    parser.add_argument('--threads', type=int, default=10, help='Количество потоков (1-50, по умолчанию 10)')
    parser.add_argument('--no-browser', action='store_true', help='Не открывать браузер')
    args = parser.parse_args()

    if args.target:
        if args.threads < 1 or args.threads > 50:
            print("Ошибка: Количество потоков должно быть от 1 до 50")
            exit(1)
        async def run_scan():
            def cb(p):
                print(f"{p['message']} ({p['current']}/{p['total']})", end='\r')
            scanner = VulnerabilityScanner(args.target, progress_cb=cb, threads=args.threads)
            vulns = await scanner.run()
            print('\nСканирование завершено')
            cms_info = scanner.get_cms_info()
            print(f"Обнаруженная CMS: {cms_info['cms']} (версия: {cms_info['version']})")
            generate_html_report(vulns, args.target, cms_info)
            print(f'HTML-отчет: {"report.html" if os.path.exists("report.html") else "не создан"}')

        loop = asyncio.get_event_loop()
        loop.run_until_complete(run_scan())
    else:
        if not args.no_browser:
            threading.Timer(1, lambda: webbrowser.open('http://127.0.0.1:5000')).start()
        app.run(host='0.0.0.0', port=5000, debug=False)
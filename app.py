# app.py
# Главная точка входа для Flask-приложения и CLI-интерфейса

import argparse
import threading
import webbrowser
import asyncio
import signal
import sys
import logging
import os
import secrets
from flask import Flask, request, jsonify, send_file

from scanner.scanner import VulnerabilityScanner
from scanner.report import generate_html_report, get_report_path
from scanner.utils import normalize_target_url
from scanner.external_engines import detect_external_engines

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")
UI_TOKEN = os.environ.get("ADVSCAN_UI_TOKEN") or secrets.token_urlsafe(16)
state_lock = threading.Lock()

# Глобальное состояние для отслеживания прогресса сканирования
scan_state = {
    "running": False,
    "cancel_requested": False,
    "progress": {"message": "Ожидание", "current": 0, "total": 1, "done": False},
    "results": [],
    "cms_info": {"cms": "Не определено", "version": "N/A"},
    "scan_info": {},
    "report_path": None,
}

# Глобальная переменная для хранения потока сканирования
scan_thread = None


def _valid_ui_token():
    return request.headers.get("X-Advscan-Token") == UI_TOKEN


def _state_value(key, default=None):
    with state_lock:
        return scan_state.get(key, default)


# Маршрут для главной страницы
@app.route('/')
def index():
    """Отображает главную страницу интерфейса"""
    from flask import render_template
    return render_template('index.html', version="6.0", ui_token=UI_TOKEN)


@app.route('/engines')
def engines():
    """Возвращает статус внешних движков, чтобы UI был понятен новичку."""
    return jsonify({'engines': detect_external_engines()})

# Маршрут для запуска сканирования
@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Запускает сканирование указанного URL в отдельном потоке"""
    global scan_thread
    logger.info("Получен запрос на /start_scan")
    data = request.get_json(force=True)
    url = data.get('url')
    threads = data.get('threads', 10)  # Значение по умолчанию 10
    scan_mode = data.get('mode', 'safe')
    authorized = bool(data.get('authorized', False))
    allow_private_ips = bool(data.get('allowPrivate', False))
    max_requests_total = _optional_int(data.get('maxRequests'))
    max_duration_seconds = _optional_int(data.get('maxDuration'))
    max_active_requests = _optional_int(data.get('maxActiveRequests'))
    logger.info(f"Полученные данные: url={url}, threads={threads}, mode={scan_mode}")
    if not _valid_ui_token():
        return jsonify({'error': 'Недействительный UI token. Обновите страницу.'}), 403
    if not url:
        logger.error("Отсутствует URL в запросе")
        return jsonify({'error': 'Требуется URL'}), 400
    try:
        url = normalize_target_url(url)
    except ValueError as e:
        logger.error(f"Недопустимый URL: {e}")
        return jsonify({'error': str(e)}), 400
    if scan_mode not in {"safe", "active", "deep"}:
        logger.error("Недопустимый режим сканирования")
        return jsonify({'error': 'Режим должен быть safe, active или deep'}), 400
    if scan_mode in {"active", "deep"} and not authorized:
        logger.error("Активный режим запрошен без подтверждения разрешения")
        return jsonify({'error': 'Для активного режима подтвердите, что у вас есть разрешение на проверку цели'}), 400
    if not isinstance(threads, int) or threads < 1 or threads > 50:
        logger.error("Недопустимое количество потоков")
        return jsonify({'error': 'Количество потоков должно быть от 1 до 50'}), 400
    with state_lock:
        if scan_state['running']:
            logger.warning("Сканирование уже выполняется")
            return jsonify({'error': 'Сканирование уже выполняется'}), 409
        scan_state.update({
            'running': True,
            'cancel_requested': False,
            'progress': {'message': 'Запуск', 'current': 0, 'total': 1, 'done': False},
            'results': [],
            'cms_info': {"cms": "Не определено", "version": "N/A"},
            'scan_info': {},
            'report_path': None,
        })

    def progress_cb(p):
        with state_lock:
            scan_state['progress'] = p
        logger.info(f"Обновлен прогресс: {p}")

    async def worker():
        try:
            logger.info(f"Запуск сканирования для URL: {url} с {threads} потоками")
            scanner = VulnerabilityScanner(
                url,
                progress_cb=progress_cb,
                threads=threads,
                scan_mode=scan_mode,
                cancel_cb=lambda: _state_value('cancel_requested', False),
                allow_private_ips=allow_private_ips,
                max_requests_total=max_requests_total,
                max_duration_seconds=max_duration_seconds,
                max_active_requests=max_active_requests,
            )
            res = await scanner.run()
            logger.info(f"Сканирование завершено, результаты: {len(res)} уязвимостей найдено")
            if not res:
                logger.warning("Список уязвимостей пуст")
            with state_lock:
                scan_state['results'] = [dict(r) for r in res]
            logger.info(f"Обновлено состояние результатов: {scan_state['results']}")
            with state_lock:
                scan_state['cms_info'] = scanner.get_cms_info()
            logger.info(f"CMS информация: {scan_state['cms_info']}")
            with state_lock:
                scan_state['scan_info'] = scanner.get_scan_info()
                cms_info = dict(scan_state['cms_info'])
                scan_info = dict(scan_state['scan_info'])
            report_path = generate_html_report(res, url, cms_info, scan_info)
            with state_lock:
                scan_state['report_path'] = report_path
            logger.info(f"Отчет успешно сгенерирован: {report_path}")
        except Exception as e:
            logger.error(f"Ошибка в worker: {str(e)} с трассировкой: {str(e.__traceback__)}")
            with state_lock:
                scan_state['progress'] = {"message": f"Ошибка: {str(e)}", "current": 0, "total": 1, "done": True}
        finally:
            with state_lock:
                if scan_state.get('cancel_requested') and not scan_state.get('progress', {}).get('done'):
                    progress = scan_state.get('progress', {})
                    scan_state['progress'] = {
                        "message": "Сканирование остановлено",
                        "current": progress.get("current", 0),
                        "total": progress.get("total", 1),
                        "done": True,
                    }
                scan_state['running'] = False
                scan_state['cancel_requested'] = False
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


@app.route('/cancel_scan', methods=['POST'])
def cancel_scan():
    """Запрашивает мягкую остановку текущего сканирования."""
    if not _valid_ui_token():
        return jsonify({'error': 'Недействительный UI token. Обновите страницу.'}), 403
    with state_lock:
        if not scan_state['running']:
            return jsonify({'status': 'idle'})
        progress_data = scan_state.get('progress', {"current": 0, "total": 1})
        scan_state['cancel_requested'] = True
        scan_state['progress'] = {
            "message": "Останавливаю сканирование...",
            "current": progress_data.get("current", 0),
            "total": progress_data.get("total", 1),
            "done": False,
        }
    logger.info("Запрошена остановка сканирования")
    return jsonify({'status': 'cancelling'})

# Маршрут для получения прогресса сканирования
@app.route('/progress')
def progress():
    """Возвращает текущий прогресс сканирования"""
    with state_lock:
        progress_data = dict(scan_state.get('progress', {"message": "Неизвестное состояние", "current": 0, "total": 1, "done": False}))
    logger.info(f"Запрос /progress, возвращается: {progress_data}")
    return jsonify({'progress': progress_data})

# Маршрут для получения результатов сканирования
@app.route('/results')
def results():
    """Возвращает результаты сканирования"""
    logger.info(f"Запрос /results, возвращается: {scan_state['results']}")
    with state_lock:
        payload = {
            'results': list(scan_state['results']),
            'cms_info': dict(scan_state['cms_info']),
            'scan_info': dict(scan_state['scan_info']),
        }
    return jsonify(payload)

# Маршрут для скачивания HTML-отчета
@app.route('/download_html')
def dl_html():
    """Отправляет HTML-отчет для скачивания"""
    report_path = _state_value('report_path') or str(get_report_path())
    if not os.path.exists(report_path) and os.path.exists('report.html'):
        report_path = 'report.html'
    if not os.path.exists(report_path):
        logger.error(f"Отчет не найден по пути: {report_path}")
        return jsonify({'error': 'Отчет не найден. Сначала выполните сканирование.'}), 404
    logger.info(f"Отчет найден, отправка: {report_path}")
    return send_file(report_path, as_attachment=True)

# Обработчик сигнала для корректного завершения
def signal_handler(sig, frame):
    logger.info("Получен сигнал завершения (Ctrl+C)")
    global scan_thread
    if _state_value('running'):
        logger.info("Остановка сканирования...")
        scan_state['running'] = False
        if scan_thread:
            logger.info("Ожидание завершения потока сканирования")
    sys.exit(0)


def _optional_int(value):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

# Точка входа для CLI
if __name__ == '__main__':
    # Регистрация обработчика сигнала
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='Сканер уязвимостей веб-приложений v6.0')
    parser.add_argument('target', nargs='?', help='URL для сканирования')
    parser.add_argument('--threads', type=int, default=10, help='Количество потоков (1-50, по умолчанию 10)')
    parser.add_argument('--mode', choices=['safe', 'active', 'deep'], default='safe', help='Режим сканирования')
    parser.add_argument('--max-requests', type=int, help='Общий лимит HTTP-запросов')
    parser.add_argument('--max-duration', type=int, help='Общий лимит времени в секундах')
    parser.add_argument('--max-active-requests', type=int, help='Лимит активных запросов')
    parser.add_argument('--authorized', action='store_true', help='Подтверждение разрешения для active/deep')
    parser.add_argument('--allow-private-ips', action='store_true', help='Разрешить localhost/private IP только для CTF/lab/self-hosted целей')
    parser.add_argument('--no-browser', action='store_true', help='Не открывать браузер')
    parser.add_argument('--host', default='127.0.0.1', help='Host для Web UI, по умолчанию 127.0.0.1')
    args = parser.parse_args()

    if args.target:
        try:
            args.target = normalize_target_url(args.target)
        except ValueError as e:
            print(f"Ошибка: {e}")
            exit(1)
        if args.threads < 1 or args.threads > 50:
            print("Ошибка: Количество потоков должно быть от 1 до 50")
            exit(1)
        if args.mode in {"active", "deep"} and not args.authorized:
            print("Ошибка: Для active/deep укажите --authorized, если у вас есть разрешение на проверку цели")
            exit(1)
        async def run_scan():
            def cb(p):
                print(f"{p['message']} ({p['current']}/{p['total']})", end='\r')
            scanner = VulnerabilityScanner(
                args.target,
                progress_cb=cb,
                threads=args.threads,
                scan_mode=args.mode,
                allow_private_ips=args.allow_private_ips,
                max_requests_total=args.max_requests,
                max_duration_seconds=args.max_duration,
                max_active_requests=args.max_active_requests,
            )
            vulns = await scanner.run()
            print('\nСканирование завершено')
            cms_info = scanner.get_cms_info()
            print(f"Обнаруженная CMS: {cms_info['cms']} (версия: {cms_info['version']})")
            report_path = generate_html_report(vulns, args.target, cms_info, scanner.get_scan_info())
            print(f'HTML-отчет: {report_path if os.path.exists(report_path) else "не создан"}')

        loop = asyncio.get_event_loop()
        loop.run_until_complete(run_scan())
    else:
        if not args.no_browser:
            threading.Timer(1, lambda: webbrowser.open('http://127.0.0.1:5005')).start()
        logger.info("UI token: %s", UI_TOKEN)
        app.run(host=args.host, port=5005, debug=False)

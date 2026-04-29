# AdvancedScanner v6.0

<div align="center">

**Локальный защитный сканер веб-уязвимостей для CTF, лабораторий и разрешенного bug bounty**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](#)
[![Mode](https://img.shields.io/badge/default-safe%2Fpassive-10B981?style=flat-square)](#режимы-сканирования)
[![Scope](https://img.shields.io/badge/scope-enforced-2563EB?style=flat-square)](#безопасность)
[![Tests](https://img.shields.io/badge/tests-59%20passed-22C55E?style=flat-square)](#тесты)

</div>

AdvancedScanner помогает быстро понять поверхность атаки веб-приложения и найти подтвержденные security-сигналы без шума от неподтвержденных common paths. Сканер работает локально, уважает scope, бюджеты запросов, rate limit и по умолчанию остается в safe/passive режиме.

Подходит для:

- CTF и HackTheBox-like лабораторий;
- PortSwigger Web Security Academy и self-hosted targets;
- bug bounty scopes, где тестирование явно разрешено;
- локальной инвентаризации attack surface перед ручной проверкой.

> Используйте только на целях, где у вас есть разрешение. Private/internal IP, localhost и metadata ranges заблокированы по умолчанию, кроме явного lab/private режима.

## Скриншоты

### Веб-интерфейс

<img src="screenshots/ui.png" alt="AdvancedScanner Web UI" width="100%">

### HTML-отчет

<img src="screenshots/report.png" alt="AdvancedScanner HTML report" width="100%">

## Что умеет

- Разделяет **Findings**, **Assets** и **Discovery candidates**.
- Не превращает `/graphql`, `/api/graphql`, `/v1/graphql` из common list в фейковые findings.
- Валидирует GraphQL, OpenAPI, source maps и exposure paths перед повышением уверенности.
- Строит `SiteProfile`: HTTP status, final URL, Server, X-Powered-By, title, content-type, IP, response time и lightweight tech hints.
- Показывает diagnostics: request counters, phase timings, skip reasons, slow requests, warnings.
- Не запускает активные проверки на неподходящих шаблонах: статике, URL без параметров, неподтвержденных candidates.
- Держит safe scan быстрым и предсказуемым: лимиты по времени, запросам, discovery и active phases.

## Быстрый старт

```bash
git clone https://github.com/Jacksony100/WebVulnScanner.git
cd WebVulnScanner

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt

python3 app.py
```

UI поднимается на `127.0.0.1:5005` и печатает startup token для защищенных POST-действий.

Откройте:

```text
http://127.0.0.1:5005
```

Для локальных labs включайте checkbox `Lab/private`. Без него scanner намеренно блокирует localhost/private ranges.

## Командная строка

Safe scan внешней разрешенной цели:

```bash
python3 app.py https://example.com --mode safe
```

Active scan только при явном разрешении:

```bash
python3 app.py https://example.com --mode active --authorized
```

Локальная лаборатория:

```bash
python3 app.py http://127.0.0.1:8080 \
  --mode active \
  --authorized \
  --allow-private-ips \
  --max-requests 120 \
  --max-duration 120
```

HTML-отчет сохраняется в:

```text
reports/report.html
```

## Режимы сканирования

| Режим | Назначение | Дефолтные лимиты | Активные payloads |
| --- | --- | --- | --- |
| `safe` | Быстрый пассивный обзор, headers, cookies, forms, JS hints, OpenAPI/GraphQL candidates | `45s`, `40` requests, `25` discovery requests | Нет |
| `active` | Разрешенные низкорисковые проверки input points | `180s`, `250` requests, `150` active requests | Да, строго bounded |
| `deep` | Более широкое discovery и optional external engines | `600s`, configurable request budget | Да, bounded |

Приоритет scheduler:

1. URL с query params.
2. Forms.
3. JSON API templates.
4. OpenAPI templates.
5. Validated GraphQL.
6. Interesting `401/403/5xx`.
7. Common candidates в последнюю очередь.

## Безопасность

AdvancedScanner спроектирован как защитный инструмент для разрешенного тестирования.

- Режим по умолчанию: `safe`.
- Active/deep требуют явного выбора режима и authorization-флага.
- Scope enforced на уровне HTTP-клиента.
- Private/internal IP blocked by default.
- Нет WAF bypass, auth bypass, brute force, password spraying, persistence, shells, destructive requests или exfiltration.
- GraphQL introspection проверяется только безопасным query и с жестким лимитом запросов.
- Evidence редактируется и не хранит sensitive headers/cookies.

## Находки, активы и кандидаты

Scanner v6.0 больше не смешивает discovery-события и security findings.

| Тип | Что означает | Пример |
| --- | --- | --- |
| `Finding` | Security-relevant issue с evidence, confidence и remediation | `GraphQL introspection enabled` |
| `Asset` | Подтвержденная часть attack surface | validated GraphQL endpoint, OpenAPI document, source map |
| `DiscoveryCandidate` | Неподтвержденный кандидат, который может быть полезен дальше | `/graphql` из common path list |

Правило простое: common path сначала candidate, после безопасной валидации asset, и только при security evidence finding.

## Архитектура

```text
scanner/
  models.py          # ScanConfig, ScanState, Finding, Asset, DiscoveryCandidate
  scope.py           # scope checks, private IP blocking, URL normalization
  http_client.py     # request gateway, budgets, rate limit, diagnostics
  registry.py        # dedupe, templates, findings/assets/candidates
  discovery/         # HTML, forms, JS, OpenAPI, GraphQL, well-known paths
  checks/            # modular passive/active checks with supports(template)
  scheduler.py       # phase budgets, prioritization, skip reasons
  scanner.py         # orchestration
```

Основной flow:

```text
InitialProbe -> SiteProfile
Discovery    -> Candidates + RequestTemplates + Assets
Scheduler    -> Passive checks -> Active checks when allowed
Report       -> Findings + Assets + Candidates + Diagnostics
```

## Проверки

- Security headers и cookie posture.
- OpenAPI/Swagger inventory с validation.
- Source map validation по JSON-ключам `version`, `sources`, `mappings`.
- JWT passive detection без cracking.
- Reflected input и XSS context hints.
- SQLi parser-error / boolean / time probes с safe budgets.
- SSTI arithmetic-only probes.
- Open redirect с корректным parsing `Location`.
- CRLF marker detection в active/deep.
- Exposure rules по signatures, не по одному `200 OK`.
- CORS reflection/wildcard checks.
- GraphQL validation, introspection и verbose error leakage.
- Potential object reference без ложного High без второго auth context.

## Внешние движки

Optional engines усиливают active/deep режимы, но не обязательны:

- Nuclei
- Katana
- ffuf
- SSLyze
- Retire.js
- Semgrep
- Gitleaks
- OSV-Scanner
- Schemathesis
- OWASP ZAP

Установка:

```bash
./scripts/install_engines.sh
```

Если инструмент отсутствует, scanner добавляет warning/status entry и продолжает работу без падения.

## Тесты

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q
PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q app.py scanner tests
python3 -m pip check
```

Текущий regression pack покрывает:

- GraphQL common candidates не становятся findings без валидации.
- Valid GraphQL endpoint становится asset.
- Introspection становится finding только после подтверждения.
- SiteProfile заполняет HTTP, Server, Powered-By, response time.
- Safe scan быстро выходит на статической странице без input points.
- Active checks пропускают unsupported templates с skip reason.
- Request budget enforced.
- Source map validation не ловит произвольный JSON.
- Open redirect parsing не принимает `https://example.com@example.test` за redirect на `example.com`.

## Ограничения

- Authenticated multi-user authorization testing пока не автоматизирован; IDOR остается `Potential` без второго auth context.
- Playwright capture оставлен как safe hook до явного browser-capture workflow.
- Scanner не обходит CAPTCHA, login protections, WAF и rate limits.
- Findings являются evidence-based сигналами для дальнейшей ручной валидации.

## Автор

Проект Jacksony: `t.me/Smesharik_lair`

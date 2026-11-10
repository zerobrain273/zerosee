# Локальная лаборатория zerosee

Зависимости: Python 3, OpenSSL CLI, собранный zerosee. Сторонние Python-пакеты не нужны.
Все серверы слушают только loopback. CA не устанавливается в систему.

## Автоматическая демонстрация

Из корня репозитория:

```bash
python3 lab/demo.py
```

Серверы используют свободные порты, а отчёты появляются в `reports/demo/`.
Повторный запуск: `python3 lab/demo.py --output reports/demo-2`.
Существующие отчёты сохраняются. Ключи временные и удаляются при завершении.

## Ручной стенд

В первом терминале:

```bash
python3 lab/server.py
```

Поднимаются HTTP :8000 и HTTPS :8443. Лабораторная CA и ключи генерируются в
`lab/.certs/`, который исключён из Git. Сертификат выписан **на localhost**, не на
IP, действует семь дней. После истечения срока создайте новый стенд с новой папкой:
`python3 lab/server.py --cert-dir /tmp/zerosee-new-certs`.

В другом терминале:

```bash
zerosee web http://127.0.0.1:8000/redirect
zerosee web https://localhost:8443/strong --connect-ip 127.0.0.1 --ca-file lab/.certs/ca.pem
```

Первый сценарий покажет цепочку 302 → 200 и cookies без защитных флагов.
Второй — TLS `verified` и отсутствие review-наблюдений для настроенных правил;
Server: Python остаётся информационной подсказкой.

Проверка отказов TLS:

```bash
# Неизвестная системе лабораторная CA: verification_failed.
zerosee web https://localhost:8443/strong --connect-ip 127.0.0.1
# CA известна, но имя IP не входит в SAN: verification_failed.
zerosee web https://127.0.0.1:8443/strong --ca-file lab/.certs/ca.pem
```

Проверка разрешённого перехода HTTP → HTTPS:

```bash
zerosee web http://localhost:8000/upgrade --connect-ip 127.0.0.1 \
  --allow-origin https://localhost:8443 --ca-file lab/.certs/ca.pem
```

## Маршруты

| Путь | Сценарий |
|---|---|
| `/weak` | HTML, отсутствующие защитные заголовки, слабые атрибуты cookies |
| `/strong` | CSP/frame-ancestors, HSTS, nosniff, защищённая cookie |
| `/redirect` | Относительный редирект на /weak |
| `/cross` | Из 127.0.0.1 на localhost: другой origin, по умолчанию блокируется |
| `/upgrade` | Переход на HTTPS-порт лаборатории, требует allow-origin |
| `/downgrade` | HTTPS → HTTP, блокируется даже при allow-origin |
| `/loop` | Цикл перенаправления |
| `/duplicate-location` | Два Location, неоднозначный ответ |
| `/cookie-redirect` | Cookie + редирект на /echo; cookie не должна отправляться обратно |
| `/echo` | JSON, показывающий наличие Cookie в запросе |
| `/json` | Ответ не-HTML: HTML-правила к нему не применяются |
| `/large` | Тело больше лимита, body_truncated=true |
| `/huge-header` | Превышение лимита заголовков |
| `/slow` | Задержка 500 мс для проверки таймаута |
| `/interim` | 103 Early Hints перед окончательным 200 |

Ctrl+C останавливает ручной стенд. Не используйте лабораторные ключи вне стенда.

## Полная проверка

```bash
ZEROSEE_REQUIRE_NETWORK_TESTS=1 python3 tests/test_web_integration.py ./build/zerosee
```

Переменная делает отсутствие разрешения на локальные сокеты ошибкой, а не пропуском.

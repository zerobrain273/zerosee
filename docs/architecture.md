# Устройство zerosee 0.2

## Два независимых входа

`scan` получает IPv4 и порты. `web` получает полный URL: схема, hostname и путь
важны для HTTP virtual hosting, TLS SNI и проверки сертификата. Номер открытого
порта сам по себе не доказывает, что там HTTP. Вызов web — явное решение пользователя.

## TCP

`cli.cpp` валидирует параметры. `scanner.cpp` выдаёт уникальные индексы порта пулу
`std::jthread`. `tcp_probe.cpp` владеет сокетом через RAII, начинает неблокирующий
connect, ждёт poll до общего steady_clock-дедлайна и читает SO_ERROR.
Результаты записываются в разные элементы заранее выделенного массива и печатаются
после join. Исключения работников передаются главному потоку.

## Веб-модуль

- `web_url.cpp`: параметры, CURLU-нормализация URL и глобальная инициализация curl.
- `web_http.cpp`: один запрос libcurl без автоматических редиректов. Функции обратного
  вызова имеют noexcept и лимиты. Заголовки промежуточных 1xx заменяются финальными,
  trailers не смешиваются с заголовками. Тело не хранится.
- `web_analysis.cpp`: разбор cookie-атрибутов, правила, проверка разрешённого origin
  перед каждым следующим запросом и сбор структурированного отчёта.
- `web_report.cpp`: читаемый вывод, JSON/Markdown, редактирование значений cookies,
  экранирование недоверенных данных, атомарная запись новых файлов.
- `web.hpp`: типы и интерфейсы. `Fetch` позволяет тестировать цепочки без сети.

Для каждого перехода создаётся новый easy handle. Cookie engine не включается;
полученные cookies не отправляются назад. Учетные данные из URL запрещены,
netrc игнорируется, прокси из окружения отключены.

## Граница scope

Origin = scheme + canonical host + effective port. Разрешены исходный origin
и явно перечисленные дополнительные origin. Имена DNS и IP — разные хосты.
Сначала URL следующего перехода нормализуется, затем проверяются downgrade,
origin, цикл и число переходов. Только после этого выполняется запрос.

HTTP → HTTPS требует явно разрешённого HTTPS-origin. HTTPS → HTTP блокируется
независимо от allowlist. DNS rebinding/IP-allowlist не реализованы: scope относится
к URL. Для лаборатории и фиксированной машины есть --connect-ip исходного hostname.

## TLS

libcurl выполняет TLS через установленный бэкенд. Включены SSL_VERIFYPEER=1 и
SSL_VERIFYHOST=2. CA bundle выбирается явно либо берётся системный. Имя проверяется
по URL даже при подмене DNS через CURLOPT_RESOLVE. После неуспеха нет insecure retry.
CERTINFO предоставляет метаданные цепочки, но их доступность зависит от бэкенда
и стадии отказа. Программа не обещает проверку отзыва, перебор шифров или полный аудит PKI.

Первичная документация, использованная при реализации:

- [SSL_VERIFYHOST](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)
- [CERTINFO](https://curl.se/libcurl/c/CURLOPT_CERTINFO.html)
- [HEADERFUNCTION](https://curl.se/libcurl/c/CURLOPT_HEADERFUNCTION.html)
- [RESOLVE](https://curl.se/libcurl/c/CURLOPT_RESOLVE.html)

## Правила и доказательства

Сначала фиксируются наблюдения, затем их ограничения. Отсутствие CSP не равно XSS,
отсутствие SameSite не равно CSRF, а Server не устанавливает версию установленного
пакета. Правила отсутствующих заголовков не выполняются для неполного ответа.
HTML-правила применяются только к 2xx с HTML MIME. HSTS рассматривается только на HTTPS.

Cookie values скрыты; имя и выбранные атрибуты сохраняются. Set-Cookie в массиве
headers заменён на [redacted]. Прочие headers и URL сохраняются, поэтому отчёты
могут содержать чувствительные сведения помимо cookies.

## Формат JSON, schema_version 1

- Метаданные: tool, version, started_at, finished_at, target.
- Параметры: scope, timeout_ms, max_redirects, connect_ip, trust_store.
- hops: url, status, ip, elapsed_ms, headers_complete, body_truncated, error,
  tls.state, tls.certificates, headers, cookies, при наличии redirect_target/error.
- findings: id, level, title, url, evidence, context, recommendation.
- stop_reason: complete, request_error, invalid_location, redirect_loop,
  redirect_limit, out_of_scope, https_downgrade_blocked.
- limitations: явно указанные ограничения.

JSON сериализует готовая nlohmann/json, не самописный генератор. Невалидные UTF-8
байты при сериализации заменяются; имена/значения не следует трактовать как исполняемый код.
Два формата отчёта пишутся независимо, без замены существующих файлов.

## Тесты

Unit tests используют реальную логику URL, анализа и отчётов с контролируемым
транспортом. Отдельно проверяются callbacks и лимиты. Интеграционный набор
использует реальный libcurl и Python HTTP/HTTPS-серверы с временной CA.
Наличие unit tests не означает прохождение интеграционных проверок.

# Изменения

## [Unreleased]

- **BREAKING:** бизнес-маршруты `/api/serving/*` и `/api/warehouse/*`, кроме `GET`/`HEAD` их `/healthz`, требуют сессию оператора; изменяющие методы — ещё точный `Origin` и `X-CSRF-Token`, неподдерживаемые методы получают `405`. Переход: токен из `GET /api/operator/csrf`, вход через `POST /api/operator/session`, затем cookie сессии со всеми запросами и `Origin` с `X-CSRF-Token` с изменяющими. `401` до отправки в upstream означает, что запрос не выполнялся: после входа его повторяют с тем же `commandID`. Для развёртывания нужны `OPERATOR_COOKIE_MODE`, `OPERATOR_PUBLIC_ORIGIN` и том в `/data/operator`, а для первого запуска — `OPERATOR_BOOTSTRAP_*`; без них gateway не запускается.
- **BREAKING:** процесс по умолчанию слушает `127.0.0.1` (`LISTEN_HOST`); образ задаёт `0.0.0.0`, поэтому контейнер доступен в сети Compose как раньше.
- Личный кабинет оператора (gateway#8): вход, выход, профиль, смена имени и пароля, JSON-файл учётной записи на томе, Argon2id (64 МиБ, t=2, p=1), серверные сессии на 30 минут без активности и не дольше 8 часов, лимиты входа, режим восстановления. Сессия отдаёт `idleExpiresAt` и `absoluteExpiresAt` (gateway#10).
- Обязательные настройки `OPERATOR_COOKIE_MODE`, `OPERATOR_PUBLIC_ORIGIN`, `OPERATOR_STORE_PATH`; для первого запуска — `OPERATOR_BOOTSTRAP_*`. Команда образа `hash-password` печатает PHC-строку для пароля из stdin, на терминале без эха.
- Собственные ошибки, кроме транспортных, используют конверт `{code, message, fieldErrors, requestID}`; ошибки полей — коды `Required`, `TooShort`, `TooLong`, `InvalidCharacters` (gateway#10). `POST /healthz` получает `405` в этом конверте.
- Gateway не передаёт upstream свои cookie и `X-CSRF-Token` и не даёт upstream установить эти cookie.
- Образ создаёт `/data/operator` (0700, 65532:65532) для тома учётной записи.

- Обновлены закреплённые GitHub Actions до выпусков с поддержкой Node.js 24.
- Обновлены минимальная версия Go и builder image до 1.26.9 для получения актуальных исправлений безопасности стандартной библиотеки.
- Preserve the original query string for service validation. Invalid escapes and semicolon parameters no longer disappear before reaching the strict HTTP adapter.

- Response writes use the exchange deadline, including an earlier incoming deadline. A stalled reader no longer retains a proxy handler indefinitely. Transport-error JSON has a separate bounded 250 ms write allowance.
- SIGTERM/SIGINT waits up to 10 seconds for active responses to drain before process exit. Failed shutdown closes the remaining connections and preserves the error.
- Added real socket and child-process regressions for stalled writes, transport timeout responses, keepalive and graceful shutdown.
- Shutdown tests also cover grace-period expiry and immediate listener failures.
- Consolidated response-write tests cover upstream cancellation, complete large responses and a POST timeout with an unknown outcome using the existing request deadline.

- Router и прокси разделены на `internal/config`, `internal/httpapi` и `internal/adapters/httpupstream` с внедряемыми `http.Handler` и `http.RoundTripper`.
- Добавлены `UPSTREAM_TIMEOUT` и JSON собственной транспортной ошибки с `outcome` `unknown`/`unavailable`. Бюджет ограничивает и приём тела запроса от клиента.
- Тесты покрывают потерю ответа после записи, таймаут, остановку передачи тела клиентом, отмену клиентом, escaped path/query и большие десятичные строки.
- Quality checks reject unsupported nested modules and support library-only builds without source-tree executables.

- Health checks preserve response-cleanup failures; encoding and gateway test IO errors are handled explicitly.

- Added Go development, architecture and Git/release rules with pinned quality tooling.

- Проверки архитектуры учитывают действующие config/httpapi/httpupstream пакеты. Ошибки установки read deadline и записи JSON обрабатываются явно; тесты проверяют отказ до вызова upstream.

## [0.1.0] - 2026-10-10

- Добавлены запускаемый каркас, Dockerfile и проверки GitHub Actions.
- Добавлена публикация образов из main по SHA коммита.


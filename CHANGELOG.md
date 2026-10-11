# Изменения

## [Unreleased]

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


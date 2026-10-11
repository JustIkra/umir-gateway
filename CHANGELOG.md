# Изменения

## [Unreleased]

- Router и прокси разделены на `internal/config`, `internal/httpapi` и `internal/adapters/httpupstream` с внедряемыми `http.Handler` и `http.RoundTripper`.
- Добавлены `UPSTREAM_TIMEOUT` и JSON собственной транспортной ошибки с `outcome` `unknown`/`unavailable`. Бюджет ограничивает и приём тела запроса от клиента.
- Тесты покрывают потерю ответа после записи, таймаут, остановку передачи тела клиентом, отмену клиентом, escaped path/query и большие десятичные строки.
- Процесс после SIGTERM/SIGINT ждёт завершения активных запросов до 10 секунд и только затем завершается; по истечении срока оставшиеся соединения закрываются явно.
- Quality checks reject unsupported nested modules and support library-only builds without source-tree executables.

- Health checks preserve response-cleanup failures; encoding and gateway test IO errors are handled explicitly.

- Added Go development, architecture and Git/release rules with pinned quality tooling.

- Проверки архитектуры учитывают действующие config/httpapi/httpupstream пакеты. Ошибки установки read deadline и записи JSON обрабатываются явно; тесты проверяют отказ до вызова upstream.

## [0.1.0] - 2026-10-10

- Добавлены запускаемый каркас, Dockerfile и проверки GitHub Actions.
- Добавлена публикация образов из main по SHA коммита.


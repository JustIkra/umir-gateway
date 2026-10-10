# Изменения

## [Unreleased]

- Router и прокси разделены на `internal/config`, `internal/httpapi` и `internal/adapters/httpupstream` с внедряемыми `http.Handler` и `http.RoundTripper`.
- Добавлены `UPSTREAM_TIMEOUT` и JSON собственной транспортной ошибки с `outcome` `unknown`/`unavailable`. Бюджет ограничивает и приём тела запроса от клиента.
- Тесты покрывают потерю ответа после записи, таймаут, остановку передачи тела клиентом, отмену клиентом, escaped path/query и большие десятичные строки.

## [0.1.0] - 2026-10-10

- Добавлены запускаемый каркас, Dockerfile и проверки GitHub Actions.
- Добавлена публикация образов из main по SHA коммита.


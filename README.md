# umir-gateway

Единый API-вход для системы одного ресторана. Gateway передаёт запросы в serving и warehouse; бизнес-правила выполняются в этих сервисах.

## Текущее состояние

Работают `GET /healthz`, проверка контейнера `/server healthcheck` и HTTP-прокси.
Тесты проверяют выбор upstream, передачу метода, пути, query, тела и ответа, а также отклонение неверного upstream URL.

| Входной путь | Путь на upstream |
| --- | --- |
| `/api/serving/healthz` | `serving:8080/healthz` |
| `/api/warehouse/healthz` | `warehouse:8080/healthz` |

Префиксы `/api/serving` и `/api/warehouse` снимаются при передаче запроса. Бизнес-endpoints ещё предстоит реализовать в соответствующих сервисах.

## Разработка

Требуется Go 1.26.5. Для запуска с соседними Go-сервисами:

```sh
go test -race ./...
go vet ./...
TZ=Europe/Moscow PORT=18081 SERVING_URL=http://127.0.0.1:18082 WAREHOUSE_URL=http://127.0.0.1:18083 go run ./cmd/server
```

Сборка отдельного контейнера:

```sh
docker compose up --build -d --wait
```

| Настройка | Значение по умолчанию |
| --- | --- |
| `PORT` | `8080` |
| `SERVING_URL` | `http://serving:8080` |
| `WAREHOUSE_URL` | `http://warehouse:8080` |
| `TZ` в контейнере | `Europe/Moscow` |

Отдельный Compose публикует `127.0.0.1:18081`. Для доступа к upstream по именам serving и warehouse используйте [общую сборку фабрики](https://github.com/JustIkra/umir-factory#readme).
В фабрике gateway по умолчанию доступен на `127.0.0.1:8081`; frontend также передаёт ему запросы `/api/`.

## Совместная работа

Main защищён активным ruleset. Обновлять main и объединять PR может только `JustIkra`.
`Kxqusos` добавлен с ролью write и работает в других ветках.
Остальные пользователи GitHub могут создать issue, fork и PR.
Владелец кода указан в `.github/CODEOWNERS`.

Перед PR выполните локальные проверки. Изменение межсервисного контракта согласуйте с вызывающей стороной.

## CI/CD

[GitHub Actions](https://github.com/JustIkra/umir-gateway/actions) проверяет push в ветки, PR в main и ручные запуски.
После успешной проверки main публикует `ghcr.io/justikra/umir-gateway:sha-<полный SHA коммита>` для `linux/amd64` и `linux/arm64`.
Публикация использует `GITHUB_TOKEN`, с `packages:write` только у задания публикации.
Коммит документации запускает тот же workflow.

[Фабрика](https://github.com/JustIkra/umir-factory) закрепляет выбранный SHA в `compose.yaml`.
Обновление фабрики выполняется отдельным PR; новый образ не развёртывается автоматически.
Секреты передаются через окружение; `.env` исключён из Git.


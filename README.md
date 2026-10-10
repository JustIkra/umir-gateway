# umir-gateway

Единый API-вход для системы одного ресторана. Gateway передаёт запросы в serving и warehouse; бизнес-правила выполняются в этих сервисах.

## Текущее состояние

Работают `GET /healthz`, проверка контейнера `/server healthcheck` и HTTP-прокси.
Gateway не содержит бизнес-правил: он не создаёт `commandID`, не проверяет тела и не повторяет запросы.

| Входной путь | Путь на upstream |
| --- | --- |
| `/api/serving/healthz` | `serving:8080/healthz` |
| `/api/warehouse/healthz` | `warehouse:8080/healthz` |
| `/api/serving/<path>` | `serving:8080/<path>` |
| `/api/warehouse/<path>` | `warehouse:8080/<path>` |

Префиксы `/api/serving` и `/api/warehouse` снимаются при передаче запроса. Метод, остальной путь, query, тело, end-to-end заголовки, статус и тело ответа upstream передаются без изменений; hop-by-hop заголовки удаляются, `X-Forwarded-*` выставляет gateway. Query с `;` или некорректным `%`-кодированием `httputil.ReverseProxy` перекодирует. Бизнес-endpoints ещё предстоит реализовать в соответствующих сервисах.

## Структура

| Пакет | Ответственность |
| --- | --- |
| `cmd/server` | Чтение настроек, сборка прокси и router, ограничение времени upstream, lifecycle и `healthcheck`. |
| `internal/config` | Проверка `PORT`, `SERVING_URL`, `WAREHOUSE_URL`, `UPSTREAM_TIMEOUT`. |
| `internal/httpapi` | `NewRouter(Upstreams)` над внедрёнными `http.Handler`, `/healthz`, JSON транспортной ошибки. |
| `internal/adapters/httpupstream` | `NewProxy(target, http.RoundTripper)` — `ReverseProxy` с внедрённым transport. |

## Собственные ошибки gateway

Ответ upstream, включая 4xx/5xx и 202, передаётся без изменений. Собственный JSON `{code, message, outcome}` gateway возвращает, только если ответ upstream не получен:

| Ситуация | Статус | `code` | `outcome` |
| --- | --- | --- | --- |
| Upstream недоступен или соединение оборвано до ответа | 502 | `UpstreamUnavailable` | `unknown` для изменяющих методов, `unavailable` для GET/HEAD/OPTIONS |
| Истёк `UPSTREAM_TIMEOUT`, в том числе пока клиент передаёт тело запроса | 504 | `UpstreamTimeout` | то же |

`unknown` означает, что запись могла произойти: исход устанавливает сервис-владелец, а клиент повторяет ту же попытку с тем же `commandID`. Обрыв после начала передачи тела ответа прерывает соединение клиента. Если бюджет истёк до получения всего тела запроса, gateway отвечает 504 и закрывает соединение. Внутренние адреса upstream пишутся только в лог.

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
| `UPSTREAM_TIMEOUT` | `15s`; общий бюджет на приём тела запроса от клиента и обмен с upstream, формат Go duration |
| `TZ` в контейнере | `Europe/Moscow` |

URL upstream принимаются только `http(s)` с хостом, без учётных данных, query и fragment; неверная настройка останавливает запуск. Переменные `HTTP_PROXY`/`HTTPS_PROXY` к upstream не применяются.

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


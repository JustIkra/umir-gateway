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

Бизнес-ядро warehouse/serving в памяти реализовано и проверено. Gateway передаёт HTTP-вызовы и не владеет FEFO, идентификаторами команд или подтверждением заказа. [OpenAPI v1](https://github.com/JustIkra/umir-factory/blob/main/docs/api/openapi.yml) определяет целевые бизнес-маршруты; HTTP-адаптеры и авторитетное разрешение незавершённых сетевых попыток ещё предстоит реализовать. Семантический результат устанавливает сервис-владелец, а gateway сохраняет полученный status/body.

| Каталог | Назначение |
| --- | --- |
| `cmd/server` | Сборка зависимостей, lifecycle, healthcheck и конечный бюджет запроса. |
| `internal/config` | Проверенные настройки процесса и URL upstream. |
| `internal/httpapi` | Маршрутизация и собственные транспортные ошибки. |
| `internal/adapters/httpupstream` | ReverseProxy с внедряемым transport. |

Границы бизнес-сервисов описаны в [архитектуре фабрики](https://github.com/JustIkra/umir-factory/blob/main/docs/go-architecture.md). Gateway не импортирует их Go-модули.

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
| `WRITE_TIMEOUT` | `UPSTREAM_TIMEOUT` + `5s`; срок передачи ответа клиенту с момента получения заголовков запроса, должен быть больше `UPSTREAM_TIMEOUT` |
| `TZ` в контейнере | `Europe/Moscow` |

`WRITE_TIMEOUT` не отменяет upstream: обмен с ним ограничивает `UPSTREAM_TIMEOUT`, а запас после него оставлен для собственного ответа 504. Клиент, который перестал читать ответ, удерживает обработчик и соединение не дольше `WRITE_TIMEOUT`.

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

## Development standard and releases

Repository instructions are in [AGENTS.md](AGENTS.md). Public compatibility covers documented requests, results, error states and operational interfaces; warehouse/serving also publish their declared Go contract surfaces when implemented. Internal refactoring does not automatically change this contract.

Go tools are pinned to golangci-lint 2.14.0 and go-arch-lint 1.19.0 in [.go-quality-versions](.go-quality-versions). Local and CI checks use the same commands:

```sh
make tools
make fmt FILES="cmd/server/main.go"
make check
make quality-test
```

`make check` verifies the module inventory, formatting without writes, build, lint, source dependency architecture and fresh race tests. The shared runner checks one root module (`.`). Declared nested modules fail explicitly and need separate effective quality gates. Library-only modules are supported; executable output stays in temporary storage. Tests and tool caches remain outside production dependencies. `make fmt-all` is reserved for a deliberate full formatting change. Service checks use `GOWORK=off`; unknown packages or modules fail. Empty future components need no placeholder packages. [Linter rules](.golangci.yml) constrain errors and imports; [architecture rules](.go-arch-lint.yml) cover the module root, including public contract/bootstrap packages.

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Stable incompatible changes increment major, compatible additions minor and fixes patch. Our pre-1.0 convention uses patch for compatible fixes and minor for additions or breaking changes. Mark breaking behavior and migration explicitly.

Release repositories independently. Use annotated `vX.Y.Z` tags for actual releases; published nested Go modules prefix tags with the logical module subdirectory (excluding a trailing major-version directory), and Go v2+ needs the matching major import path. Published tags/versions stay immutable. Record changes under Unreleased before releasing. Preserve Umir `sha-<full-SHA>` image identities and exact factory component pins; SemVer does not replace them with `latest`. API versions and service releases are separate.

Preserve unrelated local edits, stage reviewed paths and check `git diff --cached` and `git diff --check`. Tagging, publishing and shared-history rewrites require the corresponding user instruction. This standard does not create a release or change the current version.

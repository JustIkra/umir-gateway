# umir-gateway

Единый API-вход для системы одного ресторана. Gateway передаёт запросы в serving и warehouse; бизнес-правила выполняются в этих сервисах.

## Текущее состояние

Работают `GET /healthz`, проверка контейнера `/server healthcheck`, HTTP-прокси и [личный кабинет оператора](#личный-кабинет-оператора).
Бизнес-маршруты требуют сессию оператора. Без сессии доступны только `GET` и `HEAD` для `/healthz`, `/api/serving/healthz` и `/api/warehouse/healthz`.
Gateway не содержит бизнес-правил: он не создаёт `commandID`, не проверяет тела и не повторяет запросы.

| Входной путь | Путь на upstream |
| --- | --- |
| `/api/serving/healthz` | `serving:8080/healthz` |
| `/api/warehouse/healthz` | `warehouse:8080/healthz` |
| `/api/serving/<path>` | `serving:8080/<path>` |
| `/api/warehouse/<path>` | `warehouse:8080/<path>` |

Префиксы `/api/serving` и `/api/warehouse` снимаются при передаче запроса. Метод, остальной путь, query, тело, end-to-end заголовки, статус и тело ответа upstream передаются без изменений; hop-by-hop заголовки удаляются, `X-Forwarded-*` выставляет gateway. Исходный RawQuery сохраняется, включая ошибочный `%` или `;`, чтобы HTTP-адаптер сервиса мог отклонить неверные параметры. Публичные бизнес-endpoints принадлежат соответствующим сервисам. `WAREHOUSE_URL` указывает на публичный listener склада; внутренний listener `8082` доступен только serving.

Перед передачей в upstream gateway удаляет свои cookie `umir_operator_session` и `umir_operator_preauth` (и их варианты `__Host-`) и заголовок `X-CSRF-Token`. Строки `Set-Cookie` от upstream с этими именами отбрасываются, остальные cookie проходят без изменений.

## Структура

| Пакет | Ответственность |
| --- | --- |
| `cmd/server` | Чтение настроек, сборка учётной записи, прокси и router, ограничение времени upstream, lifecycle, `healthcheck` и `hash-password`. |
| `internal/config` | Проверка `PORT`, `SERVING_URL`, `WAREHOUSE_URL`, `UPSTREAM_TIMEOUT` и настроек `OPERATOR_*`. |
| `internal/httpapi` | `NewRouter(Routes)` над внедрёнными `http.Handler` с обязательным guard, `/healthz`, конверт ошибок `Problem` с `requestID`, JSON транспортной ошибки. |
| `internal/operatorhttp` | Маршруты `/api/operator/*`, guard бизнес-маршрутов, cookie, проверка `Origin` и CSRF, удаление учётных данных оператора перед upstream. |
| `internal/operator` | Учётная запись, сессии, CSRF без входа, лимиты входа и режим восстановления; без HTTP и файлов. |
| `internal/adapters/argon2id` | Хэши паролей Argon2id в формате PHC. |
| `internal/adapters/accountfile` | JSON-файл учётной записи: проверка прав, создание при первом запуске, атомарная замена. |
| `internal/adapters/httpupstream` | `NewProxy(target, http.RoundTripper)` — `ReverseProxy` с внедрённым transport. |

## Собственные ошибки gateway

Ответ upstream, включая 4xx/5xx и 202, передаётся без изменений. Собственный JSON `{code, message, outcome}` gateway возвращает, только если ответ upstream не получен:

| Ситуация | Статус | `code` | `outcome` |
| --- | --- | --- | --- |
| Upstream недоступен или соединение оборвано до ответа | 502 | `UpstreamUnavailable` | `unknown` для изменяющих методов, `unavailable` для GET/HEAD/OPTIONS |
| Истёк `UPSTREAM_TIMEOUT`, в том числе пока клиент передаёт тело запроса | 504 | `UpstreamTimeout` | то же |

`unknown` означает, что запись могла произойти: исход устанавливает сервис-владелец, а клиент повторяет ту же попытку с тем же `commandID`. Обрыв после начала передачи тела ответа прерывает соединение клиента. Если бюджет истёк до получения всего тела запроса, gateway отвечает 504 и закрывает соединение. Внутренние адреса upstream пишутся только в лог.

Бюджет ограничивает чтение входного тела, ожидание upstream и запись ответа клиенту. Более ранний deadline входного контекста сокращает его. Клиент, который перестал читать ответ, не удерживает обработчик после этого deadline. Если ответ upstream ещё не начат, собственная транспортная ошибка получает отдельные 250 ms на запись JSON; этот период также ограничен socket deadline.

Остальные собственные ответы об ошибках — личный кабинет, guard бизнес-маршрутов, `405`, `413`, `415` и неразобранное тело — используют один конверт с `Cache-Control: no-store`:

```json
{"code": "InvalidDisplayName", "message": "display name must contain 2 to 80 characters without control characters", "fieldErrors": {"displayName": "TooShort"}, "requestID": "7KB6W3EHBMZKTKVRO44KR6KSVH"}
```

`message` предназначено для журналов и разработчиков: текст для пользователя фронтенд выбирает по `code` и кодам `fieldErrors`. `fieldErrors` есть только у ответов `422`. Тот же `requestID` записывается в журнал gateway.

## Личный кабинет оператора

Один заранее заведённый оператор входит по логину и паролю (gateway#8). Правила учётной записи находятся в `internal/operator`, HTTP — в `internal/operatorhttp`. Отдельного сервиса, базы данных и внешнего провайдера входа нет.

### Маршруты

| Метод и путь | Доступ | Успешный ответ |
| --- | --- | --- |
| `GET /api/operator/csrf` | Публичный | `200 {"csrfToken"}` — токен живой сессии, а без неё токен анонимного контекста с cookie `umir_operator_preauth`. Сессию не создаёт и не продлевает. |
| `POST /api/operator/session` | `Origin` и токен анонимного контекста или живой сессии | `200 {"operator", "session"}` и новая cookie сессии; прежняя сессия отзывается. Тело: `{"login", "password"}`. |
| `DELETE /api/operator/session` | `Origin` и токен сессии, без живой сессии — анонимный токен | `204`, cookie сессии очищается. Повтор безопасен. В режиме восстановления сессии уже сброшены, поэтому выход принимает только анонимный токен из `GET /api/operator/csrf`. |
| `GET /api/operator/me` | Сессия | `200 {"operator", "session"}`, срок бездействия продлевается. |
| `PATCH /api/operator/me/display-name` | Сессия, `Origin`, `X-CSRF-Token` | `200 {"operator"}`. Тело: `{"displayName"}`. |
| `PATCH /api/operator/me/password` | Сессия, `Origin`, `X-CSRF-Token` | `204`: все сессии, включая текущую, отозваны, нужен новый вход. Тело: `{"currentPassword", "newPassword"}`. |

`operator` — это `{id, login, displayName}`. `session` — это `{expiresAt, idleExpiresAt, absoluteExpiresAt, csrfToken}`, время в RFC 3339 со смещением `+03:00`. Срок бездействия никогда не позже абсолютного, поэтому `expiresAt` равен `idleExpiresAt`. Ответы `/api/operator/*` не кешируются (`Cache-Control: no-store`).

### Сессии, cookie и CSRF

- Сессия живёт 30 минут без активности и не дольше 8 часов от входа. Любой запрос с сессией, включая `GET /api/operator/me`, продлевает срок бездействия, но не дальше абсолютного; `GET /api/operator/csrf` срок не продлевает. Фронтенд продлевает сессию только по действию пользователя, без фоновых таймеров (ГОСТ Р 52872-2019, 2.2.1).
- Сессии, анонимные контексты и счётчик неудачных входов хранятся в памяти: перезапуск gateway завершает все сессии и сбрасывает счётчик, файл учётной записи при этом не меняется. Одновременно живут не больше 32 сессий и 1024 анонимных контекстов по 30 минут; при переполнении вытесняются самые старые. Несколько реплик gateway не поддерживаются.
- Cookie ставятся с `HttpOnly`, `SameSite=Strict`, `Path=/`, без `Domain` и без срока: браузер удаляет их при закрытии, а сроки проверяет сервер. В режиме `secure` имена `__Host-umir_operator_session` и `__Host-umir_operator_preauth` с атрибутом `Secure`, в `loopback-development` — `umir_operator_session` и `umir_operator_preauth` без него.
- Каждый изменяющий запрос — вход, выход, изменения профиля и бизнес-запросы `POST`, `PUT`, `PATCH`, `DELETE` — несёт `Origin`, точно равный `OPERATOR_PUBLIC_ORIGIN`, и токен в `X-CSRF-Token`. `Sec-Fetch-Site`, если браузер его прислал, должен быть `same-origin`. Заголовки `X-Forwarded-*` в этих проверках не участвуют.

### Бизнес-маршруты

Guard проверяет каждый запрос под `/api/serving/` и `/api/warehouse/` до отправки в upstream:

| Метод | Требуется | Возможный отказ |
| --- | --- | --- |
| `GET`, `HEAD`, `OPTIONS` | Сессия | `401 Unauthenticated`, `503 AuthUnavailable` |
| `POST`, `PUT`, `PATCH`, `DELETE` | Сессия, точный `Origin`, `X-CSRF-Token` этой сессии | ещё `403 InvalidOrigin`, `403 InvalidCsrfToken` |
| Остальные | — | `405 MethodNotAllowed` с заголовком `Allow` |

Отказ guard означает, что upstream запрос не получал: после входа его можно повторить с тем же `commandID`. Если сессия истекла, когда запрос уже передан в upstream, он завершается как обычно. Транспортные ошибки прокси по-прежнему возвращают `outcome`.

### Ошибки

| Код | Статус | Когда |
| --- | --- | --- |
| `InvalidRequest` | 400 | Тело не JSON-объект нужной формы: синтаксис, лишние или отсутствующие поля, данные после объекта. |
| `InvalidCredentials` | 401 | Любое несовпадение логина или пароля; ответ не показывает, существует ли логин. |
| `Unauthenticated` | 401 | Нет живой сессии. |
| `InvalidOrigin`, `InvalidCsrfToken` | 403 | Изменяющий запрос пришёл не из публичного origin или без верного токена. |
| `CurrentPasswordIncorrect` | 403 | Неверный текущий пароль, ничего не изменено. После пяти таких ответов сессия отзывается. |
| `NotFound`, `MethodNotAllowed` | 404, 405 | Неизвестный маршрут кабинета или неподходящий метод. |
| `PayloadTooLarge`, `UnsupportedMediaType` | 413, 415 | Тело больше 8 КиБ или не `application/json`. |
| `InvalidDisplayName`, `PasswordRejected` | 422 | Поле не прошло проверку; код причины в `fieldErrors`. |
| `LoginRateLimited` | 429 | Пять неудачных входов за 60 секунд включают паузу на 60 секунд для любого входа, или очередь проверки пароля заполнена. `Retry-After` — секунды до повтора. |
| `AuthUnavailable` | 503 | Режим восстановления или внутренний сбой проверки. |
| `AccountStorageUnavailable` | 503 | Запись файла не удалась до фиксации: ничего не изменено, сессии работают. |
| `AccountUpdateOutcomeUnknown` | 503 | Неизвестно, записалось ли изменение; gateway переходит в режим восстановления. |

Коды `fieldErrors`: `Required` (пусто), `TooShort`, `TooLong`, `InvalidCharacters` (управляющие символы или некорректный UTF-8). Отображаемое имя после удаления пробелов по краям и нормализации NFC должно содержать 2–80 кодовых точек. Пароль — 8–32 кодовые точки; он хранится и сравнивается ровно в том виде, как введён, без обрезки и нормализации.

### Режим восстановления

Если неизвестно, записалось ли изменение учётной записи, gateway отвечает `503 AccountUpdateOutcomeUnknown` и до перезапуска отказывает во входе, `/me`, изменениях профиля и бизнес-маршрутах (`503 AuthUnavailable`). Работают только `/healthz`, анонимный `GET /api/operator/csrf` и выход с анонимным токеном: при переходе в этот режим все сессии сбрасываются.

Чтобы восстановить работу, проверьте файл учётной записи на томе и перезапустите контейнер. Корректный файл загружается как есть, сессии начинаются заново. Повреждённый файл останавливает запуск и никогда не перезаписывается автоматически.

Если ответ на изменение просто потерян, а gateway работает, исход проверяют так: имя — через `GET /api/operator/me`, пароль — входом с новым паролем.

### Файл учётной записи и первый запуск

`OPERATOR_STORE_PATH` указывает на JSON-файл на смонтированном томе; в образе это `/data/operator/account.json`. Каталог `/data/operator` создан в образе с правами `0700` для пользователя `65532:65532`, и новый именованный том получает эти права при первом подключении.

Файл с правами `0600` содержит `schemaVersion`, `profileID`, `login`, `displayName`, `passwordHash` (PHC Argon2id) и `credentialVersion`. Файл и каталог должны принадлежать пользователю процесса и не быть симлинками, иначе gateway не запустится. Изменение записывается во временный файл, затем `fsync`, `rename` и `fsync` каталога. Удаление тома сбрасывает учётную запись. Для резервной копии достаточно скопировать файл при остановленном gateway.

Если файла нет, gateway создаёт его из `OPERATOR_BOOTSTRAP_LOGIN`, `OPERATOR_BOOTSTRAP_DISPLAY_NAME` и `OPERATOR_BOOTSTRAP_PASSWORD_HASH`. Существующий файл главнее этих настроек. Хэш пароля даёт команда образа; пароль вводится дважды без эха и никуда не записывается:

```sh
docker run --rm -it ghcr.io/justikra/umir-gateway:sha-<SHA> hash-password
```

Без терминала команда читает из stdin ровно одну строку и печатает только PHC-строку. В `.env` для Compose значение пишется в одинарных кавычках, иначе Compose подставит переменные вместо символов `$`.

### Персональные данные

Файл учётной записи хранит логин и отображаемое имя оператора и хэш пароля. Пароль в открытом виде нигде не сохраняется. Журналы содержат только `requestID`, метод, путь и код ошибки — без паролей, хэшей, cookie, CSRF-токенов и тел запросов. Данные хранятся, пока существует том.

### Настройки

| Переменная | Обязательна | Значение |
| --- | --- | --- |
| `OPERATOR_COOKIE_MODE` | да | `secure` для публикации по HTTPS, `loopback-development` только для локальной разработки. |
| `OPERATOR_PUBLIC_ORIGIN` | да | Точный origin фронтенда: `https://<домен>` в режиме `secure`, `http://<loopback IP>:<порт>` в `loopback-development`. Без пути, query, учётных данных и порта по умолчанию, в нижнем регистре, IDN в виде A-label. |
| `OPERATOR_STORE_PATH` | да | Абсолютный путь к файлу учётной записи; в образе задан `/data/operator/account.json`. |
| `OPERATOR_BOOTSTRAP_LOGIN`, `OPERATOR_BOOTSTRAP_DISPLAY_NAME`, `OPERATOR_BOOTSTRAP_PASSWORD_HASH` | только без файла | Учётная запись для первого запуска. |
| `OPERATOR_IDLE_TIMEOUT`, `OPERATOR_ABSOLUTE_TIMEOUT` | нет | `30m` и `8h`; срок бездействия не больше абсолютного. |

Ошибка в настройках останавливает запуск; сообщение называет переменную, но не её значение. Режим cookie и допустимый origin задаются только настройками, `X-Forwarded-Proto` и `Host` на них не влияют. В Compose снаружи доступен только frontend: он передаёт `/api/` в gateway, сохраняя `Host`, `Origin`, cookie и `X-CSRF-Token`.

### Argon2id

Новые хэши: Argon2id версии 19, `m=65536` (64 МиБ), `t=2`, `p=1`, соль 16 байт, ключ 32 байта, формат PHC, библиотека `golang.org/x/crypto/argon2` v0.58.0. Проверка берёт параметры из самого хэша и принимает их в диапазоне от `19 MiB, t=2, p=1` до `1 GiB, t=16, p=16`. Одновременно выполняются не больше двух проверок, в очереди ждут не больше восьми входов; при полной очереди — `429` с `Retry-After: 1`.

Измерения `go test ./internal/adapters/argon2id -run '^$' -bench Hash`, время одного хэша:

| Машина | 19 МиБ, t=2 (минимум OWASP) | 64 МиБ, t=2 (выбрано) | Две проверки одновременно |
| --- | --- | --- | --- |
| ВМ стенда: 2 vCPU QEMU с SSE4.1, 4 ГиБ | 29 мс | 112 мс | 123 мс каждая |
| Apple M3 | 22 мс | 83 мс | — |

На ВМ полная очередь входа (2 проверки и 8 ожидающих) ждёт не больше 0,6 с. Две одновременные проверки занимают 128 МиБ памяти.

### Переход

Для развёртывания gateway теперь нужны `OPERATOR_COOKIE_MODE`, `OPERATOR_PUBLIC_ORIGIN` и том в `/data/operator`; для первого запуска с пустым томом — ещё `OPERATOR_BOOTSTRAP_*`. Без них gateway не запускается. Порт gateway на хосте больше не нужен: снаружи доступен только frontend.

Раньше бизнес-маршруты были открыты. Теперь клиент:

1. получает токен: `GET /api/operator/csrf`;
2. входит: `POST /api/operator/session` с `Origin`, `X-CSRF-Token` и `{"login", "password"}`;
3. отправляет cookie сессии со всеми запросами, а с изменяющими — ещё `Origin` и `X-CSRF-Token` из `session.csrfToken`;
4. на `401` от guard входит снова и повторяет запрос с тем же `commandID`.

## Разработка

Бизнес-ядро warehouse/serving работает в памяти. Gateway передаёт HTTP-вызовы и не владеет FEFO, идентификаторами команд или подтверждением заказа. [OpenAPI v1](https://github.com/JustIkra/umir-factory/blob/main/docs/api/openapi.yml) определяет публичные бизнес-маршруты. Семантический результат и разрешение незавершённой попытки устанавливает сервис-владелец, а gateway сохраняет полученный status/body.

| Каталог | Назначение |
| --- | --- |
| `cmd/server` | Сборка зависимостей, lifecycle, healthcheck, `hash-password` и конечный бюджет запроса. |
| `internal/config` | Проверенные настройки процесса, URL upstream и учётной записи оператора. |
| `internal/httpapi` | Маршрутизация, конверт ошибок и собственные транспортные ошибки. |
| `internal/operatorhttp` | HTTP личного кабинета и guard бизнес-маршрутов. |
| `internal/operator` | Правила учётной записи и сессий. |
| `internal/adapters/argon2id`, `internal/adapters/accountfile` | Хэши паролей и файл учётной записи. |
| `internal/adapters/httpupstream` | ReverseProxy с внедряемым transport. |

Границы бизнес-сервисов описаны в [архитектуре фабрики](https://github.com/JustIkra/umir-factory/blob/main/docs/go-architecture.md). Gateway не импортирует их Go-модули.

Требуется Go 1.26.9. Для запуска с соседними Go-сервисами:

```sh
go test -race ./...
go vet ./...
mkdir -m 700 -p /tmp/umir-operator
HASH=$(go run ./cmd/server hash-password)   # пароль вводится дважды, без эха
TZ=Europe/Moscow PORT=18081 SERVING_URL=http://127.0.0.1:18082 WAREHOUSE_URL=http://127.0.0.1:18083 \
  OPERATOR_COOKIE_MODE=loopback-development OPERATOR_PUBLIC_ORIGIN=http://127.0.0.1:18081 \
  OPERATOR_STORE_PATH=/tmp/umir-operator/account.json OPERATOR_BOOTSTRAP_LOGIN=operator \
  OPERATOR_BOOTSTRAP_DISPLAY_NAME=Оператор OPERATOR_BOOTSTRAP_PASSWORD_HASH="$HASH" go run ./cmd/server
```

Запущенный так процесс слушает только `127.0.0.1`. Образ задаёт `LISTEN_HOST=0.0.0.0`: в Compose frontend обращается к gateway по сети контейнеров, а порт gateway на хост не публикуется.

Сборка отдельного контейнера: скопируйте `.env.example` в `.env`, заполните учётную запись для первого запуска и выполните

```sh
docker compose run --rm app hash-password   # PHC-строку — в .env в одинарных кавычках
docker compose up --build -d --wait
```

| Настройка | Значение по умолчанию |
| --- | --- |
| `PORT` | `8080` |
| `LISTEN_HOST` | `127.0.0.1`; в образе `0.0.0.0`. Допустимы только loopback-адрес или `0.0.0.0` / `::`: проверка `/server healthcheck` обращается к `127.0.0.1`. |
| `SERVING_URL` | `http://serving:8080` |
| `WAREHOUSE_URL` | `http://warehouse:8080` |
| `UPSTREAM_TIMEOUT` | `15s`; общий бюджет на приём тела запроса от клиента и обмен с upstream, формат Go duration |
| `TZ` в контейнере | `Europe/Moscow` |
| `OPERATOR_*` | см. [настройки личного кабинета](#настройки) |

URL upstream принимаются только `http(s)` с хостом, без учётных данных, query и fragment; неверная настройка останавливает запуск. Переменные `HTTP_PROXY`/`HTTPS_PROXY` к upstream не применяются.

По SIGTERM или SIGINT gateway перестаёт принимать новые соединения и до 10 секунд ждёт завершения активных запросов, после чего завершается с кодом 0. Если запросы не успели завершиться, gateway закрывает оставшиеся соединения и завершается с ошибкой.

Отдельный Compose публикует `127.0.0.1:18081`. Для доступа к upstream по именам serving и warehouse используйте [общую сборку фабрики](https://github.com/JustIkra/umir-factory#readme).
В закреплённой сборке фабрики gateway пока доступен на `127.0.0.1:8081`, frontend также передаёт ему запросы `/api/`. Сборка с личным кабинетом (gateway#8) публикует только frontend, а gateway остаётся без порта на хосте.

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

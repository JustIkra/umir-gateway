# umir-gateway

The scoped FIN1 profile adds `GET /api/v2/r/{restaurantID}/warehouse/supply-suggestions` with existing `stock.read` authority and adopts the revised recommendation response on the existing Serving route. The [Factory contract supplement](https://github.com/JustIkra/umir-factory/blob/80c240065892153129b590f4bdbd2411b7c0319a/docs/completion-api-amendment.md) defines policy; Warehouse and Serving own the calculations. Private recommendation-input routes remain inaccessible to browsers. Each public read obtains a fresh Auth decision and forwards once with fixed service audiences.

FIN1 reply validation checks scope, current settings, state version, capture instant, the 168-hour window and history-coverage facts. Recommendation reasons must identify eligible horizon expiries and their captured remaining seconds. Null is allowed only for schema-declared no-history supply coverage; other inputs and replies keep their existing null refusal. Invalid or unavailable upstream data never becomes a successful empty result. Gateway preserves owner values and does not calculate ranking or supply quantities.

Единый API-вход для системы одного ресторана. Gateway передаёт запросы в serving и warehouse; бизнес-правила выполняются в этих сервисах.

## Текущее состояние

Работают `GET /healthz`, проверка контейнера `/server healthcheck`, HTTP-прокси, [личный кабинет оператора](#личный-кабинет-оператора) и [поток изменений `GET /api/live`](#реальное-время).
Бизнес-маршруты требуют сессию оператора. Без сессии доступны только `GET` и `HEAD` для `/healthz`, `/api/serving/healthz` и `/api/warehouse/healthz`, а также публичная [форма обратной связи](#форма-обратной-связи) `POST /api/feedback`.
Gateway не содержит бизнес-правил: он не создаёт бизнес-`commandID` и не повторяет запросы. Backend v2 проверяет wire-схемы на границе, а бизнес-решения остаются у сервисов.

### Realtime defect repairs (G3)

The legacy expiration runner compares Warehouse versions with the last request that
signalled a possible change. Rejected writes remain in the journal but do not hide
an external expiration. A valid reply requires evaluatedAt, a canonical nonnegative
int64 decimal stateVersion, and an explicit expired array with complete results.
Replies are limited to 1 MiB and reject unknown fields and trailing JSON. Invalid
replies keep the existing unknown signal and three-failure availability policy.

Legacy operator callbacks carry process-local revisions assigned under the commit
mutex. Stream watchers retain the highest revision even after sending it and ignore
older or duplicate callbacks. Authoritative session snapshots also advance this
revision cutoff before the greeting and after deadline checks. A delayed callback
from before the watch cannot replace a newer snapshot. An ended watcher cannot be extended again. These
revisions do not replace Auth session revisions or change stored expiry instants.

Each journal path retains at most 1024 bytes, ending at a UTF-8 boundary. Gateway
copies even short path slices so they cannot retain a larger request buffer. Proxy
requests keep their original paths. With JOURNAL_CAPACITY entries, retained path
content is bounded by JOURNAL_CAPACITY times 1024 bytes.

Run focused verification with GOWORK=off go test -race -count=1
./internal/expiration/... ./internal/live/... ./internal/journal/... . Full make
check includes the operator publication and HTTP/SSE regressions. Backend v2 scoped
SSE and scheduler integration use the frozen C2 contract.

### Backend v2 Auth transport (G1)

The internal Auth client accepts `authclient.Options.Now` for token validation
and signing-key refresh. If omitted, it uses the system clock. A composition with
an authoritative injected clock must pass that same clock here. Control-token
validation rechecks expiry after key discovery. Scheduler-token validation uses
one clock sample after the real Auth response. Network deadlines remain bounded
host timers. No fixture controls, fixture data, or signing mechanism are added to
production source.

Set `AUTH_URL` to select the backend v2 topology. Gateway then uses Auth's private
`/internal/auth/v1/public/*` session/profile facade. `AUTH_SERVICE_KEY` is required;
`AUTH_TIMEOUT` defaults to `5s`. The URL is an origin without user information, a
path, query or fragment. HTTPS uses normal certificate and hostname validation.
Plain HTTP is allowed on loopback, or with `AUTH_ISOLATED_TEST_NETWORK=true` in an
isolated synthetic test network. Keep the credential private. Gateway does not
use environment HTTP proxies for this connection.

Keep `OPERATOR_COOKIE_MODE` and `OPERATOR_PUBLIC_ORIGIN`. Auth mode does not open,
create or write `OPERATOR_STORE_PATH`, use bootstrap credentials, or hold an Auth
signing key. Auth owns durable accounts, CSRF, session activity and revocation.
An unavailable Auth never invokes the legacy account module. `clear-sessions` is
a legacy-only command. Without `AUTH_URL`, the selected legacy topology described
below retains its existing local account, proxy, SSE and scheduler behavior.

G1 exposes `/api/operator/csrf`, `/session`, `/me`, `/me/display-name`, and
`/me/password` under the operator prefix, with their existing request bodies,
response keys, errors and cookie policy. Equivalent `/api/v2` account routes use
the frozen User models. V2 login, display-name and password mutations require the
caller's `commandID`; Gateway preserves it. Old operator aliases receive a fresh
private command ID per mutation. They retain their old recovery limitations:
Gateway does not automatically retry an uncertain mutation or claim that a later
alias request can recover the original session. V2 clients retain the original
command ID and payload for owner-controlled recovery.

Unsafe routes require the exact single Origin and `X-CSRF-Token`; Auth also checks
the token's session/preauth binding. Browser internal credentials are rejected.
Gateway builds private headers itself and never forwards browser cookies or Auth
response headers. Only validated, successful SessionIssued/PreauthIssued results
install cookies. Optional `User.email` values must match the frozen email format
and contain at most 254 characters. Invalid Auth user results return 503 without
installing cookies; mutation outcomes remain unknown. Unknown login, password,
profile and logout outcomes set or clear no success cookie. Definite password-limit
revocation preserves `sessionRevoked`
and `Retry-After`. Private tokens, secrets and bodies are not logged or included
in public JSON. Every account response is `no-store`. Exact background activity
and CSRF requests do not extend idle time. Auth remains responsible for the
persisted deadline and `/me` definite-extension-failure behavior.

In Auth mode the old unscoped business routes and `/api/live` return
`400 InvalidArgument` without dispatch. Auth mode runs the scoped SSE handler and
the Auth-issued scheduler. It does not start the legacy scheduler or streams.
Real five-service acceptance belongs to J1/E.

Verify G1 with `GOWORK=off go test -race ./internal/operatorhttp/...
./internal/adapters/... ./cmd/server/... ./tests/integration/...` (one command).
The Go integration suite uses Auth HTTP transport doubles. Run `make check`
for the full pinned module gates and `make quality-test` after enforcement changes.

### Complete backend v2 Auth facade

Auth mode routes all 29 frozen Auth operations through the executable Gateway.
This includes access discovery, organization and restaurant lifecycle, settings,
membership changes, invitation and email challenges, logout-all and command lookup.
Organization analytics and restaurant business routes retain their scoped handlers.
The operator aliases retain their existing five paths and wire models.

The embedded [Auth contract](internal/operatorhttp/auth-contract.json) is a projection
of Factory's composed REG1 public/private documents. It records both source hashes. Regenerate it
with Node and compare the output before changing a contract:

```sh
node scripts/sync-auth-contract.mjs /path/to/factory/docs/api/registration-v1-composed-public.json \
  /path/to/factory/docs/api/registration-v1-composed-private.json internal/operatorhttp/auth-contract.json
```

Gateway rejects unknown or duplicate fields at every JSON depth, invalid path/body
identities, unsupported queries, duplicate browser cookies and internal credentials.
Command lookup permits only one `namespace` and one `commandID`, preserving their
original encoded values. The namespace remains Auth's opaque canonical value.
Successful and error responses are validated before projection. Response identities
must match the request, including nested challenge IDs and the one restaurant of a
restaurant deletion. Email validation preserves the Auth protocol's ASCII address
grammar, dotted domain and 254-character bound.

Session-issued replies install the session in an HttpOnly, SameSite=Strict cookie.
Their public body contains only UserView. Preauth issuance likewise returns only the
public CSRF token. Successful logout, logout-all and password changes clear the
session cookie. Uncertain changes install or clear no success cookie and perform no
automatic replay. Clients retain command identity, original input and scope.
V2 rate-limit errors preserve the frozen Auth response even when it contains no
Retry-After; an included header or delay detail must be consistent and valid.

In Auth/v2 topology, set `WAREHOUSE_URL` to the Warehouse private listener, usually
`http://warehouse:8082`. Its public port 8080 serves health only. The legacy topology
still uses the public Warehouse listener described below.

The real-service runner requires an isolated synthetic stand, Node 24, a local
Mailpit receiver and a private JSON credentials file containing `login` and
`password`. It reads no provider environment variables. It uses public Gateway
HTTP for setup, real Auth cookies/CSRF and synthetic OTP mail. No Auth store, JWT or
membership is fabricated. Credentials and state files must be private; retain the
state directory on failure. Reports contain status/coverage only.

```sh
node tests/integration/auth-facade.mjs --origin http://127.0.0.1:18880 \
  --mailpit http://127.0.0.1:18825 --credentials /private/credentials.json \
  --state-dir /private/facade-run
```

The runner creates synthetic organizations/users and deletes one organization after
checking its lifecycle. It preserves another organization to verify scope isolation.
Use it only on a disposable test stand. A retained run resumes completed setup;
expired session/challenge bindings require inspection before another attempt.
This HTTP matrix does not establish browser acceptance or full Factory J1/E/J2.

After the full matrix, add `--phase password-limit` with the same arguments to
check the fifth incorrect-password revocation and the sibling-session cooldown.
The phase report keeps retained rows on resume and states how many fresh HTTP
requests ran. A reused report is historical evidence, not a new runtime run.

### Backend v2 restaurant authorization (G2)

An expired or invalid browser session cannot block a new login. On `GET /api/v2/csrf` and its operator alias, a confirmed Auth `401 Unauthenticated/not_committed` clears that session cookie and retries the read once without the session. The response contains only CSRF data; the new preauth stays in its HttpOnly cookie. Active sessions are retained. Transport, storage and other Auth failures do not downgrade to anonymous access.

Auth mode requires `SERVING_SERVICE_KEY`, `WAREHOUSE_SERVICE_KEY`, and
`FEEDBACK_SERVICE_KEY` in addition to the Auth credential. Configure the three
service URLs as private listener origins with no path, query, fragment, or user
information. Normal HTTPS certificate and hostname checks apply. Plain HTTP is
limited to loopback or the isolated synthetic test network described above. The
legacy topology retains its existing listener configuration.

Business routes use `/api/v2/r/{restaurantID}/warehouse/*` and
`/api/v2/r/{restaurantID}/serving/*`. The restaurant ID must be a canonical UUIDv4.
Only composed contract operations are public. Gateway maps each operation to its
required capability and fixed audiences. Serving receives Serving and Warehouse
audiences for authorized consumer calls. This does not expose consumer paths to
the browser or grant public stock/writeoff access. Every dispatch obtains a fresh
Auth decision. Unavailable, revoked, or inconsistent authorization blocks dispatch.

Unsafe requests need the exact single Origin and CSRF header. Gateway compares
the token with Auth's current session/preauth CSRF result before requesting the
business token. Business requests install no success cookie. Gateway rejects
browser internal credentials and removes browser identity, role, tenant, cookie,
CSRF, and activity headers before dispatch. It supplies the Auth-issued bearer
token and configured peer key. A declared `X-Umir-Runtime-Epoch` is the original
command epoch and is validated, then preserved. No body, query override, header,
wildcard, or default restaurant assigns a scope.

The embedded `internal/httpapi/scoped-contract.json` records the exact composed REG1
profile SHA-256. It retains the C2/UA1 operation mappings and adds supply suggestions.
The predecessor authorization and scoped recommendation schemas change explicitly;
unrelated predecessor schema definitions remain unchanged. Original C2/UA1 artifacts
and evidence keep their own identities. The generator retains every reachable schema.
Inputs reject unknown/duplicate keys, nulls, trailing JSON, invalid text, duplicate
query values, and raw semicolon separators. Business bodies are limited to 1 MiB;
Feedback bodies to 16 KiB. Ordinary business bodies and raw query strings retain
their exact bytes after validation. Current Auth settings do not replace a saved
command's settings or reject retained retries in Gateway. The business owner
resolves the original command and epoch before applying fresh-form settings checks.
Validated replies retain exact decimal strings and original instants. Wrong scope,
malformed replies, and transport failures fail closed. A lost modifying reply
remains unknown; Gateway does not retry or generate another command.
Serving resolution replies must match the saved `runtimeEpoch` query. A mismatched
successful reply becomes unavailable; an authoritative `RuntimeReset` remains
indeterminate. Scope-bearing error details must identify the authorized restaurant
or its organization. Auth rate-limit refusals preserve retryability, retry details,
and the validated `Retry-After` delay through both CSRF and authorization checks.

`POST /api/v2/r/{restaurantID}/feedback` wraps the original submission values with
Auth-verified User/org/restaurant context for Feedback. The anonymous endpoint
`POST /api/v2/feedback/anonymous` stays unscoped even when cookies are present and
uses a separate Auth-issued anonymous token. Scoped reads and exports check the
reply tenant and every saved item's scope. Feedback owns durable namespaces,
fingerprints, exact retries, and delivery jobs; Gateway stores no feedback state.

`GET /api/v2/orgs/{orgID}/analytics/summary` requires own-org Admin access for every
explicit `restaurantID` before any report dispatch. Supply one to 100 distinct
restaurant IDs and `expectedSettingsVersion`. Gateway requests separate stock and
movement reports and follows all pages within a five-second budget per restaurant.
Page context, identity, settings, cutoff/period, and coverage must remain identical
within each report. Duplicate/unordered rows, empty continuing pages, repeated
cursors, drift, and unavailable pages make that restaurant unavailable. Complete
arrays omit the cursor and can exceed 500 rows. No quantities or units are summed.
Each report has a 32 MiB aggregate response budget and each peer response is bounded
to 8 MiB; exceeding a budget is explicit unavailable rather than truncation. The
response preserves restaurant input order and returns `complete`, `partial`, or
`unavailable`. An unavailable restaurant never becomes a zero report. The two
reports retain their own versions and observation times.

Verify G2 with `GOWORK=off go test -race -count=1 ./internal/httpapi/...
./internal/adapters/... ./cmd/server/...` (one command), then `make check` and
`make quality-test`. G2 tests use synthetic Auth and business HTTP peers. Scheduled
expiry is described below. Runtime acceptance requires the real five-service
J1/E assembly.

### Scoped live streams

In Auth mode, `GET /api/v2/r/{restaurantID}/live` serves the frozen C2 SSE contract.
Use the session cookie and optional `cursor` query parameter. A reconnect may use
`Last-Event-ID` instead. Supplying both, duplicate query parameters, internal
credentials, or a noncanonical restaurant ID is rejected before streaming.
An unknown, modified, cross-restaurant, or cross-session cursor returns 403 and
replays no event bytes. Cursors are bound to the session digest; another device
session must start a fresh connection even when it belongs to the same User.

Each SSE event name equals its JSON `type`. `change` includes tenantID, Gateway
epoch, an exact decimal sequence string, and invalidated topics. Only changes have
an opaque SSE id. A connection without a cursor, an expired cursor, an overwritten
journal prefix, or a changed runtime generation receives `refresh-required` with
the current Gateway epoch. Start a new read to obtain current business data.
Auth checks run before every event and heartbeat. Idle checks run every four
physical seconds from the start of the latest Auth check, with a one-second Auth
budget inside the five-second cutoff window. Greeting, refresh, replay, change, and
heartbeat writes and flushes share the remaining four-second budget. A stalled
write closes the stream at that deadline; a terminal access-ended write has at most
one second. Initial emission does not postpone the next idle check. No SSE call,
comment, or check extends the session or mints a JWT.

Revocation, deletion, expiry, and unknown/unavailable Auth outcomes emit one
`access-ended` with reason revoked, deleted, session-expired, or auth-unavailable,
then close the stream. A deleted journal cannot be revived. Neighboring restaurant
streams and the global User session remain independent. The scoped stream consumes
current Auth results directly; it does not subscribe to legacy deadline callbacks.

Journals retain at most JOURNAL_CAPACITY changes per restaurant and 10,000 scoped
contexts. Invalidation is conservative: possible/unknown business mutations and
explicit committed Warehouse read preparation invalidate the authenticated
restaurant's catalog, stock, menu, orders, and analytics. Definite rejected writes
without committed-preparation metadata do not invalidate. Summary preparation
uses the same publication path. Committed response status and headers survive
interrupted, oversized, and close-failed bodies; both direct reads and summaries
publish before returning unavailable. Partial response bodies are discarded and
Gateway does not repeat the request. Validated Warehouse/Serving epoch changes reset
only that restaurant's journal generation and signal refresh.

Gateway creates a new UUID epoch on restart. Cursor positions use authenticated
AES-GCM encryption with a random nonce and a domain-separated key derived from
the existing private Gateway-to-Auth transport secret. The cursor includes only a
session digest, scope, epoch, sequence/generation, and a five-minute deadline;
no raw cookie or service JWT is included. A valid cursor from a previous Gateway
epoch remains scope/session-bound and causes refresh, never old replay. Secret
rotation invalidates old cursors; reconnect with current authorization and no
cursor. The in-memory cursor cache holds at most 4096 positions; cursor input is
bounded to 1024 bytes. Gateway does not add an Auth signing key or durable store.

Streams are limited to eight per session and 64 per process. A rejected admission
returns 429 RateLimited with a one-second Retry-After hint. Every write has a five-second deadline. Shutdown
cancels Auth checks, removes subscriptions, stops timers, and waits for stream
owners to finish. The legacy topology retains its original stream implementation.

Verify G4 with `GOWORK=off go test -race -count=1 ./internal/live/...
./internal/journal/... ./internal/httpapi/...` (one command). The regression suite
also covers real loopback HTTP streams, restart cursors, and publication through
the public scoped routes, using synthetic Auth/business transports. Run
`make check` for the complete suite. Real Auth lifecycle/readiness, the scheduler,
and the five-service assembly are verified at the J1/E handoff.

| Входной путь | Путь на upstream |
| --- | --- |
| `/api/serving/healthz` | `serving:8080/healthz` |
| `/api/warehouse/healthz` | `warehouse:8080/healthz` |
| `/api/serving/<path>` | `serving:8080/<path>` |
| `/api/warehouse/<path>` | `warehouse:8080/<path>` |
| `POST /api/feedback` | `POST feedback:8084/feedback`, без query |
| `GET /api/live` | не уходит в upstream: поток SSE самого gateway |
| `/api/warehouse/expiration-runs` | не уходит в upstream: браузер получает `404 NotFound`, маршрут вызывает только планировщик gateway |

Префиксы `/api/serving` и `/api/warehouse` снимаются при передаче запроса. Метод, остальной путь, query, тело, end-to-end заголовки, статус и тело ответа upstream передаются без изменений; hop-by-hop заголовки удаляются, `X-Forwarded-*` выставляет gateway. Исходный RawQuery сохраняется, включая ошибочный `%` или `;`, чтобы HTTP-адаптер сервиса мог отклонить неверные параметры. Публичные бизнес-endpoints принадлежат соответствующим сервисам. `WAREHOUSE_URL` указывает на публичный listener склада; внутренний listener `8082` доступен только serving.

Перед передачей в upstream gateway удаляет свои cookie `umir_operator_session` и `umir_operator_preauth` (и их варианты `__Host-`) и заголовок `X-CSRF-Token`. Строки `Set-Cookie` от upstream с этими именами отбрасываются, остальные cookie проходят без изменений.

## Структура

| Пакет | Ответственность |
| --- | --- |
| `cmd/server` | Чтение настроек, сборка учётной записи, журнала, потоков, прокси и router, ограничение времени upstream, запуск проверки сроков, lifecycle, `healthcheck` и `hash-password`. |
| `internal/config` | Проверка `PORT`, `SERVING_URL`, `WAREHOUSE_URL`, `FEEDBACK_URL`, `UPSTREAM_TIMEOUT`, `JOURNAL_CAPACITY`, `EXPIRATION_RUN_INTERVAL` и настроек `OPERATOR_*`. |
| `internal/httpapi` | `NewRouter(Routes)` над внедрёнными `http.Handler` с обязательным guard, `/healthz`, `/api/live`, запись статусов допущенных изменяющих запросов, конверт ошибок `Problem` с `requestID`, JSON транспортной ошибки. |
| `internal/journal` | Журнал изменений в памяти: кольцевой буфер записей, итог по HTTP-статусу, подписка на возможные изменения. Тела и данные запросов не хранит. |
| `internal/live` | Поток `GET /api/live`: события `change`, `tick`, `session`, `session-ended`, `upstream`, лимиты потоков, события сессий от `internal/operator`. |
| `internal/expiration` | Плановые запуски `POST /expiration-runs` склада, их записи в журнал и доступность склада для потоков. |
| `internal/operatorhttp` | Маршруты `/api/operator/*`, guard бизнес-маршрутов и формы обратной связи, cookie, проверка `Origin` и CSRF, удаление учётных данных оператора перед upstream. |
| `internal/operator` | Учётная запись, сессии, CSRF без входа, лимиты входа, смены пароля и формы обратной связи, режим восстановления; без HTTP и файлов. |
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

`message` предназначено для журналов и разработчиков: текст для пользователя фронтенд выбирает по `code` и кодам `fieldErrors`. `fieldErrors` есть только у ответов `422`, `sessionRevoked` — только у `PasswordChangeRateLimited`. Тот же `requestID` записывается в журнал gateway.

## Реальное время

Экраны `/app` узнают об изменениях из потока SSE `GET /api/live` и перечитывают данные обычными запросами с `X-Umir-Activity: background`. Поток несёт только сигналы; данные остаются в бизнес-маршрутах.

**Журнал изменений.** Gateway хранит в памяти последние `JOURNAL_CAPACITY` записей. Запись появляется после допущенного изменяющего запроса под `/api/serving/` и `/api/warehouse/`, после `PATCH /api/operator/me/display-name` и после запуска проверки сроков. Запись хранит номер, время, источник (`request`, `expiration`, `external`), метод и путь без query, HTTP-статус и итог; тела, cookie, адреса и заголовки не хранятся. Итог определяется только по статусу:

| Статус | Итог | Сигнал потокам |
| --- | --- | --- |
| 2xx, кроме 202 | `success` | есть |
| 202 | `pending` | есть |
| 4xx | `rejected` | нет |
| 5xx, тайм-аут или транспортная ошибка | `unknown` | есть |

Сигнал после `success` может оказаться лишним, например после подготовки заказа: gateway не разбирает тела ответов. У каждого запуска gateway свой `epoch`; после перезапуска журнал пуст и номера начинаются с 1. Несколько реплик gateway не поддерживаются.

**Проверка сроков.** Gateway раз в `EXPIRATION_RUN_INTERVAL` вызывает `POST /expiration-runs` публичного listener склада (gateway#19); новый запуск не начинается, пока не закончен предыдущий. Какие партии истекли, решает склад. Списанные партии дают запись `expiration`. Если версия состояния склада выросла без запросов через gateway — например, просрочку записала обычная операция склада или склад перезапустился, — появляется запись `external`. Неудачный запуск, после которого состояние могло измениться (5xx, тайм-аут), даёт одну запись `unknown` на серию неудач; отказ соединения записи не даёт. После трёх неудачных запусков подряд потоки получают `upstream: false`, после первого удачного — `upstream: true`.

**Поток `GET /api/live`.** Нужна сессия; подключение её не продлевает. Ответ `200` с `Content-Type: text/event-stream; charset=utf-8`, `Cache-Control: no-store` и `X-Accel-Buffering: no`. Первый кадр — `retry: 3000`, затем по порядку:

| Событие | `data` | Когда |
| --- | --- | --- |
| `change` | `{"epoch", "seq"}`, `seq` — десятичная строка | при подключении и после записей с итогом `success`, `pending`, `unknown`; серия записей даёт одно событие с последним номером |
| `tick` | `{"serverTime"}` | при подключении и в начале каждой минуты |
| `session` | `{"idleExpiresAt", "absoluteExpiresAt"}` | при подключении и после продления сессии действием пользователя |
| `session-ended` | `{"reason"}`: `signed_out`, `revoked` или `expired` | выход, отзыв сменой пароля, вытеснение или истечение; затем поток закрывается |
| `upstream` | `{"available"}` | при подключении и при смене доступности склада |

Время — RFC 3339 со смещением `+03:00`. Каждые 15 секунд идёт комментарий `: ping`. Запись клиенту ограничена 5 секундами: клиент, который перестал читать, отключается. Отказы до начала потока используют общий конверт: `401 Unauthenticated`, `403 InvalidOrigin` (`Sec-Fetch-Site` не `same-origin`), `405 MethodNotAllowed`, `429 TooManyStreams` (больше 8 потоков на сессию или 64 на gateway), `503 AuthUnavailable`. Поток не ограничен `UPSTREAM_TIMEOUT`; при остановке gateway потоки закрываются сразу, и браузер переподключается к новому процессу.

## Личный кабинет оператора

Один заранее заведённый оператор входит по логину и паролю (gateway#8). Правила учётной записи находятся в `internal/operator`, HTTP — в `internal/operatorhttp`. Отдельного сервиса, базы данных и внешнего провайдера входа нет.

### Маршруты

| Метод и путь | Доступ | Успешный ответ |
| --- | --- | --- |
| `GET /api/operator/csrf` | Публичный | `200 {"csrfToken"}` — токен живой сессии, а без неё токен анонимного контекста с cookie `umir_operator_preauth`. Сессию не создаёт и не продлевает. |
| `POST /api/operator/session` | `Origin` и токен анонимного контекста или живой сессии | `200 {"operator", "session"}` и новая cookie сессии; прежняя сессия отзывается. Тело: `{"login", "password", "rememberMe"}`, где `rememberMe` — необязательный флаг «Запомнить меня». Cookie выдаётся только после записи сессии в файл. |
| `DELETE /api/operator/session` | `Origin` и токен сессии, без живой сессии — анонимный токен | `204` после записи отзыва в файл, cookie сессии очищается. Повтор безопасен. В режиме восстановления выход без cookie сессии проходит с анонимным токеном из `GET /api/operator/csrf`, а с cookie сессии получает `503 AuthUnavailable`: состояние файла неизвестно, и подтвердить выход нельзя. |
| `GET /api/operator/me` | Сессия | `200 {"operator", "session"}`. Срок бездействия обычной сессии продлевается и записывается в файл до ответа. Если запись точно не удалась, ответ всё равно `200` со сроком, который уже записан в файле, и сессия продолжает работать. С `X-Umir-Activity: background` ответ тот же, но срок не продлевается и файл не пишется. |
| `PATCH /api/operator/me/display-name` | Сессия, `Origin`, `X-CSRF-Token` | `200 {"operator"}`. Тело: `{"displayName"}`. |
| `PATCH /api/operator/me/password` | Сессия, `Origin`, `X-CSRF-Token` | `204`: все сессии, включая текущую, отозваны, нужен новый вход. Тело: `{"currentPassword", "newPassword"}`. `currentPassword` проверяется как есть, без обрезки или нормализации, и должен содержать не больше 32 Unicode code points. Если пауза не активна и новый пароль допустим, большая длина получает `422 PasswordRejected` с `fieldErrors.currentPassword=TooLong`; некорректный UTF-8 в JSON отклоняется с `400 InvalidRequest`. Эти ошибки не запускают проверку учётных данных и не входят в счёт. Пять фактических неверных проверок текущего пароля за 60 секунд, с любых сессий, включают паузу смены пароля на 60 секунд: пятая ошибка отзывает только свою сессию. Во время паузы смена отклоняется до проверки пароля, а новый вход паузу не снимает. |

`operator` — это `{id, login, displayName}`. `session` — это `{expiresAt, idleExpiresAt, absoluteExpiresAt, rememberMe, csrfToken}`, время в RFC 3339 со смещением `+03:00`. Срок бездействия никогда не позже абсолютного, поэтому `expiresAt` равен `idleExpiresAt`. Ответы `/api/operator/*` не кешируются (`Cache-Control: no-store`).

### Сессии, cookie и CSRF

- Обычная сессия живёт 30 минут без активности и не дольше 8 часов от входа. Успешно допущенный бизнес-запрос сохраняет продлённое время активности до dispatch; после перезапуска срок не откатывается. Ошибка записи блокирует dispatch с `503`. `GET /api/operator/me` продлевает срок бездействия по описанному выше правилу, но не дальше абсолютного; `GET /api/operator/csrf` срок не продлевает. Фронтенд продлевает сессию только по действию пользователя, без фоновых таймеров (ГОСТ Р 52872-2019, 2.2.1). Запросы, которые пользователь не вызывал (перечитывание по сигналу потока или по такту), несут `X-Umir-Activity: background`: они проходят те же проверки, но сессию не продлевают и файл не пишут. Значение имеет только точное `background`; заголовок не уходит в upstream.
- Вход с `"rememberMe": true` («Запомнить меня») открывает сессию ровно на 30 дней от входа. Активность, `/me` и перезапуск этот срок не сдвигают; новый 30-дневный период начинается только с нового входа по паролю.
- Все сессии хранятся в файле учётной записи и переживают перезапуск gateway, пока не истёк их срок и не сменился пароль. В файле хранится SHA-256 токена сессии, а не сам токен; CSRF-токен сессии вычисляется из её токена и после перезапуска остаётся прежним. Продление срока бездействия обычными бизнес-запросами сохраняется до их передачи upstream. Вход, выход, вытеснение и смена пароля записываются до ответа.
- Одновременно живут не больше 32 сессий обоих режимов вместе; при переполнении вытесняется самая старая, и это тоже записывается в файл. Анонимные контексты (до 1024 на 30 минут), счётчики неудачных входов и неверных паролей и счётчики формы обратной связи хранятся только в памяти и сбрасываются при перезапуске. Несколько реплик gateway не поддерживаются.
- Cookie ставятся с `HttpOnly`, `SameSite=Strict`, `Path=/`, без `Domain`. У обычной сессии cookie без срока, браузер обычно удаляет её при закрытии (некоторые браузеры восстанавливают такие cookie, поэтому закрытие браузера не доказывает выход). Cookie «запомненной» сессии получает `Expires`, равный её сроку, и `Max-Age` с оставшимися секундами (сначала 2592000). В режиме `secure` имена `__Host-umir_operator_session` и `__Host-umir_operator_preauth` с атрибутом `Secure`, в `loopback-development` — `umir_operator_session` и `umir_operator_preauth` без него.
- Каждый изменяющий запрос — вход, выход, изменения профиля и бизнес-запросы `POST`, `PUT`, `PATCH`, `DELETE` — несёт `Origin`, точно равный `OPERATOR_PUBLIC_ORIGIN`, и токен в `X-CSRF-Token`. `Sec-Fetch-Site`, если браузер его прислал, должен быть `same-origin`. Заголовки `X-Forwarded-*` в этих проверках не участвуют.

### Бизнес-маршруты

Guard проверяет каждый запрос под `/api/serving/` и `/api/warehouse/` до отправки в upstream:

| Метод | Требуется | Возможный отказ |
| --- | --- | --- |
| `GET`, `HEAD`, `OPTIONS` | Сессия | `401 Unauthenticated`, `503 AuthUnavailable` |
| `POST`, `PUT`, `PATCH`, `DELETE` | Сессия, точный `Origin`, `X-CSRF-Token` этой сессии | ещё `403 InvalidOrigin`, `403 InvalidCsrfToken` |
| Остальные | — | `405 MethodNotAllowed` с заголовком `Allow` |

Отказ guard означает, что upstream запрос не получал: после входа его можно повторить с тем же `commandID`. Допущенный изменяющий запрос попадает в [журнал изменений](#реальное-время) с итогом по статусу ответа. Если сессия истекла, когда запрос уже передан в upstream, он завершается как обычно. Транспортные ошибки прокси по-прежнему возвращают `outcome`.

### Форма обратной связи

`POST /api/feedback` — публичная форма (gateway#10), сессия не нужна. Обращения принимает и хранит приватный сервис `umir-feedback` по `FEEDBACK_URL`, у него нет порта на хосте. Gateway передаёт ему только этот путь как `POST /feedback`, без query; другие пути сервиса наружу не открыты. До передачи gateway проверяет:

1. метод `POST`, иначе `405` с `Allow: POST`;
2. точный `Origin` и `Sec-Fetch-Site`, как у других изменяющих запросов, иначе `403 InvalidOrigin`;
3. `X-CSRF-Token`: токен живого анонимного контекста из `GET /api/operator/csrf` с его cookie или токен сессии вошедшего оператора. Иначе `403 InvalidCsrfToken`. Вход удаляет анонимный контекст браузера, поэтому форма, открытая до входа, получит `403`: нужно снова взять токен из `GET /api/operator/csrf` и повторить отправку с тем же `submissionID`, запрос до сервиса не доходил. Проверка не продлевает сессию;
4. лимиты: 5 обращений за 10 минут на один CSRF-контекст (анонимный или сессию) и 60 за 10 минут на весь gateway, иначе `429 FeedbackRateLimited` с `Retry-After` до освобождения места. Считаются все обращения, прошедшие проверку токена, в том числе отклонённые дальше по телу; отклонённые до неё и ответы `429` не считаются. Новый анонимный контекст получает свои 5 мест, общий лимит остаётся. Это ограничение первой версии, а не защита от направленного спама; IP и User-Agent не хранятся;
5. тело: `application/json`, не больше 16 КиБ, один JSON-объект в UTF-8, иначе `415`, `413` или `400 InvalidRequest`. Тело читается в пределах `UPSTREAM_TIMEOUT` всего обмена; не дошедшее за это время тело получает `400 InvalidRequest` до передачи. Содержимое проверяет сервис.

Отказ gateway означает, что сервис запрос не получал. Сервису уходят метод и тело без изменений, без cookie и `X-CSRF-Token`. Его ответы, например `201 {"submissionID", "receivedAt"}`, передаются клиенту без изменений, кроме cookie оператора. `201` означает, что обращение сохранено, а не что уведомления доставлены. Gateway не повторяет запрос: таймаут или разрыв после передачи — неизвестный исход (`504 UpstreamTimeout` или `502 UpstreamUnavailable` с `outcome: unknown`), и клиент повторяет обращение с тем же `submissionID` и содержанием.

### Ошибки

| Код | Статус | Когда |
| --- | --- | --- |
| `InvalidRequest` | 400 | Тело не JSON-объект нужной формы: синтаксис, лишние или отсутствующие поля, ключ в другом регистре, повтор ключа, `null` вместо значения, данные после объекта, некорректный UTF-8 или одиночная суррогатная escape-последовательность. JSON-декодер молча заменил бы их на `U+FFFD`, поэтому они отклоняются до разбора. |
| `InvalidCredentials` | 401 | Любое несовпадение логина или пароля; ответ не показывает, существует ли логин. |
| `Unauthenticated` | 401 | Нет живой сессии. |
| `InvalidOrigin`, `InvalidCsrfToken` | 403 | Изменяющий запрос пришёл не из публичного origin или без верного токена. |
| `CurrentPasswordIncorrect` | 403 | Неверный текущий пароль, ничего не изменено; с первой по четвёртую ошибку за 60 секунд. |
| `NotFound`, `MethodNotAllowed` | 404, 405 | Неизвестный маршрут кабинета или неподходящий метод. |
| `PayloadTooLarge`, `UnsupportedMediaType` | 413, 415 | Тело больше 8 КиБ (у формы обратной связи — 16 КиБ) или не `application/json`. |
| `InvalidDisplayName`, `PasswordRejected` | 422 | Поле не прошло проверку; код причины в `fieldErrors`. |
| `FeedbackRateLimited` | 429 | Лимит формы обратной связи: 5 за 10 минут на CSRF-контекст или 60 за 10 минут на gateway. `Retry-After` — секунды до освобождения места. |
| `LoginRateLimited` | 429 | Пять неудачных входов за 60 секунд включают паузу на 60 секунд для любого входа, или очередь проверки пароля заполнена. `Retry-After` — секунды до повтора. |
| `PasswordChangeRateLimited` | 429 | Пятый неверный текущий пароль за 60 секунд или смена пароля во время паузы; пароль не изменён. `Retry-After` — секунды до конца паузы. `sessionRevoked: true`: этот ответ отозвал сессию, записал отзыв в файл и очистил cookie, нужен новый вход. `sessionRevoked: false`: этот ответ сессию не отзывал, недоступна смена пароля; сессия могла закончиться сама, это покажет следующий запрос. Если отзыв не записался, вместо `429` приходит `503 SessionStorageUnavailable` или `503 SessionUpdateOutcomeUnknown`, а пауза всё равно началась. Успешная смена пароля обнуляет счёт неверных паролей. |
| `AuthUnavailable` | 503 | Режим восстановления или внутренний сбой проверки. |
| `SessionStorageUnavailable` | 503 | Вход, выход или отзыв сессии после пятого неверного пароля не записались в файл; сессии не изменились, cookie не выдаётся и не очищается. После пятого неверного пароля пауза смены пароля при этом уже началась. |
| `SessionUpdateOutcomeUnknown` | 503 | Неизвестно, записалось ли изменение сессии; gateway переходит в режим восстановления. |
| `AccountStorageUnavailable` | 503 | Запись файла не удалась до фиксации: ничего не изменено, сессии работают. |
| `AccountUpdateOutcomeUnknown` | 503 | Неизвестно, записалось ли изменение; gateway переходит в режим восстановления. |

Ответы `401` содержат `WWW-Authenticate: Session realm="umir-operator"`: RFC 9110 требует вызов в каждом `401`, а браузер на незнакомую схему окно входа не показывает.

Коды `fieldErrors`: `Required` (пусто), `TooShort`, `TooLong`, `InvalidCharacters` (управляющие символы). Отображаемое имя после удаления пробелов по краям и нормализации NFC должно содержать 2–80 кодовых точек. Пароль — 8–32 кодовые точки; он хранится и сравнивается ровно в том виде, как введён, без обрезки и нормализации. Буквальный символ `U+FFFD` допустим везде.

### Режим восстановления

Если неизвестно, записалось ли изменение учётной записи или сессии, gateway отвечает `503 AccountUpdateOutcomeUnknown` или `503 SessionUpdateOutcomeUnknown` и до перезапуска отказывает во входе, `/me`, изменениях профиля и бизнес-маршрутах (`503 AuthUnavailable`). Работают только `/healthz`, анонимный `GET /api/operator/csrf` и выход без cookie сессии.

Чтобы восстановить работу, проверьте файл учётной записи на томе и перезапустите контейнер. Корректный файл загружается как есть, вместе с действующими сессиями. Повреждённый файл останавливает запуск и никогда не перезаписывается автоматически.

Если ответ на изменение просто потерян, а gateway работает, исход проверяют так: имя — через `GET /api/operator/me`, пароль — входом с новым паролем.

### Файл учётной записи и первый запуск

`OPERATOR_STORE_PATH` указывает на JSON-файл на смонтированном томе; в образе это `/data/operator/account.json`. Каталог `/data/operator` создан в образе с правами `0700` для пользователя `65532:65532`, и новый именованный том получает эти права при первом подключении.

Файл с правами `0600` содержит `schemaVersion` (2), `profileID`, `login`, `displayName`, `passwordHash` (PHC Argon2id), `credentialVersion` и `sessions` (не больше 32 записей; превышение отклоняется при загрузке). Запись сессии — это `digest` (SHA-256 токена), `rememberMe`, `credentialVersion`, `createdAt`, `lastSeenAt` и `expiresAt` (UTC). Ключи проверяются точно, с учётом регистра. Файл схемы 1 без сессий при первом запуске проверяется и один раз переписывается как схема 2; если запись не удалась, запуск останавливается, а файл не меняется. Образы до этой версии файл схемы 2 не читают: для отката на такой образ нужна копия файла схемы 1, сделанная до обновления.

При запуске срок сессии из файла не превышает срок, настроенный сейчас для её режима: после уменьшения `OPERATOR_ABSOLUTE_TIMEOUT` и перезапуска старые обычные сессии тоже укорачиваются. Если системные часы отступили назад, время активности записывается не раньше времени создания сессии, и gateway не записывает файл, который сам не смог бы прочитать.

Файл и каталог должны принадлежать пользователю процесса и не быть симлинками, иначе gateway не запустится. Изменение записывается во временный файл, затем `fsync`, `rename` и `fsync` каталога. Удаление тома сбрасывает учётную запись. Для резервной копии достаточно скопировать файл при остановленном gateway. После восстановления старой копии очистите её сессии командой образа при остановленном gateway, иначе снова заработают сессии, из которых с тех пор вышли:

```sh
docker compose run --rm app clear-sessions
```

Команда проверяет только учётную запись, поэтому чинит и файл, записи сессий которого gateway не принимает.

Если файла нет, gateway создаёт его из `OPERATOR_BOOTSTRAP_LOGIN`, `OPERATOR_BOOTSTRAP_DISPLAY_NAME` и `OPERATOR_BOOTSTRAP_PASSWORD_HASH`. Существующий файл главнее этих настроек. Хэш пароля даёт команда образа; пароль вводится дважды без эха и никуда не записывается:

```sh
docker run --rm -it ghcr.io/justikra/umir-gateway:sha-<SHA> hash-password
```

Без терминала команда читает из stdin ровно одну строку и печатает только PHC-строку. В `.env` для Compose значение пишется в одинарных кавычках, иначе Compose подставит переменные вместо символов `$`.

### Персональные данные

Файл учётной записи хранит логин и отображаемое имя оператора, хэш пароля и для каждой сессии хэш её токена, режим и время входа, последней записанной активности и окончания. Пароль в открытом виде нигде не сохраняется. Журналы содержат только `requestID`, метод, путь и код ошибки — без паролей, хэшей, cookie, CSRF-токенов и тел запросов. Данные хранятся, пока существует том.

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

## SSE regression checks

The legacy SSE test client has a bounded request context. Its greeting helper waits for the injected clock's three initial timers before a test advances owner time. Non-positive fake timers fire immediately. Expiry requires both the terminal event and EOF; the existing production stream behavior is unchanged.

CI repeats the expiry, moved-deadline, minute/ping and due-timer race cases 100 times on Linux before `make check`. The full build, lint, architecture and race suite remains required. Run the focused check with `GOWORK=off go test -race -count=100 -timeout=90s ./internal/live -run 'Test(ExpiryEndsTheStreamAfterPeekConfirmsIt|AMovedDeadlineIsReportedInsteadOfAnEnd|TicksFollowTheMinuteAndPingsKeepTheStreamAlive|FakeClockNonPositiveTimerIsReadyWithoutAdvance)$'`.

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
| `FEEDBACK_URL` | `http://feedback:8084`; приватный сервис обратной связи |
| `UPSTREAM_TIMEOUT` | `15s`; общий бюджет на приём тела запроса от клиента и обмен с upstream, формат Go duration. Ограничивает и каждый запуск проверки сроков |
| `JOURNAL_CAPACITY` | `1000`; сколько последних записей хранит журнал изменений, от 1 до 100000 |
| `EXPIRATION_RUN_INTERVAL` | `1s`; период запуска проверки сроков на складе, формат Go duration |
| `GATEWAY_REGISTRY_REFRESH_INTERVAL` | `2s`; период чтения реестра Auth, от 1s до 30s; только режим Auth |
| `GATEWAY_REGISTRY_MAX_AGE` | `30s`; предельный возраст последнего удачного снимка реестра для готовности, не меньше трёх периодов чтения; только режим Auth |
| `GATEWAY_INSTANCE_ID` | случайный UUID; имя реплики в `/readyz`, 1-128 видимых ASCII-символов без пробелов; только режим Auth |
| `GATEWAY_EXPIRATION_CONCURRENCY` | `8`; сколько ресторанов планировщик проверяет одновременно, от 1 до 256; только режим Auth |
| `GATEWAY_EXPIRATION_ITERATION_BUDGET` | `10s`; сколько времени итерация планировщика начинает новые проверки, от 1s до 5m; не успевшие рестораны проверяются первыми в следующей итерации; только режим Auth |
| `GATEWAY_LIVE_RING_CAPACITY` | `128`; сколько последних изменений хранит кольцо повтора одного ресторана, от 16 до 4096; память выделяется при первом изменении ресторана; только режим Auth (`JOURNAL_CAPACITY` относится к старому режиму) |
| `GATEWAY_LIVE_MAX_STREAMS` | `64`; сколько потоков SSE одновременно держит процесс, от 1 до 100000; только режим Auth |
| `GATEWAY_LIVE_MAX_STREAMS_PER_SESSION` | `8`; потоков SSE на одну сессию; только режим Auth |
| `GATEWAY_LIVE_MAX_STREAMS_PER_ORG` | `32`; потоков SSE на одну организацию, чтобы одна организация не заняла весь процесс; слот организации занимается после первой проверки доступа; только режим Auth |
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

### Scoped due-expiry scheduler and private runtime (G5)

Private runtime status uses the last successful complete Auth registry snapshot and the local registration table. It performs no synchronous call to Auth. A separate refresher reads the registry every `GATEWAY_REGISTRY_REFRESH_INTERVAL` (default `2s`, 1s to 30s); a failed read keeps the previous snapshot, and a snapshot older than `GATEWAY_REGISTRY_MAX_AGE` (default `30s`, at least three refresh intervals) makes readiness false until the next successful read. The scheduler takes the registry from the refresher instead of reading it, so a slow or stalled scheduler iteration never affects readiness. Registration (`PUT .../registry`) answers from a snapshot that is at most 2 seconds old and holds the restaurant; otherwise one registry read is shared by all concurrent registrations, and a verdict that would be 409 or 410 is confirmed by a read made after the request arrived (concurrent callers share such a read). A restaurant Auth deleted less than 2 seconds ago may therefore still be accepted when the request matches the snapshot; Auth closes it with its next call. Reads refresh the snapshot, later-started reads take precedence over earlier completions, and callers receive independent copies.

`GET /readyz` on the public listener (never proxied by the frontend) answers `{"instance":"<GATEWAY_INSTANCE_ID>","capabilities":{"http":"ok","scheduler":"ok|degraded|down"}}` with status 200 while the process serves. `GATEWAY_INSTANCE_ID` defaults to a random UUID. The scheduler state follows the time since its last successful iteration (`degraded` after three scheduler intervals or any failed iteration, `down` after ten) and never changes the status code; the details are written to the log once per state change. `GET /healthz` only says that the process is alive. The image healthcheck probes `/readyz` in Auth mode and `/healthz` in the legacy mode.

Each restaurant must have the matching local lifecycle version; deleting scopes and tombstones must be closed locally. Status does not require Auth to echo Gateway's own acknowledgment back before reporting that local registration is ready. Auth reads this status while reconciling and recording that acknowledgment. Restaurant commands still require fresh Auth authorization, and registration still checks fresh Auth state and signed control claims.

Gateway is the sole scheduled expiry owner. In Auth mode it polls immediately
after process start, then at `EXPIRATION_RUN_INTERVAL` (default `1s`). One process
goroutine owns all runs; a slow run delays later ticks and never overlaps them.
Within a run, up to `GATEWAY_EXPIRATION_CONCURRENCY` restaurants (default 8) are
dispatched in parallel and the run waits for all of them. After
`GATEWAY_EXPIRATION_ITERATION_BUDGET` (default `10s`) no new dispatch starts; the
next run begins with the first restaurant left undone, and a run cut this way is
logged; as long as it served at least one restaurant it counts as progress (scheduler state `degraded` while the cuts continue, never `down` for this reason alone).
Each cycle takes the complete Auth registry from the refresher and reads fresh Warehouse status. The runner
requires a ready restaurant, current Warehouse readiness, and acknowledgments
for Gateway’s current epoch and Serving. Each attempt has a maximum five-second
budget and uses an Auth service token for `expiry.due`, one restaurant, and that
Warehouse epoch; a token is reused until ten seconds before it expires. It never requests a human session, registration token,
or `writeoff.confirm`. Credential failure causes no Warehouse dispatch.

Every due poll has a new UUID run ID. There is one POST per selected tenant per
cycle and no transport replay. Missed ticks recover through the next due poll;
Warehouse owns the atomic idempotent transition. A lost or malformed response
keeps the outcome unknown and invalidates only that restaurant once until a
successful observation. Recovery publishes another stock, menu, and analytics
invalidation before saving the observed version, even if that poll has no new
transitions. A failed journal append retains the unknown state for the next poll.
A verified `not_committed` refusal causes no change.
Successful pending transitions invalidate stock, menu, and analytics. No final
writeoff is permitted. Scheduler failure does not change browser authorization
or the public health endpoint. Shutdown cancels and joins the runner.

Auth mode also requires `AUTH_RUNTIME_SERVICE_KEY`, a separate Auth-to-Gateway
transport secret. `PRIVATE_LISTEN_HOST` defaults to `127.0.0.1`; `PRIVATE_PORT`
defaults to `8086` and must differ from public `PORT`. Factory must bind the
private listener on its isolated backend network and must not publish that port.
Use TLS with certificate validation outside the isolated test network. The public
listener does not expose private runtime routes. Keep credentials out of logs,
browser requests, and source-controlled environment files.

The private surface is `GET /internal/gateway/v2/runtime` and
`PUT|DELETE /internal/gateway/v2/r/{restaurantID}/registry`. Status reports the
current Gateway UUID epoch, local reconciliation readiness from the bounded registry projection, and packaged Go 1.26.9
tzdata identity. Mutation additionally verifies the Auth Ed25519 signature,
60-second lifetime, exact Gateway audience, Auth caller, restaurant, epoch,
lifecycle version, and register/close permission. Registration checks fresh Auth
registry state; a deleting scope or retained local tombstone cannot reopen. Exact
registration preserves the journal. Close is idempotent, retains a tombstone, and
closes the restaurant journal/SSE context. Auth owns reconciliation and retries.

For the no-frontend lane handoff run `GOWORK=off go test -race -count=1
./cmd/server/... ./internal/expiration/... ./internal/adapters/...
./internal/httpapi/... ./internal/live/... ./internal/journal/...`, `make check`,
`make quality-test`, `go mod verify`, and `go mod tidy`. Local tests use synthetic
HTTP peers and signing keys. J1/E must use real Auth, Gateway, Warehouse, Serving,
and Feedback plus synthetic delivery infrastructure. No real-service acceptance
is implied by the local checks.

### Test-owned operational fixture (protocol 1.1.0)

`tests/fixtures/server` composes the real remote Auth client, scoped API,
Gateway runtime, journal, live streams and sole expiration scheduler. The wrapper
uses one controlled clock for token expiry and key refresh, cookie time,
scoped admission, journal time, live authority/timers and scheduler credentials.
Production composition keeps its default system clock and no iteration observer.

Build with Go 1.26.9 and `GOWORK=off`:

```sh
go build -trimpath -o /tmp/fixture-server ./tests/fixtures/server
go build -trimpath -o /tmp/fixture-control ./tests/fixtures/control
docker build --pull=false -f tests/fixtures/Dockerfile -t gateway-fixture:local .
```

The image runs as UID/GID 65532. Its entrypoint is `/fixture-server`, command
`serve`, and healthcheck `/fixture-server healthcheck`. Mount the generated
owner config directory read-only at `/run/umir-fixtures/config` and private
0600 credential files at `/run/umir-fixtures/secrets`. Use the exact
`OwnerConfig` schema embedded in `tests/fixtures/protocol/protocol.schema.json`.
The embedded snapshot has SHA256 `3fd4016cfb395c80b9492727b4d60f12b370355f81fd3356abc84984035a044c`.
Fixture compilation uses the pinned jsonschema/v6 v6.0.2 custom-regexp hook
with regexp2 v1.11.0 in ECMAScript mode. Format assertion stays enabled.
Each validation owns its compiled regex instances and budget: at most 1 MiB
of JSON, 4096 matches, and a 500 ms validation deadline. Each match has a
100 ms regexp2 timeout (its clock checks have approximately 100 ms granularity).
Compilation uses a two-second budget. A match timeout, work limit or runtime
error aborts the enclosing validation, including negation and alternative
branches. The pinned engine's dot class cannot establish ECMAScript matching
for U+2028/U+2029. Such a match also rejects the enclosing admission without
changing the authoritative regex. Failed compilation rejects admission. Concurrent controls share no
mutable match budget. These limits use physical time for resource control;
business clock behavior is unchanged.

The exact reviewed Feedback namespace/submission pairs validate as schema inputs.
Gateway returns `UnsupportedOperation` before mutation or cache insertion.
The lint policy permits regexp2 only in `tests/fixtures/protocol/*.go`.
The architecture policy registers it as a vendor used only by fixture-protocol.
Production, fixture server and fixture control cannot import it directly.
`make quality-test` checks the positive protocol import and both effective
gates at each forbidden boundary. Existing component edges, peer-module
denies and unknown-package rejection remain enforced.

Gateway requires `gateway-auth`, `auth-gateway`, `gateway-warehouse`,
`gateway-serving`, `gateway-feedback` and separate `fixture-gateway` credentials.
Service URLs name the owned project services; the public Origin is the runner's
loopback Origin. The config uses private port 8082, public port 8080, no state
file and null bootstrap. Do not put credential values in config, arguments,
environment or evidence. The helper checks file/socket modes and UID/GID.

Both server and control open private inputs with nonblocking, no-follow descriptor
admission. They reject nonregular files (including FIFOs without writers), wrong
UID/GID, unsafe modes and oversized files before bounded reading. Credentials
require exact 0600 mode and at most 64 bytes; owner config is at most 1 MiB.

The wrapper creates a 0700 control directory and 0600 Unix socket at
`/run/umir-fixtures/control.sock`. Only this socket serves
`POST /fixture/v1/control`. The business and private service listeners do not
register fixture controls. Feed one strict request to `/fixture-control request`
on stdin. The helper reads its local credential and validates the response.
Supported operations are `fixture.ready`, `clock.read`, `clock.set`,
`clock.checkpoint` and `scheduler.tick`. The protocol rejects duplicate/unknown
fields, invalid text, trailing values, depth above 16 and requests over 16 KiB.
It bounds responses to 256 KiB, concurrency to eight, requests to ten seconds
and scheduler completion waits to five seconds. Each process retains at most
256 request identities without eviction. Exact replay returns the original
response; changed payload under an existing identity conflicts. Capacity
exhaustion fails closed, including healthcheck requests; keep fixture runs bounded.

`fixture.ready` requires the observed startup scheduler baseline, healthy injected
consumers and the real private Gateway runtime's readiness. It returns actual
binary/config hashes and implemented capabilities. A completed scheduler iteration
can still have failed its Auth or Warehouse exchange; completion never establishes
business success. New process instances use a fresh instance ID and runtime epoch.
Restore clock instant/generation only from an observed checkpoint in the next
private config. In-memory business state follows the normal owner reset behavior.

`expiration.ScopedOptions.IterationCompleted` is an optional send-only sequence
channel. `Run` counts its synchronous startup iteration as 1. Each received tick
adds one sequence. An outer defer attempts one nonblocking send after the entire
tick, including scope closure, cancellation and final watermark updates. Nil,
full or closed ports drop the observation. An idle/closed/cancelled `Run` exit
without another tick emits no completion. Consumers should drain the channel and
keep it open for the run; a sequence gap cannot prove completion.

The fixture consumes startup sequence 1 before admitting manual ticks. It permits
one outstanding tick ID and FIFO-matches the next actual `Run` completion while
checking instance/generation. A lost observation or interrupted wait invalidates
the binding for that process and returns an unknown effect or unavailable evidence.
It never calls `tick`, dispatches expiry itself, manufactures `DueResult`, signs
credentials or infers completion from transport callbacks. `clock.set` and manual
ticks exclude each other. Advancing the clock releases owner-time live timers but
does not dispatch the scheduler or perform a Warehouse writeoff.

`make check` covers fixture packages and the full fresh race suite. After policy
changes, `make quality-test` checks all production boundaries plus exact fixture
registration, fixture-local imports, peer-module denies and unknown-package failure.
Local probes of this wrapper do not establish real five-service J1/E acceptance.

### Packaged timezone catalog in the isolated fixture

The ordinary test wrapper provides read-only catalog observation for the approved
`umir-owner-profiles/0.1.0-unpublished` amendment at source
`ee5ea052cf8239a40fdc3aba7c97c0a143260be284c390168a75c8afb7770460`.
The control socket accepts `POST /owner-profile/v1` with the existing
`fixture-gateway` credential. This endpoint is separate from RPC 1.1.0. It adds
no RPC capabilities. Gateway has no missing-data profile or `serve-profile` mode.

Run `/fixture-control profile --request /run/umir-fixtures/profile-request.json`.
The fixed request file must be a regular, non-symlink file owned by the fixture
user with mode 0600. Its fields are `amendment`, `project`, `requestID`,
`expectedInstanceID`, `expectedGeneration`, and `action` (`catalog-report`).
Unknown fields, duplicate keys, stale clock identities, path aliases, wrong
credentials, and unready business composition are refused. Up to 64 successful
read IDs are retained. Replaying an ID returns identical report bytes. Changing
its envelope returns `RequestConflict`. Use a fresh ID for a fresh observation.
A report does not grant normal stack readiness or E2E acceptance.

The pinned Go 1.26.9 fixture build parses the actual `zipdata` AST constant from
`GOROOT/src/time/tzdata/zzipdata.go`. It compares its bytes with
`GOROOT/lib/time/zoneinfo.zip` and verifies that the built server contains the
same archive. The scratch image includes the archive and the exact build
provenance at `/usr/local/lib/umir/zoneinfo.zip` and
`/usr/local/lib/umir/catalog-provenance.json`. Provenance binds the toolchain
image/source, executable digest, archive digest/size, and common version
`go1.26.9-embedded`. The build also embeds the sorted fixture-source manifest
digest. Its paths, numeric modes and file digests are recorded in
`/usr/local/lib/umir/fixture-source-manifest.json`; its binding is in
`/usr/local/lib/umir/fixture-source.json`.

Startup and each fresh catalog observation verify the fixed files, running
executable, provenance, ZIP structure, and Moscow timezone data. Startup passes
the measured version into the existing Gateway runtime constructor. No
`ZONEINFO` override is accepted. The final image has no host/system/GOROOT
zoneinfo directory. The runner must inspect image filesystems and mounts, retain
these original build facts, and independently qualify all four real catalogs
and runtime versions before BE-E4-16 can pass. A missing-data refusal is owned
by the separate Warehouse fixture.

The approved Feedback discovery overlay
`b2e3b3824e622d68360d73854f24920c827b9c1aefadf013241ec69262daa02f`
adds no Gateway credential or caller authority. Gateway retains its exact five
service credential references and separate control credential. Source/profile
handoff is separate from actual Auth/Feedback provisioning and J1/E acceptance.

## Composed FIN1 API profile on UA1

The UA1 projection adds GET /api/v2/r/{restaurantID}/warehouse/products/{productID}/batches, GET /api/v2/orgs/{orgID}/members, GET /api/v2/orgs/{orgID}/invitations and POST /api/v2/orgs/{orgID}/invitations/{invitationID}/resend-link. Batch reads require stock.read; organization collections and link administration require current own-org Admin authority. Warehouse and Auth own cursor state, FEFO and mail decisions.

Gateway keeps browser cookie, Origin and CSRF guards, forwards the retained command and query once, and verifies nested scope/product/capture identities. Auth collection RefreshRequired 409, LimitExceeded 503 and ScopeDeleted 410 retain their owner metadata. Link resend receipts must match the route invitation resourceID. Owner or transport uncertainty never generates a new command or automatic retry.

Generate Factory's composed REG1 public/private profiles first. Auth and scoped projections use this same profile. Regenerate the Gateway projections with:

~~~sh
node scripts/sync-auth-contract.mjs REG_PUBLIC REG_PRIVATE internal/operatorhttp/auth-contract.json
node scripts/sync-scoped-contract.mjs REG_PUBLIC internal/httpapi/scoped-contract.json
~~~

For the Auth projection, REG_PUBLIC and REG_PRIVATE are `registration-v1-composed-public.json` and `registration-v1-composed-private.json` (REG1). The scoped projection uses the same REG_PUBLIC, including the REG1 command-ID bound. Both projections record exact input SHA-256 values. The scoped compiler keeps explicit operation/capability/owner bindings and all reachable schemas. Original C2/UA1 inputs and historical evidence remain separate. Run make check, make quality-test, go mod verify and a clean go mod tidy check after regeneration.


## Public registration contract (REG1)

The Auth facade admits the configurable public registration flow from Factory issue 14. Begin email-challenges with purpose registration; complete with displayName/password and optional rememberMe after the existing code verification. Gateway forwards the original command/body, validates the strict REG1 schema and installs the confirmed session using the existing cookie path. Registration rejects newPassword, missing profile fields and path/body challenge mismatches. Auth owns the default-disabled flag, neutral address responses, limits, proof binding and atomic account creation.

Run `make sync-contract FACTORY_API=/absolute/path/to/factory/docs/api` to regenerate both projections together from registration-v1-composed-public.json and registration-v1-composed-private.json. The Auth generator requires version 2.0.0-REG.1 and records both exact source hashes. The scoped generator also requires REG1 and retains the FIN1 business routes and policy. Run make check after regeneration.

### Registration admission limits

Before forwarding registration begin to Auth, Gateway admits at most 30 distinct attempts per socket peer and 3 per preauth context per rolling 10 minutes. Identical body/preauth retries retain their admission so unknown outcomes can be recovered. Rotating preauth cookies still consumes the peer budget. The limiter is synchronized and bounded to 1024 peer and 4096 preauth identities; when full it refuses new identities instead of evicting active budgets. Entries expire after the window. Refusals use `429 RateLimited` and `Retry-After`.

IP identity is the HTTP socket peer. Browser `Forwarded` and `X-Forwarded-For` values are not trusted for admission. Behind Nginx this conservative peer budget is shared by that proxy's visitors. Limits are process-local and reset on Gateway restart; Auth keeps the durable mail, address verification and account quotas. Public registration stays disabled until the deferred Auth storage cleanup is accepted. Strict REG1 input validation precedes admission; unknown purposes, duplicate fields, null passwords, fields from other completion purposes and command IDs over 256 code points are rejected before Auth.

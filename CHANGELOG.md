# Изменения

## [Unreleased]

- Adopt the composed FIN1 profile for supply suggestions and current recommendations. Preserve exact forwarded values, narrow operation audiences and unrelated C2/UA1 schema definitions. Validate capture, period, coverage and reason identities; allow schema-declared null supply coverage without relaxing other input null checks. Keep private recommendation facts inaccessible to browsers.

- Synchronize SSE timer setup before advancing the injected clock, bound test stream reads and require terminal/EOF assertions. Repeat affected race regressions 100 times in Linux CI while preserving production stream behavior.

- Publish the complete queued change burst before waking the SSE test reader.
  Preserve the seq43 assertion and production stream/journal behavior; the
  previous test depended on goroutine scheduling between two notifications.

- Add the UA1 batch, member and invitation reads and resend-link facade.
  Validate nested owner identities, strict queries and invitation receipt targets;
  preserve collection errors and uncertain commands without retry.
- Generate reproducible Auth and scoped projections from the composed UA1 profile.

- Use the resolved platform temporary directory in private-file and Unix-socket
  fixture tests. Keep ownership, exact permissions and symlink rejection checks;
  the macOS-only path previously failed on Linux CI.

- Connect all 29 frozen Auth facade operations in the executable Gateway, including
  access, organizations, settings, memberships, invitations, email challenges,
  logout-all and command recovery. Validate the complete wire projection, canonical
  scope and nested response identities. Keep session/preauth tokens in protected
  cookies, preserve uncertain commands without replay and retain scoped business
  routing. Add a reproducible contract projection and real-service HTTP runner.

- Compute private runtime readiness from a validated Auth registry projection and local registrations without an Auth callback. Expire the projection after five seconds or a later failed read, preserve response ordering and copy isolation, and remove the circular status/acknowledgment dependency. Keep signed, epoch-bound registration and fresh business authorization checks.

- Refresh the exact reviewed observation schema. Use the fixture-only ECMAScript compiler hook with regexp2 v1.11.0, bounded per-call matching, asserted formats and enclosing validation failure on regex errors. Preserve Gateway unsupported Feedback behavior. Register regexp2 only for fixture-protocol in lint and architecture policy. Verify protocol acceptance and production/server/control rejection through the effective quality gates.

- Reject nonregular private fixture inputs without blocking on FIFOs. Check descriptor ownership, mode and size before bounded reads in both server and control consumers.

- Add test-owned Gateway operational fixture server/control binaries and Docker image for protocol 1.1.0. Bind controlled owner time, authenticated Unix-only controls, exact request replay, checkpoints and real runtime readiness.
- Add optional nonblocking scheduler iteration completion sequences after full Run ticks. The fixture matches one outstanding tick ID after the startup baseline; missing observations fail closed. Completion does not imply expiry success.
- Register only fixture server/control/protocol architecture components and narrow fixture import rules. Preserve production edges and peer-module denies; extend quality enforcement scenarios.

- Accept an injected Auth-client clock for control-token expiry, signing-key
  refresh, and scheduler-token validation. Preserve the system-clock default.
  The test wrapper supplies its controlled clock; ordinary composition retains
  the system-clock default. Real-service acceptance remains a separate gate.

- Publish a restaurant-scoped invalidation after unknown scheduler runs recover,
  including recovery polls with no new transitions. Retain the unknown state if
  publication fails, so the next successful poll can notify clients.

- Add an Auth-issued, restaurant/epoch-bound due-expiry scheduler with bounded
  attempts, no final-writeoff authority, and tenant-specific unknown invalidation.
- Add a separate private Gateway runtime listener, Auth signature verification,
  fresh registration checks, idempotent closure, and retained local tombstones.
- Require a separate `AUTH_RUNTIME_SERVICE_KEY` for the Auth-to-Gateway runtime
  caller. Preserve the public browser boundary and legacy topology.

- Preserve committed Warehouse invalidation metadata on response consumption
  failures and publish it before direct-read and summary errors.
- Include initial SSE writes, replay, and flush latency in the Auth cutoff budget.
  Bound stalled sends to the remaining budget and terminal sends to one second.

- Add restaurant-scoped SSE with current Auth checks before each event and bounded
  idle revalidation. Close only the affected scope on revoke/delete; unknown Auth
  outcomes close explicitly without extending sessions.
- Add bounded restaurant journals and encrypted session-bound reconnect cursors.
  Runtime reset/restart requires refresh; cross-scope or altered cursors replay
  no bytes. Preserve invalidation after committed read preparation fails.
- Bound scoped streams and cancel their subscriptions, timers and Auth checks
  at shutdown. Real-service acceptance remains J1/E work; no publication or
  selected image changes.

- Repair legacy realtime invalidation after rejected writes, order session callbacks
  by commit revision, reject incomplete expiration replies, and copy journal paths
  with a 1024-byte UTF-8 boundary. Preserve unknown outcomes and exact instants.

- Validate saved Serving epochs on resolution replies and authorized scope IDs in
  business errors. Preserve Auth retry metadata through scoped CSRF and authorization
  failures. Keep authoritative runtime-reset outcomes indeterminate.

- Add backend v2 restaurant routes with fresh Auth authorization, fixed service
  audiences, private peer credentials, CSRF checks, and frozen wire validation.
- Add trusted scoped Feedback intake/read/export and explicitly unscoped anonymous
  intake. Browser identity overrides never assign a Feedback tenant.
- Add own-org Admin summary composition with complete per-restaurant report pages,
  exact quantities, retained identities, and explicit partial failures.
- Require private Serving, Warehouse, and Feedback credentials and origin URLs in
  Auth topology. Preserve business retry bodies, queries, and original epochs.
  Malformed or unknown replies do not trigger an automatic retry. Scoped replies
  reject cross-tenant envelopes, nested retained outcomes, and Feedback records.

- Reject malformed or overlength Auth `User.email` values before accepting login,
  session reads or profile results. Preserve unknown mutation outcomes and install
  no success cookie. Add valid-email controls and refusal regressions.
- Add the backend v2 Auth session/profile transport selected by `AUTH_URL`, with
  required private credentials, bounded exchanges, strict replies and no mutation
  retries. This mode opens no local account aggregate and has no Auth signer.
- Preserve operator alias bodies, response keys, Origin/CSRF checks and cookie
  policy. Add the corresponding v2 account routes with caller command identities.
  Unknown outcomes do not install or clear success cookies. Background activity
  is passed to Auth without local idle extension.
- Keep the selected legacy topology independent. In Auth mode reject old unscoped
  business/live routes. Scoped authorization and SSE use the frozen v2 contract;
  scheduler wiring remains the following Gateway unit. No selected image or release changes.

- Реальное время для `/app`. Журнал изменений в памяти (`JOURNAL_CAPACITY`, по умолчанию 1000) записывает допущенные изменяющие бизнес-запросы, смену имени оператора и запуски проверки сроков: метод, путь, статус и итог по статусу, без тел и данных запроса. Поток SSE `GET /api/live` передаёт сигналы `change`, минутные `tick`, сроки `session`, `session-ended` и доступность склада `upstream`; он не продлевает сессию, ограничен 8 потоками на сессию и 64 на процесс (`429 TooManyStreams`) и закрывается при остановке.
- Заголовок `X-Umir-Activity: background` у бизнес-запросов и `GET /api/operator/me`: те же проверки без продления сессии и без записи файла учётной записи. Заголовок не уходит в upstream.
- Проверку сроков запускает gateway (gateway#19): `POST /expiration-runs` склада раз в `EXPIRATION_RUN_INTERVAL` (по умолчанию `1s`), без наложения запусков, с бюджетом `UPSTREAM_TIMEOUT`. Браузер получает `404` на `/api/warehouse/expiration-runs`. Требует склада с этим маршрутом.

- Persist ordinary business-session activity before dispatch, so restart preserves the renewed idle deadline. Known or unknown storage failures do not dispatch the business request. Reject account/session aggregates above 32 records and session limits above that bound.
- Align the default private feedback URL with the service listener at port 8084.
- Без активной паузы и при допустимом новом пароле смена пароля отклоняет `currentPassword` длиннее 32 Unicode code points до проверки учётных данных: `422 PasswordRejected` с `fieldErrors.currentPassword=TooLong`. Некорректный UTF-8 JSON по-прежнему получает `400 InvalidRequest`; сервисный слой возвращает `InvalidCharacters` для невалидной строки. В счёт и отзыв сессии входят только фактические неверные проверки пароля.
- Тела запросов кабинета принимают ключи только в точном написании, без повторов и без `null`: `{"RememberMe":true}`, `"rememberMe":null` и повтор `password` получают `400 InvalidRequest` (gateway#8). Раньше JSON-декодер сопоставлял ключи без учёта регистра и брал последний из повторов.
- Информационные ответы upstream (`1xx`, например `103 Early Hints`) тоже не могут установить cookie оператора: gateway убирает такие `Set-Cookie` и из них (gateway#8).

- **BREAKING:** бизнес-маршруты `/api/serving/*` и `/api/warehouse/*`, кроме `GET`/`HEAD` их `/healthz`, требуют сессию оператора; изменяющие методы — ещё точный `Origin` и `X-CSRF-Token`, неподдерживаемые методы получают `405`. Переход: токен из `GET /api/operator/csrf`, вход через `POST /api/operator/session`, затем cookie сессии со всеми запросами и `Origin` с `X-CSRF-Token` с изменяющими. `401` до отправки в upstream означает, что запрос не выполнялся: после входа его повторяют с тем же `commandID`. Для развёртывания нужны `OPERATOR_COOKIE_MODE`, `OPERATOR_PUBLIC_ORIGIN` и том в `/data/operator`, а для первого запуска — `OPERATOR_BOOTSTRAP_*`; без них gateway не запускается.
- **BREAKING:** процесс по умолчанию слушает `127.0.0.1` (`LISTEN_HOST`); образ задаёт `0.0.0.0`, поэтому контейнер доступен в сети Compose как раньше.
- Личный кабинет оператора (gateway#8): вход, выход, профиль, смена имени и пароля, JSON-файл учётной записи на томе, Argon2id (64 МиБ, t=2, p=1), серверные сессии на 30 минут без активности и не дольше 8 часов, «Запомнить меня» (`rememberMe`) на фиксированные 30 дней, лимиты входа, режим восстановления.
- Сессии хранятся в файле учётной записи (схема 2, SHA-256 токена вместо токена) и переживают перезапуск gateway. Файл схемы 1 переписывается как схема 2 при первом запуске. Вход, выход и вытеснение записываются до ответа; при сбое записи — `503 SessionStorageUnavailable` или `503 SessionUpdateOutcomeUnknown`. `/me` записывает продление до ответа, а если запись точно не удалась, сообщает уже записанный срок. При запуске сроки сессий ограничиваются текущими настройками. Команда образа `clear-sessions` очищает сессии после восстановления старой резервной копии и чинит файл с некорректными записями сессий. Откат на образ без схемы 2 требует копии файла схемы 1. Сессия отдаёт `idleExpiresAt` и `absoluteExpiresAt` (gateway#10).
- **BREAKING:** пятый неверный текущий пароль за 60 секунд, с любых сессий, отвечает `429 PasswordChangeRateLimited` вместо `403 CurrentPasswordIncorrect`: он отзывает только свою сессию, очищает её cookie и включает паузу смены пароля на 60 секунд (`Retry-After`, `sessionRevoked: true`). Во время паузы любая смена получает `429` с оставшимся `Retry-After` и `sessionRevoked: false` до проверки пароля. Конверт ошибки получил `sessionRevoked` только для этого кода (gateway#8).
- Публичная форма обратной связи (gateway#10): `POST /api/feedback` передаётся приватному сервису `umir-feedback` по `FEEDBACK_URL` (по умолчанию `http://feedback:8084`) как `POST /feedback`, без query, cookie и `X-CSRF-Token`. До передачи gateway проверяет `Origin`, CSRF-токен анонимного контекста или сессии (без продления сессии), тело до 16 КиБ и лимиты 5 за 10 минут на CSRF-контекст и 60 за 10 минут на процесс (`429 FeedbackRateLimited` с `Retry-After`). Ответы сервиса передаются без изменений, повторов нет.
- Обязательные настройки `OPERATOR_COOKIE_MODE`, `OPERATOR_PUBLIC_ORIGIN`, `OPERATOR_STORE_PATH`; для первого запуска — `OPERATOR_BOOTSTRAP_*`. Команда образа `hash-password` печатает PHC-строку для пароля из stdin, на терминале без эха.
- Собственные ошибки, кроме транспортных, используют конверт `{code, message, fieldErrors, requestID}`; ошибки полей — коды `Required`, `TooShort`, `TooLong`, `InvalidCharacters` (gateway#10). `POST /healthz` получает `405` в этом конверте.
- Gateway не передаёт upstream свои cookie и `X-CSRF-Token` и не даёт upstream установить эти cookie.
- Буквальный `U+FFFD` допустим в пароле, имени и логине. Некорректный UTF-8 и одиночные суррогатные escape-последовательности в JSON отклоняются при разборе (`400 InvalidRequest` для тела запроса, ошибка запуска для файла учётной записи). Ответы `401` содержат `WWW-Authenticate`.
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


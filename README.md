# umir-gateway

Единый API-вход для системы одного ресторана. Gateway передаёт запросы в serving и warehouse; бизнес-правила выполняются в этих сервисах.

## Текущее состояние

Работают `GET /healthz`, проверка контейнера `/server healthcheck`, HTTP-прокси, [личный кабинет оператора](#личный-кабинет-оператора) и [поток изменений `GET /api/live`](#реальное-время).
Бизнес-маршруты требуют сессию оператора. Без сессии доступны только `GET` и `HEAD` для `/healthz`, `/api/serving/healthz` и `/api/warehouse/healthz`, а также публичная [форма обратной связи](#форма-обратной-связи) `POST /api/feedback`.
Gateway не содержит бизнес-правил: он не создаёт `commandID`, не проверяет тела и не повторяет запросы.

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

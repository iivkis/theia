# SmartTheia v1: wire и transport контракт

**Версия:** 1 (pure frame codec и FSM в `crates/theia/src/protocol.rs`; production H2/H3 client/server и ограниченный QUIC-first fallback реализованы). **Область:** прикладной протокол проксирования поверх аутентифицированных TLS/QUIC HTTP-streams. Не собственный аналог TLS или QUIC.

## 1. Transport embedding: SmartTheia XHTTP

Единственный целевой транспорт — собственная реализация SmartTheia XHTTP, не wire-копия Xray XHTTP/VLESS. На каждом inbound явно выбирается один security mode: SmartTheia REALITY (wizard/manual) либо собственный TLS (только ручные X.509 cert/chain и private key). Оба используют один XHTTP и QUIC-first. H2/H3 — нижележащие HTTP стеки, не разные транспорты. ADR-0085. Один frame/FSM поверх двух стандартных HTTP носителей; legacy streaming POST остаётся явно версионированным stream-one совместимым режимом. Новый stream-up — отдельные HTTP upload/download на одном проверенном соединении. SmartTheia REALITY — самостоятельный security adapter, не Xray REALITY. Ни один режим не считается автоматически эквивалентным другому.

| Предпочтение | Стек | ALPN | HTTP |
| --- | --- | --- | --- |
| primary | QUIC (TLS 1.3), HTTP/3 | `h3` | SmartTheia XHTTP (stream-one / stream-up) |
| fallback | TCP (TLS 1.3), HTTP/2 | `h2` | тот же SmartTheia XHTTP mode |

Для stream-one действует следующий контракт. Stream-up описан отдельно ниже. Целевой inbound слушает UDP и TCP **одного номера порта**. TLS cert/hostname проверяется на обоих путях. Клиент посылает `POST /v1/session`; `content-type: application/octet-stream`, `Authorization: Bearer <token>` в защищённых HTTP-заголовках. Сервер отвечает HTTP 200 **после проверки HTTP headers, TLS identity и Bearer-права на inbound, но ДО получения всего request body**; двунаправленные body несут SmartTheia frames. Нужен настоящий **full-duplex**: клиент продолжает писать request body и одновременно читает response body, сервер — наоборот. Нельзя ждать EOF request body перед response headers или перед `HELLO_ACK`; иначе неизбежен deadlock. До `OPEN_OK` HTTP 200 означает лишь принятие HTTP-запроса, а не успех целевого TCP dial.

Никаких самодельных открытых UDP handshakes, отдельного нестандартного ALPN или ошибок, отключающих TLS checks. TLS ClientHello и QUIC Initial могут быть видны DPI, HTTP path/Authorization защищены TLS. Определить приложение по статистике или активному probing всё равно возможно.

## 2. Frame format

Каждый HTTP request/response body — упорядоченная последовательность бинарных кадров:

```text
+----------+----------+----------------------+-------------------------+
| type u8  | flags u8 | payload_len u32 BE   | payload [payload_len]   |
+----------+----------+----------------------+-------------------------+
```

- `flags` обязано быть `0` в v1, иначе `PROTOCOL_ERROR`; reserved future extension.
- `payload_len` максимально **65 536** bytes, до выделения памяти парсер проверяет размер; decode incremental across arbitrary chunks. Rust `Decoder::feed_each` удерживает не более одного неполного кадра (65 542 байта) и передаёт завершённые кадры callback без очереди. Упрощённый `feed()` возвращает коллекцию всех кадров из переданного чанка, поэтому вызывающий обязан ограничить размер входного чанка.
- Многобайтовые числа — big-endian, строки — UTF-8, размерность payload задаётся ниже.
- Никакой компрессии или произвольного TLV в v1.
- Неизвестный type/version → закрыть конкретный stream с `UNSUPPORTED_VERSION` или `PROTOCOL_ERROR`; никогда не panic.
- HTTP body может разбить/объединить любые границы фреймов, запрещено считать HTTP chunk границей фрейма.

| Type | Значение | Payload |
| --- | --- | --- |
| `0x01` HELLO | клиент → сервер, первым | `version: u16 (=1), capabilities: u32` |
| `0x02` HELLO_ACK | сервер → клиент, первым ответом | `version: u16 (=1), accepted_capabilities: u32` |
| `0x03` OPEN_TCP | клиент → сервер, после ACK | `addr_type: u8, addr_len: u16, addr: bytes, port: u16` |
| `0x04` OPEN_OK | сервер → клиент, после OPEN | empty |
| `0x05` OPEN_ERROR | сервер → клиент, после OPEN | `code: u16`, без свободного текста |
| `0x10` DATA | в обе стороны после OPEN_OK | raw bytes (0..65 536) |
| `0x11` FIN | в обе стороны после OPEN_OK | empty, означает half-close отправки |
| `0x12` ABORT | в обе стороны | `code: u16`, поток завершается |

Адресные типы как в SOCKS5: `0x01` IPv4 (4 байта), `0x03` ASCII IDNA DNS имя (1..253 байт; без схемы/пути), `0x04` IPv6 (16 байт). `addr_len` обязательно равен длине адреса, `port` в диапазоне 1..65535. Пустой DATA допустим, но рекомендуется не отправлять. `capabilities` и `accepted_capabilities` v1 строго равны 0; текущий Rust codec **отклоняет любые ненулевые биты** с `UnsupportedCapabilities`, чтобы не объявить несуществующую UDP/transport capability. Будущие версии потребуют явно задокументированного расширения без silent downgrade.

## 3. State machine

```text
client:  HTTP request + auth → HELLO → (HELLO_ACK) → OPEN_TCP
                               → (OPEN_OK | OPEN_ERROR)
                               → DATA* + optional FIN → CLOSED
server:  validate HTTP/auth → HELLO → HELLO_ACK → OPEN_TCP
                               → policy + dial → OPEN_OK/OPEN_ERROR
                               → DATA* + optional FIN → CLOSED
```

- Перемещение в DATA до OPEN_OK, повторный HELLO/OPEN, DATA после FIN, недопустимые payload lengths вызывают `PROTOCOL_ERROR`.
- FIN — half-close направления; после обоих FIN и drain завершать HTTP-stream. ABORT — немедленный stop, все задачи отменены.
- EOF до согласования → `TRUNCATED`, EOF после корректного закрытия → нормальное завершение. Остаток неполного frame в EOF всегда ошибка. M1.3 `Decoder::finish()` проверяет отсутствие частичного кадра, `Session::finish()` требует OPEN_ERROR/ABORT либо FIN в обоих направлениях. Обвязка transport обязана вызвать **оба** метода, прежде чем считать соединение штатно завершённым.
- Ошибки destination dial/ACL отражать `OPEN_ERROR` без раскрытия внутреннего адреса/stack trace; timeout ограничен.
- Не вводить `stream_id` и сложную очередность при v1: один HTTP-stream равен одному upstream TCP-соединению.
- **Proxy success gate:** локальный HTTP CONNECT получает `200 Connection Established`, SOCKS5 получает `REP=0x00` **только** после `OPEN_OK`. `OPEN_ERROR` конвертируется в HTTP 403/502/504 или подходящий SOCKS5 REP; локальное соединение не обозначается как работающее до успешного dial. Отказы TLS/auth/HELLO/OPEN не должны подтверждать локальному приложению соединение.
- HTTP/2 и HTTP/3 request/response body могут оставаться открытыми одновременно; `FIN` в SmartTheia означает half-close передаваемого направления, а не автоматическое закрытие обоих HTTP-направлений. После `FIN` нельзя передать `DATA` в том же направлении. Код адаптера обязан доказать управление flow control и отменой.
- После OPEN_OK inactivity относится ко всему туннелю: 30 секунд без успешно переданных непустых TCP DATA или FIN. Тишина в одном направлении не прерывает передачу в другом. Пустые DATA не продлевают idle. Записи/flow-credit и handshake сохраняют отдельные дедлайны; после обоих FIN проверяется HTTP EOF без trailers в пределах 2 секунд. Серверный абсолютный лимит 300 секунд пока сохранён. ADR-0081; нативная приёмка нового блока требуется.
- Состояния UI: `local_proxy_listening` (локальные listeners готовы), `transport_authenticated` (HTTP Bearer + HELLO_ACK), `tunnel_open` (получен OPEN_OK). Одно состояние не подменяет другое.

### Codes v1

`1` GENERAL; `2` ADDRESS_INVALID; `3` POLICY_DENIED; `4` DIAL_TIMEOUT; `5` DIAL_FAILED; `6` RESOURCE_LIMIT; `7` UNSUPPORTED_VERSION; `8` PROTOCOL_ERROR; `9` TRUNCATED. Не менять значения в рамках v1.

## 4. Аутентификация и антизлоупотребления

- TLS hostname и certificate chain валидируются **до** отправки токена.
- Каждый request проходит Bearer authentication: клиентский токен = **32 случайных байта**, передаваемых в виде **canonical base64url без padding**; сервер хэширует SHA-256 от **декодированных 32 байт**, а не от строки, и сравнивает digest constant-time. Не принимать короткие пароли или digest вместо токенов. Token hash должен быть уникален в глобальном каталоге пользователей.
- После проверки токена сервер идентифицирует `server.users[].id` и допускает request **только при включении ID в `server.inbounds[].allowed_user_ids` выбранного listener**. Отключённые пользователи и неназначенные токены не получают никаких привилегий, даже если их хеш присутствует в другом inbound. Не выбирать inbound по HTTP `Host`/`:authority`.
- Ошибка auth HTTP 401/403 до создания remote dial; отсутствие Authorization нельзя пропускать. Rate limit по IP и user id; не писать auth headers в лог.
- TLS session resumption допустим, QUIC/HTTP 0-RTT отключён в v1 во избежание 0-RTT replay.
- Ограничения: request header/body budgets, caps для конкурентных streams, таймаут handshake, ограничение исходящих соединений и DNS lookup.
- При доменном `OPEN_TCP` клиент отправляет ASCII IDNA hostname, а не выполняет локальный DNS lookup. Сервер резолвит имя, проверяет **каждый** полученный IP на deny policy; выбирает только разрешённый IP и использует **именно этот закреплённый IP** для dial (повторный непроверенный resolve запрещён). При IP literal сервер также проверяет policy. Тесты TCP echo на `127.0.0.1` используют исключительно явную **тестовую** конфигурацию `allow_private_ips=true`; production default — false.

## 5. QUIC-first и безопасный fallback

- `auto`: сначала проверка H3 до configured timeout. Fallback только на UDP timeout/ICMP unreachable/невозможность установить QUIC; затем H2 поверх **того же валидированного server name**.
- Нельзя использовать fallback после cert failure, auth failure, protocol version mismatch, TLS security alert или policy denial. Не подавлять их под общее «сеть недоступна».
- Если H3 уже принят, а destination refused connection, H2 не решит проблему и не пробуется.
- H2 fallback применим к **новым** соединениям; активные соединения не мигрируются.
- Кэширующая оптимизация QUIC-unavailable должна истекать, логироваться и очищаться после network change.

## 6. UDP (P1, не часть MVP v1 baseline)

UDP_ASSOCIATE/UDP relay позже, через отдельное документированное расширение capabilities с frame tests. QUIC DATAGRAM и H2 streaming имеют разные свойства (loss vs head-of-line blocking); **не** подделывать семантику UDP поверх H2 без документирования ограничений. Любой клиент, запрашивающий неизвестную UDP capability, получает явный отказ.

## 7. DPI/fingerprint требования

- Цель: снизить **тривиальную сигнатурную отличимость**, сохраняя стандарты HTTP/3 и HTTP/2. Не гарантируется обход любого DPI или активного анализа.
- **P0, блокирует релиз:** независимая проверка TLS/HTTP совместимости на Linux/Windows и документирование результатов измерений относительно реального закреплённого браузера отдельно для H2/TLS и H3/QUIC (ADR-0074). uTLS не является контрольным клиентом. Проверки CA/SNI/ALPN и авторизации обязательны. Совместимость не означает идентичность пакетов, и одна смена User-Agent не доказывает совместимость.
- Профиль применяется при H3 и H2 там, где соответствующие параметры существуют; ALPN `h3`/`h2` и корректное RFC-поведение обязательны, не «подгонять» протокол к неподдерживаемому браузерному следу. P0 требует измеряемой конфигурации fingerprint, **не** идентичности браузеру.
- Не использовать ложное заявление о стандартном HTTP/3, если реально посылается raw QUIC с частным ALPN.
- Passive capture tests: сравнивать pcap TLS/QUIC/HTTP metadata, длины, тайминги, частоту ретраев с выбранным контрольным клиентом; вести результаты и ограничения по версиям.
- Active probing: rate limiting, auth, корректные HTTP status и отсутствие выдачи диагностического баннера неавторизованным клиентам. Это уменьшает тривиальный fingerprint, но не исключает классификацию.
- В документации запрещены абсолютные заявления вроде «невозможно обнаружить через DPI».

### Golden vectors v1 (hex, без пробелов между chunk boundaries)

- HELLO (v1, capabilities=0, payload=6): `01 00 00 00 00 06 00 01 00 00 00 00`.
- HELLO_ACK (v1, accepted_capabilities=0): `02 00 00 00 00 06 00 01 00 00 00 00`.
- FIN (empty payload): `11 00 00 00 00 00`.
- OPEN_ERROR (POLICY_DENIED=3): `05 00 00 00 00 02 00 03`.

Тесты должны проверять **точные байты** и декодирование этих векторов, а не только поиск строки в документации. Если изменить wire, нужно явно версионировать протокол, а не молча переписать golden tests.

## 8. Контрактные тесты

M1.3: тесты `crates/theia/tests/protocol.rs` выполняются в Linux/Windows CI, включая одиночный байт и все границы разрезания, контроль отказов до OPEN_OK, half-close и детерминированный случайный bounded parser workload. Это **не** полноценный coverage-guided fuzzing: отдельные fuzz targets остаются к M5. Golden byte vectors для всех type/payload (включая HELLO payload **ровно 6 байт**), endian, границ 0/65536/65537, UTF-8+IDNA, неизвестных type/flags, фрагментации HTTP body, двойного FIN, EOF, 0-RTT denial; fuzz decode no-panic. Проверять HTTP/2+HTTP/3 **full-duplex** без ожидания EOF запроса; HTTP 200 до `OPEN_OK`, но local HTTP CONNECT 200 / SOCKS5 success **строго после** OPEN_OK; cross-inbound token rejection и server-side DNS without local resolver calls. E2E: TCP echo through H3, H2 при отключённом UDP, отсутствие fallback при bad cert/token, DNS policy, slow readers, half-close, cancellation.

Нормативные транспортные стандарты: RFC 9000/9001 (QUIC), RFC 9114 (HTTP/3), RFC 9113 (HTTP/2), RFC 8446 (TLS 1.3).

## Out-of-band F-14 connection invitations

The versioned theia://v1 invitation is **not** a SmartTheia frame, HTTP endpoint, auth handshake, or remote administration API. It is an out-of-band human-controlled profile transfer; no changes to SmartTheia v1 wire frames, HTTP request semantics, bearer verification or network fallback rules. An embedded 256-bit token is confidential and can only be issued from fresh in-memory random bytes with a verified inbound grant and matching stored digest. See docs/INVITATIONS.md. Unknown invitation versions must fail closed, independently of supported SmartTheia wire version.

## F-18/F-19: будущие security mode и TLS-in-TLS (не реализовано)

Текущий SmartTheia frame v1 и H2/H3 transport contract **не меняются**. REALITY-подобная проверка идентичности сервера и camouflaged handshake является задачей внешнего security/transport adapter, не новым SmartTheia type или собственным TLS cipher. Anti-TLS-in-TLS flow shaping не дешифрует inner TLS и обязан сохранять byte-exact TCP и OPEN_OK/FIN/backpressure. H2 и H3 требуют отдельных wire feasibility/CI и явного согласования security mode без silent downgrade. Расширения version/capabilities, TOML и invite v2 требуют ADR, миграции, негативных TLS/auth/replay/probing тестов. До реализации такого режима в бинарнике нет; см. docs/STEALTH_REALITY.md и ADR-0020.

## Дополнительный pinned-cert-v1 route (ADR-0083)

Опциональный серверный `security_mode = "pinned-cert-v1"` принимает только `POST /v1/pinned-session`; plain принимает только `/v1/session`. Одинаковый SmartTheia v1 codec, bearer grants и OPEN_OK. Клиент проверяет точный SHA-256 DER leaf после стандартной TLS1.3 PKI/SAN/ALPN и перед отправкой HTTP bearer на обоих транспортах. Ни один mode mismatch, wrong pin, CA или auth failure не вызывает downgrade. Никаких изменений frame IDs или invitation v1; настоящий REALITY не реализован. Нативная приёмка нового режима требуется.

## SmartTheia XHTTP stream-up v1 (ADR-0084, pending native acceptance)

Explicit `security_mode = "pinned-cert-stream-up-v1"` requires two requests on the **same** verified H2 or H3 connection: POST `/v2/stream-up/upload` and empty GET `/v2/stream-up/download`. Both have the same valid bearer and octet-stream content type. One pair per connection; no shared cross-connection identifier, duplicate leg reuse, or unbounded pending map. Before either stream succeeds require exact route/method, same credential, one authorization/quota permit and clean empty GET EOF. POST response is empty HTTP 200, GET response carries server frames. Upload body carries client frames. The common HELLO/OPEN/OPEN_OK/DATA/FIN state machine and existing relay budgets remain authoritative; HTTP 200 alone never means TCP success. Same-connection pairing expires after 10s. No downgrade to stream-one, plain TLS or another pin. This is a native SmartTheia carrier; not Xray XHTTP wire and not a complete REALITY-like security adapter.

**ADR-0085:** fallback H3 → H2 только при подтверждённой сетевой недоступности QUIC до прикладной авторизации, без изменения identity/endpoint, XHTTP mode, security mode и credentials. TLS/ALPN/key/auth/protocol/policy failures fail closed. Нет миграции живого TCP. Legacy pin не отдельный целевой security mode.

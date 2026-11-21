# SmartTheia v1: wire и transport контракт

**Версия:** 1 (проектный контракт, без действующей реализации). **Область:** прикладной протокол проксирования поверх аутентифицированных TLS/QUIC HTTP-streams. Не собственный аналог TLS или QUIC.

## 1. Transport embedding

| Предпочтение | Стек | ALPN | HTTP |
| --- | --- | --- | --- |
| primary | QUIC (TLS 1.3), HTTP/3 | `h3` | bidirectional streaming `POST` |
| fallback | TCP (TLS 1.3), HTTP/2 | `h2` | bidirectional streaming `POST` |

Одинаковый inbound может слушать UDP и TCP **одного номера порта**. TLS cert/hostname проверяется на обоих путях. Клиент посылает `POST /v1/session`; `content-type: application/octet-stream`, `Authorization: Bearer <token>` в защищённых HTTP-заголовках. Сервер отвечает HTTP 200 только после принятия запроса; двунаправленные body несут SmartTheia frames. HTTP-библиотеки должны поддерживать потоковую передачу request и response bodies (не буферизовать запрос целиком).

Никаких самодельных открытых UDP handshakes, отдельного нестандартного ALPN или ошибок, отключающих TLS checks. TLS ClientHello и QUIC Initial могут быть видны DPI, HTTP path/Authorization защищены TLS. Определить приложение по статистике или активному probing всё равно возможно.

## 2. Frame format

Каждый HTTP request/response body — упорядоченная последовательность бинарных кадров:

```text
+----------+----------+----------------------+-------------------------+
| type u8  | flags u8 | payload_len u32 BE   | payload [payload_len]   |
+----------+----------+----------------------+-------------------------+
```

- `flags` обязано быть `0` в v1, иначе `PROTOCOL_ERROR`; reserved future extension.
- `payload_len` максимально **65 536** bytes, до выделения памяти парсер проверяет размер; decode incremental across arbitrary chunks.
- Многобайтовые числа — big-endian, строки — UTF-8, размерность payload задаётся ниже.
- Никакой компрессии или произвольного TLV в v1.
- Неизвестный type/version → закрыть конкретный stream с `UNSUPPORTED_VERSION` или `PROTOCOL_ERROR`; никогда не panic.
- HTTP body может разбить/объединить любые границы фреймов, запрещено считать HTTP chunk границей фрейма.

| Type | Значение | Payload |
| --- | --- | --- |
| `0x01` HELLO | клиент → сервер, первым | `version: u16 (=1), capabilities: u32, client_nonce: [u8;16]` |
| `0x02` HELLO_ACK | сервер → клиент, первым ответом | `version: u16 (=1), accepted_capabilities: u32` |
| `0x03` OPEN_TCP | клиент → сервер, после ACK | `addr_type: u8, addr_len: u16, addr: bytes, port: u16` |
| `0x04` OPEN_OK | сервер → клиент, после OPEN | empty |
| `0x05` OPEN_ERROR | сервер → клиент, после OPEN | `code: u16`, без свободного текста |
| `0x10` DATA | в обе стороны после OPEN_OK | raw bytes (0..65 536) |
| `0x11` FIN | в обе стороны после OPEN_OK | empty, означает half-close отправки |
| `0x12` ABORT | в обе стороны | `code: u16`, поток завершается |

Адресные типы как в SOCKS5: `0x01` IPv4 (4 байта), `0x03` ASCII IDNA DNS имя (1..253 байт; без схемы/пути), `0x04` IPv6 (16 байт). `addr_len` обязательно равен длине адреса, `port` в диапазоне 1..65535. Пустой DATA допустим, но рекомендуется не отправлять. `capabilities` v1 первоначально = 0; неизвестные биты игнорировать или корректно отклонять при явной обязательности в будущей версии; **UDP не объявлять до реализации**.

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
- EOF до согласования → `TRUNCATED`, EOF после корректного закрытия → нормальное завершение. Остаток неполного frame в EOF всегда ошибка.
- Ошибки destination dial/ACL отражать `OPEN_ERROR` без раскрытия внутреннего адреса/stack trace; timeout ограничен.
- Не вводить `stream_id` и сложную очередность при v1: один HTTP-stream равен одному upstream TCP-соединению.

### Codes v1

`1` GENERAL; `2` ADDRESS_INVALID; `3` POLICY_DENIED; `4` DIAL_TIMEOUT; `5` DIAL_FAILED; `6` RESOURCE_LIMIT; `7` UNSUPPORTED_VERSION; `8` PROTOCOL_ERROR; `9` TRUNCATED. Не менять значения в рамках v1.

## 4. Аутентификация и антизлоупотребления

- TLS hostname и certificate chain валидируются **до** отправки токена.
- Каждый request проходит Bearer authentication: клиентский токен = 32 байта криптографически случайных данных (представление hex/base64url, формат выбрать и закрепить тестом); сервер хранит SHA-256 digest, использует constant-time comparison. Не принимать короткие пароли вместо токенов.
- Ошибка auth HTTP 401/403 до создания remote dial; отсутствие Authorization нельзя пропускать. Rate limit по IP и user id; не писать auth headers в лог.
- TLS session resumption допустим, QUIC/HTTP 0-RTT отключён в v1 во избежание 0-RTT replay.
- Ограничения: request header/body budgets, caps для конкурентных streams, таймаут handshake, ограничение исходящих соединений и DNS lookup.
- Не доверять DNS имени: после resolution проверять каждый IP на deny policy, сохранять выбранный разрешённый IP для dial.

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
- Проверить TLS fingerprint profile как самостоятельный P1-компонент: ClientHello cipher/extension ordering, SNI, ALPN, HTTP/2 SETTINGS, H3 fingerprint и согласованность с профилем. Только смена User-Agent **не** равна uTLS.
- Не использовать ложное заявление о стандартном HTTP/3, если реально посылается raw QUIC с частным ALPN.
- Passive capture tests: сравнивать pcap TLS/QUIC/HTTP metadata, длины, тайминги, частоту ретраев с выбранным контрольным клиентом; вести результаты и ограничения по версиям.
- Active probing: rate limiting, auth, корректные HTTP status и отсутствие выдачи диагностического баннера неавторизованным клиентам. Это уменьшает тривиальный fingerprint, но не исключает классификацию.
- В документации запрещены абсолютные заявления вроде «невозможно обнаружить через DPI».

## 8. Контрактные тесты

Golden byte vectors для всех type/payload, endian, границ 0/65536/65537, UTF-8+IDNA, неизвестных type/flags, фрагментации HTTP body, двойного FIN, EOF, 0-RTT denial; fuzz decode no-panic. E2E: TCP echo through H3, H2 при отключённом UDP, отсутствие fallback при bad cert/token, DNS policy, slow readers, half-close, cancellation.

Нормативные транспортные стандарты: RFC 9000/9001 (QUIC), RFC 9114 (HTTP/3), RFC 9113 (HTTP/2), RFC 8446 (TLS 1.3).

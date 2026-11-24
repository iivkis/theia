# ADR-0060: F-18 / M3.5a2, реальные QUIC Initial и H3 identity proof (research-only)

**Дата:** 2026-11-24. **Статус:** ограниченное исследование для CI, неутверждённый security protocol. **F-18 остаётся открытым P0.**

## Мотивация и границы

ADR-0020 требует REALITY-подобную защищённую идентичность сервера, защиту от активного probing/replay и раздельно измеряемое начальное TLS/QUIC/HTTP поведение. ADR-0021 доказал возможность TLS exporter поверх проверенной QUIC-сессии, ADR-0059 добавил test-only Ed25519-подпись такого канала и H2/TLS-фрейминг эксперимента, **не** модифицированный TLS handshake.

Этап M3.5a2 добавляет **реальный UDP-observation point** для исходящего QUIC v1 Initial от **штатного production Quinn/H3 endpoint** и отдельную test-only Ed25519-проверку через **реальную HTTP/3 DATA** после строгого verified QUIC/TLS1.3 handshake. Код находится **только** в `crates/theia/tests/f18_h3_first_flight.rs`, повторно использует `crates/theia/tests/support/f18_research_identity.rs`. Production code, TOML v1, `theia://v1`, CLI, TUI и политики fallback **не изменены**. Никаких публичных probe.

## Given / When / Then: что именно наблюдается

1. **Given** fresh Quinn `client_endpoint` и self-signed localhost TLS anchor, **when** клиент действительно отправляет первый UDP пакет через bounded локальный forwarder, **then** parse его QUIC v1 **незашифрованного** long-header: header form/fixed bit, version 1, Initial type, ограниченные DCID/SCID **lengths**, varint token length, protected length, UDP datagram >=1200 bytes (RFC 9000 §14.1). Прямая серверная UDP-проверка завершается полноценно; никакого «снимка» из TLS engine не выдаётся за wire capture.
2. **Given** malformed/truncated or alternate-version Initial metadata, **when** parser checks it, **then** reject as evidence. Отдельные deterministic negative tests проверяют короткий пакет, short/0-RTT/Handshake type, неверную версию, недопустимые CID lengths, oversized token/length и 1200-byte boundary.
3. **Given** строго проверенный CA/SAN/SNI/ALPN=h3 и работающий HTTP/3 POST, **when** сервер на одном H3 DATA request получает одноразовый 32-байтовый challenge, **then** подписывает Ed25519 typed H3 transcript с actual QUIC exporter, клиент сверяет **независимый pin** и принимает ровно один раз. Wrong public pin, H2/H3 branch substitution или replay → deny **в исследовательском verifier**, не в production transport.
4. **Given** обычный H3/QUIC backend, **when** исследовательский proof проходит, **then** это лишь post-handshake доказательство **дополнительной** идентичности. Сам QUIC Initial, initial TLS CRYPTO, TLS certificate, HTTP/3 SETTINGS, HTTP request URI и transport parameters остаются текущими; никакого REALITY-like modified first flight или server-side early client authentication нет.

## Wire evidence и угрозы

| Элемент | Реально подтверждено CI | Не подтверждено |
| --- | --- | --- |
| UDP QUIC Initial | первый datagram на loopback после Quinn serialization; QUIC v1 long-header dimensions, отсутствие retry token, min 1200 bytes | расшифрованный QUIC Initial CRYPTO, полный ClientHello, transport parameters/extensions, QUIC version grease и browser-equivalence |
| H3 | реальный verified Quinn TLS1.3/h3 + HTTP/3 POST DATA request/response и receipt | независимый browser QUIC/H3 reference, истинное внешнее camouflage-поведение |
| Идентичность | signed Ed25519 pinned key поверх actual exporter, transport/hostname/port/nonce binding, wrong key/H2 substitution/replay refusal | client anti-probing *до* TLS, persistent/distributed replay, trusted pin provisioning, rotation/revocation, formal crypto review |
| Windows/Linux | native cargo tests + обязательные существующие H2/H3/BBR cross-host regression jobs | реальный performance/DPI evaluation on production encrypted payloads |

**Важная граница:** QUIC Initial CRYPTO payload шифруется и header-protected. Тестовый parser не расшифровывает его, не извлекает TLS/SNI или connection ID bytes, не пишет pcap/содержимое/ключи, **не** может обосновать full first-flight fingerprint. Это намеренно документированный **blocker**, а не скрытое обещание совместимости. Любая последующая расшифровка с использованием audited packet library и capture/reference потребует отдельной безопасной исследовательской процедуры и CI-доказательств.

**H3 signature-after-handshake тоже не защищает первый probe:** злоумышленник может установить обычное QUIC соединение и различить HTTP/3 route/response до отдельного подписи. В эксперименте verifier работает на клиентской стороне после получения HTTP 200; **HTTP 200 здесь не SmartTheia OPEN_OK** и не разрешение открыть туннель.

## Сеть, ресурсы, приватность

- Только `127.0.0.1`: локальный UDP forwarder с двумя sockets и фиксированными 65_536-byte buffers, максимум 512 входящих datagrams, 24s общий test deadline, без DNS/сканирования/записи сырых datagrams и внешних IP.
- Собирается **лишь** минимальная анонимизированная структура metadata: version, CID **lengths**, token length, bounded packet/datagram size. Сами CIDs, raw Initial, TLS/QUIC secrets, target SNI, подписи и публичные ключи не сохраняются как артефакты и не попадают в logging.
- Эфемерная self-signed localhost CA допускается **только для теста** и явно добавляется в доверенные корни test client; production verifier не отключается. QUIC BBR/ALPN проверяются существующим `quic_transport::connect/accept`, no 0-RTT.
- Не добавлять security mode поля в TOML v1, не использовать unknown trust, не устанавливать system proxy, не менять protocol fallback.

## Следующее архитектурное решение

**M3.5a2 текущий срез не закрывает весь modified-handshake feasibility gate.** Для перехода к M3.5c обязательны независимый crypto review и точные native Linux/Windows доказательства *полного* ClientHello/QUIC Initial и HTTP/3/HTTP2 first-flight против закреплённых эталонов. Если текущий rustls/Quinn backend не позволяет audited handshake adjustments без ослабления TLS, это архитектурная блокировка, а не повод включить `smart-reality-v1` на основе одного signed HTTP/3 ответа.

Нужно отдельно спроектировать pre-auth anti-probing, sealed/verifiable server identity, fail-closed capability negotiation и key trust/rotation/revocation с TOML/invite v2, измерить active-probing/QUIC spoofing/downgrade и обеспечить настоящие H2/H3 security network E2E. F-19 TLS-in-TLS classifier + shaping остаётся независимым P0.

Источники: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html), [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html), ADR-0020/0021/0059.

# ADR-0061: F-18 / M3.5a3 — реальные QUIC Initial ClientHello и active-probe baseline

**Дата:** 2026-11-24. **Статус:** экспериментальная, CI-only negative evidence. Не production REALITY, не утверждённый security protocol. Независимый security audit ещё не проведён.

## Решение

После ADR-0059/0060, в которых были подтверждены отдельный Ed25519 proof по verified TLS exporter, H3 DATA challenge и открытые метаданные QUIC Initial, сделать следующий **измеряемый** шаг: восстановить **настоящий ClientHello из самого первого UDP datagram реального Quinn client**, а также на реальном production H3 endpoint доказать статус активного зондирования без bearer.

Исследовательский тест `crates/theia/tests/f18_initial_visibility.rs` перехватывает **только loopback UDP**, ограничен 18s и 256 пересылками. Вместо собственного HKDF/AES, форка TLS/QUIC или test-only обхода проверки TLS используются **публичные проверенные механизмы Quinn 0.11.12**: `quinn::crypto::rustls::QuicServerConfig::initial_keys(1, &destination_cid)`, `HeaderKey::decrypt` и `PacketKey::decrypt`. Для получения ключей исследователь намеренно строит **независимый сертификат/приватный ключ**, не имеющий отношения к действующему server endpoint. По RFC 9001 Initial-ключи зависят от **публичных** версии и destination CID, а не от серверного приватного ключа. Это не MITM, не компрометация TLS 1.3 1-RTT и не доступ к полезной нагрузке действующего соединения.

После AEAD-проверки и дешифрования Initial code **только в тесте** извлекает offset-0 QUIC CRYPTO frame, ограничивает длины и декодирует известные поля TLS ClientHello без сохранения hostname: TLS 1.3 supported_versions, признак SNI, ALPN h3, QUIC transport_parameters, число cipher suites/extensions, GREASE extension и ALPS (0x4469/0x44cd). Никакого SSLKEYLOGFILE, pcap, payload output, логирования raw CID, приватных ключей, SNI или пользовательских target. Буферы UDP transient, ephemeral, не пишутся на диск, чувствительные копии очищаются после успешной проверки. Результат исследования — typed/test-only boolean, **не capture аттестация Chrome** и не privacy claim для внешнего production-трафика.

**Важно:** тестовый parser ограниченно поддерживает один первый Initial с одним offset-0 CRYPTO frame, а не полноценный reusable QUIC/TLS decoder, coalescing, Retry, packet number reconstruction/stream reassembly. Не переносить его в production и не считать возможностью безопасного изменения TLS handshake. Отдельный audited capture/ref pipeline с browser H3 baseline по-прежнему необходим.

## Active probing: текущий статус, без самообмана

В `crates/theia/tests/h3_server.rs` добавлен explicit F-18 negative gate на **реальном production H3 listener**. Unauthenticated peer проходит обычное verified QUIC TLS1.3/ALPN=h3 рукопожатие **до** предъявления bearer и может вывести exporter на своей стороне, затем получает различимый ответ `401` на обычный `POST /v1/session`. Неверный bearer тоже даёт `401`, а верный bearer может получить `HTTP 200` **до SmartTheia OPEN_OK**. Ни один из этих фактов не даёт неавторизованному клиенту relay и не означает дефект текущей версии с обычной H3 авторизацией. **Но такой endpoint не обладает REALITY-подобной anti-probing маскировкой.** Если кто-то объявляет текущий F-18 готовым, тест демонстрирует обратное.

## Threat matrix / fail-closed критерии

| Threat | Что проверяется | Что остаётся |
| --- | --- | --- |
| Passive QUIC Initial observer | Реальная datagram сериализация → Quinn authenticated Header/Packet decrypt → offset-0 TLS ClientHello | Доказанный browser match и полный multi-packet Initial |
| Corrupt packet | Изменение последнего ciphertext байта → AEAD error, **без** принятия CRYPTO | более широкий packet fuzz и коалесцированные Initial |
| Truncation/alternative type | short/0-RTT/невалидная длина → отсутствие evidence | QUIC v2 и полный version negotiation |
| Observability | TLS1.3, SNI present, h3 ALPN, QUIC transport params; отсутствие default ALPS/GREASE, если CI подтверждает | фиксированный browser reference, transport parameters, H3 SETTINGS, traffic classifiers |
| Active probing | TLS+H3 доступно без token, HTTP 401 и 200 различимы, authorization/grants для relay не ослаблены | требуются **до** HTTP response скрытая authenticated handshake state machine, pre-auth limits/anti-probe и внешне измеренная совместимость |
| Downgrade | v1 всё ещё только default строго проверенного TLS, нового mode не существует | versioned TOML/invite v2, pinned key rotation и отрицательные integration тесты |

## Ограничения / безопасность

- Все сеть и DNS только loopback, никаких новых сканеров, публичных целей, автоматических проверок доменов, proxy-переключений.
- Нет изменения `crates/theia/src/`, wire, TLS verifier, client/server runtime, config, bearer, quota, grants или routing. `cargo test --workspace --all-targets --locked` автоматически проверяет Linux/Windows.
- Первичный Initial наблюдаем для любого пассивного adversary, но QUIC Handshake/1-RTT содержит другие защищённые ключами фазы. Не экстраполировать Initial visibility на снятие всей TLS защиты.
- Нет гарантий, что shape «выглядит как Chrome» или что anti-DPI совершен; H2 и H3 разные поверхности и исследуются раздельно.

## Вывод для F-18 / M3.5c

Текущий verified Quinn/rustls H3 first flight **не скрывает ClientHello от пассивного противника**, а нынешний H3 сервер разрешает различимую response authentication после полностью обычного TLS. Значит, **M3.5c production secure mode заблокирован** до отдельного ревью протокола аутентификации *до* выдачи отличимого HTTP-ответа, оценки возможности безопасной модификации TLS/QUIC first flight и реальных Linux/Windows first-flight сравнений с pinned browser references.

Не переименовывать обычный strict TLS + post-handshake signature в REALITY, не выключать CA/SAN и не включать опасный fallback. Нельзя считать F-18 завершённым на основании этих экспериментов.

Ссылки: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html), [RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), [Quinn crypto API](https://docs.rs/quinn/0.11.12/quinn/crypto/index.html), ADR-0020/0021/0059/0060.

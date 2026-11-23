# ADR-0059: F-18 / M3.5a1, отдельная идентичность сервера (research only)

**Дата:** 2026-11-24. **Статус:** проект для независимого криптографического review, НЕ утверждённый wire-протокол. Никакой production security mode, REALITY handshake или anti-probing на этом этапе не добавлены.

## Контекст и выбранный минимальный эксперимент

ADR-0020 требует REALITY-*подобный* SmartTheia с отдельным proof of server identity, anti-replay/active-probing и внешним TLS/H2+QUIC/H3 fingerprint. ADR-0021 показал только TLS exporter после строгой сертификатной проверки: exporter сам по себе не доказывает владения независимым ключом и не модифицирует first flight.

M3.5a1 исследует **дополнительную, независимо закреплённую Ed25519 подпись** по [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), строго связанную с session exporter уже проверенной TLS1.3 сессии ([RFC 8446 §7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5)). Ring 0.17.14 используется только как dev-dependency (уже присутствует в lockfile через rustls). Test-only helper расположен по пути crates/theia/tests/support/f18_research_identity.rs. Ни production transport, ни lib.rs, ни TOML/invite v1 не меняются.

## Формат тестового signed transcript, НЕ on-wire protocol

| Порядок | Поле | Представление |
| --- | --- | --- |
| 1 | domain | фиксированная ASCII-метка Theia/M3.5a1/RESEARCH-ONLY/server-identity/v1 с завершающим NUL |
| 2 | transport | 1 байт, H2=2 или H3=3 |
| 3 | expected TLS server DNS | length u8 + lowercase ASCII hostname, max 253 bytes, labels max 63 |
| 4 | TCP/UDP port | u16 big-endian, ненулевой |
| 5 | issued milliseconds | u64 big-endian, исключительно модель freshness |
| 6 | client nonce | ровно 32 ненулевых CSPRNG bytes |
| 7 | server nonce | ровно 32 ненулевых CSPRNG bytes |
| 8 | TLS exporter | ровно 32 ненулевых bytes verified TLS, отдельный LABEL/CONTEXT |

Ed25519 подписывает все перечисленные байты. Проверяющий требует независимо закреплённый **точный** 32-байтовый server public key; CA/SAN/SNI/ALPN проверяется TLS стеком **до** обращения к exporter. Без проверки pinned key подпись не засчитывается. Исследовательская запись не содержит пользовательских целевых адресов, bearer, URL или payload. Элементы с секретами, подписи и raw transcripts не попадают в debug trace.

## Предлагаемая future state machine (не подключена к runtime)

1. TransportPending: strict TLS1.3 CA/SAN/SNI/ALPN, H2 и H3 отдельно; 0-RTT запрещён; handshake mismatch → terminate.
2. IdentityPending: pinned server key, exact signed branch + hostname + port + exporter + fresh nonces, bounded time/bytes; key mismatch, replay, protocol mismatch → terminate **без fallback**.
3. ApplicationAuthPending: после успешного proof прежние inbound-scoped bearer SHA256, grants, quota и DNS/ACL, без изменения доверия TLS и OPEN_OK.
4. TunnelReady: HTTP CONNECT 200 / SOCKS5 success только после настоящего OPEN_OK, никогда после одной подписи.

**Критический caveat:** подпись после обычного TLS не меняет ClientHello/QUIC Initial и **не защищает сервер от первого active probe**. Нет раннего client proof, нет opaque external-camouflage reply, нет REALITY wire-совместимости. Эти свойства остаются незакрытыми P0, и такой эксперимент запрещено называть REALITY security mode.

## Negative gates и replay model

| Угроза | Тестовый отказ | Открытая задача |
| --- | --- | --- |
| MITM, чужой ключ | wrong pinned Ed25519 key или подпись → отказ | безопасное первичное provision pin |
| Cross-transport/endpoint | H2↔H3, DNS, port, nonce или exporter изменён → отказ | реально согласованный H3 first-flight и channel binding |
| Replay | повтор signed transcript внутри окна → отказ | серверная защита от active probing, рестарт/кластер |
| Время | expiry 60s, >2s future, clock rollback → отказ | монотонная clock policy, skew/restart |
| Cache exhaustion | фиксированная capacity 1..4096, никогда не вытеснять live nonce | peer limits, CPU/memory budget, per-source fairness |
| Неканоничный ввод | bad DNS, zero nonce/exporter, zero port → отказ | формальный bounded wire parser, fuzz, invalid unicode |
| Downgrade | неизвестный security mode запрещён в TOML/invite v1 | versioned migration, capability pin и rollback |

In-memory ReplayWindow демонстрирует только локальную модель на миллисекундных тестовых часах. Нет общего кеша между процессами и нет серверного anti-probing; наличие зелёного теста не меняет этого факта. Подписанные challenge не используются для открывания туннелей.

## Key lifecycle и совместимость: только требования для последующего ADR

Будущая генерация ключа должна использовать CSPRNG и отдельный защищённый server secret ref с owner-only ACL; публичный pin не берётся из SNI или незаверенного TLS. Точная семантика ключа, алгоритм/rotation, expiry, multi-inbound isolation, revocation, recovery после crash, защищённый перенос через F-14 и silent-downgrade rejection должны пройти отдельный security review. Нужны TOML schema version и invitation v2, **не** подмена старого theia://v1. Ни insecure verifier, ни TOFU по умолчанию.

## Given / When / Then

- Given strict trusted TLS1.3/H2 and pinned Ed25519 key, when server signs exact real post-TLS exporter transcript, then one verification succeeds and the replay is rejected.
- Given wrong key, altered branch/name/port/nonce/exporter/time, when verifier checks proof, then reject without admitting replay state.
- Given full replay cache, when distinct fresh proof arrives, then reject rather than evict a live nonce.
- Given mismatched CA, when ordinary TLS handshake fails, then no exporter or identity proof is available.

CI Linux/Windows: crates/theia/tests/f18_identity_lab.rs and real TLS1.3/H2 fixture in crates/theia/tests/reality_security_feasibility.rs, through cargo test --workspace --all-targets --locked. Existing H3 exporter loopback and v1 rejection tests remain required. No shipping code or user-facing flags.

## Решение о выпуске и дальнейшие шаги

Это **дизайн-кандидат, не security-reviewed protocol**. До M3.5c production требуются независимый криптографический review, полноценный early client-auth/anti-probing design, реальные first-flight captures и сравнительная оценка fingerprint на H2 и H3, отдельное M3.5a2 QUIC/Initial spike, versioned TOML/invite contract, key trust/rotation и реальные негативные server/client E2E. Если post-TLS proof не покрывает требуемый first-flight disguise, его следует отвергнуть, а не переименовать в REALITY.

F-19 TLS-in-TLS classifier и flow-shaping остаются независимым, незавершённым P0.

Источники: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html), ADR-0020/0021.

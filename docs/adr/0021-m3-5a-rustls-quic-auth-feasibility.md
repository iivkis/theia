# ADR-0021: M3.5a0, возможности TLS/QUIC channel binding для SmartTheia

**Дата:** 2026-11-22. **Статус:** исследовательский и ограничивающий ADR. Никакой REALITY-подобный режим, anti-DPI flow shaping или сканер не реализован.

## Контекст

F-18 P0 требует криптографическую идентичность сервера, устойчивость к MITM/replay/active probing и измеренный внешний TLS/HTTP-образ. F-19 P0 независимо требует доказанное снижение распознаваемости TLS-in-TLS. REALITY в XTLS реализует модифицированный TLS handshake, а не просто подмену SNI или запись публичного ключа в конфиг. Официальный Xray REALITY перечисляет RAW/XHTTP/gRPC, но не готовый drop-in H3/QUIC. Нельзя считать, что успешное TLS exporter channel binding заменяет REALITY.

## Зафиксированные границы production code

| Транспорт | Защищённое соединение | Проверенные свойства | Что отсутствует |
| --- | --- | --- | --- |
| H2/TCP | rustls 0.23.46 и tokio-rustls 0.26.6; опциональный btls/tokio-btls 0.5.6 | TLS1.3, CA/hostname/ALPN=h2, bearer/grant; реальные clienthello и H2 SETTINGS фиксируются CI | Модифицированный REALITY handshake, server key proof, anti-probing/replay и готовый browser-like профиль |
| H3/QUIC | quinn 0.11.12 с rustls 0.23.46 | TLS1.3, verified CA/hostname/ALPN=h3, BBR; реальный QUIC H3 HELLO/ACK в CI | Совместимый с REALITY QUIC Initial, внешний fingerprint, отдельная серверная идентичность и доказательства TLS-in-TLS защиты |

Оба канала сейчас используют стандартный TLS, собственную HTTP авторизацию и SmartTheia OPEN_OK; они не используют криптографию REALITY. Клиентский профиль TOML schema_version=1 и приглашение theia://v1 разрешают только tls_profile=default. TLS проверку отключать нельзя.

## Исследовательский интеграционный тест M3.5a0

Файл: crates/theia/tests/reality_security_feasibility.rs; его выполняет native Linux/Windows cargo test в обязательном CI.

1. **TCP/TLS1.3:** реальное локальное TLS соединение и ALPN=h2, временная trusted CA, вызов rustls ConnectionCommon::export_keying_material у обоих peers после проверки TLS. С одинаковым LABEL/CONTEXT 32 байта на обеих сторонах совпадают, другой CONTEXT даёт другие 32 байта. Секреты никогда не выводятся в логи.
2. **Отрицательный TLS:** тот же hostname с неверной CA отклоняется до доступа к exporter или SmartTheia. Отсутствие возможности доверять чужому ключу по одному имени есть обязательный инвариант.
3. **QUIC/TLS1.3:** отдельное реальное локальное проверенное соединение h3 с quinn::Connection::export_keying_material; одинаковый LABEL/CONTEXT совпадает между peers, другой контекст разделён. Вывод не доказывает существование modified QUIC/REALITY handshake.
4. **Fail-closed конфигурации:** прямое добавление security_mode, flow_shaping, server_public_key, insecure_skip_verify в TOML v1 отклоняется. Значения tls_profile для нереализованных режимов отвергаются. theia://v1 отвергает чужую версию и неизвестные security или server-key поля. Не открывать фиктивную функцию до настоящего audit.
5. Существующие fingerprint_h2, h2_wire_fingerprint, quic_transport, h3_server и client_h2 network CI остаются обязательными, но показывают только текущие стандартные транспорты.

**Что не доказано:** exporter НЕ аутентифицирует отдельный REALITY public key, не доказывает владение приватным ключом целевого сайта, не исправляет видимый ClientHello/QUIC Initial, не предотвращает replay/active probing, не имитирует чужой TLS endpoint и не защищает от TLS-in-TLS statistical classifiers. Исследовательская метка экспортера не является утверждённым протоколом/доменом ключей для production.

## Рассмотренные альтернативы

- **A. Обычный TLS1.3 + TLS-exporter-bound вторичная проверка:** реалистичный additional application-level auth поверх доверенной CA, но не REALITY wire camouflage. Может создать заметный protocol fingerprint. Не зачесть F-18 без измерения и формального дизайна.
- **B. Аудированный modified TLS backend, совместимый с концепцией REALITY:** ближе к внешнему handshake, но требует проверки лицензий, криптографии, transcript binding, H2 совместимости, отрицательных тестов и отдельной QUIC/HTTP3 реализации. Без готового audited backend не включать режим.
- **C. Новый versioned SmartTheia security mode с отдельным серверным ключом:** только после crypto-ADR и независимого security review, собственную реализацию TLS не писать. Не считать С реализацией, пока нет formal state machine и раздельных сетевых proof для H2/H3.
- **D. Только SNI, User-Agent, принятие любого сертификата, fake ключ или непроверяемый TLS target:** отклонено, небезопасно и не является REALITY.

**Принято:** production TLS/QUIC/TOML/invite v1 не менять. Продолжить только research-only primitive tests и design review. Не допускать security-mode flag, пока не будет verified implementation. Не замаскировать отсутствующую функциональность под green CI.

## Следующий этап M3.5a1 и условия для работы

Нужна спецификация state machine и аутентификации отдельно H2 и H3, допустимый key lifecycle/rotation, proof of server identity, handshake transcript binding, replay window/freshness, политика для неавторизованного active probe без открытого relay, криптографический security review и версионированный TOML/invitation migration. Также нужны реальные first-flight captures с оценкой возможности mimicry выбранного candidate, red-team тесты wrong key, MITM, expired credential, replay, probing и negative fallback. Если текущие TLS/QUIC backend не позволяют безопасность/мимикрию, фиксируется blocker, не молчаливое упрощение.

M3.5b scoring и M3.5d TLS-in-TLS flow-shaping остаются **отдельными незавершёнными** срезами; F-13 browser fingerprint и BBR gates тоже открыты. Все network probes только на localhost или санкционированных целях с ограничениями.

## Источники

- REALITY official design: https://github.com/XTLS/REALITY/blob/main/README.en.md
- Xray REALITY transport contract: https://xtls.github.io/en/config/transports/reality.html
- rustls 0.23.46 TLS exporter: https://docs.rs/rustls/0.23.46/rustls/struct.ConnectionCommon.html
- quinn 0.11.12 QUIC exporter: https://docs.rs/quinn/0.11.12/quinn/struct.Connection.html
- RFC 8446 TLS1.3 exporters: https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5
- USENIX Security 2024 encapsulated TLS fingerprint: https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting

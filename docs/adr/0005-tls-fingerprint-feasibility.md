# ADR-0005: TLS/HTTP fingerprint feasibility and browser-profile gate

**Дата:** 2026-11-22
**Статус:** decision recorded; browser-like profile **NOT IMPLEMENTED**; P0/F-13 remains **BLOCKED**
**Связано:** ADR-0004, IMPLEMENTATION_SPEC F-13, H2/H3 transports

## Контекст и угроза ложного результата

Theia хочет browser-like TLS/HTTP footprint для HTTP/2 по TLS/TCP и HTTP/3 поверх QUIC.
Просто задать User-Agent, ALPN или TLS 1.3 недостаточно: fingerprint включает не только
ClientHello, но и порядок расширений, GREASE, application_settings/ALPS, HTTP/2 SETTINGS
и WINDOW_UPDATE, HTTP/3 SETTINGS, QUIC transport parameters, поведение потоков.
Сравнение TLS fingerprints между TCP и QUIC без маркировки транспорта тоже ошибочно.

По итогам M0.1 transport spike, rustls 0.23.46 + Quinn 0.11.12 + h3 0.0.8 + h2 0.4.19
обеспечивают реальные TLS/H2 и QUIC/H3 соединения, certificate validation и ALPN.
Это доказательство **транспорта**, не browser impersonation.

## Измерение 2026-11-22

Файл: \`spikes/m0_1/tests/tls_fingerprint.rs\`, без новых crate dependencies.
Реально исполняются API той же \`rustls = 0.23.46\` и того же ring CryptoProvider,
что использует M0.1 network spike:

- **TCP/H2:** \`rustls::ClientConnection::write_tls()\` генерирует TLS plaintext
  records с ClientHello. Bounds-checked parser получает версии, шифры, расширения
  (в порядке сериализации), группы и ALPN. Имя сервера, случайные байты, key
  shares и содержимое ClientHello **не записываются** в журнал.
- **QUIC/H3:** \`rustls::quic::ClientConnection::write_hs()\` генерирует handshake
  CRYPTO bytes (без TLS records) с ALPN \`h3\` и QUIC transport parameters extension
  ID 57. Для проверки формы используется **иллюстративный** набор QUIC transport
  parameters (max_udp_payload_size=1200); это **не захват/расшифровка** реального
  Quinn UDP Initial и не его полного набора transport parameters.
- Отдельный malformed-input test отвергает каждый усечённый префикс, неверный
  handshake type и trailing bytes. Запрещено логировать credentials или bytes
  полного ClientHello. CI запускает тесты на Windows/Linux и показывает только
  структурные поля (\`--nocapture\` на Linux).

**Наблюдения одного Linux CI-прогона** (порядок расширений может меняться между
запусками, это **не статический JA3 hash и не browser reference**):

| Параметр | TCP TLS/H2, rustls | QUIC TLS/H3, rustls CRYPTO |
| --- | --- | --- |
| ALPN | h2 | h3 |
| Legacy version / supported version | 0x0303 / TLS 1.3 (0x0304) | 0x0303 / TLS 1.3 (0x0304) |
| Cipher suites (decimal) | 4866, 4865, 4867, 49196, 49195, 52393, 49200, 49199, 52392 | 4866, 4865, 4867 |
| Supported groups (decimal) | 29, 23, 24 | 29, 23, 24 |
| Extension IDs, observed order (decimal) | 13, 5, 23, 51, 11, 10, 45, 0, 43, 16 | 57, 0, 13, 16, 5, 23, 51, 10, 11, 43, 45 |
| GREASE extension (RFC 8701) | **missing** | **missing** |
| ALPS, old 17513 / new 17613 | **missing** | **missing** |
| QUIC transport parameters extension (57) | absent (correct for TCP TLS) | present (correct for QUIC TLS) |
| Browser profile actually compared to reference capture? | **NO** | **NO** |

\`rustls\` 0.23 уже перемешивает порядок части ClientHello extensions
в качестве anti-fingerprinting механизма. Это **не равно Chrome parity**: сам набор
и структура расширений остаются иными. BoringSSL/Chromium поддерживают GREASE и ALPS
(в BoringSSL существуют старый и новый ALPS codepoint). ALPS не обязателен
для каждого браузера/версии/протокола; данная таблица не утверждает, что все
Chrome H3 handshakes обязаны содержать ALPS. Отличие обоих observed
Rustls первых полётов означает: \`default\` нельзя продавать как \`chrome\`.

**CI evidence (Linux и Windows):** https://github.com/iivkis/theia/actions/runs/44946095883
(первый прогон без negative-control). Пиннинг и полный набор регрессий:
\`cargo test --manifest-path spikes/m0_1/Cargo.toml --locked --test tls_fingerprint -- --nocapture\`.
Итоговый PR run с negative-control и фиксацией ADR указывается в PR #10.

## Решение

1. В Theia остаётся ровно **\`tls_profile = "default"\`**. Не включать названия
   Chrome/Edge/Firefox/Safari/«browser» как реально поддерживаемые профили.
2. Не менять PKI verifier/ALPN ради внешнего сходства. Отключение проверки
   сертификата, silent fallback на неверном TLS, секреты в pcap или 0-RTT
   POST без защиты от replay запрещены.
3. Применять единый **evidence gate** для именованного профиля: real capture и
   сравнение actual TCP/H2 плюс decrypted QUIC Initial/H3 handshake на
   **конкретной версии браузера, ОС и библиотек**. В перечень входят ClientHello,
   GREASE/ALPS, extension ordering, SNI/ALPN, TLS supported versions/groups,
   QUIC TP, H2 SETTINGS/priority/window behavior и H3 SETTINGS/QPACK.
   Опубликовать **отчёт расхождений** и regression tests. Ни JA3, ни JA4
   в одиночку не могут подтверждать полное сходство.
4. Выбор backend откладывается до отдельного исполняемого M0.1 experiment.
   Самостоятельный HTTP/2 TLS impersonator не доказывает совместимость с
   Quinn/QUIC. Никакого ложного «готово».

## Кандидаты следующего эксперимента

| Кандидат | Плюс | Критический риск |
| --- | --- | --- |
| Обычный rustls + Quinn | Проведены реальные H2/H3 транспортные E2E | Наблюдаемый набор TLS-расширений не соответствует конкретному Chrome H2 профилю; управление GREASE/ALPS без patch не доказано |
| \`primp-rustls\` / \`primp\` | Публичный API browser emulator и H2 fingerprint | Форк rustls, security/maintenance/licence audit; **нет теста совместимости с текущим Quinn/h3 и BBR** |
| BoringSSL-based/alt crypto | Управление Chrome-подобным TLS ClientHello и ALPS | Требуется проверенный QUIC crypto bridge и H2+H3 совместимость; одно упоминание BoringSSL не доказывает F-13 |
| Запустить настоящий Chromium как backend | Протоколы родного браузера | Несовместимость с требованием одного Rust binary, повышенный вес, IPC/lifecycle риски |

## Next acceptance evidence

- [x] Получены rustls TLS first flights для H2/TCP и H3/QUIC CRYPTO (без raw secrets), Linux+Windows tests.
- [x] Зафиксирована отрицательная проверка default rustls H2: нет GREASE и ALPS old/new; **не Chrome profile**.
- [ ] Получить контрольный **реальный** Chrome stable capture на конкретных Linux и Windows build, зафиксировать версию/OS/flags/ALPN без персональных данных.
- [ ] Перехватить TCP/TLS 1.3 ClientHello **на проводе** у текущего H2 endpoint, проверить соответствие наблюдению engine.
- [ ] Снять QUIC UDP Initial у **реального** Quinn H3 endpoint, вывести и разобрать CRYPTO с правильной Initial decryption и QUIC transport parameters.
- [ ] Сравнить полный ClientHello + HTTP2 SETTINGS/HTTP3 SETTINGS/QPACK и QUIC transport parameters с Chrome reference, отчёт с mismatched fields.
- [ ] Собрать и проверить на Windows/Linux named browser backend **в одном Rust binary**, сохранить strict TLS cert checks, H3 BBR и fallback gate.
- [ ] Прогнать независимые packet capture сравнения и CI regressions без leaking credentials.

**F-13 и M0.1: BLOCKED/PARTIAL** до этих тестов. Этот ADR не содержит обещаний
DPI-invisibility, полной browser parity или успешной bypass capability.

## Ссылки на upstream и нормы

- BoringSSL extensions (ALPS old/new, GREASE, extension permutation):
  https://chromium.googlesource.com/external/gob/boringssl/boringssl/+/refs/heads/upstream/main/ssl/extensions.cc
- Chromium TLS client settings:
  https://chromium.googlesource.com/chromium/src/+/2ec06e00be685b89d7a77a9bb9d677f4a50130e5/net/socket/ssl_client_socket_impl.cc
- rustls QUIC ClientConnection (TLS handshake CRYPTO payload):
  https://docs.rs/rustls/0.23.46/rustls/quic/struct.ClientConnection.html
- rustls 0.23.0 note on extension-order randomization:
  https://github.com/rustls/rustls/releases/tag/v/0.23.0
- Quinn crypto compatibility constraints:
  https://docs.rs/quinn/0.11.12/quinn/crypto/index.html
- RFC 8701 GREASE and RFC 9001 QUIC TLS:
  https://datatracker.ietf.org/doc/html/rfc8701
  https://datatracker.ietf.org/doc/html/rfc9001
- Third-party browser profile candidate:
  https://docs.rs/primp-rustls/latest/rustls/client/struct.BrowserEmulator.html

# ADR-0005: baseline TLS ClientHello перед browser-like fingerprint

**Дата:** 2026-11-22  
**Статус:** default rustls fingerprint **measured**; именованный browser-like TLS/HTTP profile **P0 BLOCKED**.  
**Связанные требования:** F-13 P0, M0.1, M3.4.

## Решение и границы доказательства

В `spikes/m0_1` добавлен `src/client_hello.rs`: ограниченный по длине диагностический парсер TLS ClientHello. Он показывает TLS legacy_version, cipher suites, последовательность extension IDs, ALPN и supported_versions, а также **только булевы признаки** SNI и QUIC transport parameters. Значения SNI, TLS random и session ID не сохраняются и не выводятся. Парсер тестируется на фрагментированных TLS records, переполнении длины, обрезанных данных, дублированных extensions и GREASE.

Для **обычного H2/TLS** `tests/client_hello_baseline.rs` получает handshake record непосредственно из `rustls::ClientConnection::write_tls`. Для **QUIC/H3** этот же тест использует `rustls::quic::ClientConnection::write_hs`, которое выдаёт *plaintext* TLS handshake **до** QUIC packet encryption. Это не реальный UDP/QUIC Initial capture: в engine-only probe использованы пустые тестовые transport parameters. Обычная проверка цепочки сертификата и SNI в других H2/H3 E2E тестах не отключалась.

Результат **не** является Chrome/Firefox/Safari fingerprint, JA3/JA4 validation, браузерной имитацией, гарантией обмана DPI или реализацией HTTP/2/HTTP/3 fingerprint.

## Матрица

| Проверка | Статус |
| --- | --- |
| H2 default rustls ClientHello, TLS record parse, ALPN h2, TLS 1.3 | PASS на Linux/Windows |
| H3 default rustls plaintext QUIC ClientHello, ALPN h3, extension 57, TLS 1.3 | PASS на Linux/Windows |
| Безопасный bounded parser, malformed records и duplicate extensions | PASS |
| H3 ClientHello внутри настоящего зашифрованного QUIC Initial packet | OPEN |
| Захваты эталонного браузера с зафиксированными browser build, OS, H2 и H3 | OPEN |
| Изменение полного набора browser TLS extensions, ordering, GREASE, ALPS, сигнатур на обеих OS | OPEN |
| H2 SETTINGS/pseudo-header ordering и H3 SETTINGS/priority сопоставлены с эталоном | OPEN |
| Один реально настроенный и измеренный browser-like профиль с нормальной проверкой TLS trust на Quinn H3 и TCP H2 | **P0 BLOCKER** |

## Измерения CI: стандартный rustls 0.23.46

Linux CI: https://github.com/iivkis/theia/actions/runs/44946132698 (тест `client_hello_baseline`, вывод `--nocapture`). Значения **не относятся к браузеру** и могут меняться при обновлении crypto provider или rustls:

| Поле | H2/TCP TLS | H3/rustls QUIC plaintext |
| --- | --- | --- |
| legacy_version | 0x0303 (771) | 0x0303 (771) |
| supported_versions | 0x0304 (TLS 1.3) | 0x0304 (TLS 1.3) |
| ALPN | `h2` | `h3` |
| cipher suite IDs (wire order, десятичные) | 4866, 4865, 4867, 49196, 49195, 52393, 49200, 49199, 52392 | 4866, 4865, 4867 |
| extension IDs (wire order, десятичные) | 23, 43, 51, 45, 16, 13, 5, 11, 10, 0 | 10, 16, 5, 45, 0, 43, 23, 51, 57, 11, 13 |
| QUIC TP extension 57 | нет | есть |
| GREASE extension IDs | 0 | 0 |
| SNI | присутствует; само значение не выводится | присутствует; значение не выводится |

Эта диагностика **не** рассчитывает JA3/JA4 и не сравнивает реальный wire traffic с Chrome. Engine-only H3 использует пустые test transport params, поэтому packet-level QUIC fingerprint может отличаться. Отсутствие GREASE в одном default rustls baseline не позволяет сделать вывод о поведении любого браузера.

## Контракт диагностики

```sh
cargo test --manifest-path spikes/m0_1/Cargo.toml --locked --test client_hello_baseline -- --nocapture
```

Диагностика выводит только безопасный список ID и булевы признаки. TLS record serialization и plaintext QUIC handshake имеют **разные** wire transports, их нельзя сравнивать как один поток TCP. Замена TLS backend ради H2 сама по себе не доказывает его совместимость с Quinn H3 или BBR.

Наблюдаемые code-point IDs нужно сверять с эталонным браузером **той же версии**, захватив его ClientHello/HTTP SETTINGS в контролируемой среде. Стабильная точная перестановка TLS extensions не является надёжным критерием совпадения с Chromium: его порядок extensions может рандомизироваться, и для устойчивого сравнения нужны более полные признаки (например, методология JA4).

## Почему не объявлен браузерный профиль

Quinn предоставляет расширяемую crypto abstraction, но его стандартная интеграция TLS использует rustls; у обычного rustls не доказано управление всеми полями ClientHello, необходимыми для настоящей браузероподобной маскировки. Fork rustls, BoringSSL backend или замена QUIC stack требуют отдельных кросс-платформенных тестов, проверки лицензий и безопасности, подтверждения BBR и всех H2/H3 streaming инвариантов.

**Следующий эксперимент:** получить real browser reference captures H2 и H3, проверить несовпадающие TLS/HTTP поля и выбрать кандидат TLS backend с реальным QUIC/H3 соединением и fail-closed certificate validation. До этого `tls_profile = "default"` остаётся единственным допустимым примером конфигурации, F-13 и M0.1 **не complete**.

## Upstream evidence

- https://docs.rs/quinn/0.11.12/quinn/crypto/index.html
- https://docs.rs/rustls/0.23.46/rustls/quic/struct.ClientConnection.html
- https://blog.cloudflare.com/ja4-signals/
- https://github.com/FoxIO-LLC/ja4

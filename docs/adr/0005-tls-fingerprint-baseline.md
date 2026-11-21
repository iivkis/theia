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
| **Go uTLS v1.8.2 HelloChrome_133 H2/TLS эталон** вместо захватов браузера | PASS: generated first flight, сравнение с rustls, Linux/Windows CI |
| **Реальное TCP/TLS 1.3 + H2 Go uTLS → Rust h2 loopback** | PASS Linux/Windows: на TCP обнаружены GREASE/ALPS, x509 trust chain, SNI, ALPN h2, GET/204, wrong-name/untrusted-CA fail closed |
| **Browser-like TLS/H2 в едином Rust бинарнике** | **OPEN**: Go uTLS network helper запускается только из CI и не встроен в Rust Theia |
| QUIC/H3-совместимый эталон (Go uTLS TCP H2 для этого недостаточно) | OPEN |
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

Наблюдаемые code-point IDs для **TCP/H2** теперь сверяются с генерируемым **Go uTLS v1.8.2 HelloChrome_133**, без захвата живого браузера. Это эталон имитируемого профиля uTLS, а не доказательство байт-в-байт совместимости с конкретной установленной версией Chrome. Стабильная точная перестановка TLS extensions не является надёжным критерием совпадения с Chromium: его порядок extensions может рандомизироваться, и для устойчивого сравнения нужны более полные признаки (например, методология JA4).

## Контрольное несоответствие default rustls browser-like профилю

В дополнительном version-pinned тесте `default_rustls_h2_cannot_pass_named_browser_gate` проверены **отсутствие GREASE extension** и **отсутствие ALPS в обоих BoringSSL codepoints**, old `17513 (0x4469)` и current `17613 (0x44cd)`. Обновлённый парсер извлекает supported_groups (в одной измеренной TLS/H2 first flight: `[29, 23, 24]`), проверяет длину вектора и отвергает неверную длину. Unit tests отдельно подтверждают распознавание **обоих** ALPS кодов, не полагаясь на специфический браузерный профиль.

Ни GREASE+ALPS, ни их отсутствие не доказывают сходство/несходство **со всеми** версиями браузера. Но current pinned rustls с отсутствующими полями нельзя помечать как verified Chrome/Edge profile; при обновлении TLS-библиотеки negative-control обязан заставить пересмотреть измерительный отчёт. Go uTLS эталон для H2 генерируется без reference browser pcap, но нет QUIC/H3-compatible эталона, фактической Theia fingerprint реализации, ни HTTP2 SETTINGS/HTTP3 SETTINGS comparison. Статус F-13 остаётся **BLOCKED**.

Источники кодовых точек и поведения: [BoringSSL upstream TLS extensions](https://chromium.googlesource.com/external/gob/boringssl/boringssl/+/refs/heads/upstream/main/ssl/extensions.cc) и [Chromium TLS client settings](https://chromium.googlesource.com/chromium/src/+/2ec06e00be685b89d7a77a9bb9d677f4a50130e5/net/socket/ssl_client_socket_impl.cc).

## Почему не объявлен браузерный профиль

Quinn предоставляет расширяемую crypto abstraction, но его стандартная интеграция TLS использует rustls; у обычного rustls не доказано управление всеми полями ClientHello, необходимыми для настоящей браузероподобной маскировки. Fork rustls, BoringSSL backend или замена QUIC stack требуют отдельных кросс-платформенных тестов, проверки лицензий и безопасности, подтверждения BBR и всех H2/H3 streaming инвариантов.

**Следующий эксперимент:** использовать воспроизводимый Go uTLS HelloChrome_133 для H2/TLS, отдельно подобрать QUIC/H3 эталон (Go uTLS TCP не поддерживает QUIC CRYPTO), затем выбрать работающий backend с H2/H3 соединениями и fail-closed certificate validation, сверить фактические TLS/HTTP поля. Захваты живого браузера не требуются. До этого `tls_profile = "default"` остаётся единственным допустимым примером конфигурации, F-13 и M0.1 **не complete**.

## Upstream evidence

- https://docs.rs/quinn/0.11.12/quinn/crypto/index.html
- https://docs.rs/rustls/0.23.46/rustls/quic/struct.ClientConnection.html
- https://blog.cloudflare.com/ja4-signals/
- https://github.com/FoxIO-LLC/ja4

## Решение: Go uTLS вместо browser captures как источник эталона

По решению пользователя **больше не требуется захватывать трафик настоящего браузера** как входные данные сравнения. В `spikes/m0_1/utls_reference/` добавлен отдельный Go-инструмент, напрямую использующий `github.com/refraction-networking/utls v1.8.2` и версионированный `HelloChrome_133` (не `HelloChrome_Auto`). Он вызывает `BuildHandshakeState()` без сетевого сокета, записывает только временный raw ClientHello в приватный файл и **никогда не выводит** SNI/random/key shares/сырой TLS в журнал. Контрольные файлы Go `go.mod` + `go.sum` закрепляют версию.

Rust тест `tests/utls_reference.rs` с помощью имеющегося bounded parser сравнивает эталон со своим **default rustls**. На Linux впервые зафиксированы наблюдения:

| Поле | Go uTLS 1.8.2 HelloChrome_133 (TCP/H2) | rustls 0.23.46 default (TCP/H2) |
| --- | --- | --- |
| GREASE (extension) | Да | Нет |
| ALPS (в том числе codepoint 17613) | Да | Нет |
| Cipher suites count | 16 | 9 |
| TLS extensions count | 18 | 10 |
| supported_groups count | 5 | 3 |
| ALPN | h2, http/1.1 | h2 |
| QUIC transport parameters | Нет, это TCP TLS | Нет, это TCP TLS |

Тест проверяет поведение версионированного Go-профиля, но **не гарантирует** совпадение с установленным браузером Chrome версии 133 или будущими версиями. uTLS динамически переставляет некоторые расширения/GREASE, поэтому точное сравнение порядка байт между запусками ненадёжно. Версия профиля фиксирована, а не «текущий Chrome» на 2026 год.

```bash
cd spikes/m0_1/utls_reference
go test ./...
go run . /tmp/theia-utls-h2.bin
cd ../../..
THEIA_UTLS_HELLO_PATH=/tmp/theia-utls-h2.bin cargo test --manifest-path spikes/m0_1/Cargo.toml --locked --test utls_reference -- --ignored --nocapture
rm -f /tmp/theia-utls-h2.bin
```

**Граница:** этот Go-инструмент пока служит **только эталоном**, не TLS-бэкендом Rust Theia. Поставка остаётся одним Rust binary; Go не является runtime-зависимостью. Go uTLS TCP/H2 ClientHello не содержит mandatory QUIC transport parameters, не подключён к crypto trait Quinn и не создаёт H3 SETTINGS. Для F-13 нужны реальное изменение TLS fingerprint на H2/H3, отдельный совместимый QUIC эталон, сравнение действительного сетевого выхода Theia и CI на обеих ОС. Ни одна из этих частей пока не объявлена готовой.

## Измерение настоящего Go uTLS TCP/H2 соединения (M0.1 PR #13)

`spikes/m0_1/utls_reference/cmd/h2_probe/main.go` теперь использует pinned `HelloChrome_133` не только для генерации эталонного буфера, а для **настоящего** TLS 1.3 соединения с Rust сервером на `127.0.0.1`. Rust тест `spikes/m0_1/tests/utls_h2_loopback.rs` извлекает первый TLS ClientHello через `TcpStream::peek` **до TLS accept**, затем проверяет настоящую сессию Rust `h2 0.4.19`.

На обеих ОС проверяются три сценария:
- **Успех**: Go uTLS посылает TCP ClientHello с `h2,http/1.1`, GREASE, ALPS и SNI. Go проверяет x509 цепочку/hostname через `RootCAs` и **не** использует `InsecureSkipVerify`. Negotiated TLS 1.3 и ALPN `h2`; Go отправляет минимальный HTTP/2 preface, SETTINGS, GET HEADERS, Rust возвращает HTTP 204.
- **Wrong-hostname**: Go требует `wronghost`, certificate SAN содержит только `localhost`. Клиент должен получить `x509.HostnameError`, не послать H2.
- **Untrusted-CA**: пустой root pool, Go должен получить `x509.UnknownAuthorityError`, не послать H2.

Проверка снимает структурные признаки ClientHello с реального локального TCP-сокета. **Нет** журналирования SNI, key share, TLS random, полного сертификата или сырых TLS-байт. Отдельный Go test запрещает тестовому CLI подключения вне loopback; Go test-only binary **не** распространяется и не запускается в production. Запрос GET реализован минимальными стандартными H2 фреймами, а **не** браузерным профилем H2 SETTINGS/priority.

**Критическая граница:** это реальный Go uTLS *клиент*, подключённый к Rust H2 *серверу*. В Windows/Linux CI Go бинарник собирается специально для теста, он **не** является TLS бэкендом Rust Theia. Требование одного Rust binary сохраняется. Настоящее имитирующее `ClientHello` поведение Rust H2 клиента и отдельный QUIC/H3 профиль **OPEN/P0**. Единичный GET не доказывает full-duplex SmartTheia adapter, а факт присутствия GREASE/ALPS не обеспечивает точного соответствия Chrome.

Исходные доказательства: https://github.com/iivkis/theia/actions/runs/44952081857 (Linux/Windows, 3/3 network E2E tests); финальный PR CI: https://github.com/iivkis/theia/pull/13.

```sh
# CI builds the helper after Go dependencies are verified:
cd spikes/m0_1/utls_reference
go test ./...
go build -o /tmp/theia-utls-h2-probe ./cmd/h2_probe
cd ../../..
THEIA_UTLS_H2_PROBE=/tmp/theia-utls-h2-probe cargo test --manifest-path spikes/m0_1/Cargo.toml --locked --test utls_h2_loopback -- --ignored --nocapture
```

Для M3.4 по-прежнему нужен кроссплатформенный H2 TLS backend *внутри одного Rust бинарника* и отдельная проверка QUIC/H3. Использовать Go uTLS для эталона и CI допустимо, автоматически объявлять его production backend нельзя.

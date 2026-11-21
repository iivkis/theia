# ADR-0004: M0.1 транспортный feasibility spike

**Дата исследования:** 2026-11-22  
**Статус:** partial feasibility **verified**; production transport stack **not approved for release**.  
**Связанные требования:** F-04 / F-05 / F-11 / F-13 / F-16.

## Цель

До начала разработки клиентского/серверного ядра убедиться, что существующие Rust API способны обеспечить независимые потоки отправки/приёма в H2/H3, BBR для обеих сторон QUIC и реальную возможность настройки браузероподобного TLS/HTTP fingerprint. Проверять критические свойства исполняемым кодом, а не считать наличие документации доказательством интеграции.

## Исследованные версии (изолированный crate)

`spikes/m0_1/Cargo.toml` + **закреплённый** `spikes/m0_1/Cargo.lock`:
- `quinn = 0.11.12`: QUIC transport, `congestion::BbrConfig`.
- `h3 = 0.0.8` + `h3-quinn = 0.0.10`: HTTP/3 stream API + Quinn adapter.
- `h2 = 0.4.19`: HTTP/2 stream API.
- `tokio`, `http`, `bytes`: тестовое окружение.
- `tokio-rustls = 0.26.6` + `rustls = 0.23.46`, `rcgen = 0.13.2` (dev-only): TCP/TLS 1.3 E2E, ephemeral certificates с обычной цепочкой доверия, без custom insecure verifier.

Это **кандидаты**, не финальный production выбор. До M1 закрепить security status и MSRV, проверить лицензии и транзитивные зависимости. Для TCP/TLS явно выбирается `rustls::crypto::ring` provider и только TLS 1.3; ALPN проверяется **после** handshake. Это **не** uTLS impersonation.

## Проверяемая матрица

| Контракт | Доказательство M0.1 | Вывод |
| --- | --- | --- |
| H2 response до request EOF (in-memory) | `http2_response_before_request_eof`: POST с открытым body, HTTP response приходит до body EOF, затем сервер получает оставшиеся bytes | **PASS** на Linux и Windows; базовый тест без TLS |
| **H2 поверх TCP/TLS 1.3** | `tests/h2_tls.rs`: real loopback TCP sockets, rustls TLS 1.3, trust-store certificate validation, negotiated ALPN `h2`, HTTP/2 response before request EOF с последующим body в обе стороны, explicit `reserve_capacity/poll_capacity` и `release_capacity`; отдельные wrong-hostname, untrusted-CA, ALPN-mismatch | **PASS: 4/4 integration tests** на Linux и Windows. Открыты stress, resource/backpressure under load и production tunnel integration |
| QUIC BBR active state | Реальный QUIC loopback TLS H3 тест использует `BbrConfig` на обоих endpoints, проверяет `Connection::congestion_state().into_any().downcast::<Bbr>()` **и у клиента, и у сервера** | **ACTIVE CONTROLLER PASS** на Linux; loss/jitter benchmarks **OPEN** |
| H3 real QUIC/TLS and streaming | Настоящие UDP sockets, TLS cert generated for localhost (trusted test root, no custom verifier), ALPN `h3`, send request phase-1, receive response before request EOF, then phase-2 both ways; wrong hostname rejection | **PASS** в Linux и Windows CI; HTTP3 half-close/cancellation stress **OPEN** |
| Windows x64 | Независимый native Windows CI spike проверяет реальный H2 over TCP/TLS, H3 over UDP/QUIC/TLS и API | **PASS** в Windows-native CI; WinINet/TUI не затрагиваются |
| uTLS-like TLS fingerprint | Рассмотрены upstream rustls/Quinn ограничения и сторонние fork/BoringSSL варианты; нет проверенного одинакового профиля H3/H2 | **BLOCKER P0**; не считать feature реализованной и не включать профили кроме `default` |

Сетевые доказательства с закреплённым Cargo.lock: H2/TLS + H3/TLS + API (**9/9 Rust tests**, Linux/Windows) https://github.com/iivkis/theia/actions/runs/44941068710; ранее H3/BBR (**5/5 Rust tests**) https://github.com/iivkis/theia/actions/runs/44940250307. Ранее CI свидетельства: https://github.com/iivkis/theia/actions/runs/44938796454 (первый Linux: 3/3 tests; `cargo check --all-targets` success) и https://github.com/iivkis/theia/actions/runs/44939068608 (Linux **и Windows native** spike успешны при закреплённом `Cargo.lock`). Эти тесты доказывают только явные свойства API/HTTP2, но не релизные критерии QUIC/TLS.

## Технические выводы

### BBR

В `quinn 0.11.12` присутствуют `congestion::BbrConfig` и `TransportConfig::congestion_controller_factory`. BBR помечен **experimental**. В реальном HTTP/3 QUIC/TLS тесте оба отправителя используют `BbrConfig`; проверено через `Connection::congestion_state().into_any().downcast::<Bbr>()` на клиенте и сервере. Это **доказывает активный класс контроллера, но не качество его работы**: loss/jitter/RTT benchmarks, pacing, fairness и resilience остаются отдельным блокером F-11.

Источники: https://docs.rs/quinn/0.11.12/quinn/congestion/struct.BbrConfig.html · https://docs.rs/quinn/0.11.12/quinn/struct.TransportConfig.html · https://docs.rs/quinn/0.11.12/quinn/congestion/index.html.

### HTTP/3 и HTTP/2

`h3 0.0.8` включает `RequestStream::split` для независимых задач отправки и получения; `h3-quinn 0.0.10` работает с Quinn 0.11.x. В отдельном интеграционном тесте HTTP/3 по UDP/QUIC/TLS 1.3 **реально** получил ответ до EOF запроса и продолжил двустороннюю передачу; ALPN `h3`, hostname verification и активный BBR проверены. `h2 0.4.19` совместно с `tokio-rustls 0.26.6` **реально** прошёл TCP/TLS 1.3 + ALPN `h2` E2E response-before-EOF, включая две фазы DATA и fail-closed hostname/CA/ALPN. Дальнейшие E2E обязаны проверить request-body-without-EOF, response body, half-close, cancellation, bounded send capacity.

`h2::SendStream::send_data` **может буферизовать без верхнего предела**, если отправлять без `reserve_capacity/poll_capacity`: production adapter должен использовать явный bounded backpressure, а не копировать маленький тестовый пример.

Источники: https://docs.rs/h3/0.0.8/h3/client/struct.RequestStream.html · https://docs.rs/h3/0.0.8/h3/server/struct.RequestStream.html · https://docs.rs/crate/h3-quinn/0.0.10 · https://docs.rs/h2/0.4.19/h2/client/struct.SendRequest.html · https://docs.rs/h2/0.4.19/h2/struct.SendStream.html.

### TLS fingerprint: главный открытый блокер

Quinn поддерживает pluggable crypto abstraction, но документированная встроенная реализация TLS для QUIC основана на `rustls`. У обычного rustls **нельзя автоматически предполагать** управление всем ClientHello (extension order/GREASE/ALPS) для uTLS-совместимого профиля. `BoringSSL`-based библиотеки и RustLS forks могут быть кандидатами, но их API совместимость с **Quinn QUIC** и `h3` не доказана наличием работающего H2 TLS-клиента. Не смешивать H2-TLS fingerprints с H3-QUIC fingerprints.

Следующий отдельный `M0.1 TLS` эксперимент: подобрать один кросс-платформенный backend, поднять localhost TLS client/server с нормальной проверкой trust chain и SNI, снять pcap ClientHello H2 и H3, сравнить с контрольным браузером, проверить невозможность silent downgrade. Только тогда именованный `tls_profile` можно назвать реализованным.

Источники: https://docs.rs/quinn/0.11.12/quinn/crypto/index.html · https://github.com/rustls/rustls/issues/1932 · https://github.com/3andne/craftls · https://docs.rs/primp-rustls/latest/rustls/client/struct.BrowserEmulator.html.

## Решения

1. **В качестве базового стека для следующих локальных E2E экспериментально рекомендовать** Quinn 0.11.12 + h3 0.0.8 / h3-quinn 0.0.10 и h2 0.4.19, до security audit и решения о TLS backend.
2. Не добавлять `Cargo.toml` в корень, пока не стартовал M1.1; spike **не входит в production binary**. Использовать отдельный lock и CI job, не отключая checks `AGENTS.md`.
3. Не закрывать M0.1 полностью до реального H3/H2 TLS и browser-like profile feasibility. Остаточные P0 gates описаны ниже.

## Следующие обязательные эксперименты (open)

- [x] Реальный H3 over QUIC localhost client/server, TLS trust verification + ALPN h3, full-duplex before request EOF и negative wrong hostname на Linux **и Windows native CI**.
- [ ] H3 full-duplex half-close/cancel/backpressure under load — отдельный тест.
- [x] TLS-backed H2 over TCP TLS 1.3, ALPN h2, full-duplex body с explicit flow-control capacity, wrong-hostname/untrusted CA/ALPN-mismatch negative tests (Linux и Windows CI).
- [ ] H2 backpressure, half-close, cancellation, slow readers при большом объёме данных и concurrent streams, прежде чем переносить adapter в production.
- [ ] BBR selected on both actual endpoints + loss/jitter comparison, logs do not expose credentials.
- [ ] Один проверяемый кросс-платформенный uTLS-like profile для H2 **и** H3; packet captures с поддерживаемыми/несовпадающими полями.
- [x] Windows native spike CI пройден (API/H2).
- [ ] Windows system proxy VM smoke (M4.3) — не относится к scope spike.
- [ ] Security audit и лицензии всех production dependency candidates.

Только после выполнения этих пунктов агент имеет право пометить `M0.1` как **complete**. До этого — **partial**; принцип «не изображать готовность» обязателен.

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
| QUIC BBR active state | Реальный QUIC loopback TLS H3 тест использует `BbrConfig` на обоих endpoints, проверяет `Connection::congestion_state().into_any().downcast::<Bbr>()` **и у клиента, и у сервера** | **ACTIVE CONTROLLER PASS** на Linux/Windows; comparative loss/jitter benchmarks **OPEN** |
| **BBR recovery under controlled loss** | `tests/quic_bbr_loss.rs`: Quinn `AsyncUdpSocket`, чистый и «каждый 20-й UDP transmit dropped» на реальных localhost QUIC/TLS, в каждом сценарии передано и получено точно 768 КиБ; RTT, lost_packets, congestion_events, attempted/dropped datagrams фиксируются в `PathStats` | **RECOVERY PASS** Linux+Windows CI (без внешнего netem). Это тест synthetic UDP send loss **без HTTP/3 framing**, не воспроизводимый network benchmark или доказательство улучшения BBR |
| **H2 flow window + half-close** | `tls13_h2_megabyte_flow_control_and_half_close`: real TLS/H2 отправка 1 МиБ с остановкой после 60 КиБ без `WINDOW_UPDATE`, проверка недостаточной sender capacity для очередных 4 КиБ, затем возобновление и ответ 256 КиБ после request FIN | **FLOW CONTROL + HALF-CLOSE PASS** Linux+Windows; peak RSS stress **OPEN** |
| **H2 response slow-reader** | `tls13_h2_slow_response_reader_stalls_and_recovers`: клиент удерживает 61 440 байт stream credit, сервер не может отправить очередные 4096 байт и после `WINDOW_UPDATE` целиком передаёт 512 КиБ ответа | **PASS** Linux/Windows на одном медленном получателе; не масштабный RSS benchmark |
| **H3 response slow-reader** | `h3_quic_slow_response_reader_stalls_and_recovers`: тестовая QUIC-конфигурация `send_window=48KiB`, `stream_receive_window=32KiB`, `receive_window=256KiB`; ответ 1 МиБ не может завершиться, пока читатель не получает DATA, после чего byte-exact delivery и FIN | **PASS** Linux/Windows; ограничения относятся к Quinn send/receive buffers, не всему RSS; короткий stall check не является производительным benchmark |
| H3 real QUIC/TLS and streaming | Настоящие UDP sockets, TLS cert generated for localhost (trusted test root, no custom verifier), ALPN `h3`, send request phase-1, receive response before request EOF, then phase-2 both ways; wrong hostname rejection | **PASS** Linux+Windows; FIN, 8 streams и cancellation isolation в отдельных E2E; slow-reader/memory stress **OPEN** |
| **H2/H3 multiplexing** | `tls13_h2_eight_concurrent_full_duplex_streams` и `h3_quic_eight_concurrent_bidirectional_streams`: восемь stream HEADERS получены прежде любого ответа, затем у каждого HTTP response и DATA до request EOF, ещё один DATA в обоих направлениях | **PASS** Linux+Windows на одном TLS/H2 и одном QUIC/H3 соединении; 8 не означает сотни потоков |
| **H2/H3 cancellation isolation** | `tls13_h2_cancel_stream_preserves_connection`: RST_STREAM CANCEL и следующий 204 по тому же TLS. `h3_quic_cancel_stream_preserves_sibling_request`: QUIC RESET_STREAM/STOP_SENDING `H3_REQUEST_CANCELLED`, следующий 204 по тому же QUIC | **PASS** Linux+Windows; race/cancellation under load **OPEN** |
| Windows x64 | Независимый native Windows CI spike проверяет реальный H2 over TCP/TLS, H3 over UDP/QUIC/TLS и API | **PASS** в Windows-native CI; WinINet/TUI не затрагиваются |
| uTLS-like TLS fingerprint | **Исполняемый rustls ClientHello baseline** для TCP/H2 и QUIC/H3 TLS CRYPTO: cipher IDs, extension IDs/order, ALPN, groups, TLS versions; H2 не содержит GREASE и ALPS old/new. Отдельные bounded-parser regressions. См. ADR-0005 | **OBSERVABILITY PASS**, но реальный Quinn Initial pcap и сравнение с Chrome отсутствуют. **P0 BLOCKER**: browser-like профиль не реализован; конфиг только `default` |

Новые сценарии CI (**17 Rust tests**) включают H2/H3 slow-reader backpressure: https://github.com/iivkis/theia/actions/runs/44944894920. Предыдущий CI (**15 Rust tests**) включает H2/H3 concurrency и cancellation isolation: https://github.com/iivkis/theia/actions/runs/44943882915. Предыдущий CI (11 Rust tests) включает loss-recovery и large H2 flow control: https://github.com/iivkis/theia/actions/runs/44942565497. Сетевые доказательства с закреплённым Cargo.lock: H2/TLS + H3/TLS + API (**9/9 Rust tests**, Linux/Windows) https://github.com/iivkis/theia/actions/runs/44941068710; ранее H3/BBR (**5/5 Rust tests**) https://github.com/iivkis/theia/actions/runs/44940250307. Ранее CI свидетельства: https://github.com/iivkis/theia/actions/runs/44938796454 (первый Linux: 3/3 tests; `cargo check --all-targets` success) и https://github.com/iivkis/theia/actions/runs/44939068608 (Linux **и Windows native** spike успешны при закреплённом `Cargo.lock`). Эти тесты доказывают только явные свойства API/HTTP2, но не релизные критерии QUIC/TLS.

## Технические выводы

### BBR

В `quinn 0.11.12` присутствуют `congestion::BbrConfig` и `TransportConfig::congestion_controller_factory`. BBR помечен **experimental**. В реальном HTTP/3 QUIC/TLS тесте оба отправителя используют `BbrConfig`; проверено через `Connection::congestion_state().into_any().downcast::<Bbr>()` на клиенте и сервере. Это **доказывает активный класс контроллера**. Отдельный тест `quic_bbr_loss.rs` injects deterministic 1/20 outgoing UDP datagram loss **после TLS handshake**, проверяет byte-exact recovery и собирает `Connection::stats().path` (RTT, loss, congestion events). Это **не** доказывает, что BBR быстрее CUBIC или устойчивее при задержках: comparative controlled RTT/jitter/loss benchmarks, pacing и fairness остаются блокером F-11.

Источники: https://docs.rs/quinn/0.11.12/quinn/congestion/struct.BbrConfig.html · https://docs.rs/quinn/0.11.12/quinn/struct.TransportConfig.html · https://docs.rs/quinn/0.11.12/quinn/congestion/index.html.

### HTTP/3 и HTTP/2

`h3 0.0.8` включает `RequestStream::split` для независимых задач отправки и получения; `h3-quinn 0.0.10` работает с Quinn 0.11.x. В отдельном интеграционном тесте HTTP/3 по UDP/QUIC/TLS 1.3 **реально** получил ответ до EOF запроса и продолжил двустороннюю передачу; ALPN `h3`, hostname verification и активный BBR проверены. `h2 0.4.19` совместно с `tokio-rustls 0.26.6` **реально** прошёл TCP/TLS 1.3 + ALPN `h2` E2E response-before-EOF, включая две фазы DATA и fail-closed hostname/CA/ALPN. Новый H2/TLS мегабайтный тест удерживает credit на 60 КиБ, проверяет недостаток capacity для очередного 4 КиБ блока, затем освобождает credit и доставляет весь 1 МиБ. После request-side FIN принимается ещё 256 КиБ response DATA. **Теперь отдельно подтверждены 8 concurrent streams и отмена через RST_STREAM/QUIC RESET_STREAM без нарушения соседнего запроса** на обоих транспортах. Тесты с *одним намеренно медленным читателем* теперь подтверждают H2 WINDOW_UPDATE и H3 QUIC `send_window` с возобновлением доставки. **Но** остаются массовая отмена, сотни slow readers, peak RSS и справедливость между потоками.

`h2::SendStream::send_data` **может буферизовать без верхнего предела**, если отправлять без `reserve_capacity/poll_capacity`: production adapter должен использовать явный bounded backpressure, а не копировать маленький тестовый пример.

Источники: https://docs.rs/h3/0.0.8/h3/client/struct.RequestStream.html · https://docs.rs/h3/0.0.8/h3/server/struct.RequestStream.html · https://docs.rs/crate/h3-quinn/0.0.10 · https://docs.rs/h2/0.4.19/h2/client/struct.SendRequest.html · https://docs.rs/h2/0.4.19/h2/struct.SendStream.html.

### TLS fingerprint: главный открытый блокер

Quinn поддерживает pluggable crypto abstraction, но документированная встроенная реализация TLS для QUIC основана на `rustls`. У обычного rustls **нельзя автоматически предполагать** управление всем ClientHello (extension order/GREASE/ALPS) для uTLS-совместимого профиля. `BoringSSL`-based библиотеки и RustLS forks могут быть кандидатами, но их API совместимость с **Quinn QUIC** и `h3` не доказана наличием работающего H2 TLS-клиента. Не смешивать H2-TLS fingerprints с H3-QUIC fingerprints.

Отдельный исполняемый **ClientHello first-flight observation** уже создан для TCP/H2 и QUIC/H3 TLS CRYPTO (см. **ADR-0005**). Он фиксирует absence GREASE и ALPS old/new у pinned default rustls, **но не заменяет** pcap на проводе, QUIC Initial decryption и контрольный browser capture. Следующий M0.1 experiment обязан проверить named TLS backend с реальными H2/H3 pcap и strict PKI, а не только API совместимость. Только тогда именованный `tls_profile` можно назвать реализованным.

Источники: https://docs.rs/quinn/0.11.12/quinn/crypto/index.html · https://github.com/rustls/rustls/issues/1932 · https://github.com/3andne/craftls · https://docs.rs/primp-rustls/latest/rustls/client/struct.BrowserEmulator.html.

## Решения

1. **В качестве базового стека для следующих локальных E2E экспериментально рекомендовать** Quinn 0.11.12 + h3 0.0.8 / h3-quinn 0.0.10 и h2 0.4.19, до security audit и решения о TLS backend.
2. Не добавлять `Cargo.toml` в корень, пока не стартовал M1.1; spike **не входит в production binary**. Использовать отдельный lock и CI job, не отключая checks `AGENTS.md`.
3. H2/TLS и H3/QUIC/TLS теперь verified реальными Linux/Windows тестами, включая малое число concurrent streams и cancellation isolation. M0.1 **не complete** до browser-like TLS/H2/H3 profile feasibility, comparative BBR benchmarks и нагрузочных/memory gates. Остаточные P0 gates описаны ниже.

## Следующие обязательные эксперименты (open)

- [x] Реальный H3 over QUIC localhost client/server, TLS trust verification + ALPN h3, full-duplex before request EOF и negative wrong hostname на Linux **и Windows native CI**.
- [x] H3 multiplexing с 8 одновременно открытыми bidirectional streams, ответами до request EOF, FIN и единичной отменой stream с успешным sibling request, Linux/Windows.
- [x] H3 slow-reader: 1 МиБ ответа, малые окна QUIC, пауза без чтения и успешное восстановление передачи (Linux/Windows).
- [ ] H3 массовые cancellation races, сотни slow readers, memory-cap/RSS и fairness under load — отдельные нагрузочные тесты.
- [x] TLS-backed H2 over TCP TLS 1.3, ALPN h2, full-duplex body с explicit flow-control capacity, wrong-hostname/untrusted CA/ALPN-mismatch negative tests (Linux и Windows CI).
- [x] H2/TLS backpressure и request half-close в тесте 1 МиБ request / 256 КиБ response, sender capacity gated по WINDOW_UPDATE (Linux+Windows).
- [x] H2 multiplexing с 8 одновременно открытыми streams и RST_STREAM CANCEL с успешным sibling request в той же TLS session, Linux/Windows.
- [x] H2 slow-reader: удержание 61 440 байт WINDOW_UPDATE и восстановление доставки 512 КиБ response (Linux/Windows).
- [ ] H2 сотни concurrent slow readers, массовые cancellation races и memory-cap measurements перед переносом адаптера в production.
- [x] BBR controller выбран на обоих real QUIC endpoints; синтетическое отбрасывание каждой 20-й исходящей UDP-датаграммы на сервере после TLS handshake, восстановление 768 КиБ байт-в-байт, статистика RTT/loss/congestion (Linux+Windows).
- [ ] BBR controlled RTT/jitter/loss vs CUBIC baselines + throughput/pacing/fairness; статистика из CI **не считается** performance benchmark; не записывать учётные данные в логи.
- [x] Структурное наблюдение TCP/H2 и QUIC/H3 TLS CRYPTO first flights и negative control default rustls без GREASE/ALPS; ADR-0005.
- [ ] Один проверяемый кросс-платформенный uTLS-like profile для H2 **и** H3; **реальные** browser reference и Quinn wire packet captures с поддерживаемыми/несовпадающими полями.
- [x] Windows native spike CI пройден (API/H2).
- [ ] Windows system proxy VM smoke (M4.3) — не относится к scope spike.
- [ ] Security audit и лицензии всех production dependency candidates.

Только после выполнения этих пунктов агент имеет право пометить `M0.1` как **complete**. До этого — **partial**; принцип «не изображать готовность» обязателен.

## Синтетический controlled-loss эксперимент (добавлено M0.1)

`spikes/m0_1/tests/quic_bbr_loss.rs` оборачивает существующий `quinn::AsyncUdpSocket`, без прав администратора. **После завершения TLS-handshake** обёртка возвращает `Ok(())` вместо реальной отправки каждой 20-й исходящей датаграммы, а `max_transmit_segments=1` отключает GSO для этого сценария. Фиксированный порядок отправки делает паттерн сбросов воспроизводимым по счётчику попыток, но реальная доля потерянных QUIC пакетов не обязана быть ровно 5%, и статистика retransmission отличается от счётчика сбросов. Сценарии 0% и «каждый 20-й UDP transmit» проверяют **целостность 768 КиБ** и активный `Bbr` с обеих сторон.

```sh
cargo test --manifest-path spikes/m0_1/Cargo.toml --locked --test quic_bbr_loss -- --nocapture
```

Вывод включает `attempted_datagrams`, `dropped_datagrams`, `sent_packets`, `lost_packets`, `congestion_events`, `rtt` и `elapsed`. Никакой auth token, certificate key, содержимое payload или секрет не логируется. Эти данные диагностические, **не ранжирование BBR и CUBIC**; влияние планировщика/локального UDP/CPU не контролируется, и RTT/jitter не моделируются. Для релизного F-11 нужен отдельный baseline harness на фиксированном окружении.

## Блокировка медленным получателем (M0.1)

Оба новых теста используют реальные loopback TLS transport и выделяют **одного** медленного читателя. HTTP/2 намеренно удерживает потоковые WINDOW_UPDATE до заполнения 60 КиБ доступного кредита. Серверный `SendStream` не способен отправить полный следующий блок 4096 байт, затем при явном `release_capacity` допередаёт 512 КиБ. В отличие от предыдущего теста на медленный *серверный* receive path, здесь медленным сделан читатель *response*.

HTTP/3 ограничивает `TransportConfig::send_window(48*1024)` (максимум сохраняемых Quinn байт из application writes по всем streams), а также `stream_receive_window(32*1024)` и `receive_window(256*1024)` у клиента. При отсутствии чтения response сервер не завершает запись 1 МиБ (проверка на коротком наблюдаемом интервале), после возобновления чтения клиент получает все DATA байт-в-байт. Это доказывает действие **Quinn flow control в экспериментальной конфигурации**, но не верхнюю границу памяти TLS, HTTP/3 слоя, задачи Tokio и процесса в целом. Тест не измеряет peak RSS и не утверждает, что реальные endpoints уже используют эти настройки.

```sh
cargo test --manifest-path spikes/m0_1/Cargo.toml --locked --test h2_tls tls13_h2_slow_response_reader_stalls_and_recovers
cargo test --manifest-path spikes/m0_1/Cargo.toml --locked --test h3_quic h3_quic_slow_response_reader_stalls_and_recovers
```

Следующий release-oriented эксперимент: сотни concurrent stream readers с фиксированным суммарным payload budget, измерение process peak RSS на выделенном CI/benchmark runner, проверки fairness и отмены при полной очереди. Только после этого можно задавать пределы памяти в production конфигурации.

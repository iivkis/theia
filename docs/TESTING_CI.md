# Testing strategy и CI

**Правило CI-only:** все проверки выполняются автоматически в GitHub Actions. Разработчик и пользователь не должны запускать тесты или вручную подтверждать сценарии. Тестирование предшествует сборке релизных артефактов. CI не должен маскировать отсутствие сетевой Rust-реализации. С M1.1 корневой workspace и `Cargo.lock` существуют: Linux `rust-tests` и Windows `windows-smoke` должны запускаться. CLI `--help`/`--version` работают; с M1.2 `config validate` выполняет структурную TOML v1 validation (exit 0/2) без чтения секретов. Команда `tui` возвращает `not implemented` (exit 3); M2.2b добавляет `client run` в explicit H2 (CI pending); с M2.1 `server run` — реальный TLS1.3/H2 сервер с bearer/inbound ACL + TCP dial и ненулевым exit на invalid config/PEM. До M1.1 Rust jobs были skipped.

## 1. Test pyramid

### A. Pure unit tests (самые быстрые, обязательны в каждом PR)

- SmartTheia encode/decode golden byte vectors; arbitrary chunk splitting/aggregation; frame length 0/65536/65537; invalid flags/type/state; отсутствие паники и out-of-bounds. С M1.3 — `crates/theia/tests/protocol.rs` с реальными golden-byte assertions, per-stream client/server FSM, strict OPEN_OK gate, half-close/abort и deterministic malformed-byte regression. Настоящий coverage-guided fuzz и transport E2E остаются за пределами pure codec PR.
- Typed TOML: missing/unknown fields, duplicate IDs/hashes, bind collisions **including wildcard overlap and IPv6 dual-stack**, malformed DNS/IPv6/port, unsupported schema_version, UTF-8 errors, missing secret refs, empty user list, диапазоны таймаутов, **missing/empty/unknown/duplicate allowed_user_ids**, запрет `system_proxy=on`, отказ неизвестного `tls_profile`.
- Transport selector: строгая таблица классификации `UdpUnavailable` versus `TlsVerificationFailed`/`Unauthorized`/`IncompatibleProtocol`/`PolicyDenied`, negative-cache TTL, cancellation, no re-dial after downstream error.
- Policy: IPv4/IPv6 public/private, loopback, link-local, multicast, DNS rebinding after resolution, case folding/IDNA validation.
- TUI update model: keyboard, focus, dirty state, save and apply distinct, privacy masking, compact terminal, back navigation.
- Windows system proxy: adapter fake с сохранением оригинальных proxy/PAC настроек, compare-and-restore, отказом прав, повторным apply и simulated crash.

### B. Integration tests (локальный реальный IO)

- TLS-backed H2 echo tunnel, multiple concurrent streams, **full-duplex HTTP POST without request EOF**, half-close, abrupt EOF, timeout, bounded backpressure, broken clients and error mapping. С M2.1 `crates/theia/tests/server_h2.rs` проверяет реальное TLS1.3/H2 OPEN_OK→echo + half-close, missing bearer HTTP401, private ACL OPEN_ERROR без dial, strict wrong-hostname TLS и pure auth/IP ranges. **Дополнительные** many-stream/race/cancellation/slow-reader/peak RSS и DNS rebinding fixtures ещё не закрыты. Loopback echo тестировать только с explicit test-only `allow_private_ips=true`; отдельный negative test обязан подтвердить default=false.
- H3 echo tunnel via UDP loopback, full-duplex request/response, certificate validation, resumption/0-RTT disabled, **BBR на обоих отправителях как P0 release gate** (никаких `pending` при объявлении MVP).
- Fallback H3→H2 с симуляцией/блокировкой UDP; ни одного H2 retry при wrong cert/auth/protocol mismatch.
- HTTP CONNECT + SOCKS5 local proxy с server-side DNS, IPv4/IPv6, отказом auth и неразрешённым адресом. HTTP 200/SOCKS5 success должны приходить **строго после OPEN_OK**; неверный токен другого inbound не получает доступ; имена не резолвятся локальным клиентом.
- IPC auth/ACL (Unix socket/Windows pipe), atomic config reload, сохранение старого runtime при failed apply.
- Windows per-user proxy smoke: автоматические Windows runner tests для API adapters и отдельный автоматический сценарий на изолированном временном Windows-профиле/VM: snapshot, apply, CAS restore, конфликт и восстановление после аварии. Запуск и teardown средствами CI; до реализации сценария M4.3 и соответствующий release gate остаются открытыми. Не менять настройки пользователя или обычного runner.
- No external production endpoints in CI; TLS сертификаты для теста генерируются в памяти/fixtures, без реальных секретов.

### C. Property/fuzz + security

- Property-based encode/decode roundtrip с фиксированными seeds в CI; fuzz parser в автоматическом scheduled CI после реализации fuzz targets; никаких обязательных ручных запусков.
- Limit tests для frame headers, header counts, slowloris, concurrent streams, open proxy и unauthorized requests.
- Tests negative TLS: expired, wrong hostname, untrusted CA, mismatched key.
- Test deny private ranges **после** DNS resolve, исключить попытки установить запрещённое соединение.

### D. Performance и fingerprint (не «успех по словам»)

- Измерять throughput по H2/H3 и RTT p50/p95 при одинаковых payload/host, CPU, peak RSS, количество аллокаций, потери при 1%/5%, число H3→H2 fallback.
- CI не должен запускать шумные full benchmarks при каждом PR. Baselines автоматически измерять и сохранять как CI artifacts в стабильном изолированном benchmark runner перед релизом. Пока соответствующая автоматизация не реализована, release gate открыт.
- **P0 gate F-13:** M0.1 baseline `spikes/m0_1/tests/client_hello_baseline.rs` измеряет default rustls ClientHello для TLS/H2 (TLS record) и QUIC/H3 (plaintext CRYPTO before encryption), выводит IDs/ALPN и не пишет SNI/random/session ID. Это НЕ browser pcap, не named profile. Вместо захвата эталонного браузера CI генерирует HelloChrome_133 ClientHello из **Go uTLS v1.8.2** (H2/TLS) и сверяет его с rustls: GREASE, ALPS, supported_groups, наборы шифров и ALPN. Для H3 требуется отдельный QUIC-совместимый референс. Release gate по-прежнему требует сравнить **фактически испускаемые Theia** H2/H3 TLS/QUIC handshakes, H2 SETTINGS и H3 SETTINGS/QUIC transport parameters с релевантными эталонами и зафиксировать расхождения. Go-генератор и отдельный test-only Go uTLS сетевой клиент не заменяют работающий Rust fingerprint backend. M0.1 дополнительно проверяет настоящий Go uTLS Chrome133 TCP/TLS 1.3 H2 GET→Rust h2 HTTP 204, GREASE/ALPS на сокете и fail-closed wrong-hostname/untrusted-CA на Linux и Windows. Публиковать поддерживаемые параметры и различия, а не только «успешный» тест.
- Проверка BBR: идентификация конкретной реализации congestion controller и сравнительные loss/jitter benchmarks, а не только строковый параметр в TOML.

## 2. CI pipeline

Файл: `.github/workflows/ci.yml`.

1. `specification` (Ubuntu, самый быстрый): проверить файлы, локальные Markdown links, оба TOML и invariants; определить есть ли одновременно `Cargo.toml` и `Cargo.lock`.
2. `rust-tests` после specification: Rust toolchain + cache, `cargo test --workspace --all-targets --locked` **первым**, только после успеха `cargo fmt`, `cargo clippy -D warnings` и `cargo build --release`.
3. `windows-smoke` после Linux tests: Windows-native `cargo test` и `cargo build --release` с отдельным кэшем. Системные proxy settings на GitHub-hosted runner без явного sandbox-плана не менять.
4. Кэш: `Swatinem/rust-cache@v2` для registry/git/target, `Cargo.lock` как источник cache key; concurrency отменяет устаревшие runs на одной ветке. Запуск на push и PR.
5. Rust jobs **skipped**, пока нет production workspace; как только добавлен корневой `Cargo.toml`, отсутствие корневого `Cargo.lock` становится ошибкой CI, а не silent skip.
6. **M0.1 в отдельном `spikes/m0_1`**: `cargo test --manifest-path spikes/m0_1/Cargo.toml --locked` на Ubuntu и Windows, кэш по отдельной директории, без включения spike в поставляемый бинарник. `Cargo.lock` находится в каталоге spike и зафиксирован в git. Успех M0.1 transport tests подтверждает **H2/TLS и H3/QUIC/TLS E2E** (real loopback, TLS name+ALPN verification, body before request EOF), а также **H2/TLS 1 МиБ flow-credit + half-close**, **QUIC BBR byte-exact recovery с детерминированными 1/20 synthetic outgoing datagram drops**, **H2/H3 по 8 одновременных stream и отмену одного запроса без разрыва общей защищённой сессии**, **H2 slow response reader 512 КиБ и H3 slow response reader 1 МиБ с остановкой/восстановлением передачи при малом flow-control budget**. Это не закрывает release gates: **comparative BBR loss/jitter/pacing/throughput benchmarks, many-stream cancellation and many-slow-readers stress/peak RSS limits, SmartTheia auth/ACL tunnel, Go uTLS H2 reference + отдельный H3 QUIC эталон + реальная browser-like настройка Theia**. Отрицательные TLS tests: wrong name, untrusted CA, ALPN mismatch.

## 3. Проверки только в CI

Workflow автоматически запускается для PR, обновлений PR и push в main. Команды тестов, линтов, сборок и генерации fixtures принадлежат CI jobs, а не инструкции пользователю. TDD: red test подтверждается автоматическим PR-run до исправления, green run после реализации. Если тест нестабилен, устранить nondeterminism.

Тяжёлые benchmark/fuzz/GUI/OS recovery сценарии автоматизируются отдельными scheduled/release workflows по мере реализации; штатная проверка не требует ручного запуска. Использовать временные профили, loopback/изолированные сети, ephemeral credentials, автоматический cleanup и машинно-проверяемые assertions. Будущие автоматические security/audit checks также не требуют локальных команд. До появления и успеха необходимой автоматической проверки соответствующая функция не считается готовой.

Статус `ci-gate` агрегирует результаты шести групп jobs текущего workflow (browser-e2e включает два обязательных runner). Failure, skipped и cancelled обязательного job запрещают зелёный gate. Это не заменяет будущие ещё не реализованные release jobs. Для приёмки учитывать успешный run именно проверяемого head SHA, а не старого коммита.

## 4. Правила мержа и качества

Для branch protection использовать итоговый required check `ci-gate` на main. Настройка branch protection является отдельной настройкой GitHub, а не ручным тестированием; документ не утверждает, что она уже включена. Запретить merge при красном CI, секретах, расхождении wire/TOML с docs и непокрытых негативных тестах. Не требовать сборку бинарников от docs-only состояния.

Каждый релиз требует автоматическую CI-матрицу Linux server + Windows client на изолированных runner/VM, временный доверенный сертификат, ревокацию токена, fallback при недоступном UDP, отказ при wrong cert, автоматическую Windows proxy recovery и documented limitations. Пока обязательные проверки не реализованы и не прошли в CI, релиз не допускается.


M2.1 hardening: preflight certificate SAN matches configured DNS name (not full PKI chain/time validation), bounded shared IP request budget (120/min; 4096 peers; fixed windows; all requests), 8 KiB H2 header limit, H2/TLS handshake deadlines, single DNS/dial deadline with at most 64 results, task ownership via JoinSet, and bounded abort/drain. Remaining stress and full PKI checks are not claimed complete.

M2.1 relay regression: independently driven TCP read/write halves, bounded H2 frame send, direction-specific FSM checks, stream reset on interrupted wire frame. Production-server integration tests exercise withheld response credit (1 KiB H2 window, 256 KiB download, successful concurrent upload and FIN) and eight open tunnels on one H2 connection with one cancelled stream and byte-exact sibling transfers. These are bounded regression tests, not a peak-RSS or large-scale benchmark; await Linux/Windows CI.

M2.2a: production client core tests in `crates/theia/tests/client_h2.rs` exercise TLS1.3/H2 against the real server, DNS OPEN_TCP, 256 KiB byte-exact relay/FIN, wrong hostname/untrusted CA/token and private ACL denial before any target dial. Trust roots are explicitly injected in this slice; no local listeners or client CLI/runtime yet. Tests use ephemeral loopback certificates, not TLS verification bypass.

M2.2b adds automated local CONNECT/SOCKS5 loopback regression against production H2 client/server. Local success is emitted only after OPEN_OK, policy rejection returns HTTP403/SOCKS REP2, CONNECT does not consume pipelined bytes. Tests run only in CI. Explicit CA + env/file token runtime, no default platform roots or auto/H3. Browser/curl and OS-specific automation remain open; no user smoke test required.

M2.2b black-box CI: `client_binary_curl_connect_and_socks5h` launches the built `theia client run` with a temporary TOML, generated trusted PEM and child-only env token. Real curl uses HTTP CONNECT (`--proxytunnel`) and SOCKS5h, receives exact HTTP origin bytes on loopback, bypass disabled. Native Linux/Windows runner commands are mandatory (missing curl fails); subprocesses/fixtures cleaned up automatically. Browser automation is added in the mandatory browser-e2e matrix, pending CI.

Chromium CI: `browser-e2e` runs the pinned Playwright 1.65.2 Chromium fixture on Linux and Windows. A test-only SOCKS gate limits destinations to the generated loopback origin and forwards the permitted request to the running Theia client, then verifies HTTP 200, DOM marker and actual SOCKS success. All other page requests are blocked. Dedicated CI explicitly runs the ignored test; the aggregate ci-gate requires browser-e2e success. No change to browser TLS fingerprint or OS proxy is claimed.

M3.1a CI-only: production QUIC endpoint builders use pinned Quinn/H3 dependencies, TLS1.3 verified chain and hostname, ALPN h3, explicit no early data, active BBR guard and bounded credit. New loopback tests verify HELLO/HELLO_ACK over real H3 before request EOF, wrong-name/untrusted CA rejection, and empty trust failure before binding. This does not establish a complete H3 tunnel, BBR performance or release readiness.

M3.1b: authenticated H3 server uses the same ServerContext request admission, bearer, grants, quotas and DNS/ACL-pinned dial as H2. H3 stream ownership and bounded headers/handshake/session, independent TCP upload/download, strict OPEN_OK and FIN, stream cancellation and error handling. H3 server library not bound by CLI yet. Real loopback H3 fixtures exercise authentication, ACL rejection without dialing and TCP relay; all CI-only.

M3.1c: explicit H3 client core owns a dedicated QUIC endpoint and H3 driver, authenticates only after verified handshake; uses shared canonical bearer validation, same SmartTheia FSM, OPEN_OK gate, independent relay and FIN. Native CI tests real H3 client/server echo, invalid identity/trust/bearer and ACL. CLI and fallback remain disabled for H3. No manual verification.

M3.1d: production server CLI prepares TCP/H2 and UDP/H3 for each inbound using the same checked certificate/key and shared ServerContext quotas; startup fails before serving if any bind fails. Client CLI dispatches explicit h2/h3 via one proxy implementation; auto remains fail closed. Server address resolution only, destination DNS remains remote. Native black-box H3 CLI/curl regression required.

M3.2a: only a dedicated UDP handshake that actually sent and received no datagram before deadline is classified quic_unreachable; all partial handshakes, PKI/auth/protocol/ACL errors remain terminal. Auto cache scoped to the immutable running profile, monotonic TTL, 0 disables, cleared on success or terminal H3 error. New connection only. Network change detection pending; restart clears cache. No manual tests.

M3.2b: before a new auto tunnel, a temporary connected UDP socket observes the OS-selected local source address for the pinned QUIC peer without sending application traffic. A change (including loss of observable route) invalidates the process-local negative cache; generations reject late results of older route/probe decisions. An unknown route is never cached. No active tunnel is migrated or interrupted. This does not detect same-source-IP route/interface changes, and server DNS is still pinned at startup; full OS notifications remain open. Native CI verifies deterministic route changes, stale results, TTL and loopback socket observation.

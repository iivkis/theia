# Testing strategy и CI

**Правило:** тестирование предшествует сборке релизных артефактов. CI не должен маскировать отсутствие сетевой Rust-реализации. С M1.1 корневой workspace и `Cargo.lock` существуют: Linux `rust-tests` и Windows `windows-smoke` должны запускаться. CLI `--help`/`--version` работают; с M1.2 `config validate` выполняет структурную TOML v1 validation (exit 0/2) без чтения секретов. Команды `tui`, `server run`, `client run` обязательно возвращают `not implemented` (exit 3). До M1.1 Rust jobs были skipped.

## 1. Test pyramid

### A. Pure unit tests (самые быстрые, обязательны в каждом PR)

- SmartTheia encode/decode golden byte vectors; arbitrary chunk splitting/aggregation; frame length 0/65536/65537; invalid flags/type/state; отсутствие паники и out-of-bounds. С M1.3 — `crates/theia/tests/protocol.rs` с реальными golden-byte assertions, per-stream client/server FSM, strict OPEN_OK gate, half-close/abort и deterministic malformed-byte regression. Настоящий coverage-guided fuzz и transport E2E остаются за пределами pure codec PR.
- Typed TOML: missing/unknown fields, duplicate IDs/hashes, bind collisions **including wildcard overlap and IPv6 dual-stack**, malformed DNS/IPv6/port, unsupported schema_version, UTF-8 errors, missing secret refs, empty user list, диапазоны таймаутов, **missing/empty/unknown/duplicate allowed_user_ids**, запрет `system_proxy=on`, отказ неизвестного `tls_profile`.
- Transport selector: строгая таблица классификации `UdpUnavailable` versus `TlsVerificationFailed`/`Unauthorized`/`IncompatibleProtocol`/`PolicyDenied`, negative-cache TTL, cancellation, no re-dial after downstream error.
- Policy: IPv4/IPv6 public/private, loopback, link-local, multicast, DNS rebinding after resolution, case folding/IDNA validation.
- TUI update model: keyboard, focus, dirty state, save and apply distinct, privacy masking, compact terminal, back navigation.
- Windows system proxy: adapter fake с сохранением оригинальных proxy/PAC настроек, compare-and-restore, отказом прав, повторным apply и simulated crash.

### B. Integration tests (локальный реальный IO)

- TLS-backed H2 echo tunnel, multiple concurrent streams, **full-duplex HTTP POST without request EOF**, half-close, abrupt EOF, timeout, bounded backpressure, broken clients and error mapping. Loopback echo тестировать только с explicit test-only `allow_private_ips=true`; отдельный negative test обязан подтвердить default=false.
- H3 echo tunnel via UDP loopback, full-duplex request/response, certificate validation, resumption/0-RTT disabled, **BBR на обоих отправителях как P0 release gate** (никаких `pending` при объявлении MVP).
- Fallback H3→H2 с симуляцией/блокировкой UDP; ни одного H2 retry при wrong cert/auth/protocol mismatch.
- HTTP CONNECT + SOCKS5 local proxy с server-side DNS, IPv4/IPv6, отказом auth и неразрешённым адресом. HTTP 200/SOCKS5 success должны приходить **строго после OPEN_OK**; неверный токен другого inbound не получает доступ; имена не резолвятся локальным клиентом.
- IPC auth/ACL (Unix socket/Windows pipe), atomic config reload, сохранение старого runtime при failed apply.
- Windows per-user proxy smoke: Windows runner tests for API adapters + manual VM test of end-user settings and recovery.
- No external production endpoints in CI; TLS сертификаты для теста генерируются в памяти/fixtures, без реальных секретов.

### C. Property/fuzz + security

- Property-based encode/decode roundtrip с фиксированными seeds в CI; fuzz parser отдельно по расписанию/ручному запуску.
- Limit tests для frame headers, header counts, slowloris, concurrent streams, open proxy и unauthorized requests.
- Tests negative TLS: expired, wrong hostname, untrusted CA, mismatched key.
- Test deny private ranges **после** DNS resolve, исключить попытки установить запрещённое соединение.

### D. Performance и fingerprint (не «успех по словам»)

- Измерять throughput по H2/H3 и RTT p50/p95 при одинаковых payload/host, CPU, peak RSS, количество аллокаций, потери при 1%/5%, число H3→H2 fallback.
- CI не должен запускать шумные full benchmarks при каждом PR. Baselines записывать в отчёт на стабильном окружении перед релизом.
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

## 3. Локальная проверка

```sh
bash scripts/check-spec.sh
cargo test --manifest-path spikes/m0_1/Cargo.toml --locked  # only isolated M0.1 spike

# После M1.1 / появления Cargo.toml и Cargo.lock:
cargo test --workspace --all-targets --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --release --locked
```

TDD = сначала red test на требование, затем green code, затем refactor. При flaky тесте нужно устранить nondeterminism, а не поставить `sleep(10)`. Отдельная проверка `cargo audit`/RustSec рекомендуется для release/nightly после выбора зависимостей; блокировать известные эксплуатируемые уязвимости.

## 4. Правила мержа и качества

Branch protection следует включить владельцу репозитория после создания workflow: required check `specification` (сейчас), `rust-tests` и `windows-smoke` (после появления Rust workspace). Запретить merge при красном CI, секретах, расхождении wire/TOML с docs и непокрытых негативных тестах. Не требовать сборку бинарников от docs-only состояния.

Каждый релиз требует матрицу Linux server + Windows client на настоящих хостах, сертификат на test domain, валидную ревокацию токена, fallback при недоступном UDP, отказ при wrong cert, проверку Windows proxy recovery, и documented limitations.

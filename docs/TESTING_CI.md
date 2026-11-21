# Testing strategy и CI

**Правило:** тестирование предшествует сборке релизных артефактов. CI не должен маскировать отсутствие Rust-реализации. Пока `Cargo.toml` не создан, CI проверяет спецификацию и TOML; Rust jobs явно **skipped**, а не «passed».

## 1. Test pyramid

### A. Pure unit tests (самые быстрые, обязательны в каждом PR)

- SmartTheia encode/decode golden byte vectors; arbitrary chunk splitting/aggregation; frame length 0/65536/65537; invalid flags/type/state; отсутствие паники и out-of-bounds.
- Typed TOML: missing/unknown fields, duplicate IDs, bind collisions, malformed DNS/IPv6/port, unsupported schema_version, UTF-8 errors, missing secret refs, empty user list, диапазоны таймаутов.
- Transport selector: строгая таблица классификации `UdpUnavailable` versus `TlsVerificationFailed`/`Unauthorized`/`IncompatibleProtocol`/`PolicyDenied`, negative-cache TTL, cancellation, no re-dial after downstream error.
- Policy: IPv4/IPv6 public/private, loopback, link-local, multicast, DNS rebinding after resolution, case folding/IDNA validation.
- TUI update model: keyboard, focus, dirty state, save and apply distinct, privacy masking, compact terminal, back navigation.
- Windows system proxy: adapter fake с сохранением оригинальных proxy/PAC настроек, compare-and-restore, отказом прав, повторным apply и simulated crash.

### B. Integration tests (локальный реальный IO)

- TLS-backed H2 echo tunnel, multiple concurrent streams, half-close, abrupt EOF, timeout, bounded backpressure, broken clients and error mapping.
- H3 echo tunnel via UDP loopback, certificate validation, resumption/0-RTT disabled, BBR selection with pinned quinn (или явный pending).
- Fallback H3→H2 с симуляцией/блокировкой UDP; ни одного H2 retry при wrong cert/auth/protocol mismatch.
- HTTP CONNECT + SOCKS5 local proxy с DNS, IPv4/IPv6, отказом auth и неразрешённым адресом.
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
- Для заявлений о fingerprint resistance: packet captures H3/H2 TLS/QUIC handshake, HTTP/2 SETTINGS, SNI/ALPN, распределение пакетов; контрольное браузерное соединение с той же конфигурацией тестового окружения. Публиковать различия, а не только успешный тест.
- Проверка BBR: идентификация конкретной реализации congestion controller и сравнительные loss/jitter benchmarks, а не только строковый параметр в TOML.

## 2. CI pipeline

Файл: `.github/workflows/ci.yml`.

1. `specification` (Ubuntu, самый быстрый): проверить файлы, локальные Markdown links, оба TOML и invariants; определить есть ли одновременно `Cargo.toml` и `Cargo.lock`.
2. `rust-tests` после specification: Rust toolchain + cache, `cargo test --workspace --all-targets --locked` **первым**, только после успеха `cargo fmt`, `cargo clippy -D warnings` и `cargo build --release`.
3. `windows-smoke` после Linux tests: Windows-native `cargo test` и `cargo build --release` с отдельным кэшем. Системные proxy settings на GitHub-hosted runner без явного sandbox-плана не менять.
4. Кэш: `Swatinem/rust-cache@v2` для registry/git/target, `Cargo.lock` как источник cache key; concurrency отменяет устаревшие runs на одной ветке. Запуск на push и PR.
5. Rust jobs **skipped**, пока нет workspace; как только добавлен `Cargo.toml`, отсутствие `Cargo.lock` становится ошибкой CI, а не silent skip.

## 3. Локальная проверка

```sh
bash scripts/check-spec.sh

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

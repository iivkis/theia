# Руководство для ИИ-агента (обязательно)

Этот файл — **контракт на реализацию**, а не рекламный README. Используй его вместе с документами в `docs/`. Непроверенное требование не считается реализованным.

## Приоритет источников

1. Этот файл: рабочий процесс, запреты, Definition of Done.
2. `docs/SMARTTHEIA_PROTOCOL.md`: wire format и состояния.
3. `docs/CONFIGURATION.md`: имена и семантика параметров.
4. `docs/IMPLEMENTATION_SPEC.md` + `docs/ARCHITECTURE.md`: функциональные требования и границы.
5. `docs/TUI_UX.md`: пользовательский контракт TUI.
6. `docs/IMPLEMENTATION_PLAN.md` + `docs/TESTING_CI.md`: порядок работ и качество.

Если требования конфликтуют, **не угадывай**: исправь противоречие отдельным документированным архитектурным решением (ADR), поддержи изменение тестом и обнови зависимые документы.

## Неизменяемые требования

- **Один конечный бинарник `theia`**; сервер и клиент — режимы одного приложения. Не создавать две поставляемые программы.
- **Rust**, асинхронная сеть на Tokio, TUI на ratatui, человекочитаемые TOML без БД и внешнего control plane.
- SmartTheia v1 — прикладные фреймы внутри стандартных **HTTP/3 (QUIC)** и **HTTP/2 (TLS)**. Не вводить самодельную криптографию, TLS, HTTP/2 или QUIC.
- QUIC-first, H2-fallback **только по сетевой недоступности UDP/QUIC**, никогда вследствие отказа авторизации, ошибки сертификата или явной несовместимости протокола. Нельзя молча ослаблять проверки.
- **BBR — P0:** на обоих QUIC endpoints фактически выбран и измерен BBR. Проверить API выбранного quinn/backend, не заменять молча алгоритм; без теста и замеров MVP не готов.
- **uTLS-like browser fingerprint — P0:** минимум один именованный, реально настроенный и проверенный на Windows/Linux TLS+HTTP profile. **Эталон TLS/H2 генерирует закреплённая Go uTLS v1.8.2 HelloChrome_133 вместо захватов живого браузера**; Go используется только в отдельном исследовательском CI-tool, без runtime зависимости в one-binary Rust Theia. Дополнительный M0.1 тестовый Go uTLS TLS1.3/H2 клиент успешно подключается к Rust h2 серверу на loopback (GET/204 и x509-negative cases); это **не** встроенный браузероподобный Rust client. QUIC/H3 потребует отдельного совместимого эталона и реального backend. Не считать подмену User-Agent или генератор H2 эталона реализацией fingerprint и не обещать DPI-невидимость.
- В первой поставке: Linux-сервер, Windows x64-клиент, локальные HTTP CONNECT/SOCKS5 и пользовательский Windows system proxy с восстановлением прежних параметров.
- Секреты не пишутся в логи или TUI в открытом виде. Примеры не содержат действующих ключей.
- Каждый inbound имеет явный непустой список `allowed_user_ids`, глобальные пользователи не получают права по умолчанию. Auth: SHA-256 от декодированных 32 байт canonical base64url token, constant-time digest compare.
- Local CONNECT 200 / SOCKS5 success только после SmartTheia OPEN_OK; локальный listener ≠ авторизованный транспорт ≠ открытый туннель. При домене DNS выполняет сервер с ACL по закреплённому IP.
- Windows system proxy никогда не включается автоматически при запуске: только `manual` + TUI confirmation + сохранённый snapshot и безопасный CAS restore.

## Порядок работы с задачей

1. Выбери один **небольшой вертикальный срез** из `docs/IMPLEMENTATION_PLAN.md`.
2. Сначала сформулируй поведение (Given/When/Then), угрозы и отрицательные кейсы.
3. Напиши падающий тест; затем минимальную реализацию; затем рефакторинг.
4. Обнови TOML-примеры, wire-документацию, help/UX и тесты **в том же PR**, если изменился контракт.
5. Запусти проверки, перечисленные в `docs/TESTING_CI.md`. Не пропускай тесты без явной причины.
6. PR должен описывать: что добавлено, что **ещё не реализовано**, миграции, тесты, риски, производительность.

## Код и архитектура

- DDD = понятные **bounded contexts**, не фабрики и интерфейсы ради интерфейсов. Границы из `docs/ARCHITECTURE.md` можно объединять, пока это упрощает код без ухудшения тестируемости.
- Зависимости направлены внутрь: чистый парсер/домен не зависит от TUI/сетевого IO. Использовать traits только при реальной смене реализации или для тестового шва.
- Избегать глобального изменяемого состояния, `unwrap` в обработчиках соединений, бесконечных очередей, блокирующего IO на Tokio.
- Ограничивать размеры фреймов, параллелизм, таймауты, количество открытых соединений, число ошибок аутентификации. Утечки ресурсов и panics — баги релиза.
- Не добавлять секреты в репозиторий, не отключать TLS verification, не хранить токены в командной строке.
- Код должен собираться под Windows; платформенный код изолировать через `cfg(windows)`.
- Функции включают явные типы ошибок; наружу отправляются безопасные коды, подробности остаются в локальной диагностике без секретов.

## Зависимости, CI, оптимизация

- Фиксировать версии в `Cargo.lock`; сначала выбрать минимальное количество зрелых crates. Проверять их API по текущей документации.
- `spikes/m0_1` — **изолированный исследовательский crate**, а не production workspace. Реальные Linux/Windows loopback тесты подтверждают HTTP/2 over TCP/TLS 1.3, HTTP/3 over QUIC/TLS, strict hostname/ALPN и активный BBR class на обоих peers. Контролируемый синтетический UDP drop test показывает recovery 768 КиБ, H2 credit-window тест подтверждает 1 МиБ/half-close, а Linux/Windows CI проходит 8 concurrent H2/H3 streams и единичную отмену stream с живым sibling request. Также проверена остановка и возобновление H2/H3 response при одном медленном читателе с ограниченными окнами, **без измерения peak RSS**. Дополнительно создан bounded default rustls ClientHello parser и H2/H3 engine-only baseline. Отрицательный тест проверяет отсутствие GREASE и обоих BoringSSL ALPS codepoints у текущего H2 rustls, он **не** доказывает реальный browser-like profile, см. `docs/adr/0005-tls-fingerprint-baseline.md`. Это **не** готовый proxy и **не** сравнительный P0 BBR RTT/jitter/throughput benchmark или uTLS-like profile. Перед переносом кода в один бинарник свериться с `docs/adr/0004-m0-1-feasibility.md`.
- Базовые команды: `cargo test --workspace --all-targets --locked`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- CI сначала проверяет спецификацию и тесты, затем lint/build; кэш cargo/target через `Swatinem/rust-cache`; Windows проверяется нативно.
- Никакой микрооптимизации без замеров и регрессий в тестах. Производительность в `docs/TESTING_CI.md` — измеряется на одинаковых условиях.

- **M1.1 CLI shell:** корневой workspace `crates/theia` с зафиксированным `Cargo.lock`; отдельный `spikes/m0_1` не входит в production workspace. Работают только `--help` и `--version`. Распознаваемые `tui`, `server/client run`, `config validate` обязаны завершаться nonzero без сети, TUI и модификации OS proxy, пока реализация соответствующих M1.2/M2/M4 этапов отсутствует. Проверять unit + CLI integration tests на Linux/Windows; не называть синтаксический parser реализацией proxy.

- **M1.2 typed TOML:** `config.rs` содержит строгую serde-модель, безопасные проверки grants/binds/secret refs, upper bound 1 МиБ и атомарную запись. `config validate` структурная проверка без чтения secret content; не считать отсутствие проверки base64url токена из env/file полной runtime validation. Запуск client/server остаётся fail-closed.

- **M1.3 SmartTheia v1 pure codec:** frame layout + header 6 bytes, max 65 536 payload, strict flags/version, 8 типов, limited incremental buffer и state transitions tested. `Session::tunnel_open()` true только после правильного OPEN_OK, DATA после FIN запрещено; ABORT/OPEN_ERROR terminal. Настоящие HTTP/2/3 transports, TLS auth/ACL, local CONNECT/SOCKS5 и runtime persistence **не** реализованы. Не заявлять E2E или production readiness.

- **M2.1 H2 server inbound:** unit/loopback TLS1.3/H2 tests с проверенным hostname/ALPN, canonical base64url bearer SHA-256 constant-time digest, inbound grants, denied private IP by default, server-side DNS + pinned IP dial, OPEN_OK после TCP connect, refusal codes и bounded sessions. Это первая серверная реализация; **не** H3/QUIC и не клиентский CONNECT/SOCKS5. Не считать M2.1 полностью закрытым до mass-cancel/rate-limit/PKI cert-name binding тестов. Нельзя логировать токены или адреса целей.

## Definition of Done (для каждого среза)

- [ ] Есть автоматизированный позитивный и негативный тест; пограничные значения покрыты.
- [ ] Код соответствует спецификации; отклонения объяснены ADR, а не спрятаны.
- [ ] Проведены проверки безопасности (аутентификация, таймауты, валидация, файловые права).
- [ ] Тексты ошибок, UX и TOML обновлены, когда требуется.
- [ ] `cargo test`, `fmt`, `clippy` и целевые платформы проходят в CI.
- [ ] Нереализованные функции не доступны как работающие и не заявлены в README.

## Запрет на «фиктивную готовность»

Нельзя закрывать задачу заглушкой, возвращающей успех, snapshot-тестом без проверки поведения, ложным счётчиком скорости, «поддержкой uTLS» через единственный заголовок или fallback при любом исключении.

**Сначала минимальный защищённый TCP-туннель с тестами. Перед объявлением MVP готовым обязательно завершить P0 BBR и проверенный browser-like fingerprint профиль; ни один из этапов нельзя выдавать за уже реализованный.**


M2.1 hardening: preflight certificate SAN matches configured DNS name (not full PKI chain/time validation), bounded shared IP request budget (120/min; 4096 peers; fixed windows; all requests), 8 KiB H2 header limit, H2/TLS handshake deadlines, single DNS/dial deadline with at most 64 results, task ownership via JoinSet, and bounded abort/drain. Remaining stress and full PKI checks are not claimed complete.

M2.1 relay regression: independently driven TCP read/write halves, bounded H2 frame send, direction-specific FSM checks, stream reset on interrupted wire frame. Production-server integration tests exercise withheld response credit (1 KiB H2 window, 256 KiB download, successful concurrent upload and FIN) and eight open tunnels on one H2 connection with one cancelled stream and byte-exact sibling transfers. These are bounded regression tests, not a peak-RSS or large-scale benchmark; await Linux/Windows CI.

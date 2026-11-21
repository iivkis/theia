# План реализации для ИИ-агента

Спецификация — источник требований, а не уже написанный код. Каждая фаза делится на небольшие reviewable PR с тестами сначала. Не пытаться за один PR «сделать полный Xray», иначе получится красивое название над 4000 строками заглушек.

## Порядок, зависимости и gate

| Этап | Вертикальный срез | Тест/критерий завершения |
| --- | --- | --- |
| M0 | Документация, AGENTS, TOML examples, docs-only CI | структура спецификации проверяется CI; работающая функциональность **не заявлена** |
| M0.1 | **Feasibility spike** H2/H3 full-duplex + BBR + fingerprint backend (без заявления о готовой функции) | **Частично проверено**: реальные H2/TLS, H3/QUIC/TLS, H2 WINDOW_UPDATE/half-close (1 МиБ), BBR byte-exact recovery при synthetic loss, по 8 concurrent streams H2/H3 и отмена одного stream с успешным соседним запросом; Linux+Windows. **Также проверено**: slow-reader responses H2 (512 КиБ) и H3 (1 МиБ), остановка/возобновление по flow control. **Также измерен**: default rustls ClientHello H2/TLS и QUIC/H3 на TLS engine level (не browser profile). **Также проверено**: Go uTLS HelloChrome_133 на настоящем TCP/TLS 1.3/H2 соединении с Rust h2 сервером (GET/204, x509 wrong-hostname/untrusted-CA отказ, GREASE/ALPS на сокете) Linux+Windows. **Открыты**: BBR controlled RTT/jitter/throughput benchmark, **реальный** configurable browser-like *Rust H2 client* и QUIC/H3 backend/эталон, массовая отмена/сотни slow readers/peak RSS; ADR-0004/0005 |
| M1.1 | Cargo workspace, единый `theia` CLI, `--help`/`--version`, роли | **Реализован CLI shell**: парсер ролей и параметров, help/version, unit/CLI integration tests; Windows/Linux CI обязателен. `tui`/`run`/`validate` распознаются, но fail-closed (exit 3), runtime не реализован. `Cargo.lock` закреплён |
| M1.2 | Typed TOML v1 + validator + atomic store | **Реализуется отдельным PR:** serde/toml typed model, strict unknown keys, ID/grants, listener overlap including IPv6 wildcard, safe loopback/local proxy, secret reference syntax, atomic write with fsync. Secret contents, certificate/CA validation и live transactional reload остаются отдельным этапом |
| M1.3 | SmartTheia pure frame codec + FSM | **Реализовано в PR M1.3 (ожидает CI):** zero-IO Rust codec (8 типов), 6-byte header / 65 536 payload cap, streaming decoder across arbitrary chunks, strict version/flags/codes/ASCII DNS/length checks; client/server per-stream FSM, half-close, OPEN_OK gate, terminal OPEN_ERROR/ABORT. Golden vectors, split boundary, fuzz-like deterministic no-panic и negative FSM tests. **Это не HTTP/TLS runtime** |
| M2.1 | TLS/H2 server inbound + bearer auth + TCP dial + ACL | **PR M2.1, тестируется:** реальный TLS1.3/h2 server run + HTTP/2 full-duplex SmartTheia, canonical 32-byte bearer SHA-256 constant-time compare, inbound-scoped grants, DNS resolve then pinned SocketAddr TCP dial + ACL, quota/timeout, loopback echo with explicit allow-private, rejected local targets by default, negative TLS/auth. **Не считать этап полностью завершённым до CI и hardening:** mass concurrency/cancellation, cert-hostname matching, per-IP auth rate limits, exhaustive DNS rebinding/fuzz. H3 и local proxy не входят в этот PR |
| M2.2 | Local HTTP CONNECT/SOCKS5 + client H2 | browser/curl E2E Windows/Linux; local 200/SOCKS success **only after** OPEN_OK; remote DNS, half-close, cancellation |
| M3.1 | H3/QUIC transport with same app frames | H3↔server loopback E2E, HTTP/3 state and security invariants |
| M3.2 | QUIC-first selector + safe H2 fallback | UDP blocked → H2; wrong cert/token → no fallback; TTL; network change |
| M3.3 | P0: BBR verified on chosen quinn version | client+server send controllers verified, packet loss benchmarks, no silent CUBIC substitute |
| M3.4 | P0: uTLS-like fingerprint profile | Go uTLS v1.8.2 HelloChrome_133 служит воспроизводимым эталоном H2/TLS без захватов браузера; отдельный QUIC/H3 эталон, реально настроенный named TLS/HTTP profile Windows/Linux и проверка фактического выхода Theia + отчёт расхождений обязательны. Если backend не позволяет, M5 заблокирован |
| M4.1 | ratatui landing + server/client panels | focus/resize/dirty/save/validation UI tests, two independent modes |
| M4.2 | Local management IPC + reload | ACL, status, transactional apply, rollback, no open admin TCP port |
| M4.3 | Windows system proxy integration | WinINet user settings backup/apply/CAS restore, manual Windows smoke tests |
| M5 | Hardening/release (все P0 обязаны пройти) | Linux/Windows E2E, BBR + named fingerprint evidence, Windows proxy recovery, security checklist, release notes |
| P1+ | UDP relay, fingerprint profiles, UX extras | protocol extension and reproducible fingerprint comparison, separate PRs |

**Нельзя переходить на следующий этап, скрыв невыполненные требования в silent fallback.** Зависимость «Windows proxy» подразумевает наличие работающего loopback HTTP proxy.

## Определение задач для каждого PR

Каждая реализационная задача должна содержать:
- **Зачем:** пользовательское поведение и относящийся F-ID из `IMPLEMENTATION_SPEC.md`.
- **Scope:** ровно один законченный вертикальный кусок, ограничения платформ.
- **Given/When/Then:** положительный/негативный/пограничный сценарий.
- **Дизайн:** границы библиотек и все изменения wire/TOML/API до написания кода.
- **Threats:** доверенные/недоверенные inputs, отказ TLS/auth, exhausted resources.
- **Tests:** сначала failing test, затем код, затем регрессии.
- **Exit criteria:** команды CI, manual smoke если OS-specific, документация и known limitations.

### Пример: M3.2 fallback

**Given** client auto-profile and a valid server with both H3 and H2, **When** UDP traffic to endpoint is dropped, **Then** client connects using H2 inside a bounded timeout and reports reason `quic_unreachable`.

**Given** invalid TLS certificate and working H2, **When** QUIC handshake fails due to certificate validation, **Then** stop with `tls_verification_failed`, no H2 request is attempted.

**Given** denied token, **When** QUIC is reachable, **Then** return authorization error and do not retry over H2.

**Given** H2 is active, **When** UDP becomes available after TTL, **Then** next new session may use H3 while old H2 sessions stay alive.

## Технические решения, которые агент фиксирует ADR

- Конкретная версия quinn и API BBR, совместимость h3.
- TLS backend для **обязательного P0** browser-like fingerprint profile и его реальный footprint; при технической невозможности открыть блокирующий ADR, не помечать задачу готовой.
- Семантика half-close на HTTP streaming adapter (тест на обоих транспортах).
- Политика DNS resolve и фильтрация адресов, включая IPv6.
- Выбор OS proxy APIs и crash recovery format.
- Версионирование и миграции TOML/protocol без нарушения v1.

ADR хранить в `docs/adr/NNNN-title.md` с контекстом, альтернативами, решением, последствиями и планом проверки. Никаких ADR ради очевидных методов.

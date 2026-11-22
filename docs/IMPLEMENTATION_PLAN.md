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
| M2.1 | TLS/H2 server inbound + bearer auth + TCP dial + ACL | **PR M2.1, тестируется:** реальный TLS1.3/h2 server run + HTTP/2 full-duplex SmartTheia, canonical 32-byte bearer SHA-256 constant-time compare, inbound-scoped grants, DNS resolve then pinned SocketAddr TCP dial + ACL, quota/timeout, loopback echo with explicit allow-private, rejected local targets by default, negative TLS/auth. **Не считать этап полностью завершённым до CI и hardening:** hardening PR adds scoped cancellation, SAN/name check at startup, bounded per-peer request limiter (120/min; all attempts), one DNS/dial deadline and 64 candidates; follow-up adds independent read/write pumps and 8 simultaneous tunnels with reset isolation, slow reader with 1 KiB H2 window / 256 KiB byte-exact response; pending CI. Remaining: hundreds-of-streams stress/peak RSS measurements, complete PKI lifecycle, exhaustive DNS rebinding/fuzz. H3 и local proxy не входят в этот PR |
| M2.2 | Local HTTP CONNECT/SOCKS5 + client H2 | M2.2a: H2 client core with injected trust anchors, TLS1.3/name/ALPN verification, canonical bearer, OPEN_OK gate, independent relay/FIN, owned connection driver, DNS target passed without lookup. Pending CI. M2.2b: explicit H2 CLI, config secret refs + explicit trusted CA PEM, local CONNECT/SOCKS5 and automatic loopback E2E pending CI. Remaining platform trust roots, automated curl and Chromium SOCKS5 executable scenarios added pending CI; remaining expanded local parser/cancellation stress; no H3/auto fallback yet |
| M3.1 | H3/QUIC transport with same app frames | M3.1a: production QUIC/TLS composition root, BBR both peers, bounded flow credit, full handshake/ALPN and no 0-RTT, H3 HELLO/ACK test pending CI. M3.1b: shared H2/H3 admission/auth/quota/DNS ACL and actual H3 server OPEN_OK/TCP relay added pending CI. M3.1c: H3 client core with verified full handshake and active BBR, shared canonical bearer, HELLO/OPEN_OK gating and independent relay/FIN added pending CI. M3.1d: CLI H2/H3 server listeners and explicit H3 local proxy wiring added, pending CI. Remaining: automatic transport selection/fallback, pooling and stress. No H3 fallback or release claim |
| M3.2 | QUIC-first selector + safe H2 fallback | M3.2a: auto selector with observed UDP silence, configured deadline and profile-local TTL (0 disables), no fallback on received UDP/PKI/auth/protocol/ACL failures, no live migration. Pending CI. source-address route change invalidation and generation-safe cache updates added in M3.2b pending CI; full OS notifications (same source IP changes), server DNS refresh and broader stress remain open |
| M3.3 | P0: BBR verified on chosen quinn version | Production BBR on both senders verified. CI exploratory BBR vs CUBIC raw comparative trials with controlled synthetic loss/delay/jitter (Linux+Windows), artifact and integrity gate added pending CI; dedicated WAN bandwidth/RTT/fairness/pacing/CPU/peak RSS benchmark and statistical thresholds remain F-11 blockers, no silent CUBIC substitute |
| M3.4 | P0: uTLS-like fingerprint profile | M3.4a live production H2 ClientHello measurement merged in #28 (CI green); M3.4b BoringSSL `btls/tokio-btls` isolated H2 feasibility spike with GREASE, new ALPS, strict certificate tests and Linux/Windows Go uTLS comparison (Linux/Windows CI evidence in PR #29). **Neither** makes production browser-like; M3.4c isolated BoringSSL H2 full-duplex/strict TLS feasibility adapter merged via PR #31 (native Linux/Windows CI green); M3.4d Tokio 1.48→1.52.1 compatibility upgrade merged in PR #32 (CI green), no TLS backend switch; M3.4e optional feature-gated production H2Client BoringSSL integration with OPEN_OK/relay and negative PKI/ACL tests (PR CI pending), default rustls unchanged; real named TLS/HTTP profile, H2 SETTINGS acceptance, H3 QUIC-Initial reference/crypto adapter and full Windows/Linux E2E remain blocking for M5 |
| M4.1 | ratatui landing + server/client panels | focus/resize/dirty/save/validation UI tests, two independent modes |
| M4.2 | Local management IPC + reload | ACL, status, transactional apply, rollback, no open admin TCP port |
| M4.3 | Windows system proxy integration | WinINet user settings backup/apply/CAS restore, automated Windows CI smoke/recovery on disposable profile/VM |
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
- **Exit criteria:** все проверки автоматически в CI, включая OS-specific smoke/E2E и recovery; документация и known limitations. Ручные тесты не требуются, незавершённая автоматизация блокирует приёмку.

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

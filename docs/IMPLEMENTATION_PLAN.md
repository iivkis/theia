# План реализации для ИИ-агента

Спецификация — источник требований, а не уже написанный код. Каждая фаза делится на небольшие reviewable PR с тестами сначала. Не пытаться за один PR «сделать полный Xray», иначе получится красивое название над 4000 строками заглушек.

## Порядок, зависимости и gate

| Этап | Вертикальный срез | Тест/критерий завершения |
| --- | --- | --- |
| M0 | Документация, AGENTS, TOML examples, docs-only CI | структура спецификации проверяется CI; работающая функциональность **не заявлена** |
| M1.1 | Cargo workspace, единый `theia` CLI, `--help`/`--version`, роли | unit/CLI integration tests; Windows/Linux compile; `Cargo.lock` |
| M1.2 | Typed TOML v1 + validator + atomic store | round-trip, unknown keys, duplicate ID, missing refs, atomic rollback, file perms |
| M1.3 | SmartTheia pure frame codec + FSM | golden vectors, max frame guard, chunk fragmentation, malformed/unknown frames, fuzz |
| M2.1 | TLS/H2 server inbound + bearer auth + TCP dial + ACL | real loopback TLS echo; bad cert/token, DNS rebinding, private IP rejection |
| M2.2 | Local HTTP CONNECT/SOCKS5 + client H2 | browser/curl CONNECT and SOCKS5 E2E on Linux+Windows; half-close, cancellation |
| M3.1 | H3/QUIC transport with same app frames | H3↔server loopback E2E, HTTP/3 state and security invariants |
| M3.2 | QUIC-first selector + safe H2 fallback | UDP blocked → H2; wrong cert/token → no fallback; TTL; network change |
| M3.3 | BBR verified on chosen quinn version | actual congestion selection, packet loss benchmarks, no unverifiable flag |
| M4.1 | ratatui landing + server/client panels | focus/resize/dirty/save/validation UI tests, two independent modes |
| M4.2 | Local management IPC + reload | ACL, status, transactional apply, rollback, no open admin TCP port |
| M4.3 | Windows system proxy integration | WinINet user settings backup/apply/CAS restore, manual Windows smoke tests |
| M5 | Hardening/release | Linux and Windows full E2E matrix, security checklist, release notes, binary artifacts |
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
- TLS backend для optional browser-like fingerprint profile и его реальный footprint.
- Семантика half-close на HTTP streaming adapter (тест на обоих транспортах).
- Политика DNS resolve и фильтрация адресов, включая IPv6.
- Выбор OS proxy APIs и crash recovery format.
- Версионирование и миграции TOML/protocol без нарушения v1.

ADR хранить в `docs/adr/NNNN-title.md` с контекстом, альтернативами, решением, последствиями и планом проверки. Никаких ADR ради очевидных методов.

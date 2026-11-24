# Фактический статус Theia

**Срез состояния:** 2026-11-24, после merge [PR #115](https://github.com/iivkis/theia/pull/115) в `main` (`c85e5c3847d5bb3c91b7203b90dc6b9b31c67e69`). Это **не release-acceptance**: проект experimental/unreleased. [Exact-head CI PR #115](https://github.com/iivkis/theia/actions/runs/45419559187): **13/13 SUCCESS**, format-repair skipped. H2/H3 relay liveness принят.

Этот файл — актуальная сводка реализованных контрактов. [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) остаётся нормативной спецификацией **целевой** функциональности, [IMPLEMENTATION_PLAN](IMPLEMENTATION_PLAN.md) — историческим перечнем этапов, [ADR](adr/) — архивом решений, а [TESTING_CI](TESTING_CI.md) — контрактом тестирования.

## Реализовано и подтверждено в обычном CI

| Подсистема | Реальное состояние |
| --- | --- |
| SmartTheia v1 | Strict codec/FSM, TLS1.3/H2 и QUIC/TLS1.3/H3 end-to-end, TCP OPEN_OK, обратное давление/FIN, разрешённые по inbound пользователи и ACL. |
| Клиент | Локальный loopback HTTP CONNECT/SOCKS5, явный H2/H3, QUIC-first `auto` с ограниченным pre-auth UDP-silence fallback. |
| QUIC BBR | Выбран на обоих endpoint; Linux/Windows синтетические BBR/CUBIC сравнительные CI experiments выполняются. Это **не** полномасштабный релизный benchmark. |
| TUI M4.1 | Роли server/client, три безопасных поля существующей записи, проверка/атомарное сохранение TOML; без общего CRUD и без автоматического runtime Apply. |
| Local management M4.2 | Opt-in Linux Unix IPC / Windows SID-DACL Named Pipe, revisioned auth CAS, свежие порты, same-port TLS rotation, quota resize, pin TLS PEM bytes и one-shot 300s same-port rollback **только по явно подтверждаемым CLI-командам**. |
| F-14 частично | Canonical `theia://v1` codec, серверные `u` (CSPRNG issuance), `x` (global disable), `t` (явно подтверждённая ротация действующего bearer); клиентская TUI `i` локально импортирует приглашение с отдельным CA/защищённым credential file. Native Linux/Windows H2 binary E2E прошёл в PR #80/#81; ни одна операция не выполняет автоматический runtime Apply. M4.4e защищённый файловый экспорт (CI run 45392909341 passed all 13 jobs); M4.4f общий bounded input runtime/preflight/import и stale reveal guard; M4.4g явная замена credential существующего профиля; M4.4h восстановление отключённого пользователя с новым bearer (M4.4f–h CI 45395505034 passed all 13 jobs); M4.4i публичная ссылка без токена и native Windows recovery parity (PR #109, CI 45397074048 passed 13/13). |
| F-18 исследования | M3.5a0–a6 test-only TLS/exporter, identity/reconnect, H2/H3 DATA and local key lifecycle evidence; M3.5a7 v1 export downgrade fix and review packet; M3.5a8 bounded trust checkpoint reconstruction and isolated file recovery; M3.5a9–a10 native storage/process-exit, concurrent trust updates, local isolation regressions and shared F-14 local input and guarded configuration transaction hardening (CI run 45391036352 passed all 13 jobs); M3.5b1 offline candidate planning; M3.5b2a exact-consent strict H2 TLS; M4.5a–i passive discovery, DNS pin и согласованные отдельные H2/H3 кандидаты. Нет автоматического сканирования сторонних IP и нет REALITY режима. |

Последний слитый срез: **ADR-0079/0080, WinINet policy/ownership и реальный autoformat commit/dispatch**. ADR-0081 proposes shared H2/H3 relay liveness and bounded EOF; exact-head acceptance required. F-13/F-07 и остальные независимые P0 остаются открытыми.

## Открытые P0 и ограничения безопасности

- **F-13:** PR #83 / ADR-0057: opt-in BoringSSL H2-профиль с отдельными SETTINGS и строгой TLS1.3/PKI. PR #111 / ADR-0076: функциональный Chromium H2/H3 E2E и отрицательный QUIC ALPN на Linux/Windows. H3/QUIC browser first-flight, полные TLS vectors/HPACK pseudo порядок, benchmark и релизный F-13 остаются открытыми.
- **F-14:** PR #80 (ротация bearer) и #81 (локальный клиентский импорт с отдельным CA/credential file и нативным H2 E2E) слиты после успешного CI. Защищённый экспорт файла и автоматический Linux WSL2 server → native Windows H2/H3 E2E подтверждены CI; clipboard/QR, защищённая передача между физическими хостами и power-loss recovery не доказаны. M4.4f–h приняты: PR #108, CI 45395505034 (13/13); M4.4i принят: PR #109, CI 45397074048 (13/13). `disabled=true`/ротация из редактора действуют для новых сессий **только после** отдельного auth-only CAS Apply; активные туннели не отзываются.
- **F-18:** криптографически проверенный REALITY-подобный security mode, anti-probing/replay, безопасный двухшаговый picker/Apply и cross-host security evidence не реализованы. `TlsEvidence`/score не доказывают DPI-невидимость и не авторизуют активные сетевые проверки.
- **F-19:** flow-shaping, независимый TLS-in-TLS classifier, benchmark thresholds и измеренное улучшение не реализованы.
- **M4.3:** PR #82 / ADR-0056 accepted explicit CLI native WinINet CAS, journal and hard-kill recovery. PR #112 / ADR-0077 accepted separately confirmed TUI local start/apply/restore/stop/recovery, saved TOML/snapshot and journal ownership checks, compiled real ConPTY H2 CONNECT/SOCKS5 and hard-kill recovery. PR #114 / ADR-0079 accepted policy scope refusal and global SID plus legacy local mutex with extended recovery tests. Named VPN, real GPO, multi-session upgrade and extended acceptance remain open.
- **M5:** стабильная release CI/benchmark/security acceptance, full BBR throughput/RTT/fairness/CPU/RSS и P0 end-to-end ещё открыты.

## Что нельзя удалять при уборке

- `spikes/m0_1/` и `spikes/m3_4/` работают в обязательной Linux/Windows CI-матрице; это regression/feasibility evidence, не dead code.
- `docs/adr/` фиксирует решения и security boundaries; история не должна переписываться под нынешние даты.
- `Cargo.lock` root и отдельные lockfile в spikes нужны для воспроизводимого CI.
- `tests/` и `scripts/` используются текущим workflow, даже если их имена относятся к старым milestone.

## Как читать исторические артефакты

Старые формулировки «ожидает CI», «нет runtime» или «в review» в отдельных строках хронологического плана/ADR описывают состояние **на момент соответствующего PR**, а не сегодня. Документ первоначального design-only review от 2026-11-22 перенесён в [archive](archive/spec-review-2026-11-22.md) с предупреждением о его историческом характере.

При очередной разработке обновляйте этот статус **только на основе фактически выполненных тестов и принятого PR**, а не по наличию кода или зелёному тесту одной подсистемы.

F-14 evidence and residual gaps: [F14_ACCEPTANCE.md](F14_ACCEPTANCE.md). Do not equate a saved configuration with live authorization or release readiness.

**Reference policy (ADR-0074–0076):** Go/uTLS comparison retired; independent Python/OpenSSL strict H2 interoperability and pinned Chromium H2/H3 functional acceptance are mandatory. Browser origin navigation via local SOCKS5 is not a browser QUIC first-flight reference or packet parity claim.

### F-18 дополнительная идентичность (предлагаемый срез)

ADR-0082/0083: read-only второй шаг мастера с exact/fresh dual evidence и дополнительный `pinned-cert-v1` для собственного server inbound, H2/H3/auto client, mutual mode refusal, guarded сохранение с отдельным restart. Это не modified REALITY handshake, не pin key lifecycle audit, не F-18/F-19 acceptance. Промежуточный код прошёл 13/13 проверок на [точном head da21649](https://github.com/iivkis/theia/actions/runs/45425811970); текущая ветка PR #116 ещё не принята в main.

### Pending ADR-0084

Спецификация 0.6 (ADR-0086): единственный кастомный SmartTheia XHTTP, вдохновлён Xray XHTTP, не копия; H3/QUIC и H2/TCP; собственный SmartTheia REALITY, вдохновлён Xray REALITY, не копия, либо собственный TLS. Никакой Xray interoperability как цели. Предложен native split stream-up на одном проверенном соединении с общим FSM и pin. Промежуточный split stream-up с pin прошёл CI da21649; это не приёмка полноценного SmartTheia REALITY, целевой формы inbound или Apply. F-18/F-19 остаются открытыми.

## ADR-0087 — replacement invitation and cross-host pinned XHTTP acceptance

ADR-0087: the sole replacement theia://v1/ invitation explicitly represents SmartTheia XHTTP, own TLS stream-one or intermediate pinned TLS stream-one/stream-up, and H2/H3/auto. The old default-only envelope is rejected; no v2, no compatibility adapter. CA remains independent; no runtime downgrade or activation. Full SmartTheia REALITY is not yet implemented. Implementation and extended mandatory WSL2 Linux/native Windows binary tests are submitted; no new acceptance result is claimed. Prior PR #116 was merged at 45f42b1 after CI 45429164950. F-18/F-19 remain open.

## ADR-0088 — exporter-bound pinned XHTTP admission

Implementation submitted: H2 and H3 use separate TLS-exporter contexts, per-request HMAC, both stream-up legs and atomic one-admission connection state. Added independent raw H2/H3 negative tests and pure race/route/credential regressions. Acceptance requires exact-head CI. Independent server identity, complete candidate Apply, active-probing and F-19 remain open.

# Фактический статус Theia

**Срез состояния:** 2026-11-24, после merge [PR #83](https://github.com/iivkis/theia/pull/83) в `main` (`8ab25f7d5ad1b24ea04193af2cf7947933f30f39`). Это **не release-acceptance**: проект experimental/unreleased. [Exact-head CI PR #83](https://github.com/iivkis/theia/actions/runs/45264439305) завершился успешно (14/14 обязательных jobs); push-CI для merge commit проверяется отдельно.

Этот файл — актуальная сводка реализованных контрактов. [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) остаётся нормативной спецификацией **целевой** функциональности, [IMPLEMENTATION_PLAN](IMPLEMENTATION_PLAN.md) — историческим перечнем этапов, [ADR](adr/) — архивом решений, а [TESTING_CI](TESTING_CI.md) — контрактом тестирования.

## Реализовано и подтверждено в обычном CI

| Подсистема | Реальное состояние |
| --- | --- |
| SmartTheia v1 | Strict codec/FSM, TLS1.3/H2 и QUIC/TLS1.3/H3 end-to-end, TCP OPEN_OK, обратное давление/FIN, разрешённые по inbound пользователи и ACL. |
| Клиент | Локальный loopback HTTP CONNECT/SOCKS5, явный H2/H3, QUIC-first `auto` с ограниченным pre-auth UDP-silence fallback. |
| QUIC BBR | Выбран на обоих endpoint; Linux/Windows синтетические BBR/CUBIC сравнительные CI experiments выполняются. Это **не** полномасштабный релизный benchmark. |
| TUI M4.1 | Роли server/client, три безопасных поля существующей записи, проверка/атомарное сохранение TOML; без общего CRUD и без автоматического runtime Apply. |
| Local management M4.2 | Opt-in Linux Unix IPC / Windows SID-DACL Named Pipe, revisioned auth CAS, свежие порты, same-port TLS rotation, quota resize, pin TLS PEM bytes и one-shot 300s same-port rollback **только по явно подтверждаемым CLI-командам**. |
| F-14 частично | Canonical `theia://v1` codec, серверные `u` (CSPRNG issuance), `x` (global disable), `t` (явно подтверждённая ротация действующего bearer); клиентская TUI `i` локально импортирует приглашение с отдельным CA/защищённым credential file. Native Linux/Windows H2 binary E2E прошёл в PR #80/#81; ни одна операция не выполняет автоматический runtime Apply. |
| F-18 исследования | M3.5a0–a6 test-only TLS/exporter, identity/reconnect, H2/H3 DATA and local key lifecycle evidence; M3.5a7 v1 export downgrade fix and review packet; M3.5a8 bounded trust checkpoint reconstruction and isolated file recovery (pending CI); M3.5b1 offline candidate planning; M3.5b2a exact-consent strict H2 TLS; M4.5a–i passive discovery, DNS pin и согласованные отдельные H2/H3 кандидаты. Нет автоматического сканирования сторонних IP и нет REALITY режима. |

Последний слитый срез: **F-13 / ADR-0057 (частичный именованный H2-профиль)**. [Exact-head CI PR #83](https://github.com/iivkis/theia/actions/runs/45264439305): **14/14 SUCCESS**, включая `ci-gate`; merge в `main` выполнен после этого результата. F-13 в целом остаётся незавершённым.

## Открытые P0 и ограничения безопасности

- **F-13:** PR #83 / ADR-0057 слит после native Linux/Windows CI. Реальный opt-in `browser-h2-btls-v1` использует BoringSSL GREASE/ALPS, строгие TLS1.3/PKI и отличающиеся от `default` H2 SETTINGS, нативный CONNECT/SOCKS5 E2E. Это только частичная H2 browser-style реализация, не воспроизведение Chromium; H3 QUIC Initial, полные TLS vectors/HPACK pseudo порядок, benchmark и релизный F-13 остаются открытыми.
- **F-14:** PR #80 (ротация bearer) и #81 (локальный клиентский импорт с отдельным CA/credential file и нативным H2 E2E) слиты после успешного CI. Защищённый экспорт файла/clipboard, полная Windows ACL/collision/crash-recovery приёмка и автоматический Linux-server → Windows-client H2/H3 E2E остаются открытыми. `disabled=true`/ротация из редактора действуют для новых сессий **только после** отдельного auth-only CAS Apply; активные туннели не отзываются.
- **F-18:** криптографически проверенный REALITY-подобный security mode, anti-probing/replay, безопасный двухшаговый picker/Apply и cross-host security evidence не реализованы. `TlsEvidence`/score не доказывают DPI-невидимость и не авторизуют активные сетевые проверки.
- **F-19:** flow-shaping, независимый TLS-in-TLS classifier, benchmark thresholds и измеренное улучшение не реализованы.
- **M4.3:** PR #82 / ADR-0056 слит после успешного Windows CI: native WinINet per-user snapshot, explicit `client run --system-proxy --confirm`, SID ownership mutex, guarded CAS restore и durable HKCU recovery journal с отдельной операторской recovery-командой. Обычный `client run` остаётся off; test-only hard-kill и foreign edit проверки есть. TUI-интеграция, policy/VPN compatibility и длительная приёмка на реальном Windows-профиле всё ещё блокируют релиз.
- **M5:** стабильная release CI/benchmark/security acceptance, full BBR throughput/RTT/fairness/CPU/RSS и P0 end-to-end ещё открыты.

## Что нельзя удалять при уборке

- `spikes/m0_1/` и `spikes/m3_4/` работают в обязательной Linux/Windows CI-матрице; это regression/feasibility evidence, не dead code.
- `docs/adr/` фиксирует решения и security boundaries; история не должна переписываться под нынешние даты.
- `Cargo.lock` root и отдельные lockfile в spikes нужны для воспроизводимого CI.
- `tests/` и `scripts/` используются текущим workflow, даже если их имена относятся к старым milestone.

## Как читать исторические артефакты

Старые формулировки «ожидает CI», «нет runtime» или «в review» в отдельных строках хронологического плана/ADR описывают состояние **на момент соответствующего PR**, а не сегодня. Документ первоначального design-only review от 2026-11-22 перенесён в [archive](archive/spec-review-2026-11-22.md) с предупреждением о его историческом характере.

При очередной разработке обновляйте этот статус **только на основе фактически выполненных тестов и принятого PR**, а не по наличию кода или зелёному тесту одной подсистемы.

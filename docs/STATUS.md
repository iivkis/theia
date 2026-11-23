# Фактический статус Theia

**Срез состояния:** 2026-11-24, после merge [PR #78](https://github.com/iivkis/theia/pull/78) в `main` (`4d6f9553f7a84ada327ff622be19ba7c20e4b783`). **Это не release-acceptance**: проект experimental/unreleased. Обновление статуса не заменяет проверки точного SHA в GitHub Actions.

Этот файл — актуальная сводка реализованных контрактов. [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) остаётся нормативной спецификацией **целевой** функциональности, [IMPLEMENTATION_PLAN](IMPLEMENTATION_PLAN.md) — историческим перечнем этапов, [ADR](adr/) — архивом решений, а [TESTING_CI](TESTING_CI.md) — контрактом тестирования.

## Реализовано и подтверждено в обычном CI

| Подсистема | Реальное состояние |
| --- | --- |
| SmartTheia v1 | Strict codec/FSM, TLS1.3/H2 и QUIC/TLS1.3/H3 end-to-end, TCP OPEN_OK, обратное давление/FIN, разрешённые по inbound пользователи и ACL. |
| Клиент | Локальный loopback HTTP CONNECT/SOCKS5, явный H2/H3, QUIC-first `auto` с ограниченным pre-auth UDP-silence fallback. |
| QUIC BBR | Выбран на обоих endpoint; Linux/Windows синтетические BBR/CUBIC сравнительные CI experiments выполняются. Это **не** полномасштабный релизный benchmark. |
| TUI M4.1 | Роли server/client, три безопасных поля существующей записи, проверка/атомарное сохранение TOML; без общего CRUD и без автоматического runtime Apply. |
| Local management M4.2 | Opt-in Linux Unix IPC / Windows SID-DACL Named Pipe, revisioned auth CAS, свежие порты, same-port TLS rotation, quota resize, pin TLS PEM bytes и one-shot 300s same-port rollback **только по явно подтверждаемым CLI-командам**. |
| F-14 частично | Canonical `theia://v1` codec, серверная `u` CSPRNG new-user issuance и однократный показ после durable save, `x` global disable-only существующего пользователя в TOML (PR #78). |
| F-18 исследования | M3.5b1 offline candidate planning; M3.5b2a exact-consent strict H2 TLS; M4.5a–i passive discovery, DNS pin и согласованные отдельные H2/H3 кандидаты. Нет автоматического сканирования сторонних IP и нет REALITY режима. |

Последний завершённый вертикальный срез: **M4.4b2a**. [CI для точного head SHA `b9d46c91...`](https://github.com/iivkis/theia/actions/runs/45238684069): **14/14 SUCCESS**, включая `ci-gate`. PR был слит **после** этого результата.

## Открытые P0 и ограничения безопасности

- **F-13:** именованный, измеренный browser-like TLS/HTTP профиль для реального Windows/Linux клиента и H2/H3 ещё не поставлен. Опциональный BoringSSL backend, Go uTLS эталон и Chromium измерения являются исследованием, а не профилем.
- **F-14:** повторная выдача/ротация, безопасный файл/clipboard, проверенный клиентский импорт `theia://v1`, защищённое Windows хранилище, CA trust и автоматический Linux-server → Windows-client E2E остаются открытыми. `disabled=true` из редактора действует **только после** отдельного auth-only CAS Apply для новых запросов; активные туннели не отзываются.
- **F-18:** криптографически проверенный REALITY-подобный security mode, anti-probing/replay, безопасный двухшаговый picker/Apply и cross-host security evidence не реализованы. `TlsEvidence`/score не доказывают DPI-невидимость и не авторизуют активные сетевые проверки.
- **F-19:** flow-shaping, независимый TLS-in-TLS classifier, benchmark thresholds и измеренное улучшение не реализованы.
- **M4.3:** Windows F-07 native WinINet per-user snapshot, explicitly confirmed client process opt-in, SID mutex, guarded CAS restore and durable HKCU recovery journal реализуются в PR #82 / ADR-0056 (CI pending). Это **не** автоматический system proxy: обычный client run остаётся off. Нативный Windows тест теперь включает отдельный процесс с аварийным завершением без Drop, отказ после чужого WinINet edit и восстановление исходного snapshot (финальный exact-head CI ещё проверяется). Policy/VPN compatibility, TUI-интеграция и тесты на выделенном долговременном Windows профиле остаются релизными блокерами.
- **M5:** стабильная release CI/benchmark/security acceptance, full BBR throughput/RTT/fairness/CPU/RSS и P0 end-to-end ещё открыты.

## Что нельзя удалять при уборке

- `spikes/m0_1/` и `spikes/m3_4/` работают в обязательной Linux/Windows CI-матрице; это regression/feasibility evidence, не dead code.
- `docs/adr/` фиксирует решения и security boundaries; история не должна переписываться под нынешние даты.
- `Cargo.lock` root и отдельные lockfile в spikes нужны для воспроизводимого CI.
- `tests/` и `scripts/` используются текущим workflow, даже если их имена относятся к старым milestone.

## Как читать исторические артефакты

Старые формулировки «ожидает CI», «нет runtime» или «в review» в отдельных строках хронологического плана/ADR описывают состояние **на момент соответствующего PR**, а не сегодня. Документ первоначального design-only review от 2026-11-22 перенесён в [archive](archive/spec-review-2026-11-22.md) с предупреждением о его историческом характере.

При очередной разработке обновляйте этот статус **только на основе фактически выполненных тестов и принятого PR**, а не по наличию кода или зелёному тесту одной подсистемы.

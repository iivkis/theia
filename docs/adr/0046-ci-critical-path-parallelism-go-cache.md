# ADR-0046: CI critical-path reduction without weakening the required gate

**Дата:** 2026-11-23. **Статус:** CI optimization PR; exact-head CI required.

## Контекст

На успешном PR #70 CI (https://github.com/iivkis/theia/actions/runs/45188749768),
время по UTC timestamps логов:

| Job | Start | End | Approx. runtime |
| --- | --- | --- | --- |
| specification | 13:55:32 | 13:55:33 | 2 s |
| rust-tests (Linux) | 13:55:38 | 13:57:12 | 95 s |
| windows-smoke | **13:57:17** | 13:59:36 | 139 s |
| browser-e2e (Windows) | **13:57:18** | 13:58:58 | 100 s |
| m0-1-api-spike (Windows) | 13:55:38 | 13:58:26 | 168 s |
| ci-gate | 13:59:40 | 13:59:41 | 1 s |

ОС-специфические тесты независимы от Linux results, но
windows-smoke и browser-e2e ожидали их как обязательную зависимость.
Это создаёт приблизительно 95 секунд ненужной *последовательной*
зависимости для двух дорогих matrix branches. Фактический выигрыш
общего workflow определяется максимальной веткой (в базовом прогоне
M0.1 Windows может стать критическим путём), свободными GitHub runners
и прогревом cache, поэтому нельзя обещать конкретные секунды
без повторного измерения.

## Решение

1. Windows native smoke и browser-e2e matrix зависят только от
   specification (с сохранением rust_ready check) и могут идти
   параллельно Linux rust-tests. Это НЕ отменяет тесты и не делает
   статусы success допустимыми при skip/failure.
2. ci-gate остаётся с always() и зависит от всех прежних
   обязательных job IDs; он проверяет **каждый result == success**,
   включая Linux Rust, обе Windows/Linux browser ветки и Windows smoke.
3. Все три setup-go@v5 включают стандартный cache Go module/build,
   привязанный к существующему фиксированному
   spikes/m0_1/utls_reference/go.sum. Не сохранять новые secrets,
   не выключать go mod verify и не изменять Go/Rust версии.
   Warm-cache benefit не должен заявляться как guaranteed.
4. Новый автоматический тест tests/ci/check_workflow_parallel.py
   выполняется в specification до остальных job, проверяет dependencies,
   exact required ci-gate, native cross-SID E2E, ConPTY/VT
   зависимости, Rust tests/fmt/Clippy и Go cache wiring. Старый
   workflow сначала дал **red** на этом тесте:
   https://github.com/iivkis/theia/actions/runs/45190013448.
   Финальная доказательная проверка идёт на точном новом SHA.

## Риски и границы

Параллельные раннеры могут одновременно потреблять больше CI минут,
хотя wall-clock time уменьшается. На пиковых GitHub-hosted очередях
выигрыш может отсутствовать. Cross-SID security, actual PTY/ConPTY,
Chromium browser E2E, BBR, BoringSSL, native Windows, Clippy и
release-only build условия **не удаляются и не становятся optional**.
Меняется CI orchestration только; production runtime/бинарник,
wire protocol, network listener и системный proxy не затрагиваются.

## Acceptance

Specification static graph guard, все mandatory jobs, native
cross-user kernel denial, ConPTY и Linux PTY, ci-gate на exact-head
commit. После этого измерить реальный end-to-end workflow по
actual job timestamps и сравнить с baseline, без гарантированного
ускорения на GitHub-hosted ресурсах.

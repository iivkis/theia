# Архив исходного ревью спецификации (2026-11-22)

> **Исторический документ.** Ниже сохранены выводы specification-first PR #1 по состоянию на 2026-11-22. Утверждения об отсутствии кода, CI или runtime **устарели** и не описывают текущий проект. Актуальное состояние: [STATUS.md](../STATUS.md). Нормативные требования: [IMPLEMENTATION_SPEC.md](../IMPLEMENTATION_SPEC.md).

---

# Ревью спецификации Theia · 2026-11-22

**Объект:** specification-first ветка main, исходный PR #1. **Итог:** найденные контрактные ошибки устранены, реализация ядра по-прежнему **отсутствует**. Это не аудит существующего кода и не сертификация DPI-устойчивости.

## Критичные замечания и исправления

| ID | Критичность | До патча | После патча |
| --- | --- | --- | --- |
| R-01 | P0 / security | `server.users[]` глобальны, inbound не определяет допущенных пользователей | Каждый inbound требует явный непустой `allowed_user_ids`; проверка ID+digest+disabled+listener, отрицательный cross-inbound test |
| R-02 | P0 / host safety | `system_proxy="on"` позволял auto-apply при `client run`, несмотря на «явное действие» | Только `off/manual`; отдельное подтверждение в TUI; snapshot+CAS recovery, headless никогда не меняет OS settings |
| R-03 | P0 / protocol | HTTP 200 путался с открытым удалённым TCP dial; не определён полный дуплекс HTTP body | HTTP 200 подтверждает только auth/request; локальный HTTP CONNECT 200/SOCKS5 success **после** `OPEN_OK`; интеграционные тесты full-duplex без request EOF |
| R-04 | P0 / original scope | BBR и uTLS-like профиль отложены до P1, хотя заданы пользователем как свойства SmartTheia | F-11 и F-13 P0; M0.1 feasibility spike, M3.3/M3.4 реализация; релиз блокируется без BBR+измеряемого профиля |
| R-05 | P1 / trust boundary | Локальный proxy мог выполнить DNS раньше сервера; private-IP ACL и тесты localhost противоречили друг другу | Домены в `OPEN_TCP`, серверный DNS и ACL по закреплённому IP; localhost echo только в explicit test fixture с allow-private |
| R-06 | P1 / wire | HELLO включал `client_nonce`, который ничего не аутентифицировал и не использовался | Удалено бессмысленное поле до первой реализации, в v1 HELLO — ровно 6 байт; добавлены golden vectors |
| R-07 | P1 / testability | Docs-only CI проверял только наличие файлов и нескольких строк | Отдельные стандартные Python unittest-контракты на структуру TOML, назначение прав, links, статусы и приоритеты |
| R-08 | P2 / build time | На каждом PR выполнялись и тесты, и release-компиляция на Linux/Windows | На PR тесты, fmt, clippy и Windows smoke; release сборка только после push в main/manual dispatch |

## Остаточные инженерные риски

1. **uTLS-like ≠ гарантия невидимости.** Внедрить хотя бы один измеряемый fingerprint профиль — обязательное P0. Неизвестно, достаточно ли нынешнего TLS API выбранного Rust стека для нужного ClientHello: это решается M0.1. Если нет, нужен ADR об альтернативном backend, оценка CPU/RAM/лицензирования и повторный security review.
2. **HTTP/2 и HTTP/3 streaming** требуется проверить конкретными crate integration tests, включая response-before-request-EOF и EOF/FIN. Протокольный текст сам по себе не доказывает, что адаптер API даст нужный full-duplex.
3. **BBR** необходимо включить на каждом QUIC sender отдельно и подтвердить выбранную реализацию в конкретной версии crate. Сам факт существования класса `Bbr` в documentation не является измерением работы Theia.
4. **Local proxy loopback** не предназначен для защиты от вредоносных процессов того же хоста. В MVP нельзя bind на wildcard. Private destination policy исключает default тестовый echo на localhost без test-only override.
5. **Windows proxy** WinINet (пользовательские настройки) и WinHTTP различаются. CAS/snapshot необходимо проверять на Windows VM с реальными PAC/AutoDetect и внешними изменениями.
6. **Небраузерный HTTP-трафик** и открытые TLS/QUIC метаданные способны выдавать приложение по статистике и active probing; сравнение с xHTTP требует честных capture результатов. В спецификации нет обещания обхода DPI.

## Перед стартом разработки

Последовательность: **M0.1** (зависимости, H2/H3 full-duplex, fingerprint feasibility и BBR), M1.1 (Rust workspace + CLI), M1.2 (валидаторы TOML + inbound ACL), M1.3 (pure codec + golden vectors), M2 (H2+local proxy), M3 (H3/BBR+uTLS-like profile), M4 (ratatui+Windows), M5 (E2E/security).

## Внешние технические справки

- https://www.rfc-editor.org/rfc/rfc9114.html (HTTP/3, response may precede request completion)
- https://docs.rs/quinn/latest/quinn/congestion/struct.Bbr.html (Quinn BBR API; закрепить версию при реализации)
- https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options (WinINet per-user options)
- https://learn.microsoft.com/en-us/windows/win32/winhttp/setting-wininet-proxy-configurations-in-winhttp (WinHTTP — отдельный стек)

**Статус исправлений:** спецификация и примеры обновлены. Rust compiler, QUIC stack, fingerprint engine, WinINet adapter, CI Rust tests ещё не реализованы.

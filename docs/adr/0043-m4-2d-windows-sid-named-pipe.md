# ADR-0043: M4.2d — Windows Named Pipe с DACL по SID и авторизационным CAS Apply

**Дата:** 2026-11-23. **Статус:** PR #68, подтверждение native Windows CI.

## Проблема

Linux Unix domain socket из ADR-0038/0041/0042 защищён filesystem owner+0700/0600, но Windows пока возвращал Unsupported. Просто CreateNamedPipeW с security descriptor NULL означал бы default DACL, допускающий широкие группы и anonymous read. У Windows сервера и TUI нет права доверять такому IPC, и нельзя подменять осознанный CAS Apply непрозрачным reload.

## Решение

- Только Windows и **явный** `THEIA_CONTROL_PIPE=<id>`, где id содержит 1–48 ASCII `A-Z a-z 0-9 _ -` (не путь, не UNC, не . или \). Системное имя `\\.\pipe\theia-control-<CURRENT_TOKEN_USER_SID>-<id>` формируется программно, SID берётся из OS process token (OpenProcessToken/GetTokenInformation/ConvertSidToStringSidW), не из USERNAME/ENV или догадок. Без переменной server запускается без управления; невалидный id, ошибка OS token, DACL или уже существующая первая инстанция прерывают запуск сервера до начала обслуживания сетевых слушателей.
- Каждый CreateNamedPipe через Tokio `ServerOptions::create_with_security_attributes_raw` получает **явный protected** SDDL `D:P(A;;GA;;;<user SID>)(A;;GA;;;SY)`, выделенный ConvertStringSecurityDescriptorToSecurityDescriptorW и освобождённый LocalFree после синхронного CreateNamedPipe. Только текущий пользователь и LocalSystem, нет Everyone/Anonymous/Users/Administrators ACE, без наследования parent DACL. `bInheritHandle=0`. `reject_remote_clients(true)` устанавливается после режима, `first_pipe_instance(true)` у первого экземпляра препятствует squatting/двум server с тем же именем. Сам TCP admin port не появляется.
- 8 активных клиентов, максимум девять Named Pipe instances (восемь занятых плюс один ожидающий), один IPC запрос на клиента; лимиты 128 байт на команду, 128 байт на ответ, общий 2с timeout. После connect клиент получает типизированные `status`, `check-reload`, `apply-reload rev=N` либо `apply-reload rev=N sha256=<64lowerhex>`; сервер повторно проверяет оригинальный загруженный TLS PEM + TOML и использует общий staged CAS auth snapshot из ADR-0040/0041. Только живой Tokio handler публикует; detached blocking preflight worker не может применить конфигурацию после отмены.
- CLI `server status`, `server reload --check`, `server reload --expected-revision N` и серверная TUI (`v` read-only, `Ctrl+R` затем `y` с SHA-256 последних сохранённых TOML bytes) используют один и тот же IPC protocol/типизированный декодер, что и Linux. Windows TUI не применяет несохранённый файл, client TUI никогда не применяет серверные параметры. Потерянный ответ после отправки требует нового `status` и не считается откатом.
- После полного TLS/TCP/UDP preflight сервер поднимает pipe. Конфигурация допускает только token digest/disabled/grants **у существующих** user/inbound ID. Смена TLS, listener, квот, инвентаря пользователей, management или UI требует restart. Уже допущенные H2/H3 туннели не прерываются; лимиты/Semaphore сохраняются.

## Доверительная модель и ограничения

- Same-current-SID процессы считаются доверенными операторами, как процессы same-euid на Linux. LocalSystem имеет право на обслуживание. Администратор с SeDebug/privileges может получить контроль на уровне ОС, DACL не является изоляцией от привилегированного процесса. Сетевые/удалённые клиенты явно отклоняются. Публичного слушателя управления нет.
- Проверки включают реальный GetSecurityInfo/SDDL NT pipe handle, отсутствие широких ACE, protected DACL и fail-closed на дублирующий first-instance, invalid id. Отдельный CI login другого Windows аккаунта с фактическим denial может отсутствовать; это остаётся усилением, не подтверждённым этими тестами. Без доказательств не объявлять мультипользовательскую изоляцию сертифицированной.
- Единственная окруженческая переменная Windows — `THEIA_CONTROL_PIPE`. Linux `THEIA_CONTROL_DIR` остаётся как было. Конфигурация TOML v1/Invite v1 не меняется. Runtime Windows system proxy **никогда** не включается через control IPC.
- Все внутренние байтовые буферы и задачи bounded, но нет выделенных RPS/latency/RSS-бенчмарков Named Pipe, PTY/SSH end-to-end Windows TUI automation, cross-logon denial с отдельным SID, hard revoke активных потоков, полноценного TLS/listener rebind/rollback, F-18/F-19 или browser-like Rust transport.

## CI acceptance

- Native Windows cargo test full workspace/Clippy and actual compiled server with private named pipe + TLS/H2 and QUIC/H3 loopback. `status` показывает revision=1, check read-only; wrong bound SHA fails без revision change; exact SHA+CAS -> revision 2 на обоих transport, old auth denied/new accepted while already established relays work; stale revision, modified policy or PEM drift rejected; second CLI CAS Apply -> disabled user and revision=3.
- Native Windows unit: SID from process token, endpoint rejects path injection/invalid ID, duplicate first-instance fails, **kernel** GetSecurityInfo reports only current SID+SYSTEM DACL. Standalone server without live config does not Apply. Linux regression unchanged. Full Windows/Linux browser E2E, BoringSSL, BBR, uTLS and exact-head ci-gate must pass before review-ready.

## Последующая проверка M4.2e

Отдельный обязательный CI-only cross-logon E2E по ADR-0044 проверяет открытие реального именованного канала под другим непривилегированным SID, вместе с test-only положительным контролем. Статус результата устанавливается только после CI на точном SHA; это не меняет production API и не доказывает защиту от администратора или SYSTEM.

## Дальше

Windows cross-logon deny E2E via a second restricted OS identity, Windows PTY/SSH TUI automation and controlled restart wizard for TLS/listeners/quota. Стадии не подменяют невыполненные P0 F18/F19 или production security audit.

# ADR-0041: M4.2b1b — транзакционный Linux IPC Apply авторизации H2/H3

**Дата:** 2026-11-23. **Статус:** предложено, точный CI на PR #66.

## Контекст

ADR-0038/0039 дали локальный Linux IPC и безопасную read-only проверку `reload --check`. ADR-0040 (PR #65) дал единую внутреннюю auth revision с staged CAS для H2/H3, но не подключал файловую конфигурацию к действующему серверу. Изменять токены в `server.toml` без публикации в живом процессе было бесполезно; публиковать в фоновом `spawn_blocking` после клиентского timeout было бы опасно.

## Контракт

**Linux, только реальный `theia server run --config FILE`, явно настроенный `THEIA_CONTROL_DIR`** (существующая абсолютная euid-owned 0700 без symlink, Unix socket 0600). Оставлены границы 64 байта на команду, 128 байт на ответ, не больше 8 активных клиентов, дедлайн 2с. Нет внешнего management TCP. Same-UID владельцы директории имеют право управлять процессом; специальной криптографической аутентификации Unix-socket нет.

- `theia server status` выводит `authorization revision=N` из **фактически работающего** общего снимка; начальная ревизия 1. Сырой IPC `status\n` отвечает `theia-status-v2 running inbounds=I revision=N\n`. Старый standalone `StatusServer::bind_in` остаётся read-only, `theia-status-v1` и без ревизии, для совместимости тестов.
- `theia server reload --check` остаётся полностью read-only, без CAS.
- Только явный `theia server reload --expected-revision N` (N каноническое положительное u64 без ведущих нулей) посылает `apply-reload rev=N\n`. Запрос `reload\n` всё ещё **unsupported**, нет случайного автоприменения или скрытого implicit revision.
- Результат `theia-apply-v1 applied revision=N+1\n` отдаётся **только после завершения единого CAS** в памяти. `theia-apply-v1 rejected\n` означает отказ без публикации. CLI сверяет типизированную ревизию с ожидаемой +1, возвращает nonzero на malformed/rejected. `server status` помогает восстановить состояние после потерянного ответа.

## Граница транзакции

1. Отдельная async задача management читает ровно одну bounded команду; проверяет позитивную ревизию. Без `--expected-revision` и на Windows операция недоступна.
2. `spawn_blocking` **только считывает** не более 1 MiB TOML, строго проверяет schema, перечитывает TLS PEM через тот же защищённый `pem_data`, сверяет реальные хэши cert+key с байтами, использованными при старте H2/TLS и H3/QUIC, и сравнивает конфигурацию с неизменяемым baseline из запуска. Разрешены *только* `server.users[*].token_sha256`, `disabled`, `server.inbounds[*].allowed_user_ids` при прежнем каталоге ID, прежних listener, SNI, TLS ref, policy, management, ui. Версия кандидата читается **один раз** и затем передаётся в publish как owned document. Даже если worker завершится после отмены, **он не может применить изменения**.
3. Если async задача IPC всё ещё действует до дедлайна, она вызывает `LiveAuthorization::stage(candidate, expected_revision)` и `publish` (ADR-0040). CAS одним присваиванием `Arc<AuthSnapshot>` заменяет авторизацию **сразу для всех H2/H3 inbound**. Старые `SessionPermit`, семафоры/квоты, listener, TLS-идентичность и активные relays не меняются. При несовместимом/некорректном/неактуальном кандидате, TLS drift, overflow, lock poisoning или timeout до commit всё остаётся в прежней версии.
4. После `publish` **нет другой fallible части транзакции**. Следовательно rollback до commit = старый снимок не затронут; после commit обновление уже действительно. Потерянный/закрывшийся IPC ответ **не доказывает откат**: клиент должен проверить revision/status. Не следует автоматически повторять с новой ревизией без повторного просмотра файла.

## Семантика отзывов и ограничения

- **Новые** запросы H2/H3 и на уже открытых TCP/QUIC соединениях получают auth snapshot на момент начала их авторизации. Уже допущенный stream/туннель не отключается мгновенно и может продолжать работать по старому токену. Для hard revocation потребуется отдельная политика.
- Это hot Apply **только авторизации**, не полноценная live-реконфигурация. Изменения bind, сертификата/ключа, TLS-настроек, quota policy, реестра user/inbound, management и ui требуют restart; не реализованы REALITY/F-18/F-19, Windows Named Pipe+DACL, статус/Apply в TUI, OS proxy.
- Возможна файловая гонка: кандидат или PEM могут измениться **после** того, как они прочитаны в подготовке. Публикуется именно проверенный документ; действующая TLS идентичность не меняется. TOML/PEM на диске после snapshot не являются достоверным отражением runtime revision. Перед повторным Apply надо проверить файл заново. Это не защита от привилегированного same-UID злоумышленника.
- Status revision мониторит только память живого процесса, не версию TOML и не сохраняется при restart. Диспетчер выдаёт новое значение revision только после успешной публикации.

## CI

- Real compiled Linux server + isolated 0700 management, H2/TLS and H3/QUIC clients with explicit ephemeral rcgen CA, localhost echo. Given old token and two established tunnels, when compatible user digest rotates and expected revision matches, then **both transports** reject old/new accept new while old tunnels still echo; status revision changes 1→2. Same test checks second CLI Apply `disabled` changes revision 2→3 with real receipt.
- Given stale revision, structurally valid restart-only quota change, changed PEM cert bytes or absent active file, then Apply fails with nonzero and revision unchanged.
- CLI parser rejects missing/zero/noncanonical/overflow revisions; unsupported raw `reload` remains rejected. Tests run on loopback only, no public DNS/egress or OS proxy writes.
- Exact-head full Linux/Windows CI, fmt, clippy -D warnings, browser E2E on both, BoringSSL and BBR comparative matrix, ci-gate required. No claim of production security audit or WAN evidence.

## Следующее

M4.2c: read-only runtime revision / controlled explicit Apply entry in server TUI, Windows authenticated Named Pipe with DACL + OS identity mapping and Windows E2E. Критичные изменения listener/TLS/quotas по-прежнему отдельный безопасный restart wizard, не скрытый hot reload.

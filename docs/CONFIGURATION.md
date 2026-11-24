# TOML configuration: v1 schema

**Статус:** строгая схема TOML v1, структурная проверка и атомарная запись реализованы. `config validate` не читает secret/PEM content; runtime отдельно проверяет credentials, TLS identity/trust и bind H2/H3. Подтверждаемое управление runtime работает через native Linux/Windows IPC. Границы защиты произвольных файлов и текущая приёмка описаны ниже и в [STATUS](STATUS.md). База данных не используется.

## 1. Файлы и расположения

- В любом режиме явный аргумент `--config /path/to/file.toml` имеет приоритет.
- Linux-server default: `/etc/theia/server.toml`; Linux user config: `${XDG_CONFIG_HOME:-~/.config}/theia/{server,client}.toml`.
- Windows: `%APPDATA%\Theia\server.toml` и `%APPDATA%\Theia\client.toml`. Windows-server режим должен поддерживаться тем же бинарником, но его production-ready статус не является P0.
- Секреты: токен клиента читается **только** из `env:VARNAME` или `file:/path`, не как literal token в TOML. Сервер хранит SHA-256 хеш 256-битного токена в lower-hex.
- Схема строго проверяет `schema_version = 1`, неизвестные обязательные поля и нераспознанные ключи; unknown keys — validation error с путём поля (без silent ignore).
- Файл конфигурации UTF-8; пример содержит **недействительные** placeholder значения.

## 2. Server schema

```toml
schema_version = 1

[server]
enabled = true

[[server.inbounds]]
id = "public"
allowed_user_ids = ["device-a"]
quic_listen = "0.0.0.0:443"
h2_listen = "0.0.0.0:443"
server_name = "edge.example.org"
tls_cert = "file:/etc/theia/tls/fullchain.pem"
tls_key = "file:/etc/theia/tls/privkey.pem"

[[server.users]]
id = "device-a"
token_sha256 = "REPLACE_WITH_64_LOWERCASE_HEX"
disabled = false

[server.policy]
allow_private_ips = false
max_connections_per_user = 64
max_connections_total = 1024
connect_timeout_ms = 10000

[management]
ipc = "auto"
log_level = "info"

[ui]
language = "ru"
```

**Rules:**
- `inbounds[].id` уникален; ID не пустой, regexp `[a-zA-Z0-9_-]{1,64}`. Дубли и **перекрытия** bind endpoints (например, wildcard `0.0.0.0:443` с конкретным IPv4 на том же порту и в том же TCP/UDP transport) запрещены. При IPv6 wildcard проверять dual-stack semantics платформы. UDP и TCP на одинаковом числовом порту разрешены.
- TLS `server_name` обязательное валидное DNS-имя; сертификат должен ему соответствовать. File refs разрешаются с запретом выхода за разрешённую директорию секрета при необходимости.
- Каждый user ID и `token_sha256` уникальны; `token_sha256` — строго 64 lower-case hex symbols (placeholder не принимается). Токен должен состоять из 32 bytes, созданных CSPRNG.
- `inbounds[].allowed_user_ids` **обязателен** и непуст: все ID должны существовать в `server.users[]`, без повторов. Глобальный каталог пользователей **не предоставляет прав доступа автоматически**. Подключение разрешено только при валидном токене, активном пользователе и явном включении ID пользователя в `allowed_user_ids` конкретного inbound. Выбор inbound производится по listener socket, а не по недоверенному HTTP `Host`/`:authority`.
- `Authorization: Bearer` содержит canonical base64url без padding от **сырых 32 байт** токена. Сервер вычисляет SHA-256 от декодированных исходных байт (не текста base64url), сравнивает digest constant-time и только затем проверяет назначение inbound. Digest никогда не принимается вместо bearer token.
- `allow_private_ips=false` исключает loopback, RFC1918, link-local, unspecified, multicast и прочие недоступные назначения; перепроверять после DNS resolve.
- Limiting values >0; server должен выполнять caps с bounded resources, ошибки параметров с номером строки/полем.
- **M4.2d Windows Named Pipe:** при `THEIA_CONTROL_PIPE=id` (ASCII 1–48 `[A-Za-z0-9_-]`, без пути) тот же однобинарный `theia server run --config FILE` после TLS/TCP/UDP preflight создаёт локальный `\\.\pipe\theia-control-<process TokenUser SID>-id` с protected NT DACL только для текущего пользователя и LocalSystem, без Everyone/Anonymous/default ACL и с reject remote + first instance anti-squat. Доступны `theia server status`, `server reload --check` (read-only), `server reload --expected-revision N` и server TUI `v`/`Ctrl+R`+`y` (SHA-256 точных saved TOML bytes). Без opt-in управление недоступно, invalid id / occupied pipe / SID-DACL failure приводит к отказу запуска, а не к небезопасному fallback. Дедлайн 2с, 128-byte request/response, до 8 активных соединений. Auth-only CAS, TLS/port/quota restart-required, Windows system proxy неизменен. [ADR-0043](adr/0043-m4-2d-windows-sid-named-pipe.md).
- `management.ipc="auto"`:  **M4.2a Linux private IPC with M4.2b1b explicit auth-only Apply** при установленном `THEIA_CONTROL_DIR`: абсолютная существующая euid-owned директория `0700`, без symlink; socket `theia-server.sock` внутри с правами `0600`. При отсутствии env сервер работает без status IPC, `theia server status` возвращает ошибку; при недоверенной директории или занятом socket bind сервер отказывает до запуска обработчиков. `health/status` доступны только локально; голая команда `reload` остаётся unsupported, но `server reload --expected-revision N` применяет только совместимое изменение пользователей/грантов при строгом CAS после повторной проверки PEM и TOML. `server status` сообщает фактическую authorization revision. Socket не удаляется при startup, старый path после аварии требует проверки оператором. Windows Named Pipe+ACL, защищённые CAS/restart/quota/TLS rollback команды и TUI status/Apply добавлены последующими M4.2-срезами; их конкретные ограничения описаны ниже и в ADR. [ADR-0038](adr/0038-m4-2a-linux-readonly-management-ipc.md). `log_level`: error/warn/info/debug/trace, trace с предупреждением о метаданных.

### Независимый безопасный trace-журнал (ADR-0058, ADR-0078)

`management.log_level` остаётся проверяемым параметром TOML v1 (`error/warn/info/debug/trace`) ради совместимости. Безопасный файловый trace включён по умолчанию на уровне `info` независимо от этого поля; `THEIA_TRACE_LEVEL=error|warn|info|debug|trace` меняет порог. Неизвестное/отсутствующее значение означает `info`; `THEIA_TRACE_OFF=1` имеет приоритет. `debug` добавляет этапы протокола, `trace` — покадровые события. Новых TOML v1 keys нет. Произвольные строки из конфигурации, секреты, целевые IP/DNS/URL и payload не пишутся ни на одном уровне.

Linux по умолчанию: `${XDG_STATE_HOME:-$HOME/.local/state}/theia/logs`; Windows: `%LOCALAPPDATA%\\Theia\\logs`. `THEIA_TRACE_DIR` задаёт защищённый каталог. `THEIA_TRACE_OFF=1` полностью отключает логгер. В каждом процессе максимум два лог-файла по 25 МиБ (50 МиБ суммарно); разные запуски не ограничены общим лимитом и нуждаются в отдельной политике хранения. На Linux каталог должен иметь `0700`, файлы создаются с `0600`; на Windows используйте личный каталог с приватным ACL. При ошибке создания лога программа продолжит работу с предупреждением в stderr.

## 3. Client schema

```toml
schema_version = 1

[client]
active_profile = "home"

[[client.profiles]]
id = "home"
server = "edge.example.org:443"
server_name = "edge.example.org"
auth_token = "env:THEIA_AUTH_TOKEN"
tls_profile = "default"
transport = "auto"
quic_connect_timeout_ms = 1600
quic_negative_cache_ttl_s = 900

[client.proxy]
http_listen = "127.0.0.1:7890"
socks5_listen = "127.0.0.1:7891"
system_proxy = "off"

[management]
ipc = "auto"
log_level = "info"

[ui]
language = "ru"
```

**Rules:**
- `active_profile` указывает на существующий уникальный `profiles[].id`.
- `server` — hostname:port или [IPv6]:port. `server_name` — hostname для TLS/SNI, без insecure override.
- `auth_token` — `env:NAME` или `file:path`, содержимое должно быть canonical base64url **без padding**, декодироваться строго в **32 байта**; зафиксировать test vector и отклонять двусмысленные формы.
- `tls_profile`: `default` (строгий rustls, без имитации браузера) либо **явно выбранный** `browser-h2-btls-v1` только с `transport = "h2"` (ADR-0057; PR #83 слит после успешного native Linux/Windows CI). В обычном бинарнике BoringSSL собирается, но не выбирается автоматически. Новый профиль действительно меняет TLS backend и измеряемые H2 SETTINGS при сохранении TLS1.3/CA/SNI/ALPN и 8KiB header guard. H3/auto с данным именем, неизвестные строки и сборки без включённого BoringSSL отказывают без downgrade. Внешний Chromium159 несовпадающий reference, поэтому полная F-13 release acceptance остаётся открытой.
- `transport`: `auto`, `h3`, `h2`. В `h3` не разрешён fallback; `h2` не инициирует UDP. В `auto` fallback только при network-level QUIC failure.
- `quic_connect_timeout_ms`: рекомендуемый 1600, допустимо 500..15000. `quic_negative_cache_ttl_s`: по умолчанию 900, допускается 0 (без кеша) .. 86400.
- Proxy listeners строго loopback по умолчанию; возможность внешнего bind НЕ включать до явной аутентификации локального proxy и отдельной политики безопасности.
- `system_proxy` допускает **только `off` и `manual`**. `off` (default) не трогает OS proxy. `manual` не включает proxy само по себе: требуется явно подтверждённый Windows CLI `theia client run --config FILE --system-proxy --confirm` либо отдельное TUI подтверждение после локального старта (ADR-0077, PR #112). Обычный запуск, импорт и открытие TUI не меняют WinINet. Восстановление после аварии только явно подтверждаемое с CAS-защитой. `on` запрещён в v1, Linux возвращает `UnsupportedPlatform`. Это не TUN и не перехват всех приложений.
- `http_listen`/`socks5_listen` принимают только `127.0.0.1` или `[::1]` с уникальной парой `(IP,port)`; wildcard bind запрещён. P0 local proxy не аутентифицирует соседние локальные процессы: loopback **не означает изоляцию от иных локальных приложений**.
- При доменном HTTP CONNECT/SOCKS5 запросе клиент передаёт DNS hostname как SmartTheia `OPEN_TCP` с `addr_type=0x03`, не резолвит цель локально. Сервер делает DNS resolve, фильтрует **каждый** полученный IP через ACL и dial только закреплённого разрешённого IP. При IP literal DNS не нужен. Системные приложения вне прокси и bypass могут резолвить имена локально: обещать отсутствие любых DNS-утечек нельзя.

## 4. Валидация и запись

- `theia config validate --config ...`: реализована структурная проверка: парсинг UTF-8 TOML v1 (до 1 МиБ), строгие поля, уникальность ID/digest/grants, bind overlap, ссылки `env:`/абсолютные `file:`, loopback listeners, P0 profile guard, диапазоны чисел. **Не читает** env/file secret content и не проверяет сами TLS сертификаты: проверка существования обязательных файлов, canonical base64url и их семантики — отдельный диагностический этап до запуска runtime. Ошибки сообщают поле и причину для semantic validations; syntax/type errors редактированы во избежание утечки конфигурационных значений. Команда выводит причины, избегая вывода секрета.
- TUI редактирует **typed model**, а не строки регулярными выражениями. Перед сохранением double validation. Не перетирать неизвестные поля: в v1 лучше явно отказать при новом ключе и сохранить оригинал.
- Запись: `config::atomic_write` выполняет double validation → create_new temp файл в том же каталоге → write+fsync → rename → fsync каталога на Unix. На Unix создаётся с правами 0600; Windows ACL наследуется от директории. **Вызывающий должен обеспечивать доверенный каталог без вредоносных symlinks;** синхронизация директории на Windows отсутствует. На ошибке до rename прежний конфиг не меняется, но сбой fsync директории *после* rename может означать уже заменённый файл; не обещать rollback после commit-point. Права: server secret file 0600/ACL only intended user; публичный не секретный конфиг не должен перезаписывать секретный файл.
**M4.2g restart-only readiness (НЕ перезапуск):** при запущенном сервере с защищённым Linux/Windows IPC и сохранённым файлом `theia server restart --check` только читает валидированный TOML и строго проверяет TLS PEM/имя/ключ как runtime, затем пробует одновременно зарезервировать все **новые** TCP/UDP listen addresses и тут же освобождает их. Если адрес совпадает/пересекается с активным (включая wildcard), выводит `requires controlled maintenance`, вместо опасного освобождения действующего порта. Неизменные TLS/restart-поля дают `restart not needed ... use CAS auth Apply`. Занятый новый TCP/UDP и неверный cert/key/SAN дают nonzero reject; ранее запущенные listeners, текущая authorization revision, конфиг и системный прокси не изменяются. Успешная проверка НЕ резервирует порт после выхода, не выполняет QUIC handshake и НЕ означает успешный restart, TLS/listener/quota cutover, rollback, drain или hard revoke. Это отдельная ограниченная фаза будущего managed restart (ADR-0047).
**M4.2i same-port TLS identity rotation (ADR-0049):** Независимо от смены портов, теперь `theia server restart --check` может предложить `same-port TLS rotation ready` для изменения только TLS PEM existing inbounds при прежних listener addresses, server_name, users, grants, management и quotas. Подтверждение через прежний native protected IPC: `theia server restart --apply --expected-revision N --sha256 TOMLHEX --tls-sha256 PEMHEX --confirm` (SHA-256 точных байтов TOML). Все TLS1.3/H2 и QUIC/H3/BBR конфиги готовятся до CAS; новая identity применяется только к **новым** handshakes на старых TCP/UDP портах, существующие authenticated tunnels не теряются. Любые изменения quota, user IDs, policy, адресов, SAN mismatch и невалидные PEM отвергаются на этом пути. Подсказка TUI Shift+R read-only, без Apply. Важно: SHA TOML не закрепляет внешние PEM bytes; используйте versioned private file paths и заранее настройте trust новых CA на клиентах. Параллельные старые handshakes могут завершиться с прежним cert; после CAS автоматического rollback нет. Увеличение/снижение quotas остаётся отдельной задачей.
**M4.2j live quota-only resize (ADR-0050):** при работающем server run --config FILE через защищённый Linux Unix IPC/Windows current-user SID Named Pipe оператор сохраняет TOML, проверяет read-only `theia server quota --check`, затем отдельно подтверждает `theia server quota --apply --expected-revision N --sha256 HEX --confirm`, где HEX является SHA-256 **точных bytes** сохранённого TOML. Только `server.policy.max_connections_total` и `server.policy.max_connections_per_user` могут изменяться, также они должны оставаться валидными (>0, per-user<=total). Остальные поля конфигурации и реально загруженные TLS PEM bytes неизменны. CAS публикует новую revision и caps без закрытия H2/H3 listeners и существующих authenticated tunnels. При уменьшении ниже фактически занятых permits новые sessions и transport connections отвергаются, пока occupancy не снизится; при увеличении новые permits доступны выше startup cap. Глобальный лимит применяется **отдельно** к active sessions и active transport connections, как раньше, а не к их сумме. Запрещены смешанные изменения tokens/grants/users, ACL/timeout, TLS/SNI и listener binds. Потеря IPC ACK требует server status перед повтором; нет автоотката и нет quota Apply из TUI.
**M4.2l last same-port TLS rollback (ADR-0052):** после успешной ротации на тех же H2/H3 портах сервер сохраняет в памяти ТОЛЬКО прежние TLS-конфиги на 300 секунд. Read-only `theia server tls rollback --check` через исходный private Linux Unix IPC/Windows SID DACL сообщает доступность, текущую revision и оставшиеся секунды. Явный `theia server tls rollback --apply --expected-revision N --confirm` возвращает предыдущие сертификаты из уже проверенных **in-memory** H2/QUIC TLS-конфигов без открытия файлов или закрытия listeners, публикует revision N+1 и поглощает слот однократно; изменения токенов и квот, произошедшие после ротации, сохраняются. No slot, истечение пяти минут, stale CAS, свежая смена TCP/UDP портов, повтор команды или несогласованная generation дают отказ без side effects. Опция недоступна после перезапуска процесса. Новые PEM-файлы на диске при rollback **не переписываются**: для будущего cold start оператор обязан восстановить версионированные доверенные файлы. Это НЕ auto-rollback при health fail и НЕ история нескольких поколений, TUI Apply отсутствует. Потерянный ACK проверять status + rollback --check, не повторять вслепую.
**M4.2k pinned TLS PEM restart (ADR-0051):** для любого `server restart --apply` (и same-port TLS, и fresh-port H2/H3) теперь необходимы ДВА независимых отпечатка. Первый, `--sha256 TOMLHEX`, берётся из точных байтов сохранённого TOML. Второй вычисляется локально через read-only `theia server tls fingerprint --config /path/to/server.toml` по фактически прочитанным cert+private-key PEM каждого inbound в порядке конфигурации. Команда выдаёт только `theia-tls-pem-v1 sha256=PEMHEX`, не секреты. Подтверждение: `theia server restart --apply --expected-revision N --sha256 TOMLHEX --tls-sha256 PEMHEX --confirm`. Старый формат БЕЗ `--tls-sha256` теперь ОТКЛОНЯЕТСЯ. IPC читает защищённый bounded TOML и PEM, сверяет хеши, сохраняет один Zeroizing snapshot; supervisor строит H2/H3 TLS конфиги именно из проверенных байтов и никогда не перечитывает файлы во время commit. Изменение PEM после вычисления отпечатка даёт отказ с сохранением работающего сервера. Рекомендуются атомарные immutable/versioned PEM paths. Нет автоотката после CAS или гарантии глобальной атомарности всех TLS ClientHello; quorum и auth-only CLI не меняются. Макс. native IPC команда 256 bytes (ответ 128).

**M4.2h limited supervised fresh-port cutover:** после сохранения server TOML и отдельного `server restart --check` оператор вычисляет canonical lowercase SHA-256 **точных байтов** (`sha256sum` на Linux или Get-FileHash SHA256 на Windows) и запускает `theia server restart --apply --expected-revision N --sha256 TOMLHEX --tls-sha256 PEMHEX --confirm` через прежний private Linux/Windows IPC. Это **реальный** cutover H2/TLS+H3/QUIC на полностью новые TCP/UDP адреса: prebind всех listeners, CAS runtime view с revision N→N+1, old admission off, old tunnels drain не более 20s, использование shared global/user connection permits на время перехода. Занятый bind, TLS/SAN/key error, неполный/внешне изменённый TOML, stale revision, пересечение со старым портом, смена квот либо user ID inventory дают отказ **до** commit без остановки действующего сервера. ACK приходит после commit; потеря ответа = неизвестный итог, сначала проверить server status. После commit автоматический rollback отсутствует, старые туннели после drain timeout закрываются, zero-downtime same-port TLS и quota change не готовы. Server TUI Shift+R остаётся ТОЛЬКО read-only, у неё нет кнопки restart Apply. ADR-0048.
- Reload transaction: прочитать целиком → validate → создать listeners/prepare resources → atomic swap active snapshot, либо rollback. При сбое продолжить работу с прежним snapshot. Новые listeners не должны убить старые до успешного bind. **M4.2c:** серверная Linux TUI `v` запрашивает реальный runtime revision, `Ctrl+R` + явное `y` применяет **только** сохранённый TOML, чьи точные байты привязаны по SHA-256 к однократному чтению кандидата работающего сервера. Внешние изменения файла/несоответствие редактора запрещают Apply. Внутренний Linux IPC лимит команд увеличен до 128 байт исключительно для bounded `apply-reload rev=N sha256=...`; ответ остаётся 128, 8 клиентов, 2с. Нет Windows Named Pipe или listener/TLS Apply, ADR-0042. **M4.2b1b:** Linux-only explicit `theia server reload --expected-revision N` теперь умеет атомарно применять **только auth-compatible** digests/disabled/grants, с проверкой PEM byte identity и реальной revision в status; в случае отказа/timeout до commit старое состояние остаётся. После потерянного ACK необходим status: успешный commit уже не откатывается. Без bind/TLS/quotas/TUI/Windows Apply, ADR-0041. **M4.2b1a:** внутренние H2/H3 authorization contexts читают одну versioned Arc snapshot users/grants, для тестируемой будущей транзакции есть pure staged CAS publication с сохранением old permits и per-user/global quota, но **на этапе b1a команды Apply ещё не было**; узкий Linux auth-only Apply добавлен в b1b ([ADR-0040](adr/0040-m4-2b1a-shared-cas-auth-snapshot.md)). **M4.2b0 поддерживает только Linux `theia server reload --check`** при запущенном сервере c `THEIA_CONTROL_DIR`: валидирует кандидат без записи и без смены runtime, проверяет неизменность фактических PEM cert/key bytes и всех restart-only полей; допускает лишь потенциальную смену digest/disabled/grants для прежних пользователей. Успех = «candidate compatible; runtime UNCHANGED», **не** гарантия будущего Apply и не reserve file revision; см. [ADR-0039](adr/0039-m4-2b0-readonly-reload-preflight.md).
- Токен при создании/ротации/восстановлении пользователя показывать **один раз** или экспортировать в новый защищённый файл только после подтверждения успешной guarded записи. Сервер хранит только digest. Сохранение, отключение и замена credential не применяют runtime автоматически; активные туннели не отзываются. Подробности: [INVITATIONS](INVITATIONS.md).
- Бэкапы config и snapshot настроек Windows допускаются как TOML-файлы, но не как скрытая БД. Backups с секретами защищать file permissions.

## 4.1. F-14 P0: переносимые приглашения и секреты

- Публичный экспорт по умолчанию содержит только необходимые не-секретные endpoint/SNI/transport/профиль (без TLS private keys, digests и bearer). Конфиденциальная ссылка theia://v1/... с сырым 32-байтным bearer создаётся **только в контексте новой выдачи/ротации** пользователя, после подтверждения и проверки grants; из token_sha256 её восстановить нельзя.
- Ссылка не является URI для HTTP-загрузки; импорт — локальный строго ограниченный base64url + версионированный payload. Ограничить размер, запрещать unknown fields/versions, повторные поля, некорректный host, неверный canonical token и скрытые side effects. Никаких строк URI/токена в CLI argv, shell history, stdout/stderr, tracing, crash diagnostics и обычном TUI.
- Для импорта со встроенным токеном сохранить точные 32 bytes как canonical base64url (43 ASCII-байта без перевода строки) в новый уникальный файл trusted directory с Unix 0600 или Windows per-user ACL. В client.toml сохраняется **только** file:/env: reference; действия сбоя защищают от частичного применения и от перезаписи существующего секрета. Без полного Windows ACL и crash-test не заявлять завершение F-14.
- Ссылка не распределяет доверенные корни CA сама по себе. Перед реальным соединением клиент проверяет серверный TLS/SNI и доверенную CA из локального хранилища. Использование invalid или unauthenticated CA, отключение TLS verification, transport downgrade при auth error запрещены. CA bundle/chain provisioning остаётся отдельным шагом до безопасного импортного соединения.
- Один серверный пользователь с токеном не получает автоматический доступ ко всем inbounds; экспорт выдаётся только при явном allowed_user_ids в выбранной inbound. Не менять system_proxy, активный профиль или runtime при импорте.

## 4.2. Будущие F-18/F-19 поля (не изменять TOML v1 до реализации)

REALITY-подобный security mode, криптографическая идентичность сервера и pin **публичного** ключа, выбранный TLS образец target/SNI, версия протокола, fingerprint и anti-TLS-in-TLS policy off/optional/required требуют отдельного ADR с точными типами, схемой миграции и versioned invitation. В строгом schema_version=1 клиентский `tls_profile` допускает только `default` либо явно выбранный отдельный H2 `browser-h2-btls-v1` (ADR-0057), а экспорт theia://v1 остаётся default-only (не-default клиентский профиль нельзя экспортировать с потерей его выбора; ADR-0064); нельзя пропускать новые поля или выдавать стандартный TLS за REALITY. Server private key должен храниться через защищённый env/file; не помещать его в приглашение, логи, результаты сканера. Клиент должен проверять server identity без снятия верификации TLS; при неподдерживаемом required — отказ. См. docs/STEALTH_REALITY.md.

## 5. Windows system proxy

**Windows F-07 / M4.3 (ADR-0056; PR #82 accepted):** CLI apply requires manual mode, explicit confirmation, successful local HTTP CONNECT/SOCKS5 binds and strict TLS/credential preflight. The process holds a per-SID ownership mutex; a protected durable HKCU journal enables conditional restoration of exact prior flags, server, bypass and PAC URL. `client proxy --status` is read-only; `client proxy --recover --confirm` refuses foreign state, no force. PR #112 / ADR-0077 adds Windows TUI `p` with separate `s/y` local start, `a/y` apply, `r/y` restore, `x/y` stop, `c/y` recovery. ADR-0079 proposes explicit refusal of machine-wide or unconfirmed per-user policy scope and global SID mutex plus legacy local mutex; stop all older clients before upgrade. Приёмка нового блока ещё не подтверждена. Plain client run/server/import/opening TUI never change WinINet. Not WinHTTP/TUN; VPN/policy and upgrade acceptance remain open.

Реализация через Windows APIs (WinINet/user Internet Settings), а не `netsh winhttp` как замену пользовательскому прокси: WinHTTP и WinINet — не одно и то же. Настраивать адрес локального HTTP proxy для HTTP и HTTPS, bypass для loopback/intranet при необходимости, уведомлять систему об изменении.

Алгоритм:
1. Прочитать исходные per-user settings; создать защищённый на диске snapshot (для аварийного восстановления).
2. Проверить, что HTTP listener поднят и `system_proxy="manual"`; **только затем** по отдельному подтверждению в TUI применить system proxy. Headless start никогда не включает proxy автоматически.
3. Запомнить applied values; при отключении использовать **CAS (compare-and-swap)**: сравнить текущие настройки с нашим applied snapshot и восстановить исходные **только если настройки по-прежнему наши**. При изменении другим приложением не перетирать, показать конфликт.
4. После crash/restart предложить восстановить snapshot, если текущий proxy всё ещё указывает на Theia. Не молча перезаписывать настройки.
5. Тестировать idempotency, отказ прав, существующие PAC/AutoDetect, пользователя с другим proxy, внезапное завершение; TCP listener shutdown должен сопровождаться процедурой безопасного восстановления. Закрытие одного окна TUI при действующем headless runtime не является отключением proxy; остановка runtime вызывает безопасную попытку восстановления.
6. Snapshot хранится с per-user ACL и версией схемы и включает все исходные поля (PAC/AutoDetect/bypass). Неуспех сохранения snapshot блокирует активацию. После изменения сигнализировать WinINet о смене настроек; не путать per-user WinINet и WinHTTP.

Microsoft references: https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality , https://learn.microsoft.com/en-us/windows/win32/winhttp/setting-wininet-proxy-configurations-in-winhttp

Client runtime: `client.profiles[].tls_ca` is an absolute `file:` reference to a trusted PEM CA bundle (runtime verifies TLS name/chain and never falls back to insecure verification). `auth_token` uses an explicit env or file reference with exactly 43 canonical base64url bytes, no newline. See bounded native input rules below. Both loopback ports bind before serving; H2/H3/auto follow the transport rules in section 3; WinINet is unchanged unless separately confirmed.

**M3.5a0 security feasibility (test-only):** существующие schema_version=1 и theia://v1 **строго отвергают** неаудированные reality/security_mode/server_public_key/flow_shaping поля и tls_profile кроме default. Тестовый TLS exporter в Rust и QUIC с работающей CA НЕ создаёт новую схему доверия или wire profile; никакие новые поля не добавлены. См. ADR-0021 и crates/theia/tests/reality_security_feasibility.rs.

**Guarded editor writes (ADR-0068):** cooperating editors use a stable per-file sidecar advisory lock and compare the loaded bytes under the lock and again immediately before replacement. The sidecar remains after handle close; it contains no secret data. The guarded write reports whether failure preceded replacement or durability became uncertain after replacement. On Unix directory-open/sync failure is no longer silently ignored. An uncertain editor must be reopened before further saves, import or runtime Apply. This does not serialize arbitrary external writers, eliminate hostile parent-path races or prove power-loss durability.

**Unified native bounded inputs (ADR-0070):** configuration reads (including explicit relative CLI paths), editor reads, content-bound Apply/restart, client CA/bearer and server certificate/key all use one bounded regular-file reader. File references require an absolute native path; Windows UNC/device/stream references are refused at runtime, even if portable TOML structural validation accepts the syntax. Final symlinks/reparse objects reject, and Unix private mode is checked on both path metadata and the opened handle. Server PEM reads are limited even if the file grows. Best-effort zeroizing buffers protect raw token/key bytes. Trusted parents are still required; Windows ACL validation of arbitrary user-selected input files is not added. No changes to TLS verification or authorization.

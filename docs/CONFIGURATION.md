# TOML configuration: v1 schema

**Статус:** M1.2 typed TOML schema + structural validator and atomic file store реализованы в `crates/theia/src/config.rs`. M2.1 `server run` дополнительно читает PEM cert/key и создаёт TLS1.3/H2 listener (только server mode); при отсутствии/ошибке ключа или занятом порту отказывает. Существование/доступность секретов, совпадение TLS сертификата с именем, runtime reload и Windows ACL ещё **не проверяются**. Отсутствие БД — обязательное ограничение.

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
- `management.ipc="auto"`: Linux Unix socket с ограниченными permissions, Windows Named Pipe с ACL. `log_level`: error/warn/info/debug/trace, trace с предупреждением о метаданных.

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
- `tls_profile`: `default` (не имитирует браузер) или конкретный **реализованный и проверенный** именованный browser-like профиль (F-13, P0). Неизвестное имя = ошибка; запрещён тихий fallback на default. Для профиля необходимы воспроизводимые TLS/HTTP2/HTTP3 сравнения и документированные расхождения.
- `transport`: `auto`, `h3`, `h2`. В `h3` не разрешён fallback; `h2` не инициирует UDP. В `auto` fallback только при network-level QUIC failure.
- `quic_connect_timeout_ms`: рекомендуемый 1600, допустимо 500..15000. `quic_negative_cache_ttl_s`: по умолчанию 900, допускается 0 (без кеша) .. 86400.
- Proxy listeners строго loopback по умолчанию; возможность внешнего bind НЕ включать до явной аутентификации локального proxy и отдельной политики безопасности.
- `system_proxy` допускает **только `off` и `manual`**. `off` (default) вообще не трогает OS proxy. `manual` позволяет включить прокси **только отдельным подтверждённым действием в TUI**: запуск `theia client run` или `theia tui` не должен сам менять пользовательские настройки. `on` запрещён в v1. Это не TUN и не перехват всех приложений; на Linux включение выдаёт `UnsupportedPlatform` до реализации адаптера.
- `http_listen`/`socks5_listen` принимают только `127.0.0.1` или `[::1]` с уникальной парой `(IP,port)`; wildcard bind запрещён. P0 local proxy не аутентифицирует соседние локальные процессы: loopback **не означает изоляцию от иных локальных приложений**.
- При доменном HTTP CONNECT/SOCKS5 запросе клиент передаёт DNS hostname как SmartTheia `OPEN_TCP` с `addr_type=0x03`, не резолвит цель локально. Сервер делает DNS resolve, фильтрует **каждый** полученный IP через ACL и dial только закреплённого разрешённого IP. При IP literal DNS не нужен. Системные приложения вне прокси и bypass могут резолвить имена локально: обещать отсутствие любых DNS-утечек нельзя.

## 4. Валидация и запись

- `theia config validate --config ...`: реализована структурная проверка: парсинг UTF-8 TOML v1 (до 1 МиБ), строгие поля, уникальность ID/digest/grants, bind overlap, ссылки `env:`/абсолютные `file:`, loopback listeners, P0 profile guard, диапазоны чисел. **Не читает** env/file secret content и не проверяет сами TLS сертификаты: проверка существования обязательных файлов, canonical base64url и их семантики — отдельный диагностический этап до запуска runtime. Ошибки сообщают поле и причину для semantic validations; syntax/type errors редактированы во избежание утечки конфигурационных значений. Команда выводит причины, избегая вывода секрета.
- TUI редактирует **typed model**, а не строки регулярными выражениями. Перед сохранением double validation. Не перетирать неизвестные поля: в v1 лучше явно отказать при новом ключе и сохранить оригинал.
- Запись: `config::atomic_write` выполняет double validation → create_new temp файл в том же каталоге → write+fsync → rename → fsync каталога на Unix. На Unix создаётся с правами 0600; Windows ACL наследуется от директории. **Вызывающий должен обеспечивать доверенный каталог без вредоносных symlinks;** синхронизация директории на Windows отсутствует. На ошибке до rename прежний конфиг не меняется, но сбой fsync директории *после* rename может означать уже заменённый файл; не обещать rollback после commit-point. Права: server secret file 0600/ACL only intended user; публичный не секретный конфиг не должен перезаписывать секретный файл.
- Reload transaction: прочитать целиком → validate → создать listeners/prepare resources → atomic swap active snapshot, либо rollback. При сбое продолжить работу с прежним snapshot. Новые listeners не должны убить старые до успешного bind.
- Токен при создании пользователя показывать **один раз** и только после подтверждения успешной записи и предупреждения; хранить на сервере только digest. M4.4b1 реализует new-user CSPRNG токен и одноразовый TUI-показ URI, но защищённый файловый экспорт, отзыв и ротация ещё не реализованы. Токен не выводить в crash reports/trace.
- Бэкапы config и snapshot настроек Windows допускаются как TOML-файлы, но не как скрытая БД. Backups с секретами защищать file permissions.

## 4.1. F-14 P0: переносимые приглашения и секреты

- Публичный экспорт по умолчанию содержит только необходимые не-секретные endpoint/SNI/transport/профиль (без TLS private keys, digests и bearer). Конфиденциальная ссылка theia://v1/... с сырым 32-байтным bearer создаётся **только в контексте новой выдачи/ротации** пользователя, после подтверждения и проверки grants; из token_sha256 её восстановить нельзя.
- Ссылка не является URI для HTTP-загрузки; импорт — локальный строго ограниченный base64url + версионированный payload. Ограничить размер, запрещать unknown fields/versions, повторные поля, некорректный host, неверный canonical token и скрытые side effects. Никаких строк URI/токена в CLI argv, shell history, stdout/stderr, tracing, crash diagnostics и обычном TUI.
- Для импорта со встроенным токеном сохранить точные 32 bytes как canonical base64url (43 ASCII-байта без перевода строки) в новый уникальный файл trusted directory с Unix 0600 или Windows per-user ACL. В client.toml сохраняется **только** file:/env: reference; действия сбоя защищают от частичного применения и от перезаписи существующего секрета. Без полного Windows ACL и crash-test не заявлять завершение F-14.
- Ссылка не распределяет доверенные корни CA сама по себе. Перед реальным соединением клиент проверяет серверный TLS/SNI и доверенную CA из локального хранилища. Использование invalid или unauthenticated CA, отключение TLS verification, transport downgrade при auth error запрещены. CA bundle/chain provisioning остаётся отдельным шагом до безопасного импортного соединения.
- Один серверный пользователь с токеном не получает автоматический доступ ко всем inbounds; экспорт выдаётся только при явном allowed_user_ids в выбранной inbound. Не менять system_proxy, активный профиль или runtime при импорте.

## 5. Windows system proxy

Реализация через Windows APIs (WinINet/user Internet Settings), а не `netsh winhttp` как замену пользовательскому прокси: WinHTTP и WinINet — не одно и то же. Настраивать адрес локального HTTP proxy для HTTP и HTTPS, bypass для loopback/intranet при необходимости, уведомлять систему об изменении.

Алгоритм:
1. Прочитать исходные per-user settings; создать защищённый на диске snapshot (для аварийного восстановления).
2. Проверить, что HTTP listener поднят и `system_proxy="manual"`; **только затем** по отдельному подтверждению в TUI применить system proxy. Headless start никогда не включает proxy автоматически.
3. Запомнить applied values; при отключении использовать **CAS (compare-and-swap)**: сравнить текущие настройки с нашим applied snapshot и восстановить исходные **только если настройки по-прежнему наши**. При изменении другим приложением не перетирать, показать конфликт.
4. После crash/restart предложить восстановить snapshot, если текущий proxy всё ещё указывает на Theia. Не молча перезаписывать настройки.
5. Тестировать idempotency, отказ прав, существующие PAC/AutoDetect, пользователя с другим proxy, внезапное завершение; TCP listener shutdown должен сопровождаться процедурой безопасного восстановления. Закрытие одного окна TUI при действующем headless runtime не является отключением proxy; остановка runtime вызывает безопасную попытку восстановления.
6. Snapshot хранится с per-user ACL и версией схемы и включает все исходные поля (PAC/AutoDetect/bypass). Неуспех сохранения snapshot блокирует активацию. После изменения сигнализировать WinINet о смене настроек; не путать per-user WinINet и WinHTTP.

Microsoft references: https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality , https://learn.microsoft.com/en-us/windows/win32/winhttp/setting-wininet-proxy-configurations-in-winhttp

M2.2b: optional `client.profiles[].tls_ca` is an absolute `file:` reference to a trusted PEM CA bundle. Structural validation does not read it; explicit `transport="h2"` runtime requires it, nonempty and valid (up to 1 MiB), verifies TLS name/chain and never falls back to insecure verification. Platform roots loading remains open. `auth_token` is read from env or regular non-symlink file (exactly 43 canonical bytes, no newline; private Unix file permissions, trusted directory; Windows ACL must be provisioned). `auto`/`h3` fail before binding until the actual selector exists. Both loopback ports bind before serving; system proxy is untouched.

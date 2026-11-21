# TOML configuration: v1 schema

**Статус:** нормативный проект схемы. Отсутствие БД — обязательное ограничение. Поля этого документа должны точно совпадать с примерами и реальной `serde`-моделью.

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
- `inbounds[].id` уникален; ID не пустой, regexp `[a-zA-Z0-9_-]{1,64}`. Дубли bind IP+port+transport запрещены. UDP и TCP на одинаковом порту разрешены.
- TLS `server_name` обязательное валидное DNS-имя; сертификат должен ему соответствовать. File refs разрешаются с запретом выхода за разрешённую директорию секрета при необходимости.
- Каждый user ID уникален; `token_sha256` — строго 64 lower-case hex symbols (placeholder не принимается). Уровень защиты зависит от случайности исходного токена: обязателен CSPRNG и 32 bytes.
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
- `auth_token` — `env:NAME` или `file:path` и должен декодироваться в случайные 32 bytes. Рекомендованный формат — base64url **без padding**; зафиксировать test vector и не принимать двусмысленные формы.
- `transport`: `auto`, `h3`, `h2`. В `h3` не разрешён fallback; `h2` не инициирует UDP. В `auto` fallback только при network-level QUIC failure.
- `quic_connect_timeout_ms`: рекомендуемый 1600, допустимо 500..15000. `quic_negative_cache_ttl_s`: по умолчанию 900, допускается 0 (без кеша) .. 86400.
- Proxy listeners строго loopback по умолчанию; возможность внешнего bind НЕ включать до явной аутентификации локального proxy и отдельной политики безопасности.
- `system_proxy`: `off` по умолчанию; `manual` — TUI/CLI действие с подтверждением; `on` — явный opt-in для автоприменения при `client run`. Значение отличается от TUN и не гарантирует перехват всех приложений. На Linux этот режим должен выдавать `UnsupportedPlatform` до реализации OS adapter.

## 4. Валидация и запись

- `theia config validate --config ...`: парсинг, структурные ограничения, конфликты адресов, формат токенов и файловые ссылки; проверка доступности обязательных файлов и secret refs — отдельный диагностический этап. Команда выводит причины, избегая вывода секрета.
- TUI редактирует **typed model**, а не строки регулярными выражениями. Перед сохранением double validation. Не перетирать неизвестные поля: в v1 лучше явно отказать при новом ключе и сохранить оригинал.
- Запись: temp файл в том же каталоге → write+fsync → rename → fsync каталога, где поддерживается. Права: server secret file 0600/ACL only intended user; публичный не секретный конфиг не должен перезаписывать секретный файл.
- Reload transaction: прочитать целиком → validate → создать listeners/prepare resources → atomic swap active snapshot, либо rollback. При сбое продолжить работу с прежним snapshot. Новые listeners не должны убить старые до успешного bind.
- Токен при создании пользователя показывать **один раз**, предоставить secure copy/export с предупреждением; хранить на сервере только digest. Токен не выводить в crash reports/trace.
- Бэкапы config и snapshot настроек Windows допускаются как TOML-файлы, но не как скрытая БД. Backups с секретами защищать file permissions.

## 5. Windows system proxy

Реализация через Windows APIs (WinINet/user Internet Settings), а не `netsh winhttp` как замену пользовательскому прокси: WinHTTP и WinINet — не одно и то же. Настраивать адрес локального HTTP proxy для HTTP и HTTPS, bypass для loopback/intranet при необходимости, уведомлять систему об изменении.

Алгоритм:
1. Прочитать исходные per-user settings; создать защищённый на диске snapshot (для аварийного восстановления).
2. Проверить, что HTTP listener поднят; **только затем** по явному opt-in применить system proxy.
3. Запомнить applied values; при отключении сравнить текущие настройки с нашим applied snapshot. Восстановить исходные **только если настройки по-прежнему наши**. При изменении другим приложением не перетирать, показать конфликт.
4. После crash/restart предложить восстановить snapshot, если текущий proxy всё ещё указывает на Theia. Не молча перезаписывать настройки.
5. Тестировать idempotency, отказ прав, существующие PAC/AutoDetect, пользователя с другим proxy, внезапное завершение; TCP listener shutdown должен сопровождаться процедурой безопасного восстановления.

Microsoft references: https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality , https://learn.microsoft.com/en-us/windows/win32/winhttp/setting-wininet-proxy-configurations-in-winhttp

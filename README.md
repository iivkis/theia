# Theia / Тея

**Specification-first · Rust · one binary · TOML · ratatui · SmartTheia**

**M2.1:** `theia server run --config server.toml` принимает только TLS 1.3 + ALPN `h2` на `server.inbounds[].h2_listen`; сертификат и ключ должны существовать (`file:` absolute path), Unix private key должен быть недоступен группе/прочим. Для реальной работы замените шаблонный digest токена на SHA-256 декодированных 32 случайных байт. Сервер не запускает QUIC/HTTP3. По умолчанию частные/локальные назначения запрещены; тесты используют явный `allow_private_ips=true` на loopback. M2.2 добавляет клиентское H2-ядро и локальные CONNECT/SOCKS5 listeners (pending CI).

**M1.3:** добавлена чистая реализация SmartTheia v1 frame codec + incremental decoder + per-stream FSM в `crates/theia/src/protocol.rs` с golden/negative тестами. Она **не** открывает HTTP/TLS сессии, не проверяет токены и не запускает прокси. TUI и `server/client run` по-прежнему возвращают ошибку вместо фиктивного запуска.

Theia — проект компактной клиент-серверной прокси-платформы. Один исполняемый файл работает в режиме **сервера** (inbound, пользователи, политика подключения) или **клиента** (подключение к inbound, локальный прокси, системный прокси Windows). При запуске TUI показывает два раздела: **«Для сервера»** и **«Для клиента»**.

> **Статус: M2.1 H2 server inbound (частичный вертикальный срез).** Единый бинарник запускает реальный TLS 1.3/HTTP/2 серверный inbound с bearer auth, explicit inbound grants, IP ACL и TCP dial после SmartTheia OPEN_TCP. H3, клиентский CONNECT/SOCKS5, TUI, системный прокси и P0 fingerprint/BBR измерения **не реализованы**. Это не работающий end-to-end пользовательский прокси.

## Архитектура одним взглядом

```text
Windows/Linux client                 Linux server
applications → local HTTP/SOCKS → SmartTheia over HTTP/3 (QUIC + BBR)
                          └────→ SmartTheia over HTTP/2 (TLS fallback)
                                → authenticated inbound → target
                  theia (one Rust executable, two roles)
                  TOML ←→ ratatui TUI, no database
```

На обоих транспортных каналах применяется **один прикладной протокол SmartTheia**. HTTP/3 использует стандартный QUIC+TLS и ALPN `h3`, запасной транспорт HTTP/2 использует TLS и ALPN `h2`. Нестандартный QUIC ALPN или открытый уникальный маркер ухудшает заявленную устойчивость к сигнатурному DPI. Невидимость для DPI **не гарантируется**: это измеряемое свойство, а не маркетинговый пункт.

## Документы для ИИ-агента

| Документ | Назначение |
| --- | --- |
| [AGENTS.md](AGENTS.md) | обязательные правила работы агента и Definition of Done |
| [docs/IMPLEMENTATION_SPEC.md](docs/IMPLEMENTATION_SPEC.md) | продуктовые требования, сценарии, ограничения, критерии приемки |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | границы доменов, процессы, транспортный выбор, компоненты |
| [docs/SMARTTHEIA_PROTOCOL.md](docs/SMARTTHEIA_PROTOCOL.md) | версия 1, сообщения, состояния, авторизация, ошибки |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | схема и безопасное применение TOML |
| [docs/TUI_UX.md](docs/TUI_UX.md) | структура панелей, навигация, UX-инварианты |
| [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) | небольшие вертикальные итерации и критерии завершения |
| [docs/TESTING_CI.md](docs/TESTING_CI.md) | TDD, тестовая матрица, CI, кэш сборок |
| [docs/adr/0004-m0-1-feasibility.md](docs/adr/0004-m0-1-feasibility.md) | результаты M0.1: Rust API spike, подтверждения и открытые блокеры |
| [docs/adr/0005-tls-fingerprint-baseline.md](docs/adr/0005-tls-fingerprint-baseline.md) | измерение default rustls H2/H3, воспроизводимый Go uTLS Chrome133 эталон H2 без browser capture, открытый P0 блокер рабочего H2/H3 backend |
| [docs/SPEC_REVIEW.md](docs/SPEC_REVIEW.md) | критические находки ревью и ограничения патча |
| [examples/server.toml](examples/server.toml) | серверный шаблон |
| [examples/client.toml](examples/client.toml) | клиентский шаблон |

## CLI (M2.1: сервер H2/TLS работает, клиент и TUI отсутствуют)

```sh
theia tui                              # стартовый экран: две панели
theia tui --role server                # серверная панель
theia tui --role client                # клиентская панель
theia server run --config server.toml  # headless сервер
theia client run --config client.toml  # headless клиент
theia config validate --config client.toml
theia --version
```

`theia config validate --config FILE` выполняет структурную проверку TOML v1 и возвращает 0 при успехе, 2 при ошибке. **Проверка не раскрывает секреты и не читает содержимое `env:`/`file:` refs**; сертификаты, bearer и их доступность будут проверены отдельным диагностическим этапом. `tui` пока завершается с кодом 3 (`not implemented`). `client run` поддерживает explicit H2 с `tls_ca`; ошибки startup возвращают 2. `server run` запускает только H2/TLS inbound и требует действующую серверную конфигурацию и PEM файлы; при ошибке выходит с кодом 2. `--help`/`--version` возвращают код 0. Отдельный Rust workspace расположен в `crates/theia/`; `spikes/m0_1/` исключён из production workspace. Все проверки выполняются автоматически в GitHub Actions на PR и push в main; статус `ci-gate` относится к конкретному коммиту. Пользователю и разработчику не нужно запускать тесты вручную.

## Приоритеты

1. **Безопасность и корректность**, затем совместимость.
2. **Тесты до реализации**, сквозные сценарии до настройки «маскировки».
3. **KISS и pragmatic engineering**: не писать собственные реализации TLS/QUIC/HTTP, не вводить БД и веб-панель.
4. **P0-гейты до релиза**: работающий BBR на обоих направлениях QUIC и как минимум один реально настраиваемый, проверенный TLS/HTTP browser-like fingerprint профиль; не выдавать шаблонный User-Agent за uTLS.
5. **Измерять**, а не обещать скорость или невозможность DPI-классификации.

Пример конфигураций содержит заменяемые значения и не предназначен для реального деплоя без создания сертификата и секретов. Лицензия ещё не выбрана; перед распространением добавить `LICENSE`.

**M2.2b (pending CI):** explicit H2 client mode supports loopback CONNECT and SOCKS5, configured `tls_ca` PEM trust bundle and `auth_token` refs. `transport=auto/h3` still fail closed; TUI/OS proxy remain unavailable. All verification occurs in CI; no manual test steps.

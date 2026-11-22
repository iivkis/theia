# Theia / Тея

**Specification-first · Rust · one binary · TOML · ratatui · SmartTheia**

**Состояние M4.1a (после M3.4j):** единый Rust-бинарник поддерживает H2/TLS и H3/QUIC server/client, локальные HTTP CONNECT/SOCKS5 и строгий QUIC-first fallback. BBR включён на обоих QUIC endpoints, но полноценный release benchmark ещё открыт. Добавлен стартовый TUI с двумя панелями только для чтения. Редактирование, IPC, Windows system proxy и полноценный browser-like fingerprint остаются не реализованными.

**M3.4a–M3.4j:** на Linux/Windows проверены реальные TLS/H2 first-flight, Chromium159 SETTINGS/WINDOW_UPDATE/pseudo порядок и опциональный BoringSSL H2. Default rustls и порядок заголовков стандартного h2 пока не соответствуют Chrome. Это измерения и исследовательский feature, **не** готовый именованный browser-like профиль.

Theia — проект компактной клиент-серверной прокси-платформы. Один исполняемый файл работает в режиме **сервера** (inbound, пользователи, политика подключения) или **клиента** (подключение к inbound, локальный прокси, системный прокси Windows). При запуске TUI показывает два раздела: **«Для сервера»** и **«Для клиента»**.

> **Статус: experimental / unreleased.** H2/H3, локальные прокси и базовый read-only TUI реализованы; P0 browser-like fingerprint, конфигурационные формы TUI, Windows system proxy, BBR/performance release gates и полная проверка безопасности ещё не завершены. Это не готовый публичный MVP.

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

## CLI (H2/H3 runtime и read-only TUI)

```sh
theia tui                              # стартовое меню, только чтение
theia tui --role server                # обзор серверной панели, только чтение
theia tui --role client                # обзор клиентской панели, только чтение
theia server run --config server.toml  # headless сервер
theia client run --config client.toml  # headless клиент
theia config validate --config client.toml
theia --version
```

`theia config validate --config FILE` структурно проверяет TOML v1 (exit 0/2) без чтения содержимого секретов. `tui` работает в интерактивном терминале, а без TTY отказывает с exit 2, не меняя окружение. Пока это только навигация и безопасные заглушки статусов, без чтения конфигурации или изменения настроек. `server run` и `client run` поддерживают H2/H3 с аутентификацией, TLS-проверками и TCP relay; `auto` использует QUIC-first с ограниченным H2 fallback исключительно при сетевой UDP-недоступности до аутентификации. Локальные CONNECT/SOCKS5 работают только на loopback, для H2 требуется явно доверенная CA. Автоматические тесты выполняются GitHub Actions на Linux и Windows; ручных smoke нет. Исходный код CLI расположен в `crates/theia/`, исследовательский `spikes/m0_1/` не входит в production workspace.

## Приоритеты

1. **Безопасность и корректность**, затем совместимость.
2. **Тесты до реализации**, сквозные сценарии до настройки «маскировки».
3. **KISS и pragmatic engineering**: не писать собственные реализации TLS/QUIC/HTTP, не вводить БД и веб-панель.
4. **P0-гейты до релиза**: работающий BBR на обоих направлениях QUIC и как минимум один реально настраиваемый, проверенный TLS/HTTP browser-like fingerprint профиль; не выдавать шаблонный User-Agent за uTLS.
5. **Измерять**, а не обещать скорость или невозможность DPI-классификации.

Пример конфигураций содержит заменяемые значения и не предназначен для реального деплоя без создания сертификата и секретов. Лицензия ещё не выбрана; перед распространением добавить `LICENSE`.

**M3.4j (merged):** реальные Chromium159 H2 SETTINGS, WINDOW_UPDATE и HPACK pseudo order измерены и сравнены со стандартным h2 0.4.19 на Linux/Windows. Обычная перестановка заголовков и параметров окна не обеспечивает Chrome-порядок; релизный F-13 остаётся заблокированным. **M4.1a (in review):** read-only TUI без редактирования и управления сервисами.

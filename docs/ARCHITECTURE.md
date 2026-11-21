# Архитектура Theia

## 1. Модель развёртывания

```text
                    CLIENT (theia client run)
   ┌──────────────────────────────────────────────────────┐
   │ browser/app → 127.0.0.1 HTTP CONNECT / SOCKS5       │
   │      → session manager → transport selector         │
   │                           ├── HTTP/3 over QUIC/UDP  │
   │                           └── HTTP/2 over TLS/TCP   │
   └────────────────────────────┬─────────────────────────┘
                                │ SmartTheia v1 frames
   ┌────────────────────────────▼─────────────────────────┐
   │ SERVER (theia server run)                            │
   │ H3 + H2 listeners → auth → policy → TCP dial → target│
   └──────────────────────────────────────────────────────┘

   TUI (theia tui) → TOML store → local management IPC → runtime
            «Для сервера»       «Для клиента»
```

**Не писать свой QUIC/HTTP/TLS.** Приложение владеет только SmartTheia frames, авторизацией, transport negotiation и бизнес-правилами.

## 2. Rust workspace (целевая, не обязательная физическая разбивка)

```text
Cargo.toml
crates/
  theia/               # единый binary: CLI + composition root
  theia-core/          # доменные типы/ошибки, валидация без IO
  theia-config/        # serde/TOML, миграции, atomic store, секреты
  theia-protocol/      # pure encode/decode, protocol FSM, fuzz targets
  theia-transport/     # H3/quinn и H2/hyper adapters, fallback
  theia-server/        # inbound lifecycle, auth, policy, TCP dial
  theia-client/        # profiles, proxy adapters, session manager
  theia-tui/           # ratatui presentation, actions, forms, navigation
  theia-platform/      # Windows proxy + Linux/Windows local IPC
tests/                 # интеграционные тесты
fuzz/                  # необязательный отдельный workspace при необходимости
```

Если разделение увеличивает дублирование и не даёт независимого тестируемого контракта, объединяй соседние crates. **Один распространяемый исполняемый файл** остаётся обязательным.

### Bounded contexts и зависимости

| Контекст | Собственность | Не должен зависеть от |
| --- | --- | --- |
| Configuration | TOML schema, валидация, persist, редактирование | TUI и HTTP/QUIC |
| Protocol | кадры, state machine, лимиты, ошибки wire | Tokio sockets/TUI |
| Transport | защищённые HTTP/3/H2 duplex streams, выбор пути | бизнес-логика экранов |
| Server ingress | inbound/auth/ACL, dialer, квоты, lifecycle | деталей ratatui |
| Client access | SOCKS5/CONNECT, профили, системный proxy interface | конкретных виджетов |
| Presentation | формы, подтверждения, статусы, горячие клавиши | raw TLS sockets |
| Platform | OS proxy / IPC / права файлов | отображения UI |

Интерфейсы (`trait`) вводить там, где действительно есть две реализации (H2/H3, OS proxy, реальный/фейковый dialer). Domain errors — типизированные; перевод в сообщениях UI на внешней границе.

## 3. Контракт между transport и протоколом

Порт `SmartStream` предоставляет асинхронные `read/write/flush/shutdown` с backpressure и отменой. Адаптеры H3 и H2 реализуют его с HTTP-запросом `POST` и потоковыми request/response bodies. Поверх каждого HTTP-stream — один логический TCP dial, так что **дополнительный multiplexing в v1 не нужен**: его уже делает HTTP/2 или HTTP/3. Контрольный HELLO/OPEN и DATA остаются одинаковыми при обеих схемах.

Приёмный HTTP-сервер сначала валидирует путь, метод, TLS, Authorization, затем даёт stream процессору; неизвестные endpoint — обычный отказ HTTP. Исключить логирование Authorization.

## 4. Выбор транспорта и отказоустойчивость

```text
NEW → try H3 (within quic_connect_timeout)
           ├── usable H3 + SmartTheia accepted → ACTIVE_H3
           ├── UDP timeout / ICMP unreachable / no viable H3 handshake
           │          → try H2/TLS → ACTIVE_H2 or ERROR
           └── certificate / auth / protocol / explicit policy error
                      → ERROR (no fallback)
ACTIVE_H3/H2 → stream ends → CLOSED
```

- Запомнить сетевую недоступность QUIC **по endpoint + network context** на ограниченное время (рекомендуемо 15 минут, конфигурируемо); после TTL новой сессии дать ещё шанс H3.
- Не делать fallback из-за ошибки удалённого TCP-dial на сервере; это ошибка destination, а не QUIC.
- TLS hostname validation одинаково строгая в обеих ветках. Никакого insecure toggle в публичном релизе.
- При обрыве живого потока не «продолжать» его на новом транспорте: это не поддерживаемая миграция.
- QUIC congestion controller: настроить BBR, если выбранная версия quinn предоставляет проверенную реализацию. Если нет, блокировать обещание F-11, а не подменять код молчаливым CUBIC.
- Backpressure: bounded channels; ограничение одновременно открытых HTTP-streams и remote dials; timeouts с отменой.

## 5. Хранилище и конфигурация

- Два независимых файла `server.toml` и `client.toml` по умолчанию, явно передаваемые через `--config`; пути ОС — в `docs/CONFIGURATION.md`.
- TUI применяет изменения в два этапа: parse+validate → atomic temp write, fsync, rename → локальный `reload`. При неудачном reload живой runtime остаётся на предыдущем snapshot; UI показывает расхождение.
- Локальный IPC: Unix-domain socket на Linux с правами доступа, Named Pipe под Windows с ACL. Минимальные команды `health`, `status`, `reload`; отсутствие TCP-админки. TUI может редактировать конфиг при выключенном сервисе.
- Runtime snapshots конфигурации иммутабельны, заменяются атомарно после проверки; отказ применения не ломает старые потоки.
- Не считать логи и безопасный файл резервного состояния Windows «базой данных».

## 6. Безопасность и эксплуатация

- Удалённый inbound должен защищаться TLS 1.3 и токеном пользователя, серверной policy с проверкой destination IP **после DNS resolution** (SSRF/rebinding), квотами и rate limit.
- Токен клиента — secure file/env; сервер хранит только SHA-256 high-entropy token. Сравнение в constant time, максимум 256-bit random input, без слабых пользовательских паролей.
- Защита от исчерпания RAM/CPU: жёсткие ограничения фреймов, concurrent connection caps, timeout и предсказуемая обработка EOF/half-close.
- Логи: уровни и агрегированные метрики без целевых URL, payload, токенов по умолчанию; opt-in debug с предупреждением о метаданных.
- Протокольная и transport реализация должны быть тестируемы через fake streams и локальные localhost TLS endpoints без внешних сетевых зависимостей.

## 7. Обоснование выбора технологий

Tokio, serde, toml, thiserror, clap, tracing, ratatui/crossterm, quinn + h3 (H3), hyper/h2 + rustls (H2), socket2 и Windows APIs через `windows` crate — **кандидаты**, а не зафиксированные версии. Перед первым кодом проверить API, безопасность, поддерживаемые платформы и footprint. Документация: https://docs.rs/quinn/ · https://docs.rs/h3/ · https://docs.rs/h2/ · https://ratatui.rs/ · https://www.rfc-editor.org/rfc/rfc9114

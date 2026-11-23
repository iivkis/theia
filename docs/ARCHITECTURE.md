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

### F-14 P0: разные физические узлы, один исполняемый файл

Server UI/CLI запускается на удалённом Linux-хосте (например, через SSH) и управляет только локальными server.toml, ACL, inbound и сервисом через защищённый локальный IPC. Клиентский UI/CLI запускается на локальной Windows/Linux-машине и управляет только client.toml, сохранёнными локально секретами и локальным HTTP/SOCKS5/system proxy. Это **не** удалённая серверная админка и не единый серверный+клиентский процесс. Между узлами передаются данные подключения через явно экспортируемый theia://v1 URI или локальный файл, не control-plane HTTP/RPC. Каждый OS получает свою сборку того же исходного одно-бинарного приложения. См. docs/INVITATIONS.md.

### F-18/F-19 P0: будущие security и traffic-shaping adapters

Целевой REALITY-подобный security adapter должен отдельно аутентифицировать сервер и обеспечивать противодействие unauthorized active probing/replay без самодельного TLS. Внешние H2/TCP и H3/QUIC fingerprints требуют раздельных доказательств, при ошибках не разрешён silent fallback к непроверенному профилю. Отдельный bounded flow-shaping policy смягчает распознаваемость nested TLS, не видит private keys/inner HTTPS данных и не изменяет байтовый TCP-поток. Серверный passive/opt-in authorized evaluator IP/domain относится к отдельному контексту, не сетевой data-plane и не прямой админке: ограничения по DNS/SSRF/таймаутам/частоте, объяснимый score и fresh evidence. Применение в runtime только через проверенный local IPC и без изменения Windows proxy. Текущий binary, TOML v1 и invite v1 этих функций **не поддерживают**. См. docs/STEALTH_REALITY.md и ADR-0020.

### M3.5b1 offline candidate planner (частично реализовано)

В одном `theia` crate добавлен `camouflage_discovery`: чистая доменная модель `ServerSnapshot`, `NetworkPrefix`, `DiscoveryPlan` и `TlsEvidence`, с каталогом 14 популярных HTTPS-доменов. BGP/RDAP префикс это *контекст*, не право на probe. Из введённых извне публичных адресов и отдельно оператором одобренных CIDR формируется строго ограниченный до 256, дедуплицированный план. Широкие IPv4 сети, IPv6 /64, адреса без public interface и NAT-неопределённость не превращаются в автоматическое сканирование. Оценка пригодности — отдельная чистая функция для будущих реально полученных TLS evidence; неизвестные факты не засчитываются. Нет OS route/interface collector, DNS/CT, TLS probe, валидации чужих SSL сертификатов, сети/IPC/TUI и включения security mode. **F-18 всё ещё P0 открыт**. ADR-0022.

### M3.5b2a route-only source IP и pinned verified H2 TLS (ограниченный API)

Чистый `camouflage_discovery` не делает сеть, но рядом в одном crate появился `camouflage_probe` с **одной** явной точкой I/O: UDP `connect` для выяснения выбранного локального route source IP без пакетов и **один** pinned-IP TCP/TLS1.3 handshake с ALPN h2 после согласованного scope. Отдельное разрешение `PublicHttpsIp` действует только для указанного IP и TCP 443; test-loopback variant только для конкретного сокета. Все соединения TLS проверяют реальную chain/hostname/SAN/time, no insecure verifier; timeout ≤5s и global semaphore=4. Не отправляет HTTP запрос, не определяет сертификаты третьих лиц как пригодные к установке на сервер Theia и не строит bulk scanner. Реальные OS prefix/NAT collector, разрешение внешних доменов, rate-limited scheduler, H3, согласие в TUI и применение в runtime **не реализованы**. ADR-0023.

## 3. Контракт между transport и протоколом

Порт `SmartStream` предоставляет асинхронные `read/write/flush/shutdown` с backpressure и отменой. Адаптеры H3 и H2 реализуют его с HTTP-запросом `POST` и потоковыми request/response bodies. Поверх каждого HTTP-stream — один логический TCP dial, так что **дополнительный multiplexing в v1 не нужен**: его уже делает HTTP/2 или HTTP/3. Контрольный HELLO/OPEN и DATA остаются одинаковыми при обеих схемах. **H2/H3 full-duplex обязателен**: сервер может отправить HTTP 200 и `HELLO_ACK` при открытом request body, клиент продолжает писать DATA при чтении response DATA. До `OPEN_OK` локальный HTTP CONNECT/SOCKS5 не отвечает успехом. Запретить адаптер, буферизующий request body целиком.

Приёмный HTTP-сервер сначала валидирует путь, метод, TLS, Authorization, **назначение пользователя конкретному inbound по listener**, затем даёт stream процессору; неизвестные endpoint — обычный отказ HTTP. Глобальная запись пользователя не даёт доступ к другим inbound. Host/`:authority` не переопределяет авторизуемый inbound. Исключить логирование Authorization.

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
- QUIC congestion controller: BBR — **P0 release gate**. Выбранный QUIC backend должен реально поддерживать BBR и на client send, и на server send. Проверить установленную реализацию и тесты под loss/jitter, не подменять молча CUBIC. До реализации/замеров продукт не заявляется готовым.
- Backpressure: bounded channels; ограничение одновременно открытых HTTP-streams и remote dials; timeouts с отменой.

## 5. Хранилище и конфигурация

- Два независимых файла `server.toml` и `client.toml` по умолчанию, явно передаваемые через `--config`; пути ОС — в `docs/CONFIGURATION.md`.
- TUI применяет изменения в два этапа: parse+validate → atomic temp write, fsync, rename → локальный `reload`. При неудачном reload живой runtime остаётся на предыдущем snapshot; UI показывает расхождение.
- Локальный IPC: **M4.2a частично реализован** как *read-only* Linux Unix socket `theia-server.sock` под euid-owned 0700 `THEIA_CONTROL_DIR`, socket 0600, `health/status` и явный отказ `reload`, без TCP-админки ([ADR-0038](adr/0038-m4-2a-linux-readonly-management-ipc.md)). Важный контракт будущего M4.2: Windows Named Pipe с ACL, корректные runtime revision/health counters, транзакционный reload и rollback, интеграция TUI. Не считать сохранённый TOML применённым только потому, что local status сообщает running.
- **M4.2b1a:** оба server listener transports H2/H3 используют общий in-process `LiveAuthorization` с одним `Arc<AuthSnapshot>`/revision и кратким RwLock только для чтения/публикации. Staged update с полным compatible-document check, CAS revision и проверкой привязки stage к серверу не затрагивает существующие stream permits и общие quotas. **Внешний IPC Apply не подключён и остаётся запрещён** ([ADR-0040](adr/0040-m4-2b1a-shared-cas-auth-snapshot.md)).
- **M4.2b0:** подготовка к reload ограничена read-only `server reload --check` через Linux private Unix socket: сравнение strict typed candidate TOML с *запущенным* документом и SHA-256 PEM bytes, использованных listener'ами, с отклонением restart-only изменений. Возвращает только `compatible`/ошибку, **не** применяет изменения и не резервирует candidate от последующей подмены ([ADR-0039](adr/0039-m4-2b0-readonly-reload-preflight.md)).
- Runtime snapshots конфигурации иммутабельны, заменяются атомарно после проверки; отказ применения не ломает старые потоки. **Это ещё проектное требование M4.2b1+, не поведение M4.2b0**.
- Не считать логи и безопасный файл резервного состояния Windows «базой данных».

## 6. Безопасность и эксплуатация

- Удалённый inbound должен защищаться TLS 1.3, **inbound-scoped** пользовательским токеном и policy с проверкой destination IP **после DNS resolution** (SSRF/rebinding), квотами и rate limit. При доменном CONNECT/SOCKS5 клиент не вызывает локальный resolver; передаёт имя серверу, который dial закреплённого IP после ACL. Для E2E на loopback нужен отдельный тестовый allow-private fixture.
- Токен клиента — secure file/env; сервер хранит только SHA-256 high-entropy token. Сравнение в constant time, максимум 256-bit random input, без слабых пользовательских паролей.
- Защита от исчерпания RAM/CPU: жёсткие ограничения фреймов, concurrent connection caps, timeout и предсказуемая обработка EOF/half-close.
- Логи: уровни и агрегированные метрики без целевых URL, payload, токенов по умолчанию; opt-in debug с предупреждением о метаданных.
- Протокольная и transport реализация должны быть тестируемы через fake streams и локальные localhost TLS endpoints без внешних сетевых зависимостей.
- Клиентский `local_proxy_listening` не равен `transport_authenticated` и не равен `tunnel_open`; отображать статусы отдельно. `theia client run` сам не включает системный proxy: Windows изменение возможно только после подтверждённого TUI-действия в режиме `manual` и с безопасным snapshot/restore.
- Browser-like TLS/HTTP fingerprint профиль P0 требует отдельного benchmark/capture gate; до выбора TLS backend проверить реализуемость профилей вместе с h3/h2 и quinn. Нельзя тайно менять security settings ради «похожести».

## 7. Обоснование выбора технологий

Tokio, serde, toml, thiserror, clap, tracing, ratatui/crossterm, quinn + h3 (H3), hyper/h2 + rustls (H2), socket2 и Windows APIs через `windows` crate — **кандидаты**, а не зафиксированные версии. Перед первым кодом проверить API, безопасность, поддерживаемые платформы и footprint. Документация: https://docs.rs/quinn/ · https://docs.rs/h3/ · https://docs.rs/h2/ · https://ratatui.rs/ · https://www.rfc-editor.org/rfc/rfc9114

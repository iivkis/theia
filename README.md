# Theia / Тея

**Specification-first · Rust · one binary · TOML · ratatui · SmartTheia**

**Состояние M4.4b1 (после M4.4a):** единый Rust-бинарник поддерживает H2/TLS и H3/QUIC server/client, локальные HTTP CONNECT/SOCKS5 и строгий QUIC-first fallback. BBR включён на обоих QUIC endpoints, но полноценный release benchmark ещё открыт. Добавлен стартовый TUI и ограниченный редактор явно выбранного TOML: по три безопасных поля выбранного inbound/профиля, валидация, несохранённые изменения и атомарная запись. F-14 P0: добавляется чистый версионированный codec переносимого приглашения и строгая проверка его соответствия grants/token digest; **создание нового пользователя с CSPRNG-токеном, grant и однократным показом ссылки после сохранения добавлено в серверную TUI; безопасный файл экспорта, ротация и импорт в client.toml ещё не реализованы**. Полное CRUD пользователей и inbound, ротация/отзыв, защищённый экспорт/импорт, IPC, Windows system proxy и browser-like fingerprint остаются не реализованными.

**F-18/F-19 (спецификация 0.3, ещё не реализовано):** новый REALITY-подобный защищённый SmartTheia режим и мастер подбора IP/domain в два основных действия, а также самостоятельная измеряемая защита от TLS-in-TLS. Поиск автоматически охватывает подтверждённый диапазон сервера и встроенный каталог популярных HTTPS-доменов (google.com, samsung.com, amd.com и др.); активные проверки чужих/неподтверждённых диапазонов без разрешения запрещены, score не является гарантией обхода DPI. Старые TOML v1/theia://v1 не поддерживают новые режимы. [Нормативные требования](docs/STEALTH_REALITY.md).

**M3.5b2b0 (ограничение offline CIDR-плана, PR #49):** даже при явно переданном approval соседние IPv4 не попадают в очередь, если CIDR шире наблюдаемого префикса интерфейса; неизвестная `/0` и некорректная маска также не разрешают расширение. Это дополнительная защита, **не** подтверждение владения диапазоном; отдельно маршрутизируемые блоки при интерфейсе `/32` потребуют будущей проверки внешнего права/источника. Нет новых сетевых вызовов и сканера. [ADR-0024](docs/adr/0024-m3-5b2b-assigned-cidr-guard.md).

**M4.5a (серверная TUI: пассивный просмотр IP и подтверждение ipify):** в разделе «Для сервера» клавиша **p** показывает локальные Linux IP/префиксы и офлайн-план 14 доменов без DNS, сети, изменения TOML или proxy. Клавиша **i** показывает отдельное предупреждение о раскрытии исходящего IP оператору **`https://api64.ipify.org/`**, **y** запускает один проверяемый DNS/TLS1.3 запрос в отменяемом фоне, **n/Esc** отказывает/закрывает без побочных эффектов. На Windows локальный OS collector ещё Unsupported, но ipify может быть доступен после согласия и загрузки системных CA. UI честно различает неизвестное/совпадающее/отличающееся исходящее IP; **не** доказывает NAT/ownership и не активирует сетевой scanner, REALITY или конфигурационный apply. [ADR-0029](docs/adr/0029-m4-5a-consented-ip-discovery-panel.md).

**M3.5b2b4 (стандартный сервис публичного IP, opt-in):** по умолчанию выбран официальный двухстековый HTTPS API **[api64.ipify.org](https://api64.ipify.org/)** (именно `.org`, не `.com`); обычный `GET /` возвращает текстовый IPv4 **или** IPv6, в зависимости от маршрута. `camouflage_egress::observe_default_ipify(roots, IpifyConsent::Approved)` сначала требует явного разрешения, только затем разрешает DNS для фиксированного домена, выбирает один публичный IP:443, закрепляет TCP-адрес и проверяет TLS1.3/SAN/CA/ALPN + ограниченный ответ в общем deadline 5s. `Denied` по умолчанию не отправляет даже DNS. Это пока **библиотечная опция**, не автообращение из TUI/CLI; подключение раскрывает внешний IP сервису и не доказывает владение CIDR или NAT. [ADR-0028](docs/adr/0028-m3-5b2b4-default-ipify.md).

**M3.5b2b3 (exact-consent TLS/H2 batch, library-only):** добавлен ограниченный одновременный запуск проверок **до 8 вручную выбранных IP** с отдельным точным approval на каждый публичный IP:443, привязкой к offline-плану, запретом duplicate/неразрешённых целей до сетевого подключения и сохранением отдельных ошибок/фактов TLS1.3/h2. Один провал не выдаёт всю группу за успешную. Внутренний лимит 20s, у каждого probe собственный ≤5s и общий concurrency=4. **Нет** автоматического сканирования CIDR, популярных доменов, DNS, внешних CI endpoint, TUI/CLI команды, доказательства ownership, REALITY, H3 scan или fingerprint readiness. [ADR-0027](docs/adr/0027-m3-5b2b3-explicit-batch.md).

**M3.5b2b2 (opt-in HTTPS egress witness + offline preview, library-only):** добавлен реальный строго проверяемый TLS1.3/HTTP1.1 запрос к **одному явно разрешённому, закреплённому публичному IP:443** с переданными оператором CA/SNI, ограничениями времени/памяти/параллелизма и отказом от redirect/непубличного ответа. Публичный egress-IP является **утверждением удалённого наблюдателя**, а не доказательством владения CIDR или NAT. Linux-интерфейсы, этот результат и явный approved CIDR объединяются только в offline preview с default `PassiveOnly`; Windows native collector ещё Unsupported, но безопасный egress API и preview-тесты работают на обеих ОС. **Нет** автоматического внешнего IP-сервиса, TUI consent, active scanner, REALITY или TLS-in-TLS. [ADR-0026](docs/adr/0026-m3-5b2b2-consented-egress-preview.md).

**M3.5b2b1 (Linux native collector, library-only):** через getifaddrs читаются реальные UP интерфейсы и непрерывные IPv4/IPv6 маски без отправки сетевых пакетов, проверки external egress и предположений о CIDR ownership; нет автоматического approval или сканирования. На Windows вызов явно возвращает Unsupported (общие типы и mask tests доступны на обеих платформах). [ADR-0025](docs/adr/0025-m3-5b2b1-linux-interface-collector.md).

**M3.5b2a (experimental library API, не полноценный scanner):** добавлена реальная проверка TLS1.3/h2 к явно разрешённому закреплённому IP с обычной strict CA/SNI/SAN проверкой, лимитом 4 handshakes и временем ≤5s. Проверка локального route source IP не отправляет UDP-пакетов и не предполагает ownership CIDR. Тесты используют только loopback. Публичный доменный каталог ещё не сканируется, нет автоматического OS/CIDR collector или TUI, нет поддержки REALITY/H3/TLS-in-TLS. [ADR-0023](docs/adr/0023-m3-5b2a-explicit-tls-probe.md).

**M3.5b1 (offline planner, готово как изолированный модуль, но не scanner):** в коде есть 14 встроенных популярных доменов, контролируемое планирование явно разрешённых IPv4-подсетей и отдельная H2/H3 эвристика оценки *предоставленных* наблюдений. Ни реальных TLS-probe, ни OS collector, ни двухшагового TUI пока нет. Этот срез не означает выполнение F-18. [ADR-0022](docs/adr/0022-m3-5b1-offline-discovery-and-evidence.md).

**M3.5a0 (исследовательский CI-срез):** добавлены тесты безопасного TLS exporter channel binding на реальных H2/TCP и H3/QUIC локальных соединениях с неверной CA и явным отказом нереализованным security flags в TOML/invite v1. Это НЕ REALITY-подобная реализация, не анти-DPI защита и не TLS-in-TLS mitigation. [ADR-0021](docs/adr/0021-m3-5a-rustls-quic-auth-feasibility.md).

**M3.4a–M3.4j:** на Linux/Windows проверены реальные TLS/H2 first-flight, Chromium159 SETTINGS/WINDOW_UPDATE/pseudo порядок и опциональный BoringSSL H2. Default rustls и порядок заголовков стандартного h2 пока не соответствуют Chrome. Это измерения и исследовательский feature, **не** готовый именованный browser-like профиль.

Theia — проект компактной клиент-серверной прокси-платформы. Серверная панель рассчитана на запуск на удалённом Linux-сервере (например, через SSH), а клиентская — на локальный Windows/Linux-клиент, подобно роли управления inbound в 3x-ui и импорта профилей в v2rayN/NekoBox; **это не wire-совместимость**. Оба режима входят в бинарник, собранный под нужную ОС. Один исполняемый файл работает в режиме **сервера** (inbound, пользователи, политика подключения) или **клиента** (подключение к inbound, локальный прокси, системный прокси Windows). При запуске TUI показывает два раздела: **«Для сервера»** и **«Для клиента»**.

> **Статус: experimental / unreleased.** H2/H3, локальные прокси и базовый TUI с ограниченным редактированием TOML реализованы; P0 browser-like fingerprint, конфигурационные формы TUI, Windows system proxy, BBR/performance release gates и полная проверка безопасности ещё не завершены. Это не готовый публичный MVP.

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
| [docs/STEALTH_REALITY.md](docs/STEALTH_REALITY.md) | F-18/F-19: REALITY-подобный mode, ограниченный подбор IP/domain, anti-TLS-in-TLS и измеряемые релизные критерии |
| [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) | небольшие вертикальные итерации и критерии завершения |
| [docs/TESTING_CI.md](docs/TESTING_CI.md) | TDD, тестовая матрица, CI, кэш сборок |
| [docs/adr/0004-m0-1-feasibility.md](docs/adr/0004-m0-1-feasibility.md) | результаты M0.1: Rust API spike, подтверждения и открытые блокеры |
| [docs/adr/0005-tls-fingerprint-baseline.md](docs/adr/0005-tls-fingerprint-baseline.md) | измерение default rustls H2/H3, воспроизводимый Go uTLS Chrome133 эталон H2 без browser capture, открытый P0 блокер рабочего H2/H3 backend |
| [docs/SPEC_REVIEW.md](docs/SPEC_REVIEW.md) | критические находки ревью и ограничения патча |
| [examples/server.toml](examples/server.toml) | серверный шаблон |
| [examples/client.toml](examples/client.toml) | клиентский шаблон |

## CLI (H2/H3 runtime и ограниченный TUI editor)

```sh
theia tui                              # стартовое меню, только чтение
theia tui --role server                # обзор серверной панели, только чтение
theia tui --role client                # обзор клиентской панели, только чтение
theia tui --role server --config /path/to/server.toml  # поля DNS имени/H2 TCP/H3 UDP у выбранного inbound
theia tui --role client --config /path/to/client.toml  # endpoint/TLS SNI/transport выбранного профиля
theia server run --config server.toml  # headless сервер
theia client run --config client.toml  # headless клиент
theia config validate --config client.toml
theia --version
```

`theia config validate --config FILE` структурно проверяет TOML v1 (exit 0/2) без чтения содержимого секретов. `tui` работает в интерактивном терминале, а без TTY отказывает с exit 2, не меняя окружение. Без `--config` это только навигация. С `--role` и `--config` можно выбирать существующий inbound/профиль (↑/↓, j/k), переключать три поля (Tab/Shift+Tab), проверить черновик и сохранить TOML (без reload и запуска службы); при внешнем изменении файла запись блокируется. `server run` и `client run` поддерживают H2/H3 с аутентификацией, TLS-проверками и TCP relay; `auto` использует QUIC-first с ограниченным H2 fallback исключительно при сетевой UDP-недоступности до аутентификации. Локальные CONNECT/SOCKS5 работают только на loopback, для H2 требуется явно доверенная CA. Автоматические тесты выполняются GitHub Actions на Linux и Windows; ручных smoke нет. Исходный код CLI расположен в `crates/theia/`, исследовательский `spikes/m0_1/` не входит в production workspace.

## Приоритеты

1. **Безопасность и корректность**, затем совместимость.
2. **Тесты до реализации**, сквозные сценарии до настройки «маскировки».
3. **KISS и pragmatic engineering**: не писать собственные реализации TLS/QUIC/HTTP, не вводить БД и веб-панель.
4. **P0-гейты до релиза**: F-18 REALITY-подобный mode/подбор IP, F-19 measured TLS-in-TLS mitigation, работающий BBR на обоих направлениях QUIC и как минимум один реально настраиваемый, проверенный TLS/HTTP browser-like fingerprint профиль; не выдавать шаблонный User-Agent за uTLS.
5. **Измерять**, а не обещать скорость или невозможность DPI-классификации.

Пример конфигураций содержит заменяемые значения и не предназначен для реального деплоя без создания сертификата и секретов. Лицензия ещё не выбрана; перед распространением добавить `LICENSE`.

**M3.4j (merged):** реальные Chromium159 H2 SETTINGS, WINDOW_UPDATE и HPACK pseudo order измерены и сравнены со стандартным h2 0.4.19 на Linux/Windows. Обычная перестановка заголовков и параметров окна не обеспечивает Chrome-порядок; релизный F-13 остаётся заблокированным. **M4.1a (merged):** read-only TUI. **M4.1b (merged):** typed TOML editor с dirty, validation, save/discard/stay. **M4.1c (merged):** выбор существующих inbound/profiles и редактирование трёх безопасных полей на запись; без создания/удаления, применения к runtime и управления системным прокси.

**P0 F-14 / M4.4a (in review):** переносимое подключение theia://v1/... теперь является обязательным релизным требованием. Библиотечный codec проверяет версию, каноничность, 32-byte token, user grants и digest без раскрытия secrets по умолчанию; экспорт/импорт через UI, ротация и secure persistence пока НЕ реализованы. См. [docs/INVITATIONS.md](docs/INVITATIONS.md). Нельзя вставлять URI с токеном в командную строку или публичные логи.

**M4.4b1 (PR #43):** в явной серверной TUI после выбора inbound клавиша `u` вводит ID нового пользователя, подтверждение `y` создаёт случайный 256-битный bearer, SHA-256 digest и доступ только к выбранному inbound. После успешной атомарной записи server.toml второе `y` однократно показывает конфиденциальную ссылку, `Esc` стирает её из TUI. Сохранение не перезагружает службу. Безопасный файл экспорта, буфер обмена, QR, ротация, клиентский импорт и проверка соединения ещё не реализованы.

# ADR-0039: M4.2b0 — только проверка совместимости reload (без Apply)

**Дата:** 2026-11-23. **Статус:** предложено, до успешного CI exact-head.

## Контекст

M4.2a предоставляет настоящие локальные Linux Unix-socket `health/status`, но текущие H2/H3 listener'ы захватывают `Arc<ServerContext>`. Ротация токена или отзыв grant путём замены `server.toml` без атомарной публикации *единого* контекста для обоих транспортов привели бы к несовместимому runtime. Поскольку проверяемого rollback пока нет, нельзя включать `reload` и выдавать статус работы сокета за подтверждение применения новой конфигурации.

## Решение

В M4.2b0 добавлена **только явно вызываемая проверка** `theia server reload --check`. В Linux при активном сервере, запущенном `theia server run --config FILE`, и отдельном `THEIA_CONTROL_DIR` (0700/euid), management Unix socket (0600) принимает единственную строку `check-reload\n` (лимиты M4.2a: 64 байта, 2с, 8 клиентов). Сервер читает сохранённый `FILE` как полноценный строго валидированный TOML v1 <=1 МиБ, но не пишет его и не перезапускает listener. Текущий running документ зафиксирован при запуске, а не повторно прочитан из TOML.

Совместимость **сильно ограничена**. Разрешается лишь потенциальный будущий diff по `server.users[*].token_sha256/disabled` и `server.inbounds[*].allowed_user_ids` для **тех же** user/inbound ID в **том же порядке**. Любые изменения `enabled`, TCP/H2 и UDP/H3 binds, SNI, путей certificate/key, полей management/ui, policy (включая квоты, private IP ACL), размера/порядка каталога пользователей или inbound'ов отклоняются как требующие полноценного безопасного рестарта. Перед сравнением новая конфигурация проходит весь текущий `config::validate`.

Самих путей TLS недостаточно. На старте H2/H3 сервер сохраняет **только SHA-256 отпечатки фактически считанных PEM bytes**, с которыми построены TLS acceptor и QUIC endpoint. Preflight повторно проверяет *те же реальные файлы* (в том числе права private key, regular-file/no-symlink и лимит <=1 МиБ из существующей серверной функции) и отвергает любое расхождение содержимого или ошибку чтения. Это не раскрывает сертификат или ключ в IPC, и не отменяет проверок PKI. Дайджесты не выводятся наружу.

Проверка выполняет ограниченное файловое IO в `spawn_blocking`, результат не может изменить runtime даже если клиент не дождётся ответа. Ответ: `theia-check-v1 compatible\n` либо `theia-check-v1 rejected\n`, строго проверяется клиентом. CLI сообщает `candidate compatible with running listener; runtime UNCHANGED` только при первом ответе, при отказе возвращает nonzero. На сервере без active file (например, чистый `server::run_document`) возвращается unsupported. `reload\n` остаётся unsupported. На Windows status/check IPC по-прежнему Unsupported до ACL Named Pipe.

## Границы и риски

- **Compatible не означает Reload/Applied.** Рабочие TLS/H2/H3 listeners, auth/grants, активные потоки, quotas и метрики не меняются; никакого пересоздания/закрытия, system proxy или REALITY security mode.
- Это разовый предварительный просмотр. Внешний процесс может заменить TOML или PEM **после** проверки; результат не является ни резервированием версии файла, ни разрешением будущего применения. Настоящий `Apply` должен повторно прочитать и проверить точные candidate bytes при транзакции, подготовить все ресурсы, сделать атомарную публикацию единого snapshot с CAS-revision и гарантированным сохранением старых сеансов, иметь корректный rollback на failure.
- Same-UID процесс может подделать Unix socket без независимой криптографической аттестации, и у папки должен быть доверенный владелец/путь; M4.2a уже документирует ограничения.
- Не реализованы Windows Named Pipe/DACL, TUI status+Apply, live swap, revision/rollback, ротация сертификата и listener binds, F-18 REALITY/F-19 TLS-in-TLS.

## CI, Given/When/Then

- Given running server + unchanged candidate, when `server reload --check`, then successful typed compatible reply and explicit **runtime UNCHANGED**; `reload` по-прежнему unsupported.
- Given structurally valid auth digest/disabled/grants-only difference, when check, then candidate compatible, **без применения**.
- Given changed bind/SNI/TLS ref/policy/inbound registry/user registry or invalid grants, when check, then refused nonzero, running server still responds to status.
- Given same-path PEM bytes replaced (cert **или** key), when check, then identity drift rejects.
- Native Linux real compiled server starts on isolated loopback TCP/H2 + UDP/H3, local management Unix socket, running CLI check, invalid candidate and server survival. Pure unit tests for structural and PEM-content mismatch run on Linux/Windows; no public Internet/DNS, OS proxy changes, or active TUI probing. Full locked test/fmt/clippy (warnings denied), Windows smoke, browser E2E, BoringSSL, BBR and final exact-head CI gate required.

## Следующий M4.2b1

Динамический `ServerContext` для **обоих** H2 и H3, auth updates на новых потоках с предсказуемыми семантиками ревокации, общее согласованное состояние квот, настоящие staged prepare/atomic swap с revision/CAS, timeout/cancel-safe commit, rollback и E2E смены credential без разрыва уже работающих туннелей. Затем возможна подтверждаемая TUI Apply.

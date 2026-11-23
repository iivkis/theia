# ADR-0042: M4.2c — подтверждаемый Linux TUI Apply, привязанный к байтам TOML

**Дата:** 2026-11-23. **Статус:** предложено, PR #67.

## Проблема

ADR-0041 позволил Linux CLI применять auth-only изменения к живому H2/H3 серверу по ожидаемой CAS-ревизии. Серверная TUI (M4.1c/M4.4b) умела сохранять отдельный TOML, но не могла запросить живую ревизию и отличить **именно этот** сохранённый файл от другого `server.toml`, с которого запущен экземпляр. Кнопка Apply, которая вызвала бы старую unscoped IPC-команду, могла бы опубликовать неподтверждённый оператором файл.

## Решение

- В явно выбранной серверной панели `v` открывает **read-only** статус через существующий частный Linux Unix socket `THEIA_CONTROL_DIR`; `Ctrl+R` запускает просмотр авторизации только при загруженном `--role server --config FILE` и чистом сохранённом документе (нет несохранённого draft). Ввод поля, клиентская роль, отсутствие private IPC, legacy socket без revision и отмена просмотра **не** могут подать Apply.
- Панель неблокирующая: отдельный worker запускает bounded `management::query_in(Status)`; только типизированный `RunningRevision { inbounds, revision }` открывает окно подтверждения. Оператор видит текущую revision, ограничения auth-only, сохранение старых туннелей, необходимость `y` для фактической публикации. Клавиши `n/Esc` отменяют до отправки.
- Редактор фиксирует SHA-256 **точных байтов** последней загруженной или атомарно сохранённой TOML версии. Новое типизированное IPC-сообщение `apply-reload rev=N sha256=64lowerhex\n` (максимум 128 байт) отправляется **только после `y`**. Не содержит bearer token, приватный ключ, путь к файлу, хэш токена пользователя или другие секреты. Старое CLI `apply-reload rev=N\n` остаётся доступно для явных headless-операторов; `check-reload\n` всё ещё только чтение.
- Сервер в `spawn_blocking` читает свой `server.toml` **один раз, не более 1 МиБ** (Zeroizing buffer), сравнивает SHA-256 с ожидаемым снимком TUI, строго разбирает TOML, затем выполняет прежние проверки совместимости, реальных TLS PEM bytes и неизменности restart-only полей. Если байты расходятся (в том числе из-за внешней записи или другого файла), `rejected` означает **без публикации**. Совпадение SHA доказывает идентичность содержимого, **не пути/inode**: два разных файла с идентичными байтами допустимы, поскольку публикация соответствует точно подтверждённому документу. TOCTOU-изменения после прочитанного снимка не меняют уже проверенную и опубликованную версию.
- Лишь живая async-задача management после работы read-only worker вызывает `LiveAuthorization::stage` + `publish` с CAS. Подсистема H2/H3 использует общий снимок (ADR-0040); квоты и текущие туннели остаются. После отправленного Apply Esc/q в TUI игнорируются до результата; при потере ответа/отказе сокета результат **indeterminate**, UI запрещает автоматический повтор и предлагает независимый `r` запрос revision. Наличие server receipt `Applied { revision }` единственный положительный статус; `CandidateRejected` показывается как отказ без применения.
- Новый формат команды имеет лимит 128 байт вместо прежних 64; ответ остаётся 128, конкурентных клиентов не больше 8, общий IPC дедлайн 2 секунды, Linux private 0700/0600 unchanged. Без admin TCP. Windows `query_environment` по-прежнему `Unsupported` до Named Pipe + DACL.
- TUI не пытается применять параметры listener, TLS, SNI, quotas, добавление/удаление пользователей и inbound; пользователь может сохранить такие изменения в TOML, но backend отклоняет их для hot Apply. **Save != Apply** остаётся инвариантом.

## CI и пределы

- Unit TUI tests: dirty draft/field editing/client role do not start Apply, status-only and legacy socket cannot commit, only typed revision and additional `y` begin Apply, `n/Esc` cancels, timeout/disconnected response is not falsely reported as rollback, rejection never prints Applied. Bounded private real Unix socket test observes `status\n` then only **после y** exactly `apply-reload rev=8 sha256=<expected>\n`, and typed applied receipt.
- Existing compiled Linux server test uses real H2/TLS+H3/QUIC, wrong digest refused without revision change, correct digest commits the same user-token rotation for both, preserves old streams, stale CAS and PEM drift rejected; second CLI Apply still works. Malformed digest/revision parser tests, fmt, clippy -D warnings and full Linux/Windows exact-head ci-gate must be green.
- **Нет** настоящего Windows Named Pipe/DACL, Windows TUI Apply, автоматического запуска/остановки сервера, hard revoke уже работающих туннелей, TUI-редактирования bearer digest и новых пользователей с hot Add, TLS/listener restart, PTY/SSH end-to-end automation, production security audit, и доказательства P0 F-18/F-19/uTLS-like stealth. Текущий terminal loop тестируется через UI state/render and IPC integration, не как full PTY automation.
- Если финальный терминал завершится после подтверждения и отправки Apply, исход может быть неизвестен пользователю, хотя сервер реально опубликовал revision. Верный recovery: проверить статус, **не** отправлять повторный Apply наугад.

## Дальше

M4.2d: Windows Named Pipe с ACL, привязкой к OS user identity, эквивалентным проверяемым CAS Apply и native Windows CI E2E, затем UX/консистентность и PTY/SSH smoke. Смена listener/TLS требует отдельного restart wizard с rollback, не скрытой кнопки.

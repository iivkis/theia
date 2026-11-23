# ADR-0040: M4.2b1a — единый CAS-снимок авторизации для H2/H3 (без Apply)

**Дата:** 2026-11-23. **Статус:** предложено, проверка exact-head CI в PR #65.

## Контекст

Реализация ADR-0039 допускает лишь `reload --check`. Но `ServerContext` держал отдельные `Vec<User>` и inbound grants в каждом H2/H3 listener, так что атомарное применение отзыва пользователя во всех transport/inbound невозможно. При этом соединения H2/H3 держат свои `Arc<ServerContext>`, а общие per-user/global/connection semaphores являются критическими ограничителями ресурсов: их пересоздание после обновления открыло бы обход quotas уже активными сессиями.

## Решение (минимальный самостоятельный срез)

- `LiveAuthorization` хранит неизменяемый baseline `ServerDocument` и единственный `AuthCell` (короткий `std::sync::RwLock<Arc<AuthSnapshot>>`) на **все** H2/H3 inbound contexts, подготовленные из одного runtime документа.
- `AuthSnapshot` включает `revision: u64`, полный каталог `User` с **только SHA-256 токен-дайджестами** и карту `inbound_id → allowed_user_ids`. `ServerContext::authorize` после синтаксической проверки bearer берёт один `Arc` через read-lock, отпускает lock **до** проверки токена по configured digests, ACL, auth quota или I/O. Ни один запрос не смешивает несовместимые версии users/grants. Непрерывные сессии сохраняют прежние `SessionPermit` и релеи: обновление affects **только новые авторизации**.
- `LiveAuthorization::stage(&candidate, expected_revision)` выполняет общую строгую полную валидацию и **тот же** `assess_reload` из ADR-0039: разрешены только `token_sha256`, `disabled`, `allowed_user_ids` у прежних пользователей и inbounds (в прежнем порядке). Создаёт move-only `StagedAuthorization` с ожидаемой ревизией и привязкой к конкретному `AuthCell`. **Stage, в том числе его Drop, не меняет runtime**.
- `publish(staged)`: проверяет, что stage принадлежит ровно этому серверу; под write-lock сверяет текущую revision, делает **одну** замену `Arc<AuthSnapshot>` и возвращает monotonic revision. Отрицательные случаи `InvalidCandidate`, `RequiresRestart`, `StaleRevision`, `ForeignStage`, `Unavailable` при отравленном lock, `RevisionExhausted` на u64 boundary строго fail-closed; без публикации. Два валидных stage по одной revision не могут оба успешно завершиться. Неочевидные secrets/errors не выводятся.
- `ServerContext::new` (библиотечный single-inbound fixture) сохраняет прежний API, создаёт собственный isolated snapshot. Production `server::run_document` создаёт один `LiveAuthorization`, и все H2/H3 контексты используют его общий `AuthCell`; **существующие семафоры, peer budgets и network listeners не пересоздаются**.
- **Не открывать внешний Apply!** `management::StatusServer`, протокол `reload --check`, `server status`, `reload` unsupported и TOML v1 неизменны. Публичный in-process stage/commit API является *компонентом будущей транзакции*, но не готовым безопасным файловым Apply.

## Security semantics и пределы

- Линеаризационная точка = чтение immutable Arc внутри lock для каждого нового запроса. Запрос, начатый до публикации и уже захвативший старый Arc, может завершить авторизацию по старым правилам; после публикации **новые** запросы берут новую версию. Уже открытые H2/H3 stream/tunnel не отзываются мгновенно; для hard revoke потребуется отдельный interrupt policy и тесты.
- Drop отменённого staged candidate не меняет runtime. Два stage на старой revision: только первый publish становится действующим. Неверный/несовместимый кандидат или stage от иного `LiveAuthorization` никогда не применяются. Токены не записываются в IPC.
- Staging по in-memory документу сам по себе **не** проверяет байты TLS PEM, давность файлов или авторизованность действия. Реальный IPC Apply должен делать отдельную проверку текущего реального `server.toml` + PEM against загруженной TLS identity непосредственно перед commit, использовать revision CAS, оформить receipt и обеспечить cancel/timeout-safe semantics и rollback. Нельзя просто вызывать `publish` из старого `check-reload`: тот протокол специально **только чтение**.
- Этот срез **не** предоставляет файл-конфигурации для live apply, Windows DACL Named Pipe, атомарное изменение сетевых listener/TLS, TUI Apply, status revision или мониторинг runtime. F-18/F-19, браузерный TLS fingerprint и Windows proxy не закрыты.

## Проверки

Given two distinct inbounds with separate grants, a single live auth state and two bearer credentials: When stage is prepared and not published, Then both contexts still use old grants/users; when `publish` commits, both simultaneously observe rotated token/grants on new authorizations, no partial swapped subset. Existing permit stays valid.

Given revision=1 and two staged updates: When first publishes, Then second fails `StaleRevision`. Given a staged candidate from unrelated control: Then `ForeignStage`, no effect. Given invalid grant or changed policy/quota: Then stage fails, revision unchanged. Given active per-user permit while rotating digest: When same user reauthenticates with new digest, quota remains occupied; only release of original permit frees capacity.

No external services, no OS proxy side effects; native Linux/Windows locked cargo tests, clippy -D warnings, fmt, browser E2E, BBR/BoringSSL, final `ci-gate` on exact head required.

## Следующий шаг

M4.2b1b: controlled Linux IPC `Apply` transaction with actual on-disk candidate + TLS identity verification, prepared candidate lifetime, expected revision CAS, explicit operator approval/receipt, rollback on precommit failures, post-timeout result reconciliation and H2/H3 live transport acceptance tests. Only then wire editable TUI Apply. Avoid publishing changes on a background blocking thread after timeout without receipt.

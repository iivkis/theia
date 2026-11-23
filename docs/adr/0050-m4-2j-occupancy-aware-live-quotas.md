# ADR-0050: M4.2j — occupancy-aware live H2/H3 quotas with revision CAS

**Дата:** 2026-11-23. **Статус:** реализация в отдельном PR #75; exact-head CI и ревью обязательны.

## Мотивация

После M4.2h fresh-port cutover и M4.2i same-port TLS rotation
изменение max_connections_total и max_connections_per_user требовало
restart. Замена старых Tokio Semaphore на новые с меньшей capacity
некорректна: старые H2/H3 потоки продолжают владеть permits из
старых semaphores, а новые допустили бы ещё N потоков, обходя квоту.
Увеличение свыше начальной ёмкости без смены семафора невозможно.

## Решение

- Один долгоживущий Arc quota Ledger для **всех** H2 и H3
  contexts/inbounds и последовательных listener generations внутри
  supervised server run --config. Ledger владеет Mutex с короткой
  критической секцией без I/O: current max_total, max_per_user,
  active_sessions_total, active_connections и per_user occupancy.
- Успешный H2/H3 session admission за одну критическую секцию
  проверяет глобальный и персональный лимиты, увеличивает оба
  счётчика и выдаёт RAII Lease. Drop уменьшает occupancy.
  Отдельный RAII connection slot проверяет тот же total cap
  в независимом connection occupancy. PeerBudget остаётся общим.
- При **снижении** cap ниже фактически занятого числа потоков
  активные permits не отзываются. Новые соединения и запросы
  получают BUSY до снижения occupancy ниже cap. Возврат
  permits автоматически погашает долг допуска. **Увеличение**
  cap допускает новые permits немедленно, в том числе выше
  лимита при запуске сервера; никаких semaphore replacements.
- Через private Linux Unix IPC и Windows current-user SID DACL
  принимается **только quota-only** изменение полей
  server.policy.max_connections_total и
  server.policy.max_connections_per_user.
  Остальные typed TOML поля обязаны совпадать с активными,
  включая ACL/timeout policy, TLS refs, users, grants, schema,
  bind адреса и management. Дополнительно PEM bytes с диска
  проверяются против identity, уже загруженной runtime.
- Оператор после сохранения TOML запускает read-only:

      theia server quota --check

  Только после отдельного подтверждения и подготовки SHA-256
  точных сохранённых TOML bytes (bounded 1 MiB) запускается:

      theia server quota --apply --expected-revision N --sha256 HEX --confirm

  Revision положительная и canonical decimal, SHA строго
  lowercase 64 hex. Нет автоматической TUI команды применения.
- IPC worker только читает TOML/PEM и не может применять
  изменение после отмены. Bounded channel=1 доставляет
  owned candidate supervisor. Supervisor перепроверяет pointer
  активного runtime view и expected revision, готовит следующий
  auth snapshot на существующем AuthCell, захватывает quota
  ledger lock **до** CAS publish. Под коротким write guard
  публикуются revision=N+1, новые quota limits и новый typed
  baseline. Если validation, любой mutex lock или stale CAS
  неудачны, runtime не мутируется.
- Auth-only CAS и same-port TLS rotation работают после quota
  изменения с обновлённым baseline. Fresh-port cutover дальше
  использует тот же quota ledger. При незавершённом retire старого
  поколения новый quota update отклоняется fail closed.
- Потерянный IPC ACK делает итог неопределённым: оператор
  проверяет server status, а не повторяет по предположению.

## Безопасность и границы

- Ledger mutex не удерживается во время DNS, TLS handshake,
  H2/H3 stream I/O, TOML/PEM read, network dial/write.
  Только быстрый admission/release и копирование 2 caps.
  RAII защищает от утечек при отмене задачи, а poisoned
  ledger mutex означает fail closed, никогда over-admission.
- Старые аутентифицированные туннели не отзываются; это
  НЕ hard revoke и НЕ lossless migration. User inventory
  неизменен, поэтому per-user counters не теряют владельца.
- Есть ДВА независимых occupancy счетчика с общим числовым
  лимитом total: authenticated sessions и active transport
  connections, как в старой модели. Это НЕ совокупный лимит
  обоих видов объектов вместе.
- Для библиотечных unsupervised contexts старые fixed
  semaphores остаются. Quota Apply доступен только
  supervised file runtime с защищённым management IPC.
- Новый UI график занятости, изменение non-quota policy,
  перенос квот между процессами, persistent quotas и
  post-commit автоматический rollback ещё не реализованы.

## Автоматическая приёмка

Unit: shrink ниже occupancy и возврат permits без hard kill,
увеличение выше startup cap, user/global/transport invariant,
8 concurrent workers/resizes. Native compiled server E2E
Linux и Windows: реальные H2/TLS и H3/QUIC authenticated
tunnels при initial global=2. Read-only check, wrong SHA,
non-quota edit и invalid caps обязаны fail closed с revision=1.
CAS уменьшает quota до 1 без закрытия old connections,
new H2/H3 admission fails; CAS увеличивает до 4 и открывает
новые H2/H3 сверх стартового cap. Старые туннели передают
byte-exact echo, post-change auth-only CAS 3→4 проходит.
Все обязательные Windows different-SID DACL, ConPTY,
Chromium E2E, BBR/BoringSSL, Rust fmt, Clippy -D warnings
и exact-head final ci-gate обязательны.

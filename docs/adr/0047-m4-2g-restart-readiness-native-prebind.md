# ADR-0047: M4.2g — restart-only readiness, TLS identity и native TCP/UDP prebind

**Дата:** 2026-11-23. **Статус:** частичная подготовка; managed restart/cutover НЕ реализован.

## Зачем отдельный этап

M4.2b1b–M4.2f дают атомарный CAS Apply **только авторизации**
на действующих H2/H3 listeners. Политика квот, TLS identity,
server_name, bind addresses и набор inbound остаются restart-only.
Нельзя честно называть транзакционным перезапуском stop→start:
если новый UDP/QUIC или TCP/H2 bind не удастся, старая служба уже
отключена. Также нельзя обещать same-port zero-downtime cutover
без контролируемого владения старым socket и передачи ресурсов.

## Решение M4.2g

- Только на реально запущенном сервере с явно включённым
  защищённым Unix IPC (Linux, mode 0700/0600) либо SID+SYSTEM
  Named Pipe (Windows) доступен операторский CLI
  theia server restart --check.
- Отдельная серверная TUI клавиша R (Shift+R) открывает только
  модальную read-only проверку и умеет показать результат или отказ;
  клавиши y/a в этой модалке НИКОГДА не выполняют Apply.
  Несохранённый TUI draft требует Ctrl+S или discard до проверки.
- Один restart probe за раз на running service: fail-closed
  single-flight mutex не позволяет накопить бесконечную очередь
  spawn_blocking workers при отказе/timeout, а guard живёт до
  завершения worker даже после потери IPC клиента.
- Запрос check-restart ограничен существующими 128/128-байтными
  IPC лимитами, 8 активными клиентами и 2-секундным deadline.
  Без конфигурационного file snapshot или защищённого IPC
  всегда отказ. Извлечение конфигурации/PEM и пробные bind идут
  в spawn_blocking, а уже истёкший worker никогда не публикует CAS,
  не отменяет задачи и не посылает сигналы остановки.
- Работающий сервер читает из своего исходного config path
  **один** ограниченный валидируемый typed TOML кандидат. Его TLS
  PEM проверяются фактической production rustls TLS1.3/H2
  identity/hostname/сертификат-ключ конфигурацией.
- Только auth-compatible изменения с теми же загруженными PEM
  дают ответ AUTH-ONLY: используйте существующий CAS Apply,
  рестарт для такого изменения не требуется. Подмена байтов
  исходного PEM без смены file path не ошибочно признаётся auth-only.
- Если хотя бы один новый TCP либо UDP socket пересекается
  с действующим listener bind (в том числе wildcard), ответ
  MAINTENANCE: текущая реализация не умеет атомарную передачу
  того же порта. Никаких попыток остановить старый server.
- Когда все новые TCP+UDP адреса отличаются от старых, probe
  **одновременно** держит набор всех новых TCP Listener и UDP Socket
  в ОС. Занятый порт либо частичная ошибка приводят к RAII cleanup.
  PASS = порты оказались доступны **только в момент проверки**,
  после выхода все socket освобождаются. Никакой QUIC accept,
  сетевого handshake или изменённой конфигурации runtime.
- При invalid TOML, неверном hostname/cert/private key, занятом
  TCP/UDP, ошибке прав доступа: REJECTED (ненулевой код CLI).
  Не возвращать имена файлов, секреты или сам конфиг по IPC.
  Любой ответ содержит явное runtime UNCHANGED.

## Безопасность и ограничения

Ни PASS, ни MAINTENANCE, ни AUTH-ONLY не означает, что restart
совершён, что порт зарезервирован после проверки или что
следующий swap ресурсов гарантирован. Нет автоматического
перехода, переноса QUIC соединений, soft/hard revoke,
rollback уже опубликованного состояния или возможности
обновлять квоты без перестройки contexts. Для настоящего
safe cutover нужен отдельный runtime supervisor с состоянием,
идентификацией поколения, управлением старым accept loop,
публикацией listener/context snapshot и проверкой живости
нового поколения перед закрытием старого. Порт same-address
TLS rotation потребует отдельной maintenance стратегии
или подтверждённой ОС-специфической передачи сокета.

Read-only здесь относится к runtime state. Краткий реальный
TCP/UDP bind по явно сохранённому кандидату имеет временный
эффект в сетевом пространстве имён, поэтому нужен именно
отдельный опрос администратора через защищённый IPC.
TOCTOU между TOML/PEM и последующим запуском остаётся:
preflight не является транзакцией и не может служить
разрешением на автоматический kill→start.

## Тесты / приёмка

Native Linux и Windows автоматический integration test запускает
реальный compiled H2/H3 server + native private management IPC:
проверяет AUTH-ONLY, временное одновременное открытие новых
TCP/UDP, отказ на уже занятом TCP и UDP, MAINTENANCE при
same-port изменении квот, отказ на неверном TLS name/PEM,
сохранение status revision=1 после каждого случая, затем
настоящая серверная TUI по R показывает отдельный read-only результат
(и не реагирует на y как Apply), после чего существующий TUI CAS
Apply 1→2 остаётся неизменным. Pure unit-test
проверяет wildcard / dual-stack alias classification.
Без IPC явная CLI команда отказывает. Все обязательные
14 GitHub Actions jobs, Linux fmt/Clippy, native Windows,
ci-gate exact-head должны завершиться SUCCESS.

Этот PR не закрывает полный пункт controlled restart.

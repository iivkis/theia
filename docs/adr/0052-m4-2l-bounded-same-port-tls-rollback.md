# ADR-0052: M4.2l — single-level bounded in-memory same-port TLS rollback

**Дата:** 2026-11-24. **Статус:** отдельный CI-gated PR #77, обязательна точная приёмка Linux/Windows.

## Контекст

M4.2i/2k выполняют TLS1.3 identity rotation H2/TCP и QUIC/H3 без
повторного bind. Но после успешного CAS устаревшая identity исчезает из
управления; попытка снова прочитать файлы PEM для обратной ротации не
гарантирует, что это прежние байты (и может обнаружить повреждение
или подмену PEM). Автоматический rollback при любом сетевом сбое
опасен: непонятно, произошёл ли он из-за новой identity, а
у клиентов уже могут существовать сессии с обоими сертификатами.

## Решение

- Только **последняя успешная same-port** TLS-ротация сохраняет в
  единственном runtime supervisor точно ранее установленные
  `TlsAcceptor` H2 и `quinn::ServerConfig` H3/BBR, фактические
  identity hashes и предыдущие TLS file refs. Во время запуска
  подготовка H3 теперь сохраняет тот же конфиг, который
  установлен на bound QUIC endpoint. Raw PEM после установки
  не кэшируются; ServerConfig содержит прежний приватный signing key,
  поэтому его удержание ограничено максимум **300 секунд**.
- Приватный native Unix socket Linux и current-user SID DACL Named Pipe
  Windows остаются единственным путём управления. Read-only команда:

      theia server tls rollback --check

  отвечает доступностью, текущей revision и оставшимися секундами,
  **без** private keys, сертификатов и fingerprint. Без saved slot,
  после его expiry или с отдельным standalone IPC возвращает отказ.
- Оператор отдельно подтверждает изменение:

      theia server tls rollback --apply --expected-revision N --confirm

  Только positive canonical N и явный `--confirm`. Старая
  revision, повторное использование, истекшее окно, неподготовленный
  сервер и будущая fresh-port смена дают отказ **без side effects**.
- Обработчик IPC записывает краткий запрос в **уже существующий**
  supervisor channel capacity=1; никакой filesystem PEM/TOML read,
  ключей, network probe или нового канала с неограниченной очередью.
  После IPC timeout sender.is_closed мешает публикации.
- Supervisor проверяет deadline и текущий runtime view/revision.
  Подготавливает новый typed baseline как текущий документ с
  восстановленными **только** `tls_cert`/`tls_key` refs, сохраняя
  любые изменения auth tokens и live quotas после TLS-ротации.
  Готовит staged authorization revision N+1 на прежнем AuthCell.
  До CAS берёт все H2 write locks; ошибка lock либо stale
  CAS **не меняет** runtime. Под коротким writer CAS применяет
  сохранённые H2 acceptors и QUIC endpoint TLS configs, публикует
  новую monotonic revision и loaded identity hashes в preflight.
  Не перевязывает TCP/UDP порты, не останавливает listeners,
  не отменяет уже аутентифицированные H2/H3 streams.
- Успешный rollback **поглощает слот**. Повторная команда
  недоступна. Следующая same-port rotation может создать
  один новый слот, заменив прежний. Fresh-port cutover аннулирует
  слот; окно также снимается отдельным supervisor timer, который
  освобождает сохранённые TLS-конфиги при expiry даже без активности.
- Потерянный ACK оставляет исход неопределённым: оператор
  проверяет `server status` (revision) и `tls rollback --check`,
  а не повторяет Apply с предположением об отказе.

## Безопасность и ограничения

- Это **операторский аварийный возврат**, НЕ автоматическая
  post-commit compensation и НЕ health-driven failover.
  Не распространяется на fresh-port cutover, rollback quota
  changes или произвольную историю generations. Нет стека
  сохранённых ключей, нет persistent rollback после рестарта
  процесса, нет remote TCP управления и нет TUI Apply.
- Существующие handshakes могут закончиться со старым
  сертификатом и после CAS. Новый сертификат применяется
  только к новым подключениям; нет глобального H2+H3
  handshake barrier или hard revocation старых потоков.
- Документ после rollback возвращает исходные TLS file refs,
  **но не переписывает PEM-файлы на диске**. Если они были
  удалены/подменены, текущий runtime TLS защищён сохранёнными
  configs, но будущий startup/restart из файлов может не пройти
  strict TLS проверки. Оператор обязан восстановить доверенные
  versioned PEM на диске до будущего cold start.
- Привязка `--expected-revision` остаётся CAS, без второго
  TLS pin: здесь берутся **уже проверенные и установленные**
  TLS configs из runtime памяти, а не внешние файлы.
- Same-port rotation на старых или новых trust anchors не
  обновляет клиента автоматически. CA rollout и проверка
  hostname остаются обязательными.

## Обязательная автоматическая приёмка

Native Linux/Windows compiled server c real TLS1.3/H2 и QUIC/H3
на тех же портах. До ротации rollback отсутствует. После
1→2 read-only check подтверждает window/revision; auth CAS
2→3 обновляет токен без потери rollback eligibility; stale
rollback 2 отвергается. Повторная TLS rotation 3→4 заменяет
слот. PEM предыдущей identity намеренно повреждаются **на
диске** и rollback 4→5 должен вернуть H2/H3 сертификат из
памяти, с **новым** auth token. Повторный rollback 5
отвергается; новая revision=5. Unit проверяет expired window,
CLI требует canonical revision и --confirm, native IPC
отказывается без supervisor. Все существующие Linux/Windows
PTY/ConPTY, different-SID DACL, browser Chromium, fmt,
Clippy, BBR/BoringSSL/uTLS и final exact-head 14/14 CI.

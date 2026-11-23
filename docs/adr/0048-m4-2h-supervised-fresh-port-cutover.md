# ADR-0048: M4.2h — supervised H2/H3 fresh-port cutover с CAS

**Дата:** 2026-11-23. **Статус:** ограниченный online cutover; exact-head CI и review обязательны.

## Контекст и решение

M4.2g (ADR-0047, PR #72) добавил защищённую проверку кандидата
theia server restart --check, но преднамеренно не переключал сервер.
Обычный stop → bind → start небезопасен: если новый сертификат или
любой из TCP/H2 и UDP/H3 портов занят, старый сервер уже выключен.
В M4.2h ответственность за подготовку и переключение двух поколений
принадлежит **одному runtime supervisor**, а не IPC worker.

1. Оператор сохраняет TOML, смотрит revision действующего сервера через
   private Linux Unix socket / Windows Named Pipe SID DACL, вычисляет
   SHA-256 **точных сохранённых байтов**, затем явно подтверждает команду:

       theia server restart --apply --expected-revision N --sha256 HEX --confirm

   Без --confirm, с неконаноническим digest или revision=0 команда
   запрещена ещё на этапе CLI. Readiness --check НИКОГДА не применяет.
2. IPC читает максимум 1 МиБ TOML ровно один раз, сравнивает digest,
   парсит и передаёт owned candidate в bounded channel capacity=1.
   Read worker после отмены IPC handler **не умеет** коммитить.
3. На текущем этапе разрешены только **новые непересекающиеся** TCP/UDP
   bind адреса при неизменных global/per-user quotas, management
   policy и списке user IDs. Wildcard/dual-stack aliases консервативно
   отклоняются. Same-port TLS rotation, квоты и inventory требуют
   отдельного maintenance cutover и здесь запрещены.
4. Supervisor проверяет действительные TLS1.3 cert/SAN/key и все порты
   затем заново готовит H2/TLS и H3/QUIC production listeners с общей
   таблицей квот. Новые accept tasks стоят на барьере Prepared;
   старый сервер и его IPC остаются активными. При любой ошибке
   preparation всё новое освобождается без изменения прежней
   revision и без остановки старых listeners.
5. CAS commit сверяет ссылочную идентичность старого runtime snapshot
   и ожидаемую revision. Под коротким write guard новые
   авторизации на старом поколении выключаются, а IPC snapshot
   публикуется на новое с revision=N+1. Затем новая группа
   accept tasks переходит в Active, старая в Drain: прекращает
   принимать новые соединения/запросы и даёт старым authenticated
   tunnels **до 20 секунд** для завершения. Остаток принудительно
   закрывается; это НЕ lossless migration и НЕ hard revoke.
6. Management endpoint не перевязывается, SID DACL/Unix 0700/0600
   остаются прежними. После cutover обычные auth-only CAS Apply и
   check работают с новым baseline и TLS identity.
   In-flight auth Apply защищён общей короткой RwLock границей,
   не может подтвердить публикацию в retired generation.
   Revision монотонна. Не допускается больше одного
   одновременно draining поколения.
7. ACK отправляется после CAS. Если ACK потерян, результат
   неопределён: нужно выполнить server status, не повторять Apply.

## Угрозы и границы

- Лимитеры global/per-user/peer rate разделены между поколениями,
  даже пока старые туннели завершаются. Изменение quota или user
  inventory запрещено, чтобы не удвоить разрешённое число сессий.
- Пробный port bind и подготовка QUIC endpoint имеют реальные,
  но ограниченные сетевые побочные эффекты. Prepared QUIC endpoint
  может увидеть transport datagrams до application accept barrier:
  не обещать handshake-level atomic visibility. 0-RTT отключён.
- До commit-point при ошибке старый сервер остаётся рабочим.
  После CAS автоматического rollback нет: неожиданное завершение
  нового accept loop считается критическим сбоем сервера,
  требующим supervision/service manager. Отдельный post-commit
  compensation не реализован.
- Same-port TLS swap, quota/roster editing, H2/H3 session migration,
  удалённый SSH мастер, отменяемый post-commit rollback, полноценный
  zero-downtime maintenance и hard revoke ещё НЕ реализованы.
- Не добавляются внешняя админка TCP, Windows system proxy effects,
  новые TOML поля или секреты в IPC ответе.

## Acceptance

Native Linux и Windows E2E запускает compiled H2/H3 server,
реальные TLS/QUIC клиенты и private management IPC: проверяет
wrong digest, occupied TCP, occupied UDP, changed quota, reused
bind и внешний edit с сохранением revision 1; SHA-bound
fresh-port TLS cutover с revision 2; успешный H2/H3 на новых
портах и bounded drain старых tunnels; stale revision отказ;
затем auth-only CAS на новом baseline revision 2→3.
Unit проверяет strict CLI SHA/--confirm и отсутствие ложной
публикации stale/foreign generation. Existing cross-SID
Windows IPC, ConPTY, Linux PTY, Rust fmt/Clippy, browser E2E,
BBR/BoringSSL и final ci-gate остаются обязательны.

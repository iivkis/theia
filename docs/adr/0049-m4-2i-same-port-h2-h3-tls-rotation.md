# ADR-0049: M4.2i — in-place H2/H3 TLS identity rotation on identical ports

**Дата:** 2026-11-23. **Статус:** отдельный CI-gated PR; не завершён без exact-head 14/14 SUCCESS.

## Контекст

M4.2h умеет менять полностью новые TCP/H2 и UDP/H3 bind addresses,
но смена сертификата на **том же порту** раньше требовала остановки.
Обычный stop → bind → start ненадёжен и разрывает туннели.

API: tokio-rustls TlsAcceptor клонирует immutable rustls ServerConfig
для нового TLS handshake; quinn Endpoint.set_server_config меняет
TLS конфигурацию лишь для **новых** QUIC incoming connections, без
rebind/close существующих сессий. TLS1.3, h3 ALPN, BBR, no-0RTT
проверяются production-конфигураторами.

## Транзакция

1. Оператор сохраняет TOML и версионированные TLS PEM источники,
   проверяет server restart --check (same-port TLS rotation ready),
   считает SHA-256 **точных сохранённых TOML байтов** и отдельно
   подтверждает операцию через private Linux Unix IPC либо Windows
   SID-DACL Named Pipe:

       theia server restart --apply --expected-revision N --sha256 HEX --confirm

   TUI Shift+R только read-only; нет Apply по сохранению или запуску.
2. Разрешены **только** изменения tls_cert / tls_key существующих
   inbounds либо обновление их реальных PEM байтов по тем же
   file: refs. Порядок/ID, оба TCP/UDP listen addresses,
   server_name, inbound grants, server.users, quota/ACL policy,
   management, UI и schema_version должны быть прежними.
   Полное отсутствие изменения TLS байтов не допускает
   фиктивного нового restart commit.
3. Protected IPC читает TOML один раз с bounded size и проверяет
   SHA и expected revision. Далее ВСЕ новые TLS1.3 H2 acceptors и
   H3 QUIC server configs проверяются и создаются **до** CAS и
   без закрытия текущих сокетов. Ошибка SAN, cert/key match
   либо H2/H3 config отвергается до любой публикации.
4. Supervisor сначала берёт write locks для всех H2 acceptor
   handles; poisoned lock, stale revision или сменившееся runtime
   generation отвергаются без частичной TLS публикации.
   Под одной короткой runtime CAS boundary сервер публикует новую
   authorisation revision N+1 в **тот же AuthCell**, который
   обслуживает существующие H2/H3 контексты, затем синхронно
   меняет H2 acceptor pointers и QUIC server configs. После этого
   protected management view использует новый TOML/TLS baseline.
   Ранее авторизованные туннели и QUIC connections сохраняются.
5. ACK отправляется только после CAS; при потере ACK итог
   неопределён и оператор обязан сначала запросить server status.

## Угрозы, ограничения и не заявленные гарантии

- Существующие TCP/UDP listeners НЕ перевязываются, старые
  TLS sessions не отзываются. Новые handshakes H2 и H3
  используют новую identity. Клиент, доверяющий только прежнему
  сертификату, может перестать подключаться: trust rollout —
  ответственность оператора.
- Это НЕ handshake-level atomic switch между TCP и QUIC:
  сокет, принятый перед CAS, либо racing QUIC Initial может
  получить прежнюю TLS identity. Есть единый CAS для management
  revision и prevalidated конфигурации, но нет единого
  transport-handshake barrier.
- SHA-256 привязывает только TOML bytes, НЕ содержимое
  внешних PEM файлов. Рекомендуются приватные неизменяемые
  версионированные PEM paths; отдельный PEM content-pin нужен
  для полного устранения этой race. Не писать cert/key и токены
  в логи, IPC и TUI.
- Нет автоматического post-CAS TLS rollback, полной миграции
  старых сессий, remote SSH wizard или quota mutation.
  Уменьшать quota с held permits можно только после отдельного
  occupancy-aware дизайна без двойного admission; policy
  изменения явно отвергаются fail closed.
- Не меняет TOML schema, system proxy и не создаёт public admin TCP.

## Acceptance

Native compiled server E2E на Linux И Windows запускает реальный
H2/TLS1.3 и H3/QUIC с защищённым IPC, открывает old H2+H3
authenticated tunnels, проверяет неверный SHA, malformed TLS PEM,
изменённые quotas (все с неизменной revision=1), затем запускает
подтверждённый same-port TLS commit N=1→2. Новые H2/H3 handshakes
на исходных **тех же** портах должны проходить с RootCertStore,
содержащим **только новый** cert. Old authenticated tunnels
завершаются, а post-rotation auth-only CAS работает 2→3.
Stale revision/duplicate apply отвергается. Существующие native
Windows ConPTY и cross-logon SID security E2E остаются mandatory,
также Rust fmt/Clippy, browser, BBR/BoringSSL и final ci-gate.

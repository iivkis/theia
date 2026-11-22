# ADR-0007: M3.4c verified BoringSSL H2 duplex adapter feasibility

**Дата:** 2026-11-22  
**Статус:** исследовательский прототип, **CI ожидается**. Production F-13 P0 остаётся BLOCKED.  
**Связанные решения:** ADR-0005, ADR-0006.

## Контекст и ограничение

M3.4b доказал, что `btls 0.5.6` выдаёт GREASE + ALPS 17613 на TCP и работает с настоящим TLS 1.3, проверенными сертификатами и ALPN `h2` на Linux/Windows. Это ещё не демонстрирует, что `tokio-btls::SslStream` совместим с `h2 0.4.19` в **действительно полнодуплексном HTTP/2 POST**.

Production `H2Client::open` использует `rustls 0.23.46`, `tokio 1.48.0`, credential-bearing POST, SmartTheia HELLO/OPEN_TCP/OPEN_OK и один H2 connection driver на туннель. `tokio-btls 0.5.6` требует Tokio ^1.52.1, поэтому преждевременный перенос BoringSSL в production меняет runtime dependency graph и может нарушить проверенный H2/H3 транспорт.

## M3.4c: решение

Следующий вертикальный срез остаётся **только в `spikes/m3_4`**. Добавить минимальный `h2_transport::connect_verified_h2`, не выставляя его пользователю и не изменяя production/TOML/wire:

- Принимает только готовый `SocketAddr`, DNS-имя TLS и непустой test-only CA PEM; не отключает X.509-проверку, TLS 1.3-only, hostname verification, ALPN h2. Сертификаты и имена никогда не выводятся.
- Дедлайн всего TCP/TLS/H2 handshake: 12 секунд, без возврата HTTP request handle при любой ошибке. Нельзя отправлять bearer до успешного TLS handshake.
- `tokio-btls::SslStream` передаётся в стандартный `h2::client::Builder`; owned driver постоянно поллится, `Drop` прерывает driver. Не добавлять кастомный TLS или HTTP/2.
- Test-only сервер `tokio-rustls` + стандартный `h2::server`. Peer выдаёт HTTP 200 и первые DATA **до** END_STREAM запроса. Клиент принимает ответ и продолжает отправлять DATA, затем обе стороны получают независимый EOS. Положительная проверка завершается за 25 секунд, окна потока управляются явным `reserve_capacity/poll_capacity/release_capacity`.
- Отрицательные тесты: wrong SAN, untrusted CA и ALPN `http/1.1` завершаются без `VerifiedH2`; HTTP 403 по заголовкам доступен до EOF запроса, не интерпретируется как разрешение создать туннель.
- Все тесты выполняются в обязательной Linux/Windows `m3-4-btls-spike` CI matrix; `cargo test --locked`, `fmt`, `clippy -D warnings`, Go uTLS comparison и полный `ci-gate` требуются на точном SHA.

Проверки сертификатов встроены в библиотечный handshake. Клиент не получает H2 sender до завершения строгой TLS identity verification. Никакие приватные ключи, token или TLS raw bytes не логируются.

## Не является и не доказывает

- **Не** добавлен browser-like TLS профиль в production или новый `tls_profile`; `rustls` и его `Cargo.lock` не изменены, Go uTLS остаётся CI эталоном.
- **Не** выполнены SmartTheia HELLO/OPEN_OK/full tunnel relay с реальным production `H2Client`; текстовые DATA тестового POST не являются SmartTheia wire.
- **Не** доказано соответствие Chrome H2 SETTINGS, pseudo-header order, HTTP/2 streams, JA3/JA4 или H3 QUIC Initial. Модули TLS/H2 у Go reference и BoringSSL по составу cipher/extensions всё ещё отличаются.
- **Не** сравнивались CPU/RSS, размер статического бинарника, jitter/latency, FFI лицензия/supply chain. Перед production интеграцией необходимы эти проверки и отдельный Tokio upgrade PR с проверкой Windows.
- **Не** обойдены требования P0 F-11 (BBR production benchmark), F-13 и M5.

Rollback: удалить этот изолированный адаптер и его тесты, восстановить spike lockfile. Ни runtime, ни пользовательские конфиги не меняются.

# ADR-0023: M3.5b2a, strict pinned TLS/H2 probe behind exact socket consent

**Дата:** 2026-11-23. **Статус:** research-only functional library subfeature. Real network TLS/H2 loopback test required; **не** UI scan, REALITY, full F-18/F-19.

## Контекст

M3.5b1 создаёт план кандидатов без сетевых вызовов, но никак не проверяет предъявляемый сертификат. Одно лишь наличие CT/DNS или популярности имени не доказывает TLS пригодность. Прямое соединение по CIDR/провайдерской сети без разрешения может нарушать допустимый scope. Вводить массовое сканирование до строгого per-IP auth, deadlines, verified CA и критериев недостоверности TLS было бы небезопасно.

## Решение

- `route_selected_local_ip(SocketAddr)` использует `std::net::UdpSocket::bind/connect/local_addr`, **не вызывает UDP send** и не отправляет пакет, не запрашивает внешний IP через чужой API. Результат — только *selected route local source IP*. Он может быть RFC1918 при NAT; не даёт netmask, subnet ownership, egress IP или разрешения на scan. Получение реальных интерфейсов/prefix/routing table остаётся M3.5b2b.
- `probe_tls_h2` открывает ровно **одно** TCP соединение по переданному `SocketAddr`, без DNS/HTTP GET/redirect и только после `ProbeApproval`: `Denied` по умолчанию; `PublicHttpsIp` ограничен точным публичным IP:443 (caller должен получить внешнее operator approval); `IsolatedLoopbackFixture` допускает исключительно совпадающий loopback SocketAddr для CI fixture. Нельзя выводить approval из BGP, RDAP или server local IP. Это explicit **programmatic** contract, **не реализованный UI consent** и не подтверждение юридического права владеть IP.
- Проверки из готовых rustls/tokio-rustls 0.23/0.26: TLS1.3-only, ALPN=h2, RootCertStore не пуст, стандартный hostname/SAN/CA-chain/notBefore/notAfter verifier, без TOFU/insecure mode или TLS1.2 fallback. Успех помечает **только** проверенные TLS1.3, chain, SNI/SAN, certificate_current, reachability и h2 ALPN, а h3 ALPN и actual Theia fingerprint остаются Unknown. Это не означает REALITY совместимость, невозможность DPI классификации или право использовать чужой приватный ключ.
- `Semaphore::const_new(4)` ограничивает параллелизм всех вызовов процесса; `min(request.deadline, 5 seconds)` покрывает ожидание семафора, TCP connect и TLS handshake. В случае отказа/timeout возвращается **ошибка**, не частичный `TlsEvidence` с `Verified`; не извлекаем/не логируем персональные данные, certificate chain/hostname/token или приватные ключи. Не создаём новых конфигурационных/CLI/TUI параметров.
- Native Linux/Windows tests только на изолированном `127.0.0.1` с временными test-only certificates. Verify wrong CA, invalid SNI/hostname, ALPN h3-only rejection on TCP, no trust roots, no approval, wrong authorized port/IP и handshake timeout. Main Rust CI/pinned browser checks остаются обязательными.

## Остаётся открытым

M3.5b2b: real interface/CIDR/IPv6/egress NAT OS discovery with provenance; passive DNS/CT/RDAP evidence with freshness; bounded active scheduler with per-target rate limits, explicit owner authorization UI and safe logging; external popular domains только после разрешения; separate H3/QUIC TLS probe and first-flight, fingerprint compatibility/independent security review. **F-18 REALITY security mode, M4.5 two-action wizard and F-19 TLS-in-TLS mitigation не реализованы.** Не включать невыполненные режимы в `theia://v1` или TOML v1.

## Risks

Этот API не может юридически подтвердить ownership. `PublicHttpsIp` подтверждает только явно переданный вызывающим кодом IP и порт: future caller MUST independently prove consent/ownership before instantiating approval. Системная функция UDP route selection не является discovery всей подсети и не эквивалентна публичному IP через NAT. Один успешный TLS1.3/H2 handshake не доказывает mimicry или H3 support. Покрытие потенциальной SSRF защиты ограничено pinned address и loopback/public admission; future DNS collector needs separate rebinding tests. 

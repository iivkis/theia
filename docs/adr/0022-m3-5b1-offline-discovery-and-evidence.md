# ADR-0022: M3.5b1, offline discovery planner и TLS evidence-only ranking

**Дата:** 2026-11-23. **Статус:** реализован первый ограниченный pure-data срез; реальный TLS scanner, OS collector, REALITY и TLS-in-TLS не реализованы.

## Problem / threat model

F-18 требует находить HTTP/TLS-кандидатов в публичной сети сервера и среди известных доменов без ручного списка, но простое «просканировать соседнюю /24» потенциально обращается к чужому провайдерскому диапазону. Фальшивые сертификаты, CDN/anycast, недостоверная SNI, DNS rebinding, сетевые таймауты, /64 IPv6 enumeration и неконтролируемые лимиты мешают качественному подбору. Кроме того, нельзя засчитывать популярность `google.com` или наличие DNS/CT записи как доказательство реально подходящего или воспроизводимого browser TLS fingerprint.

## Decision: zero-I/O pure module

В `crates/theia/src/camouflage_discovery.rs` публичные `ServerSnapshot`, `InterfaceAddress`, `NetworkPrefix`, `Candidate`, `DiscoveryPlan` и `TlsEvidence`. Никаких новых Cargo dependencies, OS API, DNS/TCP/QUIC/HTTP/CT/RDAP I/O и никаких изменений протокола/TOML/CLI/TUI.

1. `build_plan(snapshot, approved)` всегда добавляет каталог из 14 явных HTTPS-domain seeds (Google, Samsung, AMD, Microsoft, Apple, Amazon, Cloudflare, GitHub, Mozilla, Wikipedia, Adobe, Intel, Nvidia, Ubuntu). Это **кандидаты, не сканированные или проверенные серверы**. Затем добавляет только plausible public local interface IP и отдельно помечает неизвестную NAT/egress ассоциацию.
2. `NetworkPrefix::from_str` валидирует и канонизирует IP/CIDR. Inferred BGP/RDAP provider prefixes не расширяются никогда. IPv4 plan расширяется исключительно из `approved` (операторское право должно быть подтверждено будущим UI) и только если соответствующий CIDR **содержит реально заявленный публичный адрес локального интерфейса**. Префиксы шире /24 блокируются; `/31` и `/32` корректно допускаются. Зарезервированные, localhost, RFC1918, CGNAT и documentation addresses отфильтрованы консервативно; IPv6 никакие /64 не перечисляет.
3. Очередь не более `MAX_CANDIDATES=256` элементов, включая 14 seed-доменов; дедуп по host. Излишек отклонён с warning. Оператору должен быть показан источник каждого IP и запрет на использование одного лишь его адреса как авторизации.
4. `TlsEvidence::suitability(H2|H3)` принимает лишь **переданные извне** значения `Verified / Rejected / Unknown` для TLS1.3, доверенной цепочки сертификата, SNI/SAN, срока действия, достижимости, правильного ALPN и воспроизводимого в Theia TLS/HTTP fingerprint. По умолчанию все UNKNOWN → score=0/confidence=0/eligible=false. `eligible` только когда все семь релевантных фактов VERIFIED; H2 и H3 ALPN independent. Score 0–100 эвристический, **не** вероятность обхода DPI. У этой функции нет способа получить/доказать TLS observations, значит она не делает сканирование и не закрывает F-18.

## Tests and non-goals

`crates/theia/tests/camouflage_discovery.rs`: положительные/отрицательные fixtures для CDN-доменов, public IPv4+IPv6, неизвестного NAT, чужого provider RDAP/BGP, одобренных малых CIDR и неавторизованных/слишком широких диапазонов, IPv6 no enumeration, private/CGNAT/documentation deny, dedup, cap, invalid CIDR, evidence unknown/rejected/verified и отдельных H2/H3 scores. Обязательный native Linux/Windows cargo test CI.

**Не реализовано**: сбор интерфейсов через ОС, маршруты и публичный IP, verified ownership и opt-in UI, настоящий DNS/CT/RDAP сбор, TLS1.3/ALPN/CA/SAN проверка, активное сканирование, рейтинговая калибровка по данным, экспорт конфигурации или применение. Никакой новый TLS security mode, криптография или flow shaping. `approved` это контракт на внешний consent, а не внутренний экран авторизации; сам модуль не может проверить юридическое владение CIDR.

## M3.5b2b0 conservative refinement (ADR-0024)\n\nПервоначальное правило «approved CIDR содержит публичный локальный IP» оказалось недостаточным для интерфейсов с `/32` и более узкими префиксами: оно создавало более широкий офлайн-план соседей. Для перечисления IPv4 теперь дополнительно требуется, чтобы approved range находился внутри **наблюдаемого корректного assigned interface prefix**. Неизвестный `/0`, некорректная маска и approved более широкий диапазон возвращают `RangeExceedsAssignedPrefix`, не перечисляя соседей. Это не доказывает права оператора на CIDR; будущий отдельный proof-of-authorization для маршрутизируемых блоков остаётся открытым. См. [ADR-0024](0024-m3-5b2b-assigned-cidr-guard.md).\n\n## Next M3.5b2

1. Linux native route/interface collector с независимой Windows-compatible моделью, явный source provenance; если public IP неизвестен, не выдумывать /24 из egress NAT.
2. Passive DNS + published CT/HTTPS/SVCB observations с ограничением источников/свежести, no private/SSRF, отдельной сетью/датой измерения. Не считать CT verified negotiated TLS.
3. После отдельного явного opt-in: **только** разрешённые цели из проверенного CIDR с bounded concurrency/tokens/deadlines/cancellation и DNS pinning, реальные strict TLS1.3/CA/SNI/ALPN handshake tests. Third-party popular domains require permission for active probes.
4. M4.5 TUI, typed preview, rollback/IPC и новый versioned invitation после security ADR. F-18 и F-19 остаются P0 блокерами релиза.

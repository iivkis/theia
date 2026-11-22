# ADR-0024: M3.5b2b0, fail-closed CIDR scope against observed interface prefix

**Дата:** 2026-11-23. **Статус:** ограниченный offline safety hardening; до точного CI head SHA не считать принятым.

## Контекст и угроза

M3.5b1 `build_plan(snapshot, approved)` требует явный список разрешённых IPv4 CIDR и проверяет, что хотя бы один публичный локальный IP попадает внутрь range. Но сохранённая длина `InterfaceAddress.prefix_len` до M3.5b2b0 не учитывалась. Поэтому назначенный серверу `93.184.216.10/32` с одобренным `93.184.216.0/24` производил очередь соседей, хотя локальное назначение не доказывает право на эти адреса. Сам planner не вызывает сеть, но будущий активный runner не должен наследовать такую опасную предпосылку.

## Решение

1. Сохранить обязательный caller-provided `approved`, фильтр публичных IP, предел /24, ограничение 256 элементов и `NoPublicServerAddress`/NAT/provider warnings.
2. Перед **расширением IPv4** проверить, что существует публичный `InterfaceAddress`, IP которого входит в approved CIDR, а присвоенная IPv4-маска корректна (`1..=32`) и **не уже**, чем approved range: `approved.bits >= interface.prefix_len`. Никаких новых предположений о маске, egress, AS или ownership.
3. Если approved CIDR содержит публичный IP, но не укладывается в достоверную назначенную маску, оставить сам адрес сервера в плане, **не** перечислять соседей, дать явный `RangeExceedsAssignedPrefix` warning. Для чужого CIDR сохранить `RangeNotOnServer`, для префикса шире /24 `RangeTooBroad`. IPv6 по-прежнему не перечислять.
4. Это дополнительный *necessary but not sufficient* admission gate. Даже точно совпадающие interface CIDR + caller approval сами по себе не являются проверкой законного владения/согласия на active scan. Сети, маршрутизируемые через хост с интерфейсом `/32`, **намеренно** не перечисляются этим API: требуется будущий отдельный проверенный scope/provenance контракт, который нельзя неявно вывести из RDAP/BGP.

## Given / When / Then, threat cases

- **Given** назначенный публичный `/32`, `/28` или неизвестный `/0`, либо неверная маска `/33`, **when** approved содержит локальный адрес, но запрашивает соседний `/24`, **then** offline план не включает соседей; выдаётся diagnostic warning.
- **Given** назначенный `/29` и явно одобренный вложенный `/30`, **when** строится план, **then** добавляются только допустимые адреса `/30`, без network/broadcast или выходов за subnet.
- **Given** назначенный и approved `/32`, **then** остаётся один локальный IP без ошибочного предупреждения.
- IPv6, NAT-only, private/CGNAT/localhost, не принадлежащий интерфейсу CIDR, слишком широкие prefixes и 256 cap сохраняют прежнюю безопасную семантику.

## Альтернативы, последствия, доказательства

- **Только operator approval:** отвергнуто, поскольку оно не доказывает, что IP внутри чужого провайдерского /24 можно перечислять.
- **Всегда разрешать /24 при наличии local IP:** отвергнуто как опасная эвристика.
- **OS discovery/ownership proof прямо здесь:** вне объёма, потребует отдельных ограниченных API, формата provenance и CI на Linux/Windows.

Без новых зависимостей, сети, system proxy, протокола, TOML или TUI. Позитивные и негативные Rust-тесты: `crates/theia/tests/camouflage_discovery.rs`; обязательны Linux/Windows `cargo test --workspace --all-targets --locked`, `fmt`, `clippy`, и успешный `ci-gate` на **точном head SHA** GitHub Actions. Ни этот ADR, ни один offline тест не доказывают готовности F-18/F-19, режима REALITY, сканера, DNS/CT/RDAP, TLS fingerprint или ownership.

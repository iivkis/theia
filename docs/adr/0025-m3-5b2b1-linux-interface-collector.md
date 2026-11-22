# ADR-0025: M3.5b2b1, native Linux interface/prefix observation without network traffic

**Дата:** 2026-11-23. **Статус:** ограниченный functional library slice; приёмка только после точного Linux/Windows CI head SHA.

## Контекст

M3.5b1 offline `build_plan(ServerSnapshot, approved)` работает с искусственно переданными адресами/префиксами. M3.5b2a умеет наблюдать один **локальный адрес выбранного UDP route**, но не возвращает интерфейсы и маски. Без нативного наблюдения нельзя корректно оценить, какой IPv4/IPv6 префикс действительно назначен Linux-серверу; угадывание `/24` или провайдерского BGP/RDAP range опасно. NAT public egress нельзя вывести из локального адреса интерфейса.

## Решение: минимальный Linux-native collector

- Публичный модуль `camouflage_interfaces` предоставляет `collect_assigned_interfaces()` и `NativeInterfaces::server_snapshot()`, а также каждую запись с названием интерфейса, IP, назначенной длиной prefix, флагом `is_up` и точным `InterfaceSource::LinuxGetifaddrs`. Это библиотечный API без CLI/TUI и сетевого доступа.
- Linux вызывает локальный libc `getifaddrs/freeifaddrs` (точная версия `libc = 0.2.191` в lockfile), копирует только `AF_INET`/`AF_INET6` адреса UP интерфейсов с непустым именем и присутствующей маской. Чтение локальной ОС **не посылает датаграммы, DNS запросы, HTTP, STUN или TLS handshakes** и не меняет настройки ОС.
- `contiguous_netmask_prefix` допускает только непрерывные IPv4/IPv6 masks с `1..=32` и `1..=128`; неизвестная `/0`, отсутствующая, неправильной address family и разреженная маски не выдаются как назначенный CIDR. Это fail-closed отказ от гипотетического /24 или /64. Результаты ограничены `MAX_INTERFACE_ADDRESSES=4096`, список освобождается через RAII при любой ветке выхода, записи с одинаковыми name/IP/prefix дедуплицируются.
- Выходной `ServerSnapshot` сохраняет только перечисленные локальные записи, всегда `egress=None` и `inferred_provider_prefixes=[]`. Он **не** доказывает принадлежность CIDR, не создаёт `approved` и не инициирует `build_plan` автоматически. Локальные/private IPv4/IPv6 остаются наблюдениями и всё ещё отсекаются сетевым planner.
- Windows и прочие платформы получают явный `io::ErrorKind::Unsupported`, а не ложный результат: серверная сборка пока только Linux. Типы и проверка mask одинаково компилируются на Linux/Windows; реальный native Windows collector должен быть отдельным срезом.

## Given/When/Then и negative scenarios

- Given Linux CI runner со стандартным UP loopback `127.0.0.1`, When native collector запускается, Then получает реальную запись интерфейса с корректной маской, source provenance и `egress=None`; не выполняет внешние запросы.
- Given `/29`, `/24`, `/32`, IPv6 `/64` или `/128`, When mask проверена, Then возвращается точная длина.
- Given нулевая, дырявая или смешанная маска, Then `None`, нет догадок о префиксе. Null sockaddr/netmask, семейство не совпадает, выключенный интерфейс или слишком много записей: отбросить запись либо вернуть bounded error; не расширять сеть.
- Given Windows runner, Then код компилируется и collector возвращает Unsupported; нет тихого полного/пустого успешного результата.

## Нереализовано, риски, проверка

Нет публичного egress discovery, NAT/STUN, prefix ownership, BGP/RDAP, passive CT/DNS, capability approval, bounded active scheduler, TLS/H3 scan, TUI, REALITY/anti-TLS-in-TLS. Даже публичный UP интерфейс с mask **не разрешает** сканировать его CIDR: нужен отдельный explicit ownership/consent collector, а внеполосные маршрутизируемые диапазоны с `/32` могут потребовать собственную проверенную provenance.

Позитивные и негативные тесты: `crates/theia/tests/camouflage_interfaces.rs`. Linux/Windows CI с `cargo test --workspace --all-targets --locked`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` и итоговым `ci-gate` на точном SHA обязательны; ручное подтверждение не заменяет CI. Нет изменений TOML v1, invite v1, wire, proxy, конфигурации, секретов или библиотек TLS.

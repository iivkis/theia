# ADR-0010: M3.4f H2 SETTINGS and pseudo-header first-flight measurement

**Дата:** 2026-11-22  
**Статус:** PR awaiting native Linux/Windows CI, exact SHA required.  
**Критично:** F-13 (browser-like named profile) и M5 остаются **BLOCKED**.

## Зачем

M3.4e добавил экспериментальный, не включённый по умолчанию BoringSSL TLS-бэкенд в настоящий `H2Client`; SmartTheia `HELLO_ACK/OPEN_OK` и проверка токена уже общие для обоих TLS-вариантов. Наличие GREASE и ALPS 17613 в ClientHello **не доказывает** сходство HTTP/2. Оба бэкенда используют один и тот же `h2::client::Builder`.

В Go uTLS v1.8.2 `HelloChrome_133` описан **TLS ClientHello**. Существующий `spikes/m0_1/utls_reference/cmd/h2_probe/main.go` вручную посылает **пустой SETTINGS** и простейший HPACK GET с порядком `:method, :scheme, :path, :authority`. Это **не** достоверный эталон Chrome 133 для HTTP/2. Нельзя приписывать ему настройки браузера.

## Решение: только измерение, без смены wire

Добавить тестовый ограниченный по размеру `h2_wire_fingerprint` с синтетическими отрицательными случаями и реальными loopback TLS1.3/ALPN h2 соединениями:

- Положительное измерение `H2Client::new` и opt-in `H2Client::new_experimental_btls` по одному production API `open`, с **отдельными сертификатами CA/leaf** и строгой цепочкой/SAN. BoringSSL feature не включается в CLI и пользовательских TOML.
- На тестовом TLS-сервере завернуть уже **расшифрованный** `tokio-rustls::TlsStream` в read-only наблюдатель. Ни сокетный TCP ClientHello, ни TLS шифртекст не считаются H2 фреймами. Первый клиентский preface, SETTINGS с упорядоченными парами `(id, value)`, frame types до HEADERS и точный порядок четырёх HPACK псевдозаголовков извлекаются из **реальных байтов**.
- Принимать только bounded H2 preface (до 64 KiB), frame length (до 16 KiB), HPACK header block (до 32 KiB), ограничения числа и типов полей и корректные CONTINUATION. Не угадывать неизвестный dynamic HPACK index: ошибку явно отклонять. Никакие header values или Authorization не декодировать, не выводить и не сохранять; временную raw-буферизацию перезаписывать нулями после разбора.
- Сервер после получения POST **немедленно** отдаёт HTTP 403 до END_STREAM; клиент должен вернуть Unauthorized и **никогда** Tunnel/OPEN_OK. Это делает измерение аутентифицированного H2 без успешного целевого TCP dial и не подменяет серверный ACL.
- Сравнить две реальные последовательности SETTINGS и HPACK order: поскольку TLS-движок отличается, но H2-движок общий, ожидаем одинаковые значения/порядок; **не ожидаем** browser-like Chrome.
- Отдельно документировать известную ручную Go минимальную последовательность как отрицательный контроль и не считать её Chrome. Пока нет воспроизводимого проверенного Chrome H2/H3 эталона, выпуск с named fingerprint блокируется.
- Приёмка: default `cargo test --workspace --all-targets --locked` (включает rustls измерение); обязательный feature job на **каждом** native Linux/Windows выполняет `--test h2_wire_fingerprint --features experimental-btls-h2` вместе с прошлым M3.4e E2E; rustfmt/clippy `-D warnings`, Chromium proxy E2E, BBR/H3 и exact-SHA `ci-gate` сохраняются.

## Измеренный first-flight baseline, Linux и Windows

В первоначальном PR CI получены **одинаковые** результаты для `H2Client::new` (rustls) и `H2Client::new_experimental_btls` (btls) на обеих ОС:

| Поле на реальном HTTP/2/TLS соединении | Значение |
| --- | --- |
| Первый клиентский SETTINGS | `[(6, 8192)]`, то есть `SETTINGS_MAX_HEADER_LIST_SIZE = 8192` |
| Фреймы между первым SETTINGS и HEADERS | Нет |
| Псевдозаголовки в точном HPACK порядке | `:method, :scheme, :authority, :path` |
| Обычные HPACK заголовки | 2 (имена, не значения) |
| `END_STREAM` на HEADERS | `false` (полнодуплексный POST) |
| Ответ тестового сервера до EOF | HTTP 403, клиент возвращает `Unauthorized`, без `OPEN_OK` |

Эти факты теперь закреплены регрессионными проверками для реального production H2-движка. Это **не** эталон браузера. Для сравнения ручной Go uTLS TCP/H2 smoke-процесс из репозитория отправляет пустой SETTINGS и `:method, :scheme, :path, :authority`, поскольку специально не реализует Chrome H2 fingerprint. Иные TLS настройки Go `HelloChrome_133` не меняют этот факт. До документированного независимого Chrome HTTP/2 SETTINGS/HPACK эталона F-13 остаётся заблокированным.

## Границы и нерешённые требования

1. Это измерение **HTTP/2 после TLS**, не Chrome HTTP/2 сравнение. Метаданные ALPN/TLS уже проверены отдельно (ADR-0009), это не H3 QUIC fingerprint.
2. H2 SETTINGS ID/value сами по себе не фиксируют приоритеты/HPACK Huffman/CONTINUATION интерливинг/псевдозаголовки настоящего браузера. Для F-13 нужен воспроизводимый Chrome reference, затем корректировка и E2E на реальном production wire.
3. В проектах по умолчанию остаётся `rustls`; BoringSSL только feature/Cargo/API. Нет новой конфигурации, fallback, HTTP/2 engine replacement, новой опасной доверенной CA, ослабления TLS/ACL, изменений SmartTheia, H3 или release claims.
4. Известная флуктуация теста `auto_wrong_h3_certificate_never_retries_working_h2` на послемерджевом main run #45012943070 (TCP connection reset вместо HTTP 502) требует отдельной проверки race/infra без ослабления политики отсутствия fallback по H3 TLS. До точного зелёного CI PR не объединять.

Rollback: удалить test-only parser, observer, assertions и CI test invocation. Production runtime не изменён.

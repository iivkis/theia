# ADR-0006: M3.4b кандидаты TLS/H2 browser-like backend (исследовательская ветка)

**Дата:** 2026-11-22  
**Статус:** BoringSSL feasibility-тесты подтверждены нативным Linux/Windows CI в PR #29 (real TCP ClientHello, strict PKI, Go uTLS comparison, fmt, clippy); F-13 P0 **НЕ выполнен**.  
**Связанные требования:** F-06, F-11, F-13, M3.4, ADR-0005.

## Контекст

Production `H2Client` использует `rustls 0.23.46`, его реальный сетевой ClientHello измерен в M3.4a: он не имеет Chrome133-подобных GREASE/ALPS. Один User-Agent, переупорядочивание HTTP-заголовков или подмена записанных TLS байт не являются безопасной реализацией browser-like fingerprint.

Выпускается **один Rust binary** для каждой платформы; Go uTLS v1.8.2 HelloChrome_133 остаётся **только CI эталоном**, без runtime зависимости. Нельзя ослаблять проверку имени и цепочки, менять алгоритм BBR на H3 или маскировать несовместимость через H2 fallback.

## Кандидаты

1. **Стандартный `rustls`**: зрелый рабочий TLS 1.3 и Quinn/H3 интеграция, но текущий production ClientHello не имеет необходимых GREASE/ALPS признаков.
2. **`boring 5.2.0` + `tokio-boring`**: BoringSSL с GREASE и permutation, но публичное API текущей upstream обёртки не содержит полного ALPS конфигуратора. Подмена одним GREASE не закрывает F-13.
3. **`btls = 0.5.6` + `tokio-btls = 0.5.6`**: Rust bindings к BoringSSL с `add_application_settings(b"h2")`, `set_alps_use_new_codepoint(true)`, GREASE и permutation, подходящий кандидат на **TCP/H2**. Дополнительный native C/BoringSSL build, лицензии, Windows toolchain, FFI и surface атаки требуют проверки. Эти версии закреплены в отдельном spike lockfile после его генерации в CI.
4. **`wreq` / `rquest`**: HTTP client с готовыми профилями, но нельзя автоматически считать его HTTP request API совместимым с требованием Theia отправлять SmartTheia POST в режиме истинного full-duplex с открытым request body и OPEN_OK-gated CONNECT. Без собственного E2E такой переход запрещён.

## Решение

Первым минимальным вертикальным исследованием выбрать `btls/tokio-btls` **только в `spikes/m3_4`**, не добавлять в production Cargo.lock и не предлагать `tls_profile = "chrome133"` в TOML.

Реальный H2/TCP клиент-кандидат должен:

- запрашивать TLS 1.3, ALPN `h2,http/1.1`; иметь строгие доверенные корни и проверку DNS/SAN.
- включать GREASE, ALPS нового codepoint **17613**, перестановку расширений, сохраняя проверку TLS.
- на первом TCP ClientHello на loopback показывать GREASE и ALPS, а при отсутствии защищённого peer прекращать соединение без туннеля.
- на реальном TLS 1.3 сервере принимать доверенный правильный сертификат и отвергать неправильный SAN/untrusted root. Проверки не используют `InsecureSkipVerify` и не выключают hostname verification.
- на Linux и Windows сравниваться со **свежегенерированным приватным** Go uTLS HelloChrome_133 handshake: совпадение ключевых классов GREASE, ALPS, ALPN, но никаких заявлений о байтовой совместимости, JA3/JA4 или современной версии Chrome.

Применяется bounded parser из M0.1 только в исследовательских тестах. Ни реальный сырой TLS handshake, ни SNI, random, key share, bearer не попадают в логи/артефакты. Сравнение выводит лишь количество шифров/расширений и признаки.

## Приёмка и оставшиеся блокеры

- CI-only `m3-4-btls-spike` на native Linux и Windows; обязательное `cargo test --locked`, `cargo fmt`, `cargo clippy -D warnings` и private Go reference; совокупный `ci-gate` проверяется для точного SHA PR.
- Исследовательский стек с корректным H2 ClientHello **не делает** производственную Theia browser-like. Перед интеграцией необходимы production `H2Client` с реальным full-duplex и TLS+H2 SETTINGS/pseudo-header acceptance, сравнение с релевантным H2 reference и полная матрица тестов.
- `btls` **не является готовым Quinn QUIC crypto backend**. Требуются самостоятельный QUIC/H3 эталон, actual H3 Initial/SETTINGS/transport parameters, verified certificate chain и сохранение BBR, иначе H3 browser-like профиль не заявляется.
- Лицензионный анализ C/BoringSSL и Rust binding, статическая линковка, бинарный размер/CPU/RSS, supply chain audit и CI сборка Windows обязательны перед production переносом.
- Незавершённый P0 F-13 **блокирует M5**. Изменение `tls_profile`/wire/TOML в данном PR не производится. Rollback тривиален: удаление независимого spike и CI job, production runtime не затронут.

## API evidence

- [BoringSSL Rust `boring` upstream](https://docs.rs/boring/5.2.0/boring/ssl/struct.SslConnectorBuilder.html)
- [`btls` ALPS/verification API](https://docs.rs/btls/0.5.6/btls/ssl/struct.SslRef.html)
- [`tokio-btls` async TLS adapter](https://docs.rs/tokio-btls/0.5.6/tokio_btls/)
- [`wreq` browser-fingerprint HTTP client](https://docs.rs/wreq/0.16.4/wreq/)


# Theia / Тея

**Experimental / unreleased.** Theia — один Rust-бинарник с двумя ролями: сервер (в том числе Linux-сервер через SSH) и клиент (Windows/Linux). Транспорт SmartTheia v1 поверх стандартных HTTP/3 (QUIC/TLS 1.3, ALPN `h3`) и HTTP/2 (TLS 1.3, ALPN `h2`); локальные HTTP CONNECT/SOCKS5, TOML v1 и терминальная панель ratatui. Это не реализация протоколов Xray/VLESS/REALITY и не обещание обхода DPI.

**Текущее состояние на 2026-11-24:** [матрица готовности и релизных блокеров](docs/STATUS.md). Исторические состояния отдельных этапов находятся в [плане реализации](docs/IMPLEMENTATION_PLAN.md) и [ADR](docs/adr/), а не в этом README.

## Что реально работает

- **H2/H3 сервер и клиент:** TLS-проверка сертификата/SNI/ALPN, авторизация по 256-битному bearer и SHA-256 digest, отдельные grants на inbound, лимиты соединений, DNS и ACL на сервере, TCP relay с `OPEN_OK`. Режим `auto` начинает с QUIC и использует H2 fallback **только при доказанной сетевой недоступности UDP до авторизации**, не при ошибке TLS, токена или протокола.
- **BBR в QUIC:** выбран на обоих концах и проверяется в обязательной CI-матрице; полноценные release-измерения bandwidth/RTT/fairness/CPU/RSS **не завершены**.
- **TUI и конфигурация:** выбор существующих inbound/profiles, ограниченное редактирование трёх полей, атомарная запись TOML с защитой от внешних изменений. Серверная TUI умеет создавать пользователя (`u`), однократно показывать секретное приглашение после сохранения и **глобально отключать существующего пользователя** (`x` с отдельным подтверждением, этап M4.4b2a). Сохранение **не применяет** конфигурацию к работающему серверу.
- **Защищённое локальное управление:** Linux Unix socket и Windows SID-защищённый Named Pipe по opt-in. Подтверждаемый auth-only CAS Apply, CLI-переключение fresh-port listener, same-port TLS rotation, живые квоты, одноразовый откат последнего TLS-identity на том же порту в течение 300 секунд. TLS restart требует отдельного PEM-фингерпринта. Все операции подчиняются revision/confirmation и ограничениям [документации конфигурации](docs/CONFIGURATION.md).
- **Исследовательские проверки кандидатов:** M3.5b1 даёт только offline-план и неизвестные оценки по умолчанию; M3.5b2a даёт строго проверяемый, явно разрешённый TLS/H2 probe. Последующие M4.5 добавляют отдельное согласие на точечные H2/H3 пробы и DNS pin. **Это не автоматический интернет-сканер и не готовый REALITY-подобный режим.**

## Что ещё блокирует релиз

**Статус полной релизной реализации:** не реализовано для перечисленных ниже P0; экспериментальные исследования нельзя считать заменой готового продукта.

| Требование | Текущее ограничение |
| --- | --- |
| **F-13 browser-like fingerprint** | Нет поставляемого измеренного именованного H2/H3 browser-like профиля. BoringSSL/Chromium/uTLS эталоны и экспериментальные адаптеры не заменяют релизную реализацию. |
| **F-14 приглашения** | Серверная выдача и disable-only существуют; импорт в клиентскую TUI с защищённым файлом/CA и native H2 E2E находится в PR/CI. Защищённый экспорт, ротация (отдельный PR #80), H3 и Linux→Windows cross-host E2E пока не завершены. |
| **F-18 REALITY-подобная защита** | Нет согласованного криптографического identity/security mode, антипробинга и законченного двухшагового мастера с безопасным Apply. Текущие H2/H3 TLS probes — только evidence. |
| **F-19 TLS-in-TLS** | Нет измеренной flow-shaping защиты с независимым classifier и release thresholds. |
| **Windows system proxy / M4.3** | Автоматический WinINet snapshot/apply/CAS restore с проверенной аварийной recovery ещё не поставляется. |
| **M5 release** | Нужны дополнительные сравнительные BBR/fingerprint/performance/security gates и end-to-end приёмка всех P0. |

**Важно:** отключение пользователя в TUI ставит `users[].disabled = true` в **сохранённом TOML**, но не завершает активные туннели и не обновляет runtime само по себе. Для отказа в *новых* подключениях нужно отдельно подтвердить auth-only Apply в защищённом локальном IPC. Нельзя считать это hard revocation. Подробности: [инвайты](docs/INVITATIONS.md) и [ADR-0053](docs/adr/0053-m4-4b2a-explicit-existing-user-disable.md).

## Как запустить уже реализованные части

```sh
theia --help
theia config validate --config client.toml
theia server run --config server.toml
theia client run --config client.toml
theia tui --role server --config server.toml
theia tui --role client --config client.toml
```

Для opt-in управления действующим сервером: на Linux заранее создайте частный каталог `0700` и передайте `THEIA_CONTROL_DIR`; на Windows задайте `THEIA_CONTROL_PIPE` для текущего SID. Команды `theia server status`, `theia server reload --check`, подтверждаемое Apply и отдельные TLS/restart/quota CLI-операции описаны в [CONFIGURATION](docs/CONFIGURATION.md) и [TUI UX](docs/TUI_UX.md). Не включайте `Windows system proxy` автоматически; включение и восстановление ещё не реализованы.

Шаблоны [server.toml](examples/server.toml) и [client.toml](examples/client.toml) содержат **негодные заглушки**; для реального запуска нужны корректные сертификаты, секреты, маршруты и доверенные CA. Ссылку `theia://v1/...` с bearer нельзя помещать в shell history, Git или логи.

## Документы и порядок доверия

| Документ | Назначение |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Обязательный контракт разработки, CI-only и Definition of Done |
| [STATUS.md](docs/STATUS.md) | Текущий статус и доказательства, отдельно от исторических PR |
| [IMPLEMENTATION_SPEC.md](docs/IMPLEMENTATION_SPEC.md) | Продуктовые F-ID, сценарии и release acceptance |
| [SMARTTHEIA_PROTOCOL.md](docs/SMARTTHEIA_PROTOCOL.md) | Wire-протокол, state machine, auth/fallback |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | TOML v1, секреты, управление и ограничения |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Границы подсистем, роли и транспорт |
| [TUI_UX.md](docs/TUI_UX.md) | Контракт терминальной панели |
| [STEALTH_REALITY.md](docs/STEALTH_REALITY.md) | F-18/F-19, модель угроз и экспериментальные пробы |
| [INVITATIONS.md](docs/INVITATIONS.md) | F-14, выдача, отзыв и будущий клиентский импорт |
| [IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) | Хронология вертикальных срезов, не live-статус |
| [TESTING_CI.md](docs/TESTING_CI.md) | Linux/Windows CI-only приёмка |
| [docs/adr/](docs/adr/) | Неизменяемая история архитектурных решений |

Все автоматические тесты, включая реальные Linux/Windows loopback/E2E, запускаются в GitHub Actions. Финальный `ci-gate` обязан быть зелёным для точного SHA; пропущенный/отменённый job не считается успехом. Исследовательские `spikes/` **используются обязательным CI**, поэтому не удаляются как «старые файлы».

Проект пока без выбранной лицензии и не предназначен для публичной production-поставки.

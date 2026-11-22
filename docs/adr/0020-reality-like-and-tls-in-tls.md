# ADR-0020: REALITY-подобный SmartTheia и независимая защита TLS-in-TLS

**Дата:** 2026-11-22
**Статус:** спецификация принята для планирования; runtime не реализован.

## Контекст

Пользователь ожидает аналог UX VLESS REALITY и удобный инструмент подбора IP/доменов с измеренной пригодностью для мимикрии, а также отдельную защиту от классификации вложенных TLS-соединений. Существующий F-13 browser fingerprint не означает наличие этих функций, а у SmartTheia сейчас только стандартный TLS/H2 и QUIC/H3, строгая сертификатная проверка и bearer grants. Научная работа USENIX Security 2024 показывает detectability некоторых encapsulated TLS flows на уровне статистики, но не доказывает, что именно Theia распознаётся и что конкретный countermeasure работает.

## Решение

1. Добавить **F-18 P0**: REALITY-*подобный* явно именованный security mode с независимым server-key authentication, anti-probing/replay и строгой совместимостью H2/H3; не объявлять совместимость с Xray/VLESS/XTLS REALITY wire. Название будущего режима, криптография, fallback, расширения wire, server identity и trust sources требуют feasibility + нового технического ADR до реализации.
2. Добавить **F-18 P0 мастер**: две главные подтверждённые операции `Проверить и подобрать` → `Применить`, кроме обязательных security confirmations; прозрачный рейтинг кандидатов и доверительные оговорки. По умолчанию пассивные данные; активный probe только собственных/разрешённых целей, bounded, no SSRF, no massive arbitrary scans. Никаких обещаний обхода DPI по одному score.
3. Добавить **F-19 P0** как независимую защиту от классификации **TLS-in-TLS**, основанную на измеряемом flow-shaping, без MITM inner TLS, с bounded overhead и fail closed when required; принимать только при реальном воспроизводимом различении trace/capture baseline vs enabled, classifier TPR@FPR и perf regressions.
4. Не менять в этом PR TOML schema v1, `theia://v1`, SmartTheia frame v1, CLI и default TLS. Режимы и capabilities/версии будут вводиться отдельными PR, без silent fallback и без тестовых заглушек. Не создавать второй бинарник, админскую сеть, свою TLS криптографию или SQL.
5. Обязательные проверки CI Linux/Windows: real fingerprint H2/H3, server authentication fail-closed, active-probe rate and SSRF tests, scorer calibration + freshness, nested-TLS classifier vs real mixed HTTPS workloads, release-overhead benchmarks. Если реализация/пороги безопасности не подтверждены, **P0 блокирует релиз**.

## Альтернативы

- Назвать текущий `tls_profile=default` REALITY, просто подменить SNI/UA или сослаться на Go uTLS reference: **отвергнуто** как фиктивная поддержка.
- Сквозное массовое сканирование чужих IP без разрешения: **отвергнуто** из-за неэтичной/небезопасной нагрузки, SSRF и недостоверного скоринга.
- Объявить padding достаточной защитой TLS-in-TLS без classifier и overhead benchmark: **отвергнуто**.
- Ослабить hostname/сертификатную проверку, игнорировать server key, автоматически менять режим при PKI/auth failure: **отвергнуто**.

## Референсы

- https://github.com/XTLS/REALITY/blob/main/README.en.md
- https://xtls.github.io/en/config/transports/reality.html
- https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting

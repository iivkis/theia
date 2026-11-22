## Цель и user story

Укажи F-ID из `docs/IMPLEMENTATION_SPEC.md` и этап из `docs/IMPLEMENTATION_PLAN.md`.

## Изменения

Что реализовано; какие требования/платформы всё ещё **не реализованы**.

## Тесты сначала

- [ ] Падающий тест сформулирован до реализации (Given/When/Then)
- [ ] Positive, negative, boundary и security checks добавлены
- [ ] Автоматический CI для текущего head SHA: specification, Linux/Windows tests, fmt, clippy, M0.1 regression jobs и итоговый ci-gate
- [ ] OS-specific/E2E/performance сценарии автоматизированы в CI, если требуются этим PR
- [ ] Нет обязательных ручных тестов; незавершённые автоматические сценарии отмечены как blockers

## Контракты и безопасность

- [ ] `docs/SMARTTHEIA_PROTOCOL.md` обновлён, если изменился wire
- [ ] `docs/CONFIGURATION.md` и examples обновлены, если изменилась TOML schema
- [ ] Для TUI изменён `docs/TUI_UX.md`
- [ ] TLS/auth/ACL/timeouts/secret handling не ослаблены
- [ ] Нет фальшивых обещаний DPI invisibility или неиспытанного BBR
- [ ] Добавлены bench/measurements, если заявлена производительность

## Известные ограничения / rollback

Опиши недоступные функции, возможные регрессии, как откатить конфигурацию.

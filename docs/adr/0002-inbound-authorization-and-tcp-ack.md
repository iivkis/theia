# ADR-0002: inbound-scoped identity и remote TCP acknowledgement

**Status:** accepted for specification · 2026-11-22

## Контекст

В v1 TOML был глобальный `server.users[]`, но связь с inbound не задана. Это могло создать непреднамеренную авторизацию любого токена на любом inbound. Кроме того, HTTP 200 от SmartTheia streaming request мог быть ошибочно принят локальным HTTP CONNECT как подтверждение удалённого TCP dial.

## Решение

1. `server.users[]` содержит идентичности + SHA-256 digests, а каждый `server.inbounds[]` обязательно задаёт непустой `allowed_user_ids`. Авторизация проверяет токен и соответствие выбранному по listener inbound. Никаких неявных прав глобальных пользователей.
2. Canonical Bearer token: 32 CSPRNG bytes -> base64url(no padding) в headers. Сервер хэширует SHA-256 от декодированных байт, сравнивает constant-time. Hash token — не credential для отправки.
3. HTTP 200 означает auth/принятие request headers; приложение продолжает писать request body параллельно чтению response. Только SmartTheia `OPEN_OK` означает успешный upstream dial.
4. Локальный HTTP CONNECT success и SOCKS5 success отправляются только после `OPEN_OK`, отказ направляется клиенту с корректным кодом. DNS домена выполняет сервер, после IP ACL и pinning.

## Альтернативы

- Вложить пользователей в каждый inbound: проще право доступа, но дублирует credential hashes и мешает ротации. Явные ссылки на глобальный каталог дают меньше повторений без расширения прав.
- Возвращать HTTP 200 только после `OPEN_OK`: требует другой negotiation choreography и создаёт взаимные ожидания при streaming. HTTP success и TCP dial success разделены на разных слоях, что соответствует структуре Theia.

## Последствия и тесты

- Изменены v1 TOML samples; код ещё отсутствует, миграции runtime не требуются.
- Contract tests: missing/unknown/duplicate `allowed_user_ids`, disabled/revoked user, cross-inbound reuse, HTTP 200 before `OPEN_OK` vs local proxy success gate, full-duplex response while body open, DNS/ACL.
- Утверждения безопасности не считаются доказанными до E2E тестов на конкретных crates.

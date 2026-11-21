# ADR-0001: SmartTheia внутри HTTP/3 и HTTP/2

**Status:** accepted for v1 specification · 2026-11-22

## Контекст

Проекту нужен единый лёгкий протокол на QUIC с BBR и запасным TLS/H2 при ограничении UDP. Требуется снизить тривиальную сигнатуру DPI, сохраняя надёжность и небольшое ядро. Собственный сырой QUIC с нестандартным ALPN или узнаваемым plaintext handshake одновременно усложняет реализацию и облегчает протокольную классификацию.

## Рассмотренные варианты

1. **Raw QUIC со своим ALPN** + custom stream frames: просто применить frames, но виден нестандартный ALPN и не соответствует HTTP/3.
2. **SmartTheia по standard HTTP/3 и HTTP/2 streaming**: можно использовать зрелые протоколы, согласованный ALPN и один прикладной frame parser; HTTP/2 имеет TCP HOL, и fingerprint не становится автоматически браузерным.
3. Самодельный transport с имитацией HTTP: противоречит KISS и безопасности, высокие interoperability/security риски.

## Решение

В v1 использовать **HTTP/3 over QUIC, ALPN h3**, и **HTTP/2 over TLS, ALPN h2**. Один прикладной SmartTheia frame format идёт в streaming request/response bodies на каждом транспорте. QUIC-first fallback только при сетевой недоступности QUIC, а не при отказах авторизации и безопасности. BBR — измеряемая отдельная конфигурация конкретного QUIC стека.

## Последствия

- Нужен доказанный bidirectional streaming adapter для h3 и h2, тест half-close и flow control.
- DPI может видеть IP, SNI без ECH, TLS/QUIC fingerprint, временные профили и active probing; непохожесть на обычный браузер **возможна** даже при стандартном ALPN. Нельзя обещать невозможность обнаружения.
- Для uTLS-like поведения потребуется отдельное профильное решение с TLS/H2/H3 consistency tests, а не User-Agent header.
- UDP через H2 может потребовать отдельного расширения протокола и другой QoS; не входит в P0.

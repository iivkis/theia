# ADR-0045: M4.2f — настоящий терминал для серверной TUI CAS Apply на Linux/Windows

**Дата:** 2026-11-23. **Статус:** exact-head CI обязателен.

## Риск

Проверки модели и ratatui TestBackend не доказывают, что интерактивные
клавиши из **настоящего терминала** доходят до скомпилированной TUI,
а необратимый Apply действительно требует отдельного согласия.
ADR-0042 проверял созданные unit-тестами события и Linux IPC;
ADR-0043 проверял Windows IPC отдельно от ConPTY.

## Решение

- Один cross-platform Rust integration test запускает реальный скомпилированный
  Theia TLS/H2 + QUIC/H3 server на **loopback**, с native IPC:
  Linux THEIA_CONTROL_DIR (0700) или Windows THEIA_CONTROL_PIPE (SID-DACL).
  Конфигурация и PEM временные, без новых токенов в логах.
- Отдельный Python CI-only terminal driver запускает **тот же скомпилированный**
  binary TUI в настоящем kernel PTY на Linux или Windows ConPTY через
  закреплённый test-only pywinpty 3.0.5. Чтобы учитывать разреженные
  ANSI перерисовки ratatui, проверяется восстановленный экран с pinned
  pyte 0.8.2, а не наличие целых фраз в исходном byte stream.
  Это не runtime/Cargo зависимость.
- Отправляются *реальные* символы и Ctrl+R: предварительный status
  показывает revision без публикации; n отменяет; a повторно открывает
  подтверждение; только y отправляет Apply и публикует ревизию 1→2.
  Каждый gate дополнительно спрашивает **скомпилированный** server status:
  доверять надписи TUI недостаточно.
- Другой проход меняет точные байты TOML извне после чтения редактором:
  Apply обязан получить Reject без увеличения revision. Dirty draft
  блокирует Ctrl+R; status-only без config и client TUI не применяют
  авторизацию. Проверяется выход из alternate-screen и завершение
  скомпилированного бинарника.
- Потенциальный секретный вывод терминала не публикуется в CI artifacts
  или логи при ошибке, проверяются только несекретные маркеры.
- Удалённый SSH по сети сюда не входит, только настоящий PTY/ConPTY,
  без внешних адресов, runtime feature flags и системного proxy.

## Acceptance / ограничения

Обязательный cargo test --workspace --all-targets --locked запускает
этот integration test на обоих OS; Windows runner устанавливает pinned
pywinpty до тестов. Никаких ignored/skipped проходов. rustfmt,
Clippy -D warnings, полная CI matrix и exact-head ci-gate обязательны.

Этап не доказывает production SSH workflow, restart-only
TLS/listener/quota, hard revoke открытых туннелей или готовность
F-18/F-19 и полного security audit.

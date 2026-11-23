# ADR-0056: F-07 Windows user WinINet proxy, scoped ownership and conditional crash recovery

**Date:** 2026-11-24. **State:** implementation proposed; native CI pending.

## Decision

Theia's ordinary client run and both TUI roles still have **no OS proxy effects**. A new explicit **Windows-only** entry point requires all of \`theia client run --config FILE --system-proxy --confirm\` and \`client.proxy.system_proxy = "manual"\`. The process must validate typed config, TLS trust and bearer references, successfully initialize the H2/H3/auto client, and bind both private loopback HTTP CONNECT and SOCKS5 sockets **before** touching WinINet. Server runs and users on Linux cannot access this Windows API. This is *not* TUN/WinHTTP/machine-wide proxy.

The client snapshots the **current user's default-LAN WinINet** per-connection FLAGS_UI (fallback FLAGS), HTTP(S) proxy server, bypass list and PAC URL using \`InternetQueryOptionW\`. Strings are bounded and the WinINet-allocated UTF-16 buffers are released using \`GlobalFree\`. The process constructs an explicit localhost HTTP(S) proxy \`http=<loopback>;https=<loopback>\` with direct/proxy flags and a conservative loopback bypass; it preserves the original PAC URL data in the applied snapshot. Both the existing and requested settings are validated. Exotic/unsupported unknown flags fail closed.

A versioned, strict TOML recovery journal containing exactly old and new WinINet field snapshots and user SID is written as **one protected HKCU registry value**. The recovery registry key uses a protected SID + LocalSystem DACL, verified against the actual native ACEs before use. \`RegFlushKey\` completes **before** any WinINet write. A user-SID-scoped named mutex is held for the entire process proxy lifetime to prevent a second cooperating Theia client from stealing ownership. A second check before set verifies original fields; the WinINet write changes the default LAN per-connection options and calls SETTINGS_CHANGED + REFRESH. The actual post-write snapshot must match the expected one.

On normal Windows Ctrl+C/return, owned rollback compares the live snapshot against the *exact Theia-applied snapshot* and restores old flags, proxy server, bypass and PAC URL only if they still match. A process kill may leave WinINet pointing at a dead localhost; the durable journal permits only **operator-requested** \`theia client proxy --recover --confirm\` when no owner holds the named mutex. If the user or a VPN/group policy changed any managed field, recovery refuses and preserves that foreign state. If the exact original is already present, the stale journal is cleared with no OS write. The \`proxy --status\` command reads current/journal state but makes no changes; **no force override exists**. A loss of registry flush acknowledgement is treated as indeterminate and must not allow further unguarded mutations.

## Limitations and residual risk

WinINet is per-user/per-default-connection and not all Windows processes honor it; it does not affect WinHTTP, manual SOCKS/TUN, named VPN adapter settings or apps that bypass system settings. Non-Theia applications do not honor the Theia named mutex, so an external writer between compare-before-write and native WinINet apply can still race; post-write validation and ownership checks prevent silent *restoration* of a later foreign state but cannot offer true interprocess atomic transactions against other vendors. On force-kill, user must explicitly recover; auto-recovery of crash state and full third-party policy reconciliation require separate safe tests/UX. Some connection-specific and policy-managed configurations may not be represented by default LAN fields and must be treated as unsupported, not declared successful globally. TUI-side apply is not part of this scope. Do not claim M4.3/F-07 release complete until cross-process kill/recovery and policy/VPN edge-case CI in disposable Windows environments.

## Given / When / Then

1. Given normal config, \`theia client run --config FILE\` does not invoke WinINet.
2. Given an explicitly confirmed Windows client with \`manual\` mode and both listeners prepared, apply saves durable old state, installs owned localhost HTTP(S) proxy, and conditionally restores on Ctrl+C/normal exit.
3. Given another live Theia client holding the same user SID mutex, a second apply/recover fails Busy without changes.
4. Given a hard-killed owner, a new process \`client proxy --recover --confirm\` restores *only* if actual state equals exact applied snapshot; if foreign PAC/server/bypass/flags changed it fails Conflict and never forces the previous values.
5. Given no journal or exact original already present, explicit recovery is read-only or clears a stale journal without an OS proxy write.
6. Given Linux role, server role, missing confirmation, \`Off\` mode, absent TLS trust, invalid user PAC state, or failed listener bind, system proxy remains unchanged.
7. All live WinINet mutations in tests require a **disposable Windows CI runner and dedicated environment opt-in**, with actual query/set/restoration checks. Strict Rust/CI tests must pass before ready for review.

See [Microsoft WinINet per-connection options](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options) for exact native API semantics.

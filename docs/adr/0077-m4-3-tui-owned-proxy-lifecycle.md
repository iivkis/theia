# ADR-0077: M4.3 Windows TUI-owned client and WinINet lifecycle

**State:** proposed implementation; exact-head native CI pending. Extends ADR-0056, not a replacement for its CLI contract.

## Behavior and threats

The client TUI requires an explicitly loaded, clean saved client document. Opening the panel reads status only. The user separately reviews and confirms local start, WinINet apply, owned restore, abandoned-journal recovery and stop. A dedicated worker runtime owns the local serving task; ADR-0056's separate native thread continues to own the SID mutex and the actual WinINet transaction. On ordinary stop or terminal teardown, restoration is attempted before dropping the local listeners. Failure is not a successful restore and the journal is retained when the native transaction cannot safely complete.

- Given a server editor, Linux client, dirty draft, bare y or canceled review, no WinINet operation is executed.
- Given changed TOML, missing CA/credential or failed listener bind, local startup fails without WinINet effects. Given off mode or no live local client, activation refuses.
- Given a saved manual configuration and live listeners, review captures the exact current WinINet snapshot; confirming compares that snapshot again under the SID mutex. No raw PAC/server/bypass strings or tokens are displayed. Existing durable journal and native post-write validation remain mandatory.
- Given an owned lease, restore changes only the exact matching applied state; stopping attempts restoration before releasing listeners. Foreign changes are not forcibly overwritten. Recovery review captures the exact journal and observed state, and confirmation must match both under the mutex.
- Given a busy owner, foreign edit, changed journal, stale saved TOML or unknown native result, refuse rather than force. Hard exit retains the recovery journal. Recovery never runs automatically.

## Evidence and limitations

The existing opt-in Windows native test exercises the TUI panel and worker with real loopback sockets and WinINet; the separate child hard-exit and foreign-edit cases remain. Pure key/channel tests check separate review and confirmation, cancellation and duplicate y. No CI job or dependencies are added. Exact-head CI has not yet been observed. Local bind does not prove authentication, OPEN_OK, browser parity or transport availability.

Only current-user default-LAN WinINet is in scope; no WinHTTP, TUN, machine-wide settings or true atomic CAS against non-cooperating external applications. The external writer race from ADR-0056 remains. A journal match by itself is not proof of a live owner. A native API failure or killed process may leave a journal requiring explicit recovery. The panel is modal and keeps the local client scoped to the session. A compiled ConPTY scenario now exercises real keyboard consent, authenticated H2 CONNECT/SOCKS5 relay, restore, stop, hard-kill and recovery in the same mandatory Windows job. Exact-head results are not yet available. Policy/VPN/named-connection and upgrade scenarios remain release blockers. Journal v1 validation reconstructs the only valid applied loopback snapshot and rejects any other server, bypass or flags. No changes to wire protocol, TOML schema, credential handling or fallback policy.

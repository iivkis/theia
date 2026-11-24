# ADR-0090 — BBR-first with CUBIC fallback

Status: owner-approved policy, implementation submitted; native CI and performance evidence pending. Supersedes the unpublished strict BBR-only draft.

## Decision

Prefer BBR for SmartTheia H2/TCP and H3/QUIC on both peers and all security modes. When BBR cannot be selected, use CUBIC. The policy is fixed and not configurable or negotiated. No global TCP settings are changed. This controller policy does not change TLS/auth checks or the network-only QUIC fallback rule.

Linux H2 selects TCP_CONGESTION=bbr before connect/listen; if unavailable or readback does not match, selects cubic and verifies it. Connected/accepted sockets are checked. Reject other Linux controllers. H3 retains Quinn BbrConfig and actual controller check: BBR is available in this backend on both supported platforms, so no alternative is needed today.

Windows H2 delegates TCP congestion control to the native OS. Microsoft documents CUBIC as the default on client Windows (https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpsetting). TCP supplemental templates can be inspected via Get-NetTCPSetting or netsh interface tcp show supplemental. Do not mutate host templates or require elevation from the app. No supported per-socket selection/readback contract has been confirmed (https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options). Customized OS policy can select a different controller; report os_managed_unverified, not a verified CUBIC claim. Lack of BBR2 does not block H2. This is a documented platform limitation, not an application setting.

## Acceptance

Native Linux: actual controller readback on listener and both connected peers, byte transfer, CUBIC positive and optional Reno negative. Native Windows: real TCP byte transfer without a false controller label. Keep all prior H2/H3, security, cross-host and QUIC BBR checks. Performance comparisons remain required. No new CI job, no test skip, no claim of measured advantage.

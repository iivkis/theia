# ADR-0076: native browser functional coverage over H3 and QUIC protocol rejection

**Status:** proposed, pending full native CI.

The current Chromium browser smoke exercises the compiled native client through a guarded local SOCKS5 path with an H2 tunnel. Extend the same functional test to explicit H3, using the existing production QUIC endpoint and authenticated server. The server has no H2 TCP listener; no automatic fallback is possible. Keep the origin, guard, CA, authorization, request/response markers and DOM assertion unchanged. This tests browser use of the proxy over the H3 transport, not browser-origin HTTP/3 or equality of browser network packets.

Separately, configure isolated real QUIC peers with the correct trusted test certificate but incompatible or absent ALPN. The production H3 client must reject TLS before any application streams. Preserve existing wrong-hostname, wrong-CA, wrong-bearer, wrong-grant and ACL negative checks. No change to runtime transport configuration, TLS verification, auth or HTTP framing.

Native Linux and Windows execute both browser scenarios within the existing browser matrix. Existing direct Chromium H2 reference remains mandatory. Actual browser-origin H3 functional reference remains separate and open; no synthetic parity, no DPI-invisibility claim, no release readiness. Full exact-head CI required. Record observed Go-removal timings separately from these tests.

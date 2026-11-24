# Theia local rustls dependency

Upstream: https://github.com/rustls/rustls/tree/f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb/rustls (0.23.46).
The ordinary library sources were copied from that exact commit. The three
license files are the contents of the upstream root license files (the
upstream crate paths are symlinks). The standalone dependency manifest
expands upstream workspace dependency declarations and omits upstream
test targets/dev dependencies. Upstream binary test fixtures are not
vendored; upstream tests are not a workspace member.

The only protocol change is an optional initial ClientHello random callback.
It is called before the message is committed to the transcript and updates
both the typed ClientHello and the internal connection random. It rejects
HRR, ECH, resumption and early data when configured. Existing callers retain
upstream behavior. No claim of browser fingerprint parity or production
readiness is implied. Mandatory independent regression and review remain
part of the main acceptance stage.

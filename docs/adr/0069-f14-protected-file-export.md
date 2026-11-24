# ADR-0069: F-14 M4.4e — protected one-time invitation file export

**Status:** prepared, pending native CI.

## Decision

Reuse the platform private credential creation primitives rather than create a second permissions mechanism. After durable server issuance/rotation save, allow a separately confirmed file export from the one-time offer. The worker consumes the offer, compares the saved config bytes and creates a fresh protected directory and create-new file beside the configured server TOML. The output is the canonical v1 URI with no new fields. Display only the resulting path, not the URI. Failed confirmed attempts are not retried with the same bearer; explicit new issuance or rotation is required.

## Acceptance

- Given unsaved issuance, stale saved config, wrong role or consumed offer, export refuses.
- Given saved issuance, f enters review; cancel returns to offer; separate y starts protected file creation. Rendering remains responsive and never shows URI.
- Given exported file, existing local reader decodes exact bearer and normal guarded import creates an inactive profile. No implicit CA trust or runtime Apply.
- Given previous output, a fresh export cannot overwrite it. Native Linux mode and Windows DACL use shared creation primitives; existing native ACL tests stay mandatory.

- Existing native H3 binary E2E uses actual Editor issuance, protected file export, import, explicit profile selection and real OPEN_OK over both local proxies. The test reserves a common TCP/UDP port and explicitly selects its numeric fixture endpoint after import; no automatic profile activation or endpoint rewriting.
- Uncertain write state in issuance/rotation and disable panels does not claim the old file survived, and retry is blocked pending reopen.

## Limits

The destination parent must be trusted. No secure transport to a client, clipboard, QR, automatic cleanup, durable publication across power loss, or physical-local-volume guarantee. Process interruption may leave a private orphan. The exported credential is intentionally readable by its owner. No production F-18 change. Full exact-head CI required.

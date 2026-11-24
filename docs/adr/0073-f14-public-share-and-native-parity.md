# ADR-0073: saved public sharing and native F-14 lifecycle parity

**Status:** accepted in PR #109, exact-head run 45397074048 (13/13).

## Decision

Make the normative public default available as a separate read-only editor action (l). Use the selected saved typed server inbound or client profile and the existing strict v1 public codec. Refuse dirty/editing/pending-issuance or stale files. Never recover a token from a digest or read env/file credentials. No CA or authorization is conveyed. Incompatible ports and non-default TLS profile remain unrepresentable.

Given a valid selected saved record, when opening public share, then a repeatable tokenless URI is shown without changing config or generating a user. Esc/Enter closes the view. Given dirty or stale state or incompatible record, refuse.

Port the already implemented Linux binary account recovery acceptance sequence into the existing native Windows Named Pipe Apply test: import the original grant with independent CA, export a new bearer after explicit disabled-user recovery, update only credential reference and preserve old file, require no admission before separate content-bound Apply, and reject both previous tokens afterward. The new saved bearer must reach H2/H3 OPEN_OK. Keep existing negative cases and CI gates.

## Limits

No remote management, automatic Apply, new TLS/profile/wire behavior, hard revocation, secure deletion, physical host transfer or power-loss guarantee. Public data may still contain sensitive endpoint information; sharing is an explicit action. Windows and Linux local recovery tests are separate from the existing WSL2 cross-host gate. F-14 status must reflect exact CI evidence, not merely this implementation.

See [F14_ACCEPTANCE.md](../F14_ACCEPTANCE.md) for the requirements-to-evidence map and outstanding limitations. Do not close the P0 gate solely on the existence of this PR.

## Additional cross-host acceptance

Use the existing wrong-token scenarios as the public import negative cases. An explicitly selected incorrect environment credential must fail both proxies. After stopping the process, replace only the saved credential using the matching confidential invitation and prove a new native Windows client succeeds on the unchanged Linux grant for both H2/H3. Compare the full typed client configuration and retain strict CA. No extra CI job or server restart; two additional client launches. This does not prove cross-host server-side rotation.

# ADR-0071: F-14 M4.4g — explicit credential-only replacement

**Status:** accepted in PR #108, exact-head run 45395505034 (13/13).

Server rotation previously required a new client profile ID or manual credential file editing because duplicate import is deliberately rejected. Preserve that refusal. Add a separate credential replacement transaction, only after explicit user review of a matching existing profile.

Given an existing client profile and a confidential invitation matching ID, endpoint, SNI, default TLS profile and existing transport (or auto invitation), when r/y confirms replacement, then create a fresh private bearer and change only auth_token using the guarded TOML commit. Do not use preview CA; preserve all saved profile fields and active pointer. Reject public, mismatched, missing, dirty and uncertain states. Ordinary import remains unchanged.

Given a before-replacement refusal, remove only the newly created secret; after uncertain replacement, retain the potentially referenced secret and require reload. Never overwrite or remove the old file, even if it is referenced by another profile or process. No automatic cleanup.

The operation is local and does not establish that the token is accepted by the server. No new protocol or trust mode, no automatic Apply, connect or system proxy. Native CI and existing mandatory gates remain required. Regression tests compare complete saved documents except the new reference, exercise public/wrong endpoint/SNI/transport/stale inputs, inject failure on both sides of replacement, and drive the separate confirmation/cancellation in TUI. ADR-0070 is in the same consolidated CI block, including the known rustfmt correction.

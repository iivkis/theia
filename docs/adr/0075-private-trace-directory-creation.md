# ADR-0075: atomic private trace directory creation

**Status:** accepted in PR #110, exact-head run 45401698499 (13/13).

Run 45401060957 failed the original CLI contract because successful --help emitted unexpected stderr. The old assertion did not print the warning, so the exact cause is not established by the log. Inspection found a real race: create_dir_all followed by chmod allows concurrent process initialization to encounter a transient public mode. Repair the race without disabling diagnostics or weakening stderr checks.

Use recursive DirBuilder with Unix 0700 at creation; preserve the existing refusal of nonprivate directories without chmod of an existing path. Reject final Windows directory reparse points as well as symlinks. Preserve unique create-new trace files, bounded asynchronous logging and path-free warnings on genuine failure. Trusted parent path and Windows inherited ACL assumptions remain.

Given a fresh shared nested directory, when twelve native CLI processes start concurrently, then all return successful help with empty stderr, distinct traces and complete startup/completion markers. Given an existing public directory on Unix, refuse without changing its permissions, write no logs and emit a path-free warning while the CLI remains available. Unit tests cover private nested creation, final symlink refusal and existing mode. Preserve the original CLI assertion, add diagnostic output to identify any future failure.

No runtime TLS/HTTP changes. No new workflow jobs; validate in the same consolidated Go-removal PR. The new test is a controlled concurrency regression, not a proof against hostile parent replacement or Windows ACL attacks.

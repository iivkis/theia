# ADR-0080: Rustfmt repair before native CI

**State:** proposed; exact-head CI and real repair/dispatch acceptance required.

Rustfmt is still checked before all native jobs. A successful local formatting pass that changes only tracked regular Rust files marks repairable drift and fails specification. Native jobs are skipped and the old ci-gate cannot pass. Syntax/tool failures or unexpected file changes are hard failures, not a request to push.

Only a same-repository pull_request head that is not main, default or base is eligible for the separate repair job. Checkout exact original head with no persisted credentials, run rustfmt for all three workspaces, require clean idempotent tracked Rust-only diff, create a single direct-child commit. Only the repair job receives contents/actions write; the final push uses an exact old-head lease and cannot overwrite a concurrent edit. No PAT, no force history rewrite, no fork writes. Explicit workflow_dispatch is necessary because GITHUB_TOKEN pushes do not automatically run ordinary push CI, and bot PR events may need approval.

Dispatch carries the new SHA, and specification refuses a mismatch. Full mandatory matrix runs, no release-only build, no recursive auto-repair on dispatch. Clean ordinary runs still have 13 mandatory successes; repair is skipped. No post-green change, no test overlays. If the branch moved, tool fails, permissions forbid push or dispatch fails, CI remains unaccepted. Manual dispatch remains available. Actual GitHub permissions and branch rules may prevent auto-repair; never bypass them.

Reference: [GitHub token workflow triggers](https://docs.github.com/en/actions/concepts/security/github_token).

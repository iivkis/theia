# ADR-0078: Compact default safe trace and current testing contract

## Decision

Preserve ADR-0058 default-on privacy, process-local correlation, bounded asynchronous queue, per-process rotation, path-free diagnostic warnings and failure artifacts. Filter by severity before formatting or enqueueing. Default to info; accept the exact environment values error, warn, info, debug, trace via THEIA_TRACE_LEVEL. Invalid/absent values select info. THEIA_TRACE_OFF=1 still wins. No TOML schema change; management.log_level remains independent.

Successful tunnel establishment and intermediate relay events are debug; retain process/listener lifecycle, server request completion and local proxy session completion at info, together with every preexisting warn/error. Trace retains per-frame events only when explicitly requested. Keep the existing record format, source locations and counters, and two 25 MiB segments. Do not automatically delete historical or potentially live process logs; that requires a separate cross-process retention design. No promise of measured speed or storage savings.

The testing guide describes current gates instead of repeating historical PR reports. Historical ADRs, implementation plan, CI performance evidence and all test/CI jobs remain.

## Acceptance and limitations

Native tests cover severity ordering, default/invalid settings, off precedence, quiet failure retention, real client preflight debug filtering, existing rotation, concurrency and privacy regressions. CI-only acceptance remains required for the exact head. This is not an audit proving that all log callsites are useful or all public Rust APIs are reachable. No changes to TLS, proxy semantics, wire/TOML formats, dependencies or CI DAG.

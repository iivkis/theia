# F-15 routing acceptance

Run from the exact tested revision. This external diagnostic is deliberately
not a substitute for mandatory native CI or a real physical-node test.

## Actual XTLS DAT and snapshot CPU/size

```sh
cargo test -p theia --locked --release --test routing_real_dat -- --ignored --nocapture
```

The test downloads a single current XTLS release using the production loader
(GeoSite Standard `geosite.dat` and GeoIP Lite `geoip-lite.dat`),
verifies both published hashes and selected categories, reloads the pinned
files, checks IPv4/IPv6 and domain decisions, then builds and decodes three
snapshots and rejects corruption. It prints exact release, hashes, byte sizes,
download+activation wall time, and local build/decode timings. These are not
network RTT or throughput. Save raw output, git SHA, OS, CPU and test date.

The compact pair is the only default source. It lacks worldwide IP
geolocation and expanded domain lists; XTLS Lite aliases cn/ru/ir have
regional whitelist semantics, not full-edition country geolocation.
Use explicit in-cn/in-ru/in-ir for the regional meaning and review old
rules before selecting compact data. An unavailable category rejects
the candidate; no automatic fallback or category substitution.
Old full/expanded files and active.toml are retained but are not used
as compact data. Existing pinned configurations must be reviewed and
re-selected through the guarded routing draft, save and Apply. A new
compact pointer is active-standard-lite.toml; a matching upstream
release tag alone never authorizes reuse of the old edition.

## External routing evidence

Use `scripts/routing-two-host.py` on authorized machines: a client, a VPS with
distinct observable public egress, and a controlled origin reachable from both
(the origin can be a separate witness). Use unique uncached DNS names and
collect independent complete client and VPS DNS evidence, including any
encrypted resolver paths. Run both proxy protocols for H2/H3 and own TLS/REALITY.
Record exact SHA, configuration revision, DAT release and hashes, distinct
egress addresses and origin and DNS evidence for each run. Missing captures
or virtualized hosts must not be labeled physical acceptance.

## Conditional snapshot refresh (DEV v1)

The authenticated routing GET may carry a single canonical lowercase 64-hex
`theia-routing-digest` header without a domain header. The server returns the
full snapshot on a different digest; an exact match returns 40 bytes:
ASCII `THEIANC1` then the 32-byte digest. It retains existing status, body
bounds, TLS identity, grants, channel binding and quota admission. The DNS
preflight (domain + digest) remains unchanged. A client accepts a receipt
only against its own previously verified in-memory snapshot and rechecks the
durable revision/digest floor before extending freshness. No offline direct
fallback. Changed snapshots still transfer fully; category-level delta and
native TUN/UDP remain separate work.

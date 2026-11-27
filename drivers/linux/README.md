# Linux pre-verdict attribution boundary

The normal NFQUEUE consumer still classifies application and domain evidence as Unknown. The optional isolated tagged-socket consumer runs the same native verdict path with an additional mandatory kernel socket gate:

- The kernel nftables LOCAL_OUT socket mark and complete TCP/UDP tuple select a separate non-bypass queue for an explicitly owned, connected socket.
- The private queue identity, exact socket cookie, rule owner nonce and nftables generation must agree before the policy lookup and immediately before the actual NFQUEUE verdict. Carrier rule CAS transactions preserve the tagged rule. An unmarked packet with the reserved tuple on the ordinary queue is denied.
- `serve_linux_collected_queues` additionally owns a live, pinned CO-RE cgroup connect/sendmsg collector on the namespace's current-thread executor. A `VerdictCollector` is created from that collector, the live tagged descriptor and the original process FD number. Its private ring is drained before and after policy work, with loss checks, process birth, socket cookie, executable inode/dev and SHA-256 corroboration. Missing, stale, conflicting or revoked observations deny the tagged packet, and the raw flow latch cannot be reused under a different cookie.
- `cgroup_skb/egress` is downstream of LOCAL_OUT: its observations are not used to approve the held NFQUEUE packet.
- This is a one-tagged-socket lab and not an application hash authorization source. A connect/sendmsg observation plus a live descriptor does not identify every sender using a shared or inherited socket. Expiry is intentionally conservative (two seconds); persistent traffic without fresh corroboration is denied. No arbitrary-application acquisition, production host capture, loaded-image attestation or transparent application-based routing is claimed.

The existing privileged tagged-queue fixture now exercises actual kernel queue selection, owned rules CAS, a stale generation, a cleared mark on the same tuple and a different ordinary socket. Native raw verdict regressions cover cookie replacement and attempts to reuse a denied flow. The optional collector still requires verifier and physical integration acceptance. Do not equate fixture source or static code inspection with test execution.


## Managed arbitrary-destination redirect in a disposable network namespace

This is an isolated F-15 lab entry point, not production Connect. It requires a separately provisioned network namespace, an already working ordinary route to the literal configured carrier peer(s), and a root-owned 0700 journal directory. No host routing rules or sysctls are changed by Theia. Do not run in a namespace with untrusted CAP_NET_ADMIN/CAP_NET_RAW holders, foreign packet mark manipulation, raw L2 access or an independent privileged network owner. For this static fixture, IPv6 carrier neighbor resolution must already be provisioned; external ICMPv6/NDP is not generally admitted by the new guard.

Run only inside the reviewed namespace, for example:

    ip netns exec THEIA_LAB theia client linux --redirect-lab --config /absolute/client.toml --journal /absolute/private/guard.toml --port 49001 --confirm-isolated

The executable checks the current namespace against /proc/1/ns/net. The owner binds four transparent TCP/UDP listeners before atomically installing one inet table with route_out, output, redirect_in, egress and forward base chains. Policy route readback uses kernel RTM_GETROUTE for multiple IPv4 and IPv6 probes; it is not exhaustive proof of all routes. The managed runtime owns dual-stack policy routes and queues external TCP/UDP packets for the policy decision. Pass uses a reserved verdict mark; Redirect uses the separate reroute mark and must leave through lo. Carrier exemptions remain bound to authenticated live sockets. Missing routing or listeners results in a drop, not original egress. Local traffic is intentionally outside this external scope. Carrier admissions require actual non-inheritable non-sharing descriptors, matching live cookie, protocol and exact tuple; all three egress gate rules change in one generation-checked transaction. The heartbeat checks the retained live sockets and the owned rules. Local UDP replies do not obtain external egress exemptions in this mode.

The same NativeIngress, policy cache, FlowLease, TCP/UDP relay and XHTTP H2/H3 factories are used for arbitrary nonlocal unicast destinations with a usable original route. Unresolved policy, Drop, unsupported protocols, ambiguous destination/identity, TCP early data where unsupported and UDP reverse-bind conflicts (including the listener's own port) are denied, not silently passed. No application or domain identity is inferred from the socket tuple. Pass and Redirect share the native flow decision. Modify uses the conservative Redirect fallback only; active modification is not accepted.

On explicit local Ctrl+C, stop the test applications first. Runtime revokes carrier leases, drains/aborts relays and restores only its owned nftables table by generation CAS. Owned route objects are recovered first, while the nft guard still exists. Foreign or uncertain objects require manual review. After hard-kill, the table is intended to remain fail-closed in the same live namespace; recovery is explicitly requested, never automatic:

    ip netns exec THEIA_LAB theia client linux --recover-lab --journal /absolute/private/guard.toml --confirm-isolated-recovery

A foreign generation or partial uncertain transaction is a refusal requiring manual review. The namespace table is not persistent across reboot. Do not claim production, crash or reboot acceptance until the new exact-SHA kernel fixture and independent physical H2/H3 traffic tests pass. The privileged fixture now uses the real installer and a peer-veth AF_PACKET observer for carrier-positive, same-target ordinary-negative, revoke, missing listener, missing policy route, owner drop and explicit-recovery positive controls.

## Explicit host and boot laboratory

The host lab is restricted to root in the PID-1 network namespace and requires an existing root-owned protected /var/lib/theia/guard directory. It uses host.toml plus host.toml.routes, machine/boot identity and exact object readback. The RTNL manager owns two local routes and two fwmark rules using table and priority 21577; no pre-existing reserved object is adopted. RTNL does not offer a generation CAS like nftables; concurrent privileged route changes and uncertain create/readback require review. Do not run with an independent network administrator or untrusted raw sockets.

`theia client linux --host-redirect-lab --config PATH --port N --confirm-disposable-local-console` is only for a disposable static-network machine with an independent console. DHCP, NDP, ARP/raw L2, local resolver caches, interface churn and foreign firewall managers require acceptance. Do not run on a remotely managed machine. The optional theia-host-guard.service is an uninstalled systemd example. It rearms a previously active same-machine journal with empty carrier admissions and a non-bypass queue before network-pre.target; it does not prove initramfs or early-network ordering. Explicit recovery is `theia client linux --host-guard-recover --confirm-disposable-local-console`. Production Connect remains disabled.

TCP/UDP port 53 is locally terminated for single IN A/AAAA questions. The authenticated H2/H3 routing request uses the explicit theia-native-dns header; server and client recheck policy, ACL and digest. Answers have TTL zero because the current wire format lacks authoritative TTL. Unsupported queries are refused; DoH/DoT, DNSSEC, application/domain binding, local resolver service/cache interception and arbitrary DNS types are not completed. Native bootstrap requires a literal carrier endpoint. No local DNS fallback.

All new kernel and physical fixtures require execution on the exact build SHA. Source changes are not acceptance evidence.

# Linux pre-verdict attribution boundary

The normal NFQUEUE consumer still classifies application and domain evidence as Unknown. The optional isolated tagged-socket consumer runs the same native verdict path with an additional mandatory kernel socket gate:

- The kernel nftables LOCAL_OUT socket mark and complete TCP/UDP tuple select a separate non-bypass queue for an explicitly owned, connected socket.
- The private queue identity, exact socket cookie, rule owner nonce and nftables generation must agree before the policy lookup and immediately before the actual NFQUEUE verdict. Carrier rule CAS transactions preserve the tagged rule. An unmarked packet with the reserved tuple on the ordinary queue is denied.
- `serve_linux_collected_queues` additionally owns a live, pinned CO-RE cgroup connect/sendmsg collector on the namespace's current-thread executor. A `VerdictCollector` is created from that collector, the live tagged descriptor and the original process FD number. Its private ring is drained before and after policy work, with loss checks, process birth, socket cookie, executable inode/dev and SHA-256 corroboration. Missing, stale, conflicting or revoked observations deny the tagged packet, and the raw flow latch cannot be reused under a different cookie.
- `cgroup_skb/egress` is downstream of LOCAL_OUT: its observations are not used to approve the held NFQUEUE packet.
- This is a one-tagged-socket lab and not an application hash authorization source. A connect/sendmsg observation plus a live descriptor does not identify every sender using a shared or inherited socket. Expiry is intentionally conservative (two seconds); persistent traffic without fresh corroboration is denied. No arbitrary-application acquisition, production host capture, loaded-image attestation or transparent application-based routing is claimed.

The existing privileged tagged-queue fixture now exercises actual kernel queue selection, owned rules CAS, a stale generation, a cleared mark on the same tuple and a different ordinary socket. Native raw verdict regressions cover cookie replacement and attempts to reuse a denied flow. The optional collector still requires verifier and physical integration acceptance. Do not equate fixture source or static code inspection with test execution.


## Managed arbitrary-destination redirect in a disposable network namespace

This is an isolated F-15 lab entry point, not production Connect. It requires a separately provisioned network namespace, externally owned IPv4/IPv6 policy routes (fwmark 0x5449 -> a dedicated routing table with default local routes via lo), an already working ordinary route to the literal configured carrier peer(s), and a root-owned 0700 journal directory. No host routing rules or sysctls are changed by Theia. Do not run in a namespace with untrusted CAP_NET_ADMIN/CAP_NET_RAW holders, foreign packet mark manipulation, raw L2 access or an independent privileged network owner. For this static fixture, IPv6 carrier neighbor resolution must already be provisioned; external ICMPv6/NDP is not generally admitted by the new guard.

Run only inside the reviewed namespace, for example:

    ip netns exec THEIA_LAB theia client linux --redirect-lab --config /absolute/client.toml --journal /absolute/private/guard.toml --port 49001 --confirm-isolated

The executable checks the current namespace against /proc/1/ns/net. The owner binds four transparent TCP/UDP listeners before atomically installing one inet table with route_out, output, redirect_in, egress and forward base chains. Policy route readback uses kernel RTM_GETROUTE for multiple IPv4 and IPv6 probes; it is not exhaustive proof of all routes. External TCP/UDP packets receive a reserved routing mark and are redirected to the transparent listeners; the actual postrouting device must be lo unless the packet carries an authenticated live carrier's distinct mark and exact tuple. Missing routing or listeners results in a drop, not original egress. Local traffic is intentionally outside this external scope. Carrier admissions require actual non-inheritable non-sharing descriptors, matching live cookie, protocol and exact tuple; all three egress gate rules change in one generation-checked transaction. The heartbeat checks the retained live sockets and the owned rules. Local UDP replies do not obtain external egress exemptions in this mode.

The same NativeIngress, policy cache, FlowLease, TCP/UDP relay and XHTTP H2/H3 factories are used for arbitrary nonlocal unicast destinations with a usable original route. Unresolved policy, Pass/Drop, unsupported protocols, ambiguous destination/identity, TCP early data where unsupported and UDP reverse-bind conflicts (including the listener's own port) are denied, not silently passed. No application or domain identity is inferred from the socket tuple. This is a Redirect-only native lab, not a complete Pass/Modify/DNS host backend.

On explicit local Ctrl+C, stop the test applications first. Runtime revokes carrier leases, drains/aborts relays and restores only its owned nftables table by generation CAS. Externally provisioned routes remain unchanged. After hard-kill, the table is intended to remain fail-closed in the same live namespace; recovery is explicitly requested, never automatic:

    ip netns exec THEIA_LAB theia client linux --recover-lab --journal /absolute/private/guard.toml --confirm-isolated-recovery

A foreign generation or partial uncertain transaction is a refusal requiring manual review. The table is not persistent across reboot. Do not claim production, crash or reboot acceptance until the new exact-SHA kernel fixture and independent physical H2/H3 traffic tests pass. The privileged fixture now uses the real installer and a peer-veth AF_PACKET observer for carrier-positive, same-target ordinary-negative, revoke, missing listener, missing policy route, owner drop and explicit-recovery positive controls.

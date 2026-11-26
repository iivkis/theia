#!/usr/bin/env python3
"""Explicit, authorized two-machine F-15 TCP routing acceptance.

origin: run on a controlled destination reachable from the client and VPS.
Use three exclusive ports, no other traffic, and firewall access to test
participants. Configure three fresh DNS names in the test zone, all resolving
to this destination. Configure Theia rules for those names before probe.

probe: run on the actual client with its already running Theia HTTP/SOCKS5
proxy. Destination names are sent only in CONNECT/SOCKS5, not resolved here.

verify: compare the two logs and complete DNS query evidence collected from
the client and VPS resolvers (including encrypted resolver paths). The DNS
files contain one queried name per line. Use fresh, uncached names and isolate
the test from other applications. No change to host networking is made here.
A missing/incomplete capture is NOT a DNS leak test pass.
"""
import argparse
import ipaddress
import json
import re
import secrets
import socket
import socketserver
import struct
import threading
from pathlib import Path

MAX_LINE = 4096
TIMEOUT = 15
ROUTES = ("direct", "allowed", "blocked")
TRANSPORTS = ("http", "socks5")


def name(value):
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        raise ValueError("use explicit lower-case ASCII DNS names")
    if "." not in value or ".." in value:
        raise ValueError("use a fully qualified test DNS name")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("DNS names, not IP literals, required")


def endpoint(value):
    host, port = value.rsplit(":", 1)
    address = ipaddress.ip_address(host.strip("[]"))
    if not address.is_loopback:
        raise ValueError("local proxy must be loopback")
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return str(address), port


def receive(stream, count):
    data = bytearray()
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise RuntimeError("premature EOF")
        data.extend(chunk)
    return bytes(data)


def line(stream):
    data = bytearray()
    while len(data) < MAX_LINE:
        data.extend(receive(stream, 1))
        if data.endswith(b"\n"):
            return bytes(data)
    raise RuntimeError("response exceeds bound")


def establish(stream, protocol, hostname, port):
    raw = hostname.encode("ascii")
    if protocol == "http":
        authority = f"{hostname}:{port}"
        stream.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
        status = line(stream)
        match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3}) [^\r\n]*\r\n", status)
        if not match:
            raise RuntimeError("invalid HTTP response")
        size = len(status)
        while True:
            header = line(stream)
            size += len(header)
            if size > MAX_LINE:
                raise RuntimeError("HTTP headers exceed bound")
            if header == b"\r\n":
                break
        code = int(match.group(1))
        return code == 200, code
    stream.sendall(b"\x05\x01\x00")
    if receive(stream, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 greeting rejected")
    stream.sendall(b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + struct.pack("!H", port))
    version, code, reserved, atyp = receive(stream, 4)
    if version != 5 or reserved != 0 or code > 8:
        raise RuntimeError("invalid SOCKS5 reply")
    size = {1: 4, 4: 16}.get(atyp)
    if atyp == 3:
        size = receive(stream, 1)[0]
    if size is None:
        raise RuntimeError("invalid SOCKS5 bound address")
    receive(stream, size + 2)
    return code == 0, code


def origin(args):
    lock = threading.Lock()
    servers = []
    ports = [args.direct_port, args.allowed_port, args.blocked_port]
    if len(set(ports)) != 3 or not all(1 <= p <= 65535 for p in ports):
        raise ValueError("three distinct dedicated ports required")
    with Path(args.log).open("x", encoding="utf-8") as log:
        def record(item):
            with lock:
                log.write(json.dumps(item, separators=(",", ":")) + "\n")
                log.flush()

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                peer = str(ipaddress.ip_address(self.client_address[0]))
                route = self.server.route
                record({"event": "accept", "route": route, "peer": peer})
                self.request.settimeout(TIMEOUT)
                try:
                    nonce = line(self.request).decode("ascii").strip()
                    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
                        return
                    record({"event": "payload", "route": route, "peer": peer, "nonce": nonce})
                    self.request.sendall((json.dumps({"nonce": nonce, "peer": peer}) + "\n").encode("ascii"))
                except (OSError, RuntimeError, UnicodeError):
                    return

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            address_family = socket.AF_INET6 if ipaddress.ip_address(args.listen).version == 6 else socket.AF_INET

        threads = []
        try:
            for route, port in zip(ROUTES, ports):
                server = Server((args.listen, port), Handler)
                server.route = route
                servers.append(server)
            for server in servers:
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                threads.append(worker)
            record({"event": "ready", "ports": dict(zip(ROUTES, ports))})
            print("Origin ready; stop after probe completes.", flush=True)
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
        finally:
            for server in servers[:len(threads)]:
                server.shutdown()
            for server in servers:
                server.server_close()
            record({"event": "stopped"})


def probe(args):
    names = dict(zip(ROUTES, map(name, [args.direct_name, args.allowed_name, args.blocked_name])))
    ports = dict(zip(ROUTES, [args.direct_port, args.allowed_port, args.blocked_port]))
    expected = {"direct": str(ipaddress.ip_address(args.direct_peer)),
                "allowed": str(ipaddress.ip_address(args.allowed_peer))}
    if len(set(names.values())) != 3 or len(set(ports.values())) != 3 or expected["direct"] == expected["allowed"]:
        raise ValueError("distinct test names, ports and observable egress IPs required")
    rows = []
    for protocol, proxy in zip(TRANSPORTS, [args.http, args.socks5]):
        for route in ROUTES:
            nonce = secrets.token_hex(16)
            with socket.create_connection(endpoint(proxy), timeout=TIMEOUT) as stream:
                accepted, status = establish(stream, protocol, names[route], ports[route])
                row = {"protocol": protocol, "route": route, "accepted": accepted,
                       "status": status, "nonce": nonce}
                if route == "blocked":
                    if accepted:
                        raise RuntimeError("blocked connection unexpectedly accepted")
                else:
                    if not accepted:
                        raise RuntimeError(f"{route} rejected: {status}")
                    stream.sendall((nonce + "\n").encode("ascii"))
                    response = json.loads(line(stream))
                    peer = str(ipaddress.ip_address(response["peer"]))
                    if response["nonce"] != nonce or peer != expected[route]:
                        raise RuntimeError(f"{route}: unexpected egress or response")
                    row["peer"] = peer
                rows.append(row)
    with Path(args.report).open("x", encoding="utf-8") as out:
        json.dump({"names": names, "ports": ports, "expected": expected, "rows": rows}, out, indent=2)
    print("TCP probe passed; origin and DNS evidence must still be verified.")


def verify(args):
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    rows = report["rows"]
    events = [json.loads(value) for value in Path(args.origin_log).read_text(encoding="utf-8").splitlines()]
    if not events or events[0].get("event") != "ready" or events[-1].get("event") != "stopped":
        raise RuntimeError("origin log must contain the complete isolated run")
    if events[0]["ports"] != report["ports"]:
        raise RuntimeError("origin port mismatch")
    if len(rows) != 6 or {(r["protocol"], r["route"]) for r in rows} != {(p, r) for p in TRANSPORTS for r in ROUTES}:
        raise RuntimeError("incomplete probe matrix")
    if any(row["accepted"] != (row["route"] != "blocked") for row in rows):
        raise RuntimeError("wrong connection result")
    if report["expected"]["direct"] == report["expected"]["allowed"]:
        raise RuntimeError("egress addresses must be distinct")
    for route in ROUTES:
        accepted = [e for e in events if e.get("event") == "accept" and e.get("route") == route]
        payload = [e for e in events if e.get("event") == "payload" and e.get("route") == route]
        matching = [r for r in rows if r["route"] == route]
        if route == "blocked":
            if accepted or payload:
                raise RuntimeError("blocked destination received a connection")
        else:
            expected = report["expected"][route]
            if len(accepted) != 2 or len(payload) != 2 or any(e["peer"] != expected for e in accepted + payload):
                raise RuntimeError(f"{route}: origin connection or peer mismatch")
            if {e["nonce"] for e in payload} != {r["nonce"] for r in matching} or any(r.get("peer") != expected for r in matching):
                raise RuntimeError(f"{route}: origin payload mismatch")
    # Explicit, complete capture is required: empty client DNS evidence cannot
    # pass because the fresh direct name must have been observed locally.
    client = {v.strip().lower().rstrip(".") for v in Path(args.client_dns).read_text(encoding="utf-8").splitlines() if v.strip()}
    server = {v.strip().lower().rstrip(".") for v in Path(args.server_dns).read_text(encoding="utf-8").splitlines() if v.strip()}
    direct, allowed, blocked = (report["names"][r] for r in ROUTES)
    if direct not in client or allowed in client or blocked in client or allowed not in server or direct in server or blocked in server:
        raise RuntimeError("DNS query placement does not match policy")
    print("PASS: two proxy protocols, distinct origin peers, no blocked accept, expected DNS query placement in supplied complete captures.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    a = sub.add_parser("origin")
    a.add_argument("--listen", required=True)
    a.add_argument("--log", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--http", required=True)
    p.add_argument("--socks5", required=True)
    p.add_argument("--report", required=True)
    for route in ROUTES:
        a.add_argument(f"--{route}-port", type=int, required=True)
        p.add_argument(f"--{route}-port", type=int, required=True)
        p.add_argument(f"--{route}-name", required=True)
    p.add_argument("--direct-peer", required=True)
    p.add_argument("--allowed-peer", required=True)
    v = sub.add_parser("verify")
    for option in ("report", "origin-log", "client-dns", "server-dns"):
        v.add_argument(f"--{option}", required=True)
    args = parser.parse_args()
    {"origin": origin, "probe": probe, "verify": verify}[args.mode](args)


if __name__ == "__main__":
    main()

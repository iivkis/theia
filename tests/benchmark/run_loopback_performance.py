#!/usr/bin/env python3
"""Controlled, local-only native binary benchmark. No user traffic or pcap.

The witness counts encrypted carrier socket payload bytes in both directions,
NOT IP/link bytes or TCP retransmissions. TCP delay is application-relay delay,
not packet-level impairment. UDP loss is injected at the witness. All trials
use fresh client/server processes and identical deterministic application data.
A same-binary run is a smoke test and cannot establish performance acceptance.
"""
import argparse
import base64
import concurrent.futures
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import selectors
import socket
import socketserver
import statistics
import subprocess
import tempfile
import threading
import time

LOOP = "127.0.0.1"
WORKLOADS = {"interactive": (1, 16, 256), "bulk": (1, 8, 65536),
             "parallel": (4, 8, 8192)}
TIMEOUT = 8
MAX_PEERS = 16


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        data = sock.recv(size - len(result))
        require(data, "premature EOF")
        result.extend(data)
    return bytes(result)


def reserve_port(stack, kind=socket.SOCK_STREAM):
    """Use the OS allocator for the actual transport, holding the reservation."""
    sock = stack.enter_context(socket.socket(socket.AF_INET, kind))
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    sock.bind((LOOP, 0))
    return sock


class TrialPorts:
    """Own-TLS permits distinct TCP/UDP listeners. Never guess a UDP port from TCP.

    Reservations are held concurrently until the process needs the ports.
    The close-to-bind handoff is not atomic; a competing bind fails the trial.
    """
    def __init__(self, stack):
        self.h2_socket = reserve_port(stack)
        self.h3_socket = reserve_port(stack, socket.SOCK_DGRAM)
        self.http_socket = reserve_port(stack)
        self.socks_socket = reserve_port(stack)
        self.h2, self.h3, self.http, self.socks = (
            sock.getsockname()[1] for sock in
            (self.h2_socket, self.h3_socket, self.http_socket, self.socks_socket))
        require(len({self.h2, self.http, self.socks}) == 3, "TCP reservations overlap")

    def release_server(self):
        self.h2_socket.close()
        self.h3_socket.close()

    def release_client(self):
        self.http_socket.close()
        self.socks_socket.close()


class Counter:
    def __init__(self, condition):
        self.lock = threading.Lock()
        self.condition = condition
        self.counts = [0, 0, 0, 0, 0]  # bytes, units, dropped, delayed, forwarded
        self.errors = []

    def observe(self, size, datagram=False):
        with self.lock:
            self.counts[0] += size
            self.counts[1] += 1
            drop = datagram and self.condition == "udp-loss" and self.counts[1] % 20 == 0
            if drop:
                self.counts[2] += 1
            else:
                self.counts[4] += size
                if self.condition == "relay-delay":
                    self.counts[3] += 1
        if drop:
            return False
        if self.condition == "relay-delay":
            time.sleep(0.002)
        return True

    def snapshot(self):
        with self.lock:
            require(not self.errors, "controlled witness failed")
            return dict(zip(("carrier_bytes", "observed_units", "dropped_datagrams",
                             "delayed_units", "forwarded_bytes"), self.counts))

    def fail(self):
        with self.lock:
            self.errors.append("witness I/O failure")


class TCPFixture(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False

    def __init__(self, handler, target=None, counter=None):
        super().__init__((LOOP, 0), handler)
        self.target = target
        self.counter = counter
        self.stopping = threading.Event()
        self.slots = threading.BoundedSemaphore(MAX_PEERS)
        self.accept_lock = threading.Lock()
        self.accepted = 0
        self.thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05})
        self.thread.start()

    @property
    def port(self):
        return self.server_address[1]

    def accepted_count(self):
        with self.accept_lock:
            return self.accepted

    def process_request(self, request, address):
        with self.accept_lock:
            self.accepted += 1
        if not self.slots.acquire(blocking=False):
            if self.counter:
                self.counter.fail()
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        if self.counter and not self.stopping.is_set():
            self.counter.fail()

    def close(self):
        self.stopping.set()
        self.shutdown()
        self.server_close()
        self.thread.join(TIMEOUT)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(TIMEOUT)
        while True:
            block = self.request.recv(65536)
            if not block:
                self.request.shutdown(socket.SHUT_WR)
                return
            self.request.sendall(block)


class TCPWitness(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.create_connection((LOOP, self.server.target), TIMEOUT) as remote:
            def copy(src, dst):
                src.settimeout(0.25)
                while not self.server.stopping.is_set():
                    try:
                        block = src.recv(65536)
                    except socket.timeout:
                        continue
                    if not block:
                        dst.shutdown(socket.SHUT_WR)
                        return
                    self.server.counter.observe(len(block))
                    dst.sendall(block)

            def guarded(src, dst):
                try:
                    copy(src, dst)
                except OSError:
                    if not self.server.stopping.is_set():
                        self.server.counter.fail()
                    for sock in (src, dst):
                        try:
                            sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

            upload = threading.Thread(target=guarded, args=(self.request, remote), daemon=True)
            upload.start()
            guarded(remote, self.request)
            upload.join(TIMEOUT)
            if upload.is_alive() and not self.server.stopping.is_set():
                self.server.counter.fail()


class UDPWitness:
    def __init__(self, target, counter):
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind((LOOP, 0))
        self.port = self.front.getsockname()[1]
        self.target = target
        self.counter = counter
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        peers = {}
        with selectors.DefaultSelector() as sel:
            sel.register(self.front, selectors.EVENT_READ, None)
            try:
                while not self.stopping.is_set():
                    for key, _ in sel.select(0.05):
                        if key.data is None:
                            data, peer = self.front.recvfrom(65536)
                            require(peer[0] == LOOP, "non-loopback witness source")
                            if peer not in peers:
                                require(len(peers) < MAX_PEERS, "witness peer limit")
                                upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                upstream.connect((LOOP, self.target))
                                peers[peer] = upstream
                                sel.register(upstream, selectors.EVENT_READ, peer)
                            if self.counter.observe(len(data), datagram=True):
                                peers[peer].send(data)
                        else:
                            data = key.fileobj.recv(65536)
                            if self.counter.observe(len(data), datagram=True):
                                self.front.sendto(data, key.data)
            except (OSError, RuntimeError):
                if not self.stopping.is_set():
                    self.counter.fail()
            finally:
                for upstream in peers.values():
                    upstream.close()
                self.front.close()

    def close(self):
        self.stopping.set()
        self.thread.join(TIMEOUT)
        require(not self.thread.is_alive(), "UDP witness did not stop")


def config_files(directory, cert, key, h2, h3, front, http, socks, transport, token):
    q = lambda value: json.dumps(str(value), ensure_ascii=False)
    common = '\n[management]\nipc = "auto"\nlog_level = "error"\n[ui]\nlanguage = "en"\n'
    server = f'''schema_version = 1
[server]
enabled = true
[[server.inbounds]]
id = "bench"
path_prefix = "/v1/bench"
security_mode = "own-tls"
allowed_user_ids = ["fixture"]
h2_listen = "{LOOP}:{h2}"
quic_listen = "{LOOP}:{h3}"
server_name = "localhost"
tls_cert = {q("file:" + str(cert))}
tls_key = {q("file:" + str(key))}
[[server.users]]
id = "fixture"
token_sha256 = "{hashlib.sha256(token).hexdigest()}"
disabled = false
[server.policy]
allow_private_ips = true
max_connections_per_user = 16
max_connections_total = 32
connect_timeout_ms = 2000
'''
    client = f'''schema_version = 1
[client]
active_profile = "bench"
ingress_mode = "system_proxy"
[[client.profiles]]
id = "bench"
path_prefix = "/v1/bench"
server = "{LOOP}:{front}"
server_name = "localhost"
auth_token = "env:THEIA_BENCH_TOKEN"
security_mode = "own-tls"
tls_ca = {q("file:" + str(cert))}
transport = "{transport}"
xhttp_mode = "stream-one"
quic_connect_timeout_ms = 1600
quic_negative_cache_ttl_s = 900
[client.proxy]
http_listen = "{LOOP}:{http}"
socks5_listen = "{LOOP}:{socks}"
'''
    for name, content in (("server", server), ("client", client)):
        (directory / (name + ".toml")).write_text(content + common, encoding="utf-8")


def wait_port(port, processes):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        require(all(p.poll() is None for p in processes), "fixture process exited")
        try:
            with socket.create_connection((LOOP, port), 0.1):
                return
        except OSError:
            time.sleep(0.025)
    raise RuntimeError("fixture listener readiness deadline")


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def exchange(http_port, origin, stream, count, size, barrier):
    with socket.create_connection((LOOP, http_port), TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)
        barrier.wait(timeout=TIMEOUT)
        opened = time.perf_counter()
        authority = f"{LOOP}:{origin}"
        sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            require(len(header) < 8192, "unbounded proxy response")
            header.extend(recv_exact(sock, 1))
        require(header.startswith(b"HTTP/1.1 200 "), "CONNECT did not reach OPEN_OK")
        open_ms = (time.perf_counter() - opened) * 1000
        began = time.perf_counter()
        latencies = []
        for block in range(count):
            unit = bytes((stream + block + i) % 251 for i in range(min(size, 251)))
            data = (unit * ((size + len(unit) - 1) // len(unit)))[:size]
            t = time.perf_counter()
            sock.sendall(data)
            require(recv_exact(sock, size) == data, "byte-exact echo mismatch")
            latencies.append((time.perf_counter() - t) * 1000)
        sock.shutdown(socket.SHUT_WR)
        require(sock.recv(1) == b"", "missing clean half-close")
        return dict(open_ms=open_ms, latency_ms=latencies,
                    stream_bps=2 * count * size * 8 / (time.perf_counter() - began))


def cpu_seconds(processes):
    return sum(t.user + t.system for t in (p.cpu_times() for p in processes))


def sample_rss(processes):
    return sum(p.memory_info().rss for p in processes)


def trial(binary, cert, key, transport, workload, condition):
    import psutil

    streams, count, size = WORKLOADS[workload]
    reservations = ExitStack()
    counter = Counter(condition)
    witness = None
    origin = None
    children = []
    sampler = None
    sampling_stop = threading.Event()
    scratch = None
    try:
        ports = TrialPorts(reservations)
        witness = (TCPFixture(TCPWitness, ports.h2, counter) if transport == "h2"
                   else UDPWitness(ports.h3, counter))
        origin = TCPFixture(Echo)
        http, socks = ports.http, ports.socks
        token = secrets.token_bytes(32)
        env = dict(os.environ)
        for name in tuple(env):
            if name.startswith("THEIA_"):
                del env[name]
        env["THEIA_BENCH_TOKEN"] = base64.urlsafe_b64encode(token).decode().rstrip("=")
        if platform.system() == "Windows":
            # The immutable reference uses Tokio's default std-thread stack.
            # Match the candidate's worker reserve for both variants.
            env["RUST_MIN_STACK"] = str(8 * 1024 * 1024)
        scratch = tempfile.TemporaryDirectory(prefix="theia-perf-")
        if scratch:
            directory = Path(scratch.name)
            config_files(directory, cert, key, ports.h2, ports.h3, witness.port, http, socks, transport, token)
            for role, port, release in (("server", ports.h2, ports.release_server),
                                        ("client", http, ports.release_client)):
                release()
                # Keep diagnostics for failed startup of the controlled
                # fixture, not user traffic. Files avoid pipe backpressure.
                diagnostics = reservations.enter_context(tempfile.TemporaryFile())
                child = subprocess.Popen([str(binary), role, "run", "--config",
                                          str(directory / (role + ".toml"))],
                                         env=env, stdin=subprocess.DEVNULL,
                                         stdout=diagnostics, stderr=diagnostics)
                children.append(child)
                try:
                    wait_port(port, children)
                except RuntimeError as error:
                    diagnostics.seek(0, os.SEEK_END)
                    diagnostics.seek(max(0, diagnostics.tell() - 2048))
                    detail = diagnostics.read(2048).decode("utf-8", errors="replace")
                    detail = detail.replace(env["THEIA_BENCH_TOKEN"], "[redacted]")
                    raise RuntimeError(f"{role} startup failed (exit={child.poll()}): {detail}") from error
            ps = [psutil.Process(p.pid) for p in children]
            initial_cpu = cpu_seconds(ps)
            peak = [sample_rss(ps)]
            sample_errors = []
            def sample():
                try:
                    while not sampling_stop.wait(0.01):
                        peak[0] = max(peak[0], sample_rss(ps))
                except psutil.Error:
                    sample_errors.append(True)
            sampler = threading.Thread(target=sample)
            sampler.start()
            before = counter.snapshot()
            # Authenticated routing synchronization is legitimate startup traffic.
            # Charge it to total wire overhead, but forbid target connections
            # before the workload and separately prove its encrypted byte delta.
            require(origin.accepted_count() == 0, "unexpected target dial before trial")
            start = time.perf_counter()
            barrier = threading.Barrier(streams)
            with concurrent.futures.ThreadPoolExecutor(max_workers=streams) as executor:
                results = list(executor.map(
                    lambda i: exchange(http, origin.port, i, count, size, barrier),
                    range(streams)))
            duration = time.perf_counter() - start
            after = counter.snapshot()
            peak[0] = max(peak[0], sample_rss(ps))
            cpu = cpu_seconds(ps) - initial_cpu
            sampling_stop.set()
            sampler.join(TIMEOUT)
            require(not sampler.is_alive() and not sample_errors, "resource sampling failed")
            require(all(p.poll() is None for p in children), "fixture process exited during trial")
            application = 2 * streams * count * size
            require(after["carrier_bytes"] - before["carrier_bytes"] >= application,
                    "missing encrypted carrier evidence during workload")
            require(origin.accepted_count() == streams, "unexpected number of target connections")
            require(cpu >= 0 and peak[0] > 0, "invalid process resource evidence")
            if condition == "udp-loss":
                require(after["dropped_datagrams"] > before["dropped_datagrams"], "loss condition not exercised during workload")
            if condition == "relay-delay":
                require(after["delayed_units"] > before["delayed_units"], "delay condition not exercised during workload")
            result = dict(application_bytes=application, duration_s=duration,
                          cpu_s=cpu, sampled_peak_rss_bytes=peak[0],
                          latency_ms=[v for r in results for v in r["latency_ms"]],
                          open_ms=[r["open_ms"] for r in results],
                          stream_bps=[r["stream_bps"] for r in results],
                          errors=0, fallback=0, **after)
            return result
    finally:
        sampling_stop.set()
        if sampler:
            sampler.join(TIMEOUT)
        for child in reversed(children):
            stop(child)
        reservations.close()
        if witness:
            witness.close()
        if origin:
            origin.close()
        if scratch:
            scratch.cleanup()


def sha256(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def run(args):
    binary = {name: getattr(args, name).resolve(strict=True) for name in ("baseline", "candidate")}
    digests = {name: sha256(path) for name, path in binary.items()}
    smoke = digests["baseline"] == digests["candidate"]
    if not smoke:
        require(args.baseline_revision != args.candidate_revision, "comparative revisions must differ")
    rows = []
    for transport in ("h2", "h3"):
        for condition in args.conditions:
            if condition == "udp-loss" and transport == "h2":
                continue  # TCP relay cannot model TCP packet loss.
            for workload in WORKLOADS:
                for repetition in range(args.repetitions):
                    # Alternate order to reduce systematic warm-cache bias.
                    order = ("baseline", "candidate") if repetition % 2 == 0 else ("candidate", "baseline")
                    for variant in order:
                        try:
                            result = trial(binary[variant], args.cert.resolve(strict=True),
                                           args.key.resolve(strict=True), transport, workload, condition)
                        except Exception as error:
                            raise RuntimeError(
                                f"trial failed: {transport}/{condition}/{workload}/{repetition}/{variant}"
                            ) from error
                        rows.append(dict(transport=transport, condition=condition, workload=workload,
                                         trial=repetition, variant=variant, **result))
    return dict(schema=1, scope="controlled-loopback", mode="smoke" if smoke else "comparison",
                platform=platform.system().lower(), machine=platform.machine(),
                python=platform.python_version(), revisions=dict(baseline=args.baseline_revision,
                candidate=args.candidate_revision), binaries_sha256=digests,
                accounting="carrier-socket-payload-excludes-ip-and-tcp-retransmissions",
                rss="sampled-sum-client-server-10ms", conditions=args.conditions,
                repetitions=args.repetitions, rows=rows)


def main():
    p = argparse.ArgumentParser()
    for name in ("baseline", "candidate", "cert", "key", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--baseline-revision", required=True)
    p.add_argument("--candidate-revision", required=True)
    p.add_argument("--repetitions", type=int, default=2)
    p.add_argument("--conditions", nargs="+", choices=("clean", "relay-delay", "udp-loss"), default=["clean"])
    args = p.parse_args()
    require(2 <= args.repetitions <= 30 and len(set(args.conditions)) == len(args.conditions),
            "bounded repetitions and unique conditions required")
    require("clean" in args.conditions, "clean reference required")
    for value in (args.baseline_revision, args.candidate_revision):
        require(len(value) == 40 and all(c in "0123456789abcdef" for c in value), "exact revision required")
    require(not args.output.exists(), "refusing to overwrite evidence")
    result = run(args)
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(result, f, allow_nan=False, indent=2)
    print("Native controlled loopback measurements written; no release acceptance implied")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""CI-only Linux process inside a separate WSL2 VM.

Runs the *Linux* Theia executable (not a Windows process, mock server or
localhost client fixture). Only sanitized config and public trust anchors are
shared with the Windows test runner. The bearer itself never crosses to this
process: it receives only a SHA-256 digest on stdin.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time


def certificate(directory: Path, name: str) -> tuple[Path, Path]:
    cert = directory / (name + ".pem")
    key = directory / (name + ".key")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=localhost", "-days", "1",
            "-addext", "subjectAltName=DNS:localhost",
            # The actual Linux server presents this certificate as a TLS
            # end entity. CA:TRUE/keyCertSign was rejected by strict clients:
            # trust anchor registration does not make a CA valid as the leaf.
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature",
            "-addext", "extendedKeyUsage=serverAuth",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=True,
        timeout=25,
    )
    return cert, key


def relay(socket_to_echo: socket.socket) -> None:
    with socket_to_echo:
        data = bytearray()
        while True:
            chunk = socket_to_echo.recv(65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 2 * 1024 * 1024:
                return
        socket_to_echo.sendall(data)
        socket_to_echo.shutdown(socket.SHUT_WR)


def origin_listener(port: int, stop: threading.Event) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as origin:
        origin.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        origin.bind(("127.0.0.1", port))
        origin.listen(32)
        origin.settimeout(0.5)
        while not stop.is_set():
            try:
                connection, _ = origin.accept()
            except socket.timeout:
                continue
            threading.Thread(target=relay, args=(connection,), daemon=True).start()


def require_guest_ipv4(raw: str) -> None:
    try:
        guest_ip = ipaddress.ip_address(raw)
    except ValueError as error:
        raise RuntimeError("Linux server needs a valid guest IPv4") from error
    if guest_ip.version != 4 or guest_ip.is_loopback or guest_ip.is_unspecified:
        raise RuntimeError("Linux server must bind to a valid non-loopback guest IPv4")


def serve(args: argparse.Namespace) -> None:
    if os.name != "posix" or os.uname().sysname != "Linux":
        raise RuntimeError("Cross-OS server must run inside real Linux")
    require_guest_ipv4(args.ip)
    digest = input().strip()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise RuntimeError("invalid 32-byte bearer SHA-256 digest")

    shared = Path(args.shared)
    shared.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()

    with tempfile.TemporaryDirectory(prefix="theia-f14-linux-") as raw:
        private = Path(raw)
        trusted, key = certificate(private, "server")
        untrusted, _ = certificate(private, "untrusted")
        binary = private / "theia"
        shutil.copy2(args.binary, binary)
        binary.chmod(0o700)
        shutil.copyfile(trusted, shared / "trusted-ca.pem")
        shutil.copyfile(untrusted, shared / "wrong-ca.pem")
        configuration = f"""schema_version = 1

[server]
enabled = true

[[server.inbounds]]
path_prefix = "/v1/theia-example"
id = "cross"
allowed_user_ids = ["cross-user"]
quic_listen = "0.0.0.0:{args.port}"
h2_listen = "0.0.0.0:{args.port}"
server_name = "localhost"
tls_cert = "file:{trusted}"
tls_key = "file:{key}"

[[server.users]]
id = "cross-user"
token_sha256 = "{digest}"
disabled = false

[server.policy]
allow_private_ips = true
max_connections_per_user = 32
max_connections_total = 64
connect_timeout_ms = 2000

[server.policy.routing]
revision = 2

[[server.policy.routing.rules]]
name = "local direct"
action = "direct"
domains = ["full:localhost"]

[[server.policy.routing.rules]]
name = "blocked test name"
action = "blocked"
domains = ["full:blocked.invalid"]

[management]
ipc = "auto"
log_level = "error"

[ui]
language = "ru"
"""
        server_toml = shared / "server.toml"
        server_toml.write_text(configuration, encoding="utf-8")
        echo = threading.Thread(
            target=origin_listener, args=(args.origin_port, stop), daemon=True
        )
        echo.start()
        logs = private / "server.log"
        with logs.open("wb") as stderr:
            process = subprocess.Popen(
                [str(binary), "server", "run", "--config", str(server_toml)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr,
            )
            try:
                # A TCP listener alone is not an authenticated tunnel; the
                # native Windows tests verify real H2 and H3 OPEN_OK later.
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("Linux Theia server exited before readiness")
                    try:
                        with socket.create_connection(("127.0.0.1", args.port), timeout=0.25):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Linux Theia server failed to bind")
                (shared / "ready").write_text("LINUX_SERVER_READY\n", encoding="ascii")
                while not (shared / "stop").exists():
                    if process.poll() is not None:
                        raise RuntimeError("Linux Theia server exited during cross-OS test")
                    time.sleep(0.25)
            finally:
                stop.set()
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--shared", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--origin-port", type=int, required=True)
    serve(parser.parse_args())

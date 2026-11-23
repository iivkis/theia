#!/usr/bin/env python3
"""Mandatory native Windows + Linux WSL2 VM F-14 acceptance driver.

Not a cross-machine Internet test: both OS instances share an ephemeral hosted
Windows runner, but WSL2 uses a separate *real Linux kernel*, process space and
virtual NIC. There is no external relay, public scanner, private credential,
or "skip when unsupported": failure to provision WSL2 fails the CI job.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time

DISTRO = "Ubuntu-24.04"


def linux(*args: str, timeout: float = 20) -> str:
    result = subprocess.run(
        ["wsl.exe", "--distribution", DISTRO, "--", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
        timeout=timeout,
    )
    return result.stdout.strip()


def wsl_path(path: Path) -> str:
    return linux("wslpath", "-a", "-u", str(path.resolve()))


def guest_ip() -> str:
    candidates = linux("hostname", "-I").split()
    for address in candidates:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_loopback() and not ip.is_unspecified:
            return str(ip)
    raise RuntimeError("WSL2 has no routable non-loopback IPv4 NIC")


def is_listening(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=0.75):
            return True
    except OSError:
        return False


def main(binary: Path) -> None:
    if os.name != "nt":
        raise RuntimeError("native Windows runner is mandatory")
    if linux("uname", "-s") != "Linux":
        raise RuntimeError("WSL guest did not report a real Linux kernel")
    if not binary.is_file():
        raise RuntimeError("Linux-built server artifact was not downloaded")
    ip = guest_ip()
    print("F-14: native Windows client + WSL2 Linux VM; separate virtual NIC validated")
    token = secrets.token_bytes(32)
    digest = hashlib.sha256(token).hexdigest()
    token_b64 = base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")
    # Nothing here logs either secret, serialized invitation, or token file.
    port = secrets.randbelow(8000) + 42000
    origin = secrets.randbelow(8000) + 52000
    if port == origin:
        origin += 1

    with tempfile.TemporaryDirectory(prefix="theia-f14-xhost-") as dirname:
        shared = Path(dirname)
        server_script = Path(__file__).resolve().with_name("f14-wsl-server.py")
        command = [
            "wsl.exe", "--distribution", DISTRO, "--",
            "python3", wsl_path(server_script),
            "--shared", wsl_path(shared),
            "--binary", wsl_path(binary),
            "--ip", ip, "--port", str(port), "--origin-port", str(origin),
        ]
        server = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            assert server.stdin is not None
            server.stdin.write(digest.encode("ascii") + b"\n")
            server.stdin.close()
            deadline = time.monotonic() + 65
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    details = server.stderr.read().decode("utf-8", "replace")
                    raise RuntimeError("Linux test server failed to boot: " + details[-1500:])
                if (shared / "ready").is_file() and is_listening(ip, port):
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("Windows cannot reach Linux VM's actual TCP listener")

            print("F-14: verified Linux VM listener from native Windows over its guest IPv4")
            env = os.environ.copy()
            env.update(
                THEIA_F14_XHOST_RUN="yes",
                THEIA_F14_XHOST_ENDPOINT=f"{ip}:{port}",
                THEIA_F14_XHOST_ORIGIN_PORT=str(origin),
                THEIA_F14_XHOST_SERVER_CONFIG=str(shared / "server.toml"),
                THEIA_F14_XHOST_CA=str(shared / "trusted-ca.pem"),
                THEIA_F14_XHOST_WRONG_CA=str(shared / "wrong-ca.pem"),
                THEIA_F14_XHOST_TOKEN=token_b64,
            )
            subprocess.run(
                [
                    "cargo", "test", "--workspace", "--locked", "--test",
                    "f14_cross_host", "--", "--ignored", "--exact",
                    "linux_server_windows_client_f14_h2_h3_open_ok", "--nocapture",
                ],
                env=env,
                check=True,
                timeout=270,
            )
            print("F-14: real H2/H3 OPEN_OK, SOCKS5/CONNECT and negative PKI/auth passed")
        finally:
            (shared / "stop").write_text("stop\n", encoding="ascii")
            try:
                server.wait(timeout=12)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--linux-binary", type=Path, required=True)
    args = parser.parse_args()
    try:
        main(args.linux_binary)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as error:
        print(f"F-14 cross-OS acceptance failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error

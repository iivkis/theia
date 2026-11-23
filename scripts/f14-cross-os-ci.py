#!/usr/bin/env python3
"""Mandatory native Windows client -> real Linux WSL2 VM F-14 acceptance.

WSL2 is a separate Linux kernel and virtual NIC on a Windows-hosted runner,
NOT two independent physical/Internet machines. Files cross the OS boundary
only through explicit bounded stdin/stdout streams, NEVER through fragile
DrvFs /mnt/c or wslpath assumptions. No raw bearer is sent into Linux, TOML,
argv or logs; Linux receives its SHA-256 digest through a private pipe.
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
MAX_TRANSFER_BYTES = 256 * 1024 * 1024


def wsl_command(*args: str) -> list[str]:
    return ["wsl.exe", "--distribution", DISTRO, "--", *args]


def linux(*args: str, timeout: float = 20) -> str:
    result = subprocess.run(
        wsl_command(*args),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
        timeout=timeout,
    )
    return result.stdout.strip()


def guest_ip() -> str:
    candidates = linux("hostname", "-I").split()
    for address in candidates:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_loopback and not ip.is_unspecified:
            return str(ip)
    raise RuntimeError("WSL2 has no routable non-loopback IPv4 NIC")


def is_listening(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=0.75):
            return True
    except OSError:
        return False


def guest_exists(path: str) -> bool:
    result = subprocess.run(
        wsl_command("test", "-f", path),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=12,
    )
    return result.returncode == 0


def copy_into_guest(source: Path, destination: str) -> None:
    """Stream a non-secret source into a private absolute Linux path."""
    data = source.read_bytes()
    if not 0 < len(data) <= MAX_TRANSFER_BYTES:
        raise RuntimeError("Linux input artifact is empty or oversized")
    # Run dd directly: WSL command-line translation on Windows does not
    # preserve nested sh -c quotes reliably (exit 2 on native runners).
    # Linux coreutils dd is a binary-safe, bounded stdin consumer.
    result = subprocess.run(
        wsl_command("dd", f"of={destination}", "bs=1M", "status=none"),
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=65,
    )
    if result.returncode != 0:
        # Paths are random fixture names and no credentials were sent in stdin.
        diagnostics = result.stderr.decode("utf-8", "replace")[-800:].strip()
        raise RuntimeError(
            f"WSL dd transfer failed (status {result.returncode}): {diagnostics}"
        )
    linux("chmod", "700", destination)
    expected = hashlib.sha256(data).hexdigest()
    actual = linux("sha256sum", destination).split()[0]
    if expected != actual:
        raise RuntimeError("Linux artifact differs from the original Windows-side bytes")


def copy_public_from_guest(source: str, destination: Path) -> None:
    """Fetch only explicitly enumerated public certs and hash-only TOML."""
    result = subprocess.run(
        wsl_command("cat", source),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
    )
    if result.returncode != 0 or not 0 < len(result.stdout) <= 1024 * 1024:
        raise RuntimeError("Cannot read bounded Linux guest public fixture")
    destination.write_bytes(result.stdout)


def main(binary: Path, windows_test: Path, windows_client: Path) -> None:
    if os.name != "nt":
        raise RuntimeError("native Windows runner is mandatory")
    if linux("uname", "-s") != "Linux":
        raise RuntimeError("WSL guest did not report a real Linux kernel")
    if not binary.is_file():
        raise RuntimeError("Linux-built server artifact was not downloaded")
    if not windows_test.is_file() or not windows_client.is_file():
        raise RuntimeError("Precompiled native Windows test/client artifacts are missing")
    ip = guest_ip()
    print("F-14: native Windows client and separate WSL2 Linux VM virtual NIC verified")
    token = secrets.token_bytes(32)
    digest = hashlib.sha256(token).hexdigest()
    token_b64 = base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")
    port = secrets.randbelow(8000) + 42000
    origin = secrets.randbelow(8000) + 52000
    if port == origin:
        origin += 1

    # /tmp path is generated locally, cannot escape this fixed safe prefix.
    guest_dir = "/tmp/theia-f14-xhost-" + secrets.token_hex(12)
    subprocess.run(
        wsl_command("mkdir", "-m", "700", guest_dir),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=True,
        timeout=15,
    )
    try:
        server_script = Path(__file__).resolve().with_name("f14-wsl-server.py")
        guest_script = guest_dir + "/f14-wsl-server.py"
        guest_binary = guest_dir + "/theia"
        copy_into_guest(server_script, guest_script)
        copy_into_guest(binary, guest_binary)
        print("F-14: SHA-256 verified both Linux inputs over WSL stdin without DrvFs mounts")

        with tempfile.TemporaryDirectory(prefix="theia-f14-host-") as dirname:
            host_files = Path(dirname)
            command = wsl_command(
                "python3", guest_script,
                "--shared", guest_dir,
                "--binary", guest_binary,
                "--ip", ip, "--port", str(port), "--origin-port", str(origin),
            )
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
                        raise RuntimeError("Linux server failed to start: " + details[-1500:])
                    if guest_exists(guest_dir + "/ready") and is_listening(ip, port):
                        break
                    time.sleep(0.25)
                else:
                    raise RuntimeError("Native Windows cannot reach real WSL2 Linux TCP listener")

                print("F-14: Windows connected to the Linux VM on its non-loopback IPv4")
                for filename in ("server.toml", "trusted-ca.pem", "wrong-ca.pem"):
                    copy_public_from_guest(guest_dir + "/" + filename, host_files / filename)
                env = os.environ.copy()
                env.update(
                    THEIA_F14_XHOST_RUN="yes",
                    THEIA_F14_XHOST_ENDPOINT=f"{ip}:{port}",
                    THEIA_F14_XHOST_ORIGIN_PORT=str(origin),
                    THEIA_F14_XHOST_SERVER_CONFIG=str(host_files / "server.toml"),
                    THEIA_F14_XHOST_CA=str(host_files / "trusted-ca.pem"),
                    THEIA_F14_XHOST_WRONG_CA=str(host_files / "wrong-ca.pem"),
                    THEIA_F14_XHOST_TOKEN=token_b64,
                    THEIA_F14_CLIENT_BIN=str(windows_client.resolve()),
                )
                subprocess.run(
                    [
                        str(windows_test.resolve()), "--ignored", "--exact",
                        "linux_server_windows_client_f14_h2_h3_open_ok", "--nocapture",
                    ],
                    env=env,
                    check=True,
                    timeout=270,
                )
                print("F-14: real H2/H3 OPEN_OK, SOCKS5/CONNECT and PKI/auth negatives passed")
            finally:
                subprocess.run(
                    wsl_command("touch", guest_dir + "/stop"),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=15, check=False,
                )
                try:
                    server.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
    finally:
        subprocess.run(
            wsl_command("rm", "-rf", guest_dir),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=20, check=False,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--linux-binary", type=Path, required=True)
    parser.add_argument("--windows-test", type=Path, required=True)
    parser.add_argument("--windows-client", type=Path, required=True)
    args = parser.parse_args()
    try:
        main(args.linux_binary, args.windows_test, args.windows_client)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as error:
        print(f"F-14 cross-OS acceptance failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error

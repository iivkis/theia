#!/usr/bin/env python3
"""Independent standard TLS/H2 loopback test client. Not a browser emulator."""
import argparse
import ipaddress
import os
import socket
import ssl
import struct

MAX_FRAME = 16_384


def validate_loopback(address):
    host, separator, port = address.rpartition(":")
    if not separator:
        raise ValueError("numeric loopback address required")
    ip = ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
    if not ip.is_loopback or not port.isascii() or not port.isdecimal():
        raise ValueError("loopback only")
    number = int(port)
    if not 1 <= number <= 65535:
        raise ValueError("invalid port")
    return str(ip), number


def frame(kind, flags, stream, payload=b""):
    if len(payload) > MAX_FRAME or not 0 <= stream < 2**31:
        raise ValueError("invalid frame")
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + struct.pack(">I", stream) + payload


def exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ValueError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def receive_no_content(conn):
    for _ in range(64):
        header = exact(conn, 9)
        size = int.from_bytes(header[:3], "big")
        if size > MAX_FRAME:
            raise ValueError("frame exceeds bound")
        kind, flags = header[3:5]
        stream = int.from_bytes(header[5:], "big") & 0x7fffffff
        body = exact(conn, size)
        if kind == 4:
            if stream or (flags & 1 and size):
                raise ValueError("invalid SETTINGS")
            if not flags & 1:
                conn.sendall(frame(4, 1, 0))
        elif kind == 1:
            if stream != 1 or flags & 5 != 5 or body != b"\x89":
                raise ValueError("expected final HTTP 204")
            return
        elif kind == 7:
            raise ValueError("unexpected GOAWAY")
    raise ValueError("response frame count exceeded")


def run(address, mode, pem):
    host, port = validate_loopback(address)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.set_alpn_protocols(["h2"])
    if mode != "untrusted-ca":
        context.load_verify_locations(cadata=pem)
    name = "wronghost" if mode == "wrong-name" else "localhost"
    with socket.create_connection((host, port), timeout=10) as tcp:
        tcp.settimeout(15)
        try:
            tls = context.wrap_socket(tcp, server_hostname=name)
        except ssl.SSLCertVerificationError as error:
            if mode == "wrong-name" and error.verify_code == 62:
                print("rejected wrong hostname")
                return
            if mode == "untrusted-ca" and error.verify_code in (18, 19, 20, 21):
                print("rejected untrusted CA")
                return
            raise
        with tls:
            if mode != "ok" or tls.version() != "TLSv1.3" or tls.selected_alpn_protocol() != "h2":
                raise ValueError("unexpected TLS result")
            if not tls.getpeercert():
                raise ValueError("verified peer certificate missing")
            # Minimal standard H2 GET, deliberately not a browser profile.
            tls.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))
            tls.sendall(frame(1, 5, 1, b"\x82\x87\x84\x01\x09localhost"))
            receive_no_content(tls)
    print("TLS1.3 h2 GET -> 204")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address")
    parser.add_argument("mode", choices=("ok", "wrong-name", "untrusted-ca"))
    args = parser.parse_args()
    run(args.address, args.mode, os.environ["THEIA_TEST_ROOT_PEM"])

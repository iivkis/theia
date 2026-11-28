#!/usr/bin/env python3
"""Independent, loopback-only OpenSSL record observer for F-15.

This is a deliberately narrow synthetic policy: reject a ClientHello carried
in one TLS record. It is not a model or claim about any commercial DPI.
The observer shares no parsing or transformation code with Theia.
"""
import argparse
import socket
import ssl
import sys

CASES = (
    ("baseline", 1, True, True),
    ("blocked", 1, False, False),
    ("header-probe", 2, True, False),
    ("header", 2, True, True),
    ("middle-probe", 2, True, False),
    ("middle", 2, True, True),
    ("balanced-probe", 4, True, False),
    ("balanced", 4, True, True),
    ("https-baseline", 1, True, "head"),
    ("https-blocked", 1, False, False),
    ("https-header", 2, True, "head"),
    ("https-middle", 2, True, "head"),
    ("https-balanced", 4, True, "head"),
)
PING = b"theia-dpi-ping"
PONG = b"theia-dpi-pong"


def exact(sock, length):
    data = bytearray()
    while len(data) < length:
        block = sock.recv(length - len(data))
        if not block:
            raise EOFError("truncated TLS record")
        data.extend(block)
    return bytes(data)


def first_flight(sock):
    wire = bytearray()
    hello = bytearray()
    for count in range(1, 17):
        header = exact(sock, 5)
        length = int.from_bytes(header[3:5], "big")
        if header[0] != 22 or header[1] != 3 or header[2] not in (1, 2, 3):
            raise ValueError("unexpected record")
        if not 0 < length <= 16384:
            raise ValueError("record length")
        payload = exact(sock, length)
        wire.extend(header)
        wire.extend(payload)
        hello.extend(payload)
        if len(hello) > 32768:
            raise ValueError("flight length")
        if len(hello) >= 4:
            total = 4 + int.from_bytes(hello[1:4], "big")
            if hello[0] != 1 or total > 32768 or len(hello) > total:
                raise ValueError("not exactly one ClientHello")
            if len(hello) == total:
                return bytes(wire), count
    raise ValueError("record count exceeded")


def exchange(sock, context, wire, application):
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=True)
    incoming.write(wire)

    def flush():
        while outgoing.pending:
            sock.sendall(outgoing.read())

    def drive(operation):
        while True:
            try:
                result = operation()
                flush()
                return result
            except ssl.SSLWantReadError:
                flush()
                block = sock.recv(16384)
                if not block:
                    raise EOFError("unexpected TLS EOF")
                incoming.write(block)
            except ssl.SSLWantWriteError:
                flush()

    drive(tls.do_handshake)
    if application == "head":
        expected = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        data = bytearray()
        while len(data) < len(expected):
            block = drive(lambda: tls.read(len(expected) - len(data)))
            if not block:
                raise EOFError("missing HTTPS request")
            data.extend(block)
        if data != expected:
            raise ValueError("unexpected HTTPS diagnostic request")
        reply = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        if drive(lambda: tls.write(reply)) != len(reply):
            raise ValueError("short HTTPS reply")
    elif application:
        data = bytearray()
        while len(data) < len(PING):
            block = drive(lambda: tls.read(len(PING) - len(data)))
            if not block:
                raise EOFError("missing application data")
            data.extend(block)
        if data != PING:
            raise ValueError("application bytes mismatch")
        if drive(lambda: tls.write(PONG)) != len(PONG):
            raise ValueError("short TLS write")
        drive(tls.unwrap)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = 0
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(args.cert, args.key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(12)
        print(f"READY {listener.getsockname()[1]}", flush=True)
        for label, expected_records, allow, application in CASES:
            sock, address = listener.accept()
            with sock:
                sock.settimeout(8)
                if address[0] != "127.0.0.1":
                    raise ValueError("non-loopback client")
                wire, records = first_flight(sock)
                if records != expected_records:
                    raise ValueError(f"{label}: expected {expected_records}, observed {records}")
                # Baseline explicitly bypasses the synthetic rule. The
                # blocked control and all strategy cases use that same rule.
                permitted = label in ("baseline", "https-baseline") or records > 1
                if permitted != allow:
                    raise ValueError(f"{label}: filter decision mismatch")
                if permitted:
                    exchange(sock, context, wire, application)
                print(
                    f"PASS {label} records={records} handshake={int(allow)} "
                    f"exchange={int(bool(application))}",
                    flush=True,
                )
    print(f"OPENSSL {ssl.OPENSSL_VERSION}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"independent TLS peer failed: {error}", file=sys.stderr, flush=True)
        sys.exit(1)

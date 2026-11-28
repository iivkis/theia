"""Independent loopback STUN peer for the actual Rust UDP relay.

Use Python's standard-library CRC32, not Theia's parser or transformer.
The synthetic filter drops requests without FINGERPRINT. This is a
controlled differential, not evidence about a provider's real DPI.
"""
import socket
import struct
import sys
import zlib

COOKIE = 0x2112A442


def request(transaction):
    return struct.pack("!HHI12s", 1, 0, COOKIE, transaction)


def response(transaction, address):
    port = address[1] ^ (COOKIE >> 16)
    ip = int.from_bytes(socket.inet_aton(address[0]), "big") ^ COOKIE
    attr = struct.pack("!HHBBHI", 0x20, 8, 0, 1, port, ip)
    return struct.pack("!HHI12s", 0x101, len(attr), COOKIE, transaction) + attr


def fingerprint_ok(data, original):
    if len(data) != len(original) + 8 or len(data) != 28:
        return False
    if data[:2] != original[:2] or data[4:20] != original[4:20]:
        return False
    if data[2:4] != b"\x00\x08" or data[20:24] != b"\x80\x28\x00\x04":
        return False
    return int.from_bytes(data[-4:], "big") == (zlib.crc32(data[:-8]) ^ 0x5354554E)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as app:
        for sock in (origin, app):
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(3)
        dest = origin.getsockname()
        # Positive baseline without the filter.
        baseline = request(b"baseline0001")
        app.sendto(baseline, dest)
        got, peer = origin.recvfrom(512)
        assert got == baseline and peer == app.getsockname()
        answer = response(baseline[8:20], peer)
        origin.sendto(answer, peer)
        assert app.recvfrom(512) == (answer, dest)

        # Negative control with the filter: a distinct transaction, no echo.
        blocked = request(b"blocked00001")
        app.sendto(blocked, dest)
        got, peer = origin.recvfrom(512)
        assert got == blocked and not fingerprint_ok(got, blocked)
        app.settimeout(.1)
        try:
            app.recvfrom(512)
            raise AssertionError("unmodified control was not blocked")
        except socket.timeout:
            pass
        app.settimeout(3)

        sys.stdout.buffer.write(
            dest[1].to_bytes(2, "big")
            + app.getsockname()[1].to_bytes(2, "big"))
        sys.stdout.buffer.flush()
        raw = sys.stdin.buffer.read(2)
        assert len(raw) == 2
        ingress = ("127.0.0.1", int.from_bytes(raw, "big"))
        first = request(b"modified0001")
        app.sendto(first, ingress)
        actual, relay_peer = origin.recvfrom(512)
        assert relay_peer != app.getsockname()
        assert fingerprint_ok(actual, first)
        reply = response(first[8:20], relay_peer)
        # Wrong transaction must not reach the application.
        origin.sendto(response(b"unrelated001", relay_peer), relay_peer)
        origin.sendto(reply, relay_peer)
        assert app.recvfrom(512) == (reply, ingress)


if __name__ == "__main__":
    main()

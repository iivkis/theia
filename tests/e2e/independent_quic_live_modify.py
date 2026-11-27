"""Independent real loopback UDP/H3 acceptance for byte-exact QUIC de-coalescing.

Both TLS/QUIC endpoints use pinned aioquic. The fixture origin constructs one
coalesced Initial + genuine 0-RTT datagram before transmitting anything. Only
the Rust transformer outputs cross the UDP socket. This is not a WAN/DPI or
production native-ingress acceptance test.
"""
import socket
import ssl
import sys
import time
from pathlib import Path

from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted
from aioquic.quic.packet import QuicPacketType, QuicProtocolVersion, pull_quic_header

RESPONSE = b"independent modify response"
MAX_PACKET = 65527


def header(data):
    buf = Buffer(data=data)
    item = pull_quic_header(buf, host_cid_length=12)
    return item, buf.tell()


def field(data):
    assert 0 < len(data) <= MAX_PACKET
    return len(data).to_bytes(4, "big") + data


def read_field():
    stream = sys.stdin.buffer
    size = int.from_bytes(stream.read(4), "big")
    assert 0 < size <= MAX_PACKET
    data = stream.read(size)
    assert len(data) == size
    return data


def config(directory, version, client, ticket=None):
    cfg = QuicConfiguration(
        is_client=client, alpn_protocols=H3_ALPN,
        supported_versions=[version], connection_id_length=12,
        max_datagram_size=1452)
    if client:
        cfg.server_name = "localhost"
        cfg.verify_mode = ssl.CERT_REQUIRED
        cfg.load_verify_locations(cafile=str(directory / "cert.pem"))
        cfg.session_ticket = ticket
    else:
        cfg.load_cert_chain(str(directory / "cert.pem"), str(directory / "key.pem"))
    return cfg


def padded_origin_initial(packet, item, offset, version):
    """Fixture sender only: pad the genuine, not-yet-transmitted Initial.

    aioquic can pad a whole coalesced datagram outside the Initial. A split
    Initial must itself be at least 1200 bytes, so originate authenticated
    PADDING here, before either encoding has been sent. This is NOT a feature
    of the transformer; it never re-encrypts, changes PN or inserts padding.
    """
    receive = CryptoPair()
    receive.setup_initial(cid=item.destination_cid, is_client=False, version=version)
    _, plain, pn = receive.decrypt_packet(packet, offset, expected_packet_number=0)
    assert pn == 0 and not item.token
    prefix = bytes([0xc3 if version == QuicProtocolVersion.VERSION_1 else 0xd3])
    prefix += int(version).to_bytes(4, "big")
    for cid in (item.destination_cid, item.source_cid):
        prefix += bytes([len(cid)]) + cid
    prefix += b"\0"  # empty token
    target = max(1200, len(prefix) + 2 + 4 + len(plain) + 16)
    payload_size = target - len(prefix) - 2 - 4 - 16
    length = 4 + payload_size + 16
    assert 64 <= length < 16384
    protected_header = prefix + (0x4000 | length).to_bytes(2, "big") + pn.to_bytes(4, "big")
    send = CryptoPair()
    send.setup_initial(cid=item.destination_cid, is_client=True, version=version)
    padded = send.encrypt_packet(protected_header, plain.ljust(payload_size, b"\0"), pn)
    assert len(padded) == target
    return padded


def originate_first(datagrams, version):
    initial = None
    early = None
    for datagram, _ in datagrams:
        remaining = datagram
        while remaining:
            if not any(remaining):
                break  # sender's terminal datagram padding
            item, offset = header(remaining)
            packet = remaining[:item.packet_length]
            assert len(packet) == item.packet_length
            remaining = remaining[item.packet_length:]
            assert item.version == version
            if item.packet_type == QuicPacketType.INITIAL:
                assert initial is None
                initial = padded_origin_initial(packet, item, offset, version)
            elif item.packet_type == QuicPacketType.ZERO_RTT:
                assert early is None
                early = packet
            else:
                raise AssertionError("unexpected first-flight packet type")
    assert initial is not None and early is not None, "genuine 0-RTT flight required"
    original = initial + early
    assert len(original) <= MAX_PACKET
    return initial, early


def transform_first(datagrams, version):
    initial, early = originate_first(datagrams, version)
    original = initial + early
    sys.stdout.buffer.write(field(original))
    sys.stdout.buffer.flush()
    count = sys.stdin.buffer.read(1)
    assert count == b"\x02", "Rust transformer did not emit exactly two datagrams"
    outputs = [read_field(), read_field()]
    assert outputs == [initial, early], "transformer changed authenticated packet bytes"
    return outputs


class Pair:
    def __init__(self, directory, version, tickets, received_tickets, ticket=None):
        self.version = version
        self.tickets = tickets
        self.directory = directory
        self.resumed = ticket is not None
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for sock in (self.client_socket, self.server_socket):
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(1)
        self.client_addr = self.client_socket.getsockname()
        self.server_addr = self.server_socket.getsockname()
        self.client = QuicConnection(
            configuration=config(directory, version, True, ticket),
            session_ticket_handler=received_tickets.append)
        self.client.connect(self.server_addr, now=time.monotonic())
        self.client_h3 = H3Connection(self.client)
        self.server = None
        self.server_h3 = None
        self.client_handshake = None
        self.server_handshake = None
        self.requests = 0
        self.status = None
        self.body = bytearray()
        self.done = False
        self.stream = None

    def close(self):
        self.client_socket.close()
        self.server_socket.close()

    def start_request(self):
        self.stream = self.client.get_next_available_stream_id()
        self.client_h3.send_headers(self.stream, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", b"/modify")
        ], end_stream=True)

    def transfer(self, data, source, destination, server, now):
        peer = destination.getsockname()
        assert source.sendto(data, peer) == len(data)
        actual, addr = destination.recvfrom(65535)
        assert actual == data and addr == source.getsockname()
        if server:
            self.receive_server(actual, addr, now)
        else:
            self.client.receive_datagram(actual, addr, now=now)

    def receive_server(self, actual, addr, now):
        if self.server is None:
            item, _ = header(actual)
            assert item.packet_type == QuicPacketType.INITIAL
            self.server = QuicConnection(
                configuration=config(self.directory, self.version, False),
                original_destination_connection_id=item.destination_cid,
                session_ticket_handler=lambda t: self.tickets.__setitem__(t.ticket, t),
                session_ticket_fetcher=lambda key: self.tickets.pop(key, None))
            self.server_h3 = H3Connection(self.server)
        self.server.receive_datagram(actual, addr, now=now)

    def events(self, connection, h3, server):
        while True:
            event = connection.next_event()
            if event is None:
                break
            if isinstance(event, ConnectionTerminated):
                raise AssertionError("QUIC connection terminated during acceptance")
            if isinstance(event, HandshakeCompleted):
                assert event.alpn_protocol == "h3"
                if server:
                    self.server_handshake = event
                else:
                    self.client_handshake = event
            for item in h3.handle_event(event):
                if server and isinstance(item, HeadersReceived):
                    assert dict(item.headers)[b":method"] == b"GET"
                    assert dict(item.headers)[b":path"] == b"/modify"
                    assert item.stream_ended and self.requests == 0
                    self.requests += 1
                    h3.send_headers(item.stream_id, [(b":status", b"200")])
                    h3.send_data(item.stream_id, RESPONSE, end_stream=True)
                elif not server and isinstance(item, HeadersReceived):
                    assert item.stream_id == self.stream
                    self.status = dict(item.headers)[b":status"]
                elif not server and isinstance(item, DataReceived):
                    assert item.stream_id == self.stream
                    self.body.extend(item.data)
                    if item.stream_ended:
                        self.done = True
                elif isinstance(item, DataReceived):
                    raise AssertionError("unexpected request body")

    def exchange(self, done):
        deadline = time.monotonic() + 10
        first = True
        while time.monotonic() < deadline:
            now = time.monotonic()
            for conn in (self.client, self.server):
                if conn is not None:
                    timer = conn.get_timer()
                    if timer is not None and timer <= now:
                        conn.handle_timer(now=now)
            outgoing = self.client.datagrams_to_send(now=now)
            if first and self.resumed:
                assert outgoing, "resumed client did not emit first flight"
                assert all(addr == self.server_addr for _, addr in outgoing)
                outgoing = [(data, self.server_addr) for data in transform_first(outgoing, self.version)]
            first = False
            for data, addr in outgoing:
                assert addr == self.server_addr
                self.transfer(data, self.client_socket, self.server_socket, True, now)
            if self.server is not None:
                self.events(self.server, self.server_h3, True)
                for data, addr in self.server.datagrams_to_send(now=now):
                    assert addr == self.client_addr
                    self.transfer(data, self.server_socket, self.client_socket, False, now)
            self.events(self.client, self.client_h3, False)
            if done():
                return
            time.sleep(.001)
        raise AssertionError("independent QUIC/H3 acceptance timed out")


class RelayPair(Pair):
    """The Rust product UDP relay owns the actual emission, not this sender.

    Warm-up is ordinary verified TLS/H3. In the resumed exchange a synthetic
    independent observer refuses a coalesced first datagram; it accepts the
    two byte-exact packets only when they really arrive separately on UDP.
    This is a loopback structural control, not a physical DPI measurement.
    """
    def exchange(self, done):
        assert self.resumed
        sys.stdout.buffer.write(
            self.server_addr[1].to_bytes(2, "big")
            + self.client_addr[1].to_bytes(2, "big"))
        sys.stdout.buffer.flush()
        raw = sys.stdin.buffer.read(2)
        assert len(raw) == 2
        ingress = ("127.0.0.1", int.from_bytes(raw, "big"))
        assert ingress[1]
        deadline = time.monotonic() + 10
        first = True
        relay_peer = None
        while time.monotonic() < deadline:
            now = time.monotonic()
            for conn in (self.client, self.server):
                if conn is not None:
                    timer = conn.get_timer()
                    if timer is not None and timer <= now:
                        conn.handle_timer(now=now)
            outgoing = self.client.datagrams_to_send(now=now)
            if first:
                assert outgoing
                assert all(addr == self.server_addr for _, addr in outgoing)
                initial, early = originate_first(outgoing, self.version)
                original = initial + early
                assert header(original)[0].packet_length < len(original)
                assert self.client_socket.sendto(original, ingress) == len(original)
                for expected in (initial, early):
                    actual, addr = self.server_socket.recvfrom(65535)
                    # A received coalesced packet is a failed synthetic
                    # filter case; never silently repair it in the peer.
                    assert actual == expected
                    if relay_peer is None:
                        relay_peer = addr
                    assert addr == relay_peer
                    assert addr != self.client_addr
                    self.receive_server(actual, addr, now)
                first = False
            else:
                for data, addr in outgoing:
                    assert addr == self.server_addr
                    assert self.client_socket.sendto(data, ingress) == len(data)
                    actual, source = self.server_socket.recvfrom(65535)
                    assert actual == data and source == relay_peer
                    self.receive_server(actual, source, now)
            if self.server is not None:
                self.events(self.server, self.server_h3, True)
                for data, addr in self.server.datagrams_to_send(now=now):
                    assert addr == relay_peer
                    assert self.server_socket.sendto(data, addr) == len(data)
                    actual, source = self.client_socket.recvfrom(65535)
                    assert actual == data and source == ingress
                    self.client.receive_datagram(actual, self.server_addr, now=now)
            self.events(self.client, self.client_h3, False)
            if done():
                return
            time.sleep(.001)
        raise AssertionError("independent product QUIC relay timed out")


def main(directory, version, relay=False):
    tickets = {}
    received = []
    warm = Pair(directory, version, tickets, received)
    try:
        warm.exchange(lambda: warm.client_handshake is not None and warm.server_handshake is not None and bool(received))
        assert not warm.client_handshake.session_resumed
        ticket = received[-1]
        assert ticket.max_early_data_size and ticket.ticket in tickets
    finally:
        warm.close()
    resumed = (RelayPair if relay else Pair)(directory, version, tickets, received, ticket)
    try:
        resumed.start_request()
        resumed.exchange(lambda: resumed.done and resumed.client_handshake is not None and resumed.server_handshake is not None)
        assert resumed.client_handshake.session_resumed and resumed.server_handshake.session_resumed
        assert resumed.client_handshake.early_data_accepted and resumed.server_handshake.early_data_accepted
        assert resumed.requests == 1 and resumed.status == b"200" and bytes(resumed.body) == RESPONSE
    finally:
        resumed.close()


if __name__ == "__main__":
    main(Path(sys.argv[1]), QuicProtocolVersion(int(sys.argv[2])), relay="--relay" in sys.argv[3:])

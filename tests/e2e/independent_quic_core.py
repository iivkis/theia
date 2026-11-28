"""Pinned aioquic reference for the native QUIC core. Loopback only."""
import asyncio
from pathlib import Path
import ssl
import sys

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicProtocolVersion

REQUEST = b"independent request"
RESPONSE = b"independent response"
VERSIONS = [QuicProtocolVersion.VERSION_1, QuicProtocolVersion.VERSION_2]


def configuration(directory, version, client):
    cfg = QuicConfiguration(
        is_client=client, alpn_protocols=H3_ALPN,
        supported_versions=[version], connection_id_length=12,
        max_datagram_size=1200)
    if client:
        cfg.server_name = "localhost"
        cfg.verify_mode = ssl.CERT_REQUIRED
        cfg.load_verify_locations(cafile=str(directory / "cert.pem"))
    else:
        cfg.load_cert_chain(str(directory / "cert.pem"), str(directory / "key.pem"))
    return cfg


class Server(QuicConnectionProtocol):
    def __init__(self, *args, seen, errors, label, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.requests = {}
        self.seen = seen
        self.errors = errors
        self.label = label

    def quic_event_received(self, event):
        try:
            for item in self.http.handle_event(event):
                if isinstance(item, HeadersReceived):
                    headers = dict(item.headers)
                    assert headers[b":method"] == b"POST"
                    assert headers[b":path"] == b"/interop"
                    self.requests[item.stream_id] = bytearray()
                elif isinstance(item, DataReceived):
                    self.requests[item.stream_id].extend(item.data)
                else:
                    continue
                if item.stream_ended:
                    assert bytes(self.requests.pop(item.stream_id)) == REQUEST
                    assert self.label not in self.seen
                    self.seen.add(self.label)
                    self.http.send_headers(item.stream_id, [(b":status", b"200")])
                    self.http.send_data(item.stream_id, RESPONSE, end_stream=True)
                    self.transmit()
        except Exception as exc:
            self.errors.append(repr(exc))
            self.close()


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.response = asyncio.get_running_loop().create_future()
        self.body = bytearray()
        self.status = None
        self.stream = None

    async def request(self):
        self.stream = self._quic.get_next_available_stream_id()
        self.http.send_headers(self.stream, [
            (b":method", b"POST"), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", b"/interop")])
        self.http.send_data(self.stream, REQUEST, end_stream=True)
        self.transmit()
        await asyncio.wait_for(self.response, 12)

    def quic_event_received(self, event):
        try:
            for item in self.http.handle_event(event):
                if not isinstance(item, (HeadersReceived, DataReceived)):
                    continue
                assert item.stream_id == self.stream
                if isinstance(item, HeadersReceived):
                    self.status = dict(item.headers)[b":status"]
                else:
                    self.body.extend(item.data)
                if item.stream_ended:
                    assert self.status == b"200"
                    assert bytes(self.body) == RESPONSE
                    if not self.response.done():
                        self.response.set_result(None)
        except Exception as exc:
            if not self.response.done():
                self.response.set_exception(exc)
            self.close()


async def serve_both(directory):
    seen, errors, servers = set(), [], []
    try:
        for i, version in enumerate(VERSIONS):
            def factory(*args, label=i, **kwargs):
                return Server(*args, seen=seen, errors=errors, label=label, **kwargs)
            servers.append(await serve("127.0.0.1", 0,
                configuration=configuration(directory, version, False),
                create_protocol=factory, retry=True))
        ports = [server._transport.get_extra_info("sockname")[1] for server in servers]
        temp = directory / "ready.tmp"
        temp.write_text("\n".join(map(str, ports)), encoding="ascii")
        temp.replace(directory / "ready")
        while not (directory / "done").exists():
            await asyncio.sleep(.02)
        assert not errors, errors
        assert seen == {0, 1}, seen
    finally:
        for server in servers:
            server.close()


async def client_one(directory, port, version):
    async with connect("127.0.0.1", port,
            configuration=configuration(directory, VERSIONS[version-1], True),
            create_protocol=Client) as protocol:
        await protocol.request()


if __name__ == "__main__":
    mode, directory = sys.argv[1:3]
    if mode == "serve":
        asyncio.run(asyncio.wait_for(serve_both(Path(directory)), 50))
    elif mode == "client":
        asyncio.run(asyncio.wait_for(client_one(Path(directory), int(sys.argv[3]), int(sys.argv[4])), 18))
    else:
        raise ValueError(mode)

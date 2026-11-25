"""Independent controlled H2 and H3 reference, direct vs passive REALITY.
No external traffic, credentials, marker, shared Rust TLS, or disabled PKI.
Only the fixture's final DNS address is mapped to loopback by cfg(test).
"""
import asyncio
import errno
import pathlib
import ssl
import sys

import h2.config
import h2.connection
import h2.events
from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated

NAME = "reference.example.org"
PATH = b"/independent-reality-reference"
BODY = b"independent-reference-response"
HEADERS = [(b":method", b"GET"), (b":scheme", b"https"),
           (b":authority", NAME.encode()), (b":path", PATH)]
RESPONSE = [(b":status", b"200"), (b"content-type", b"application/octet-stream"),
            (b"content-length", str(len(BODY)).encode())]


async def h2_server(reader, writer, seen):
    try:
        tls = writer.get_extra_info("ssl_object")
        assert tls.version() == "TLSv1.3"
        assert tls.selected_alpn_protocol() == "h2"
        session = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False))
        session.initiate_connection()
        writer.write(session.data_to_send())
        await writer.drain()
        requests = set()
        while data := await reader.read(65536):
            for event in session.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    assert dict(event.headers) == dict(HEADERS)
                    requests.add(event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    assert event.stream_id in requests
                    seen.append("h2")
                    session.send_headers(event.stream_id, RESPONSE)
                    session.send_data(event.stream_id, BODY, end_stream=True)
                elif isinstance(event, h2.events.DataReceived):
                    session.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            writer.write(session.data_to_send())
            await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


async def h2_request(port, cert):
    ctx = ssl.create_default_context(cafile=str(cert))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2"])
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=ctx, server_hostname=NAME)
    try:
        tls = writer.get_extra_info("ssl_object")
        assert tls.version() == "TLSv1.3"
        assert tls.selected_alpn_protocol() == "h2"
        fingerprint = tls.getpeercert(binary_form=True)
        session = h2.connection.H2Connection()
        session.initiate_connection()
        stream = session.get_next_available_stream_id()
        session.send_headers(stream, HEADERS, end_stream=True)
        writer.write(session.data_to_send())
        await writer.drain()
        status = None
        body = bytearray()
        while data := await reader.read(65536):
            for event in session.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    assert event.stream_id == stream
                    status = dict(event.headers)
                elif isinstance(event, h2.events.DataReceived):
                    body.extend(event.data)
                    session.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    assert status == dict(RESPONSE) and bytes(body) == BODY
                    return fingerprint, status, bytes(body)
            writer.write(session.data_to_send())
            await writer.drain()
        raise AssertionError("H2 ended without complete response")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


class ReferenceH3(QuicConnectionProtocol):
    def __init__(self, *args, seen, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.seen = seen
        self.requests = set()

    def quic_event_received(self, event):
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                assert dict(item.headers) == dict(HEADERS)
                self.requests.add(item.stream_id)
            elif isinstance(item, DataReceived):
                assert not item.data
            else:
                continue
            if item.stream_ended:
                assert item.stream_id in self.requests
                self.requests.remove(item.stream_id)
                self.seen.append("h3")
                self.http.send_headers(item.stream_id, RESPONSE)
                self.http.send_data(item.stream_id, BODY, end_stream=True)
                self.transmit()


class ClientH3(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.result = asyncio.get_running_loop().create_future()
        self.headers = None
        self.body = bytearray()
        self.stream = None

    async def request(self):
        self.stream = self._quic.get_next_available_stream_id()
        self.http.send_headers(self.stream, HEADERS, end_stream=True)
        self.transmit()
        return await self.result

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            if not self.result.done():
                self.result.set_exception(ConnectionError("H3 terminated"))
            return
        for item in self.http.handle_event(event):
            if getattr(item, "stream_id", None) != self.stream:
                continue
            if isinstance(item, HeadersReceived):
                self.headers = dict(item.headers)
            elif isinstance(item, DataReceived):
                self.body.extend(item.data)
            if getattr(item, "stream_ended", False) and not self.result.done():
                self.result.set_result((self.headers, bytes(self.body)))


async def h3_request(port, cert):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name=NAME)
    cfg.verify_mode = ssl.CERT_REQUIRED
    cfg.load_verify_locations(cafile=str(cert))
    async with connect("127.0.0.1", port, configuration=cfg, create_protocol=ClientH3) as client:
        response = await asyncio.wait_for(client.request(), 8)
        assert response == (dict(RESPONSE), BODY)
        return response


async def main(directory, relay_port):
    cert, key = directory / "cert.pem", directory / "key.pem"
    seen = []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2"])
    ctx.load_cert_chain(str(cert), str(key))
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    cfg.load_cert_chain(str(cert), str(key))
    # TCP and UDP have separate ephemeral port pools/reservations, notably
    # Windows excluded UDP ranges. Keep TCP bound while acquiring UDP, and
    # retry only bind conflicts before publishing the shared fixture port.
    for attempt in range(32):
        h2_listener = await asyncio.start_server(
            lambda r, w: h2_server(r, w, seen), "127.0.0.1", 0, ssl=ctx)
        port = h2_listener.sockets[0].getsockname()[1]
        try:
            h3_listener = await serve(
                "127.0.0.1", port, configuration=cfg, retry=True,
                create_protocol=lambda *a, **kw: ReferenceH3(*a, seen=seen, **kw))
        except BaseException as error:
            h2_listener.close()
            await h2_listener.wait_closed()
            if (attempt == 31 or not isinstance(error, OSError)
                    or (error.errno != errno.EADDRINUSE
                        and getattr(error, "winerror", None) not in (10013, 10048))):
                raise
        else:
            break
    try:
        tmp = directory / "reference-port.tmp"
        tmp.write_text(str(port), encoding="ascii")
        tmp.replace(directory / "reference-port")
        while not (directory / "relay-ready").exists():
            await asyncio.sleep(0.02)
        direct_h2 = await asyncio.wait_for(h2_request(port, cert), 5)
        relay_h2 = await asyncio.wait_for(h2_request(relay_port, cert), 5)
        assert direct_h2 == relay_h2
        direct_h3 = await h3_request(port, cert)
        relay_h3 = await h3_request(relay_port, cert)
        assert direct_h3 == relay_h3
        assert seen == ["h2", "h2", "h3", "h3"], seen
        print("Independent TLS1.3 H2 and Retry/H3 reference comparisons passed", flush=True)
    finally:
        h3_listener.close()
        h2_listener.close()
        await h2_listener.wait_closed()


if __name__ == "__main__":
    scratch = pathlib.Path(sys.argv[1])
    relay_host, relay_port = sys.argv[2].rsplit(":", 1)
    assert relay_host == "127.0.0.1"
    asyncio.run(asyncio.wait_for(main(scratch, int(relay_port)), 30))

"""Controlled independent OpenSSL/hyper-h2 and aioquic peer.

Only local ephemeral certificates and a public synthetic test credential.
No packet capture, production keys, target dial or external host.
"""
import asyncio
import base64
from pathlib import Path
import ssl
import sys

import h2.config
import h2.connection
import h2.events
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration

EXPECTED = b"Bearer " + base64.urlsafe_b64encode(bytes([0x42]) * 32).rstrip(b"=")


def verify_headers(headers):
    values = dict(headers)
    assert len(values) == len(headers), "unexpected duplicate fixture headers"
    assert values.get(b":method") == b"POST"
    assert values.get(b":scheme") == b"https"
    assert values.get(b":authority") == b"localhost"
    assert values.get(b":path") == b"/v1/theia-example/session"
    assert values.get(b"authorization") == EXPECTED
    assert values.get(b"content-type") == b"application/octet-stream"


async def h2_peer(reader, writer, seen, errors):
    try:
        tls = writer.get_extra_info("ssl_object")
        assert tls.version() == "TLSv1.3"
        assert tls.selected_alpn_protocol() == "h2"
        session = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False))
        session.initiate_connection()
        writer.write(session.data_to_send())
        await writer.drain()
        while data := await reader.read(65536):
            for event in session.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    verify_headers(event.headers)
                    assert "h2" not in seen
                    seen.append("h2")
                    session.send_headers(event.stream_id, [(b":status", b"403")], end_stream=True)
                elif isinstance(event, h2.events.DataReceived):
                    assert not event.data, "application data before HTTP admission"
            writer.write(session.data_to_send())
            await writer.drain()
    except (ConnectionError, ssl.SSLError):
        pass
    except Exception:
        errors.append("independent H2 fixture rejected unexpected input")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


async def wrong_h2_peer(reader, writer, errors):
    try:
        if await asyncio.wait_for(reader.read(1), 3):
            errors.append("application data after incorrect ALPN")
    except (asyncio.TimeoutError, ConnectionError, ssl.SSLError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


class ReferenceH3(QuicConnectionProtocol):
    def __init__(self, *args, seen, errors, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.seen = seen
        self.errors = errors

    def quic_event_received(self, event):
        try:
            for item in self.http.handle_event(event):
                if isinstance(item, HeadersReceived):
                    verify_headers(item.headers)
                    assert "h3" not in self.seen
                    self.seen.append("h3")
                    self.http.send_headers(item.stream_id, [(b":status", b"403")], end_stream=True)
                    self.transmit()
                elif isinstance(item, DataReceived):
                    assert not item.data, "application data before HTTP admission"
        except Exception:
            self.errors.append("independent H3 fixture rejected unexpected input")
            self.close()


def tls_config(cert, key, alpn):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(alpn)
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def quic_config(cert, key, alpn):
    cfg = QuicConfiguration(is_client=False, alpn_protocols=alpn)
    cfg.load_cert_chain(str(cert), str(key))
    return cfg


async def main(directory):
    cert, key = directory / "cert.pem", directory / "key.pem"
    seen, errors = [], []
    h2_listener = await asyncio.start_server(
        lambda r, w: h2_peer(r, w, seen, errors), "127.0.0.1", 0,
        ssl=tls_config(cert, key, ["h2"]))
    wrong_h2 = await asyncio.start_server(
        lambda r, w: wrong_h2_peer(r, w, errors), "127.0.0.1", 0,
        ssl=tls_config(cert, key, ["http/1.1"]))
    h3_listener = await serve("127.0.0.1", 0, configuration=quic_config(cert, key, H3_ALPN),
        create_protocol=lambda *a, **kw: ReferenceH3(*a, seen=seen, errors=errors, **kw))
    wrong_h3 = await serve("127.0.0.1", 0, configuration=quic_config(cert, key, ["hq-29"]))
    try:
        # aioquic 1.2.0 exposes its bound datagram transport only on QuicServer.
        ports = [h2_listener.sockets[0].getsockname()[1], wrong_h2.sockets[0].getsockname()[1],
                 h3_listener._transport.get_extra_info("sockname")[1],
                 wrong_h3._transport.get_extra_info("sockname")[1]]
        tmp = directory / "ready.tmp"
        tmp.write_text("\n".join(map(str, ports)), encoding="ascii")
        tmp.replace(directory / "ready")
        while not (directory / "done").exists():
            await asyncio.sleep(.02)
        await asyncio.sleep(.1)
        assert not errors, errors
        assert seen == ["h2", "h3"], "unexpected application request count"
        print("Independent native H2/H3 trust and ALPN checks passed", flush=True)
    finally:
        h3_listener.close()
        wrong_h3.close()
        h2_listener.close()
        wrong_h2.close()
        await h2_listener.wait_closed()
        await wrong_h2.wait_closed()


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(Path(sys.argv[1])), 48))

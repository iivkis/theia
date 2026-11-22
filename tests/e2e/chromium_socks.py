"""CI-only Chromium smoke. Restrict the test browser to one loopback origin.

The guard is not a substitute proxy: it forwards the browser's SOCKS5
CONNECT to the real Theia client and copies bytes only after its success.
A direct browser connection cannot satisfy the guard success assertion.
"""
import asyncio
import ipaddress
import struct
import sys

from playwright.async_api import async_playwright


async def read_address(reader, atyp):
    if atyp == 1:
        return str(ipaddress.IPv4Address(await reader.readexactly(4)))
    if atyp == 4:
        return str(ipaddress.IPv6Address(await reader.readexactly(16)))
    if atyp == 3:
        size = (await reader.readexactly(1))[0]
        return (await reader.readexactly(size)).decode("ascii")
    raise ValueError("invalid SOCKS address type")


async def copy(reader, writer, marker, matched):
    tail = b""
    try:
        while data := await reader.read(16384):
            combined = tail + data
            if marker in combined:
                matched.set()
            tail = combined[-(len(marker) - 1):]
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (ConnectionError, OSError):
        pass


async def scenario(proxy, port):
    host, proxy_port = proxy.rsplit(":", 1)
    assert host == "127.0.0.1"
    success = asyncio.Event()
    request_seen = asyncio.Event()
    response_seen = asyncio.Event()
    tasks = set()

    async def guard(reader, writer):
        upstream = None
        try:
            version, count = await asyncio.wait_for(reader.readexactly(2), 5)
            methods = await reader.readexactly(count)
            if version != 5 or 0 not in methods:
                return
            writer.write(b"\x05\x00")
            await writer.drain()
            version, command, reserved, atyp = await reader.readexactly(4)
            address = await read_address(reader, atyp)
            requested_port = struct.unpack("!H", await reader.readexactly(2))[0]
            if (
                (version, command, reserved) != (5, 1, 0)
                or address not in ("localhost", "127.0.0.1", "::1")
                or requested_port != port
            ):
                writer.write(b"\x05\x02\x00\x01" + bytes(6))
                await writer.drain()
                return
            upstream_reader, upstream = await asyncio.open_connection(host, int(proxy_port))
            upstream.write(b"\x05\x01\x00")
            await upstream.drain()
            assert await upstream_reader.readexactly(2) == b"\x05\x00"
            # Preserve a DNS request to the actual Theia SOCKS listener.
            name = b"localhost"
            upstream.write(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", port))
            await upstream.drain()
            reply = await upstream_reader.readexactly(10)
            writer.write(reply)
            await writer.drain()
            if reply[1] != 0:
                return
            success.set()
            await asyncio.gather(
                copy(reader, upstream, b"GET /ci-browser HTTP/1.", request_seen),
                copy(upstream_reader, writer, b"theia-browser-ci-ok", response_seen),
            )
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
            pass
        finally:
            writer.close()
            if upstream is not None:
                upstream.close()
            await asyncio.gather(
                writer.wait_closed(),
                *([upstream.wait_closed()] if upstream is not None else []),
                return_exceptions=True,
            )

    def accept(reader, writer):
        task = asyncio.create_task(guard(reader, writer))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    guard_port = server.sockets[0].getsockname()[1]
    url = f"http://localhost:{port}/ci-browser"
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                proxy={"server": f"socks5://127.0.0.1:{guard_port}", "bypass": "<-loopback>"},
                args=[
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--no-first-run",
                    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                ],
                timeout=20000,
            )
            try:
                context = await browser.new_context(service_workers="block")
                async def restrict(route):
                    if route.request.url == url:
                        await route.continue_()
                    else:
                        await route.abort()
                await context.route("**/*", restrict)
                page = await context.new_page()
                response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                assert response is not None and response.status == 200
                assert await page.locator("#result").inner_text(timeout=5000) == "theia-browser-ci-ok"
                assert success.is_set(), "browser bypassed the Theia SOCKS5 path"
                assert request_seen.is_set() and response_seen.is_set(), "navigation bytes did not traverse Theia"
                await context.close()
                print("Chromium DOM and Theia SOCKS5 CONNECT verified")
            finally:
                await browser.close()
    finally:
        server.close()
        await server.wait_closed()
        for task in list(tasks):
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(scenario(sys.argv[1], int(sys.argv[2])), timeout=50))

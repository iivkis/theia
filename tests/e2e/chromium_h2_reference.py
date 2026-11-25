"""CI-only *real Chromium* HTTP/2 first-flight reference on a loopback origin.

Unlike Go uTLS HelloChrome_133, the actual Chromium binary authors the HTTP/2
SETTINGS and HEADERS here. This IS NOT a test of Chrome or Theia X.509 trust:
only this isolated browser reference context accepts the ephemeral self-signed
loopback fixture certificate. Production Theia never changes TLS verification.
No external URLs, proxies, raw HPACK, or credentials are recorded.
"""
import asyncio
import ipaddress
import sys
from playwright.async_api import async_playwright


async def scenario(endpoint: str) -> None:
    host, sep, port = endpoint.rpartition(":")
    assert sep and host == "127.0.0.1" and port.isdigit()
    assert ipaddress.ip_address(host).is_loopback
    assert 1 <= int(port) <= 65535
    url = f"https://localhost:{port}/ci-chromium-h2-reference"

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-quic",
                "--no-first-run",
                "--no-proxy-server",
                "--host-resolver-rules=MAP localhost 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
            ],
            timeout=20000,
        )
        try:
            # Narrow trust exception for browser REFERENCE ONLY, never Theia.
            # The test server is generated and reachable only via 127.0.0.1.
            context = await browser.new_context(
                ignore_https_errors=True, service_workers="block"
            )
            try:
                async def only_fixture(route):
                    if route.request.url == url:
                        await route.continue_()
                    else:
                        await route.abort()

                await context.route("**/*", only_fixture)
                page = await context.new_page()
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=15000
                )
                assert response is not None and response.status == 200
                assert (await page.locator("#h2-reference").inner_text()) == "chromium-h2"
                print("Actual Chromium HTTPS/H2 loopback navigation succeeded")
            finally:
                await context.close()
        finally:
            await browser.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: chromium_h2_reference.py <127.0.0.1:port>")
    asyncio.run(asyncio.wait_for(scenario(sys.argv[1]), timeout=45))

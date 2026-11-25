"""CI-only real Chromium H3 reference, isolated to an ephemeral loopback SPKI."""
import asyncio
import base64
import sys
from playwright.async_api import async_playwright


async def scenario(endpoint: str, spki: str) -> None:
    host, sep, port = endpoint.rpartition(":")
    if not sep or host != "127.0.0.1" or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("loopback endpoint required")
    if len(base64.b64decode(spki, validate=True)) != 32:
        raise ValueError("exact SHA-256 SPKI pin required")
    url = f"https://{endpoint}/ci-chromium-h3-reference"
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--enable-quic",
                f"--origin-to-force-quic-on={endpoint}",
                f"--ignore-certificate-errors-spki-list={spki}",
                "--disable-background-networking",
                "--disable-component-update",
                "--no-first-run",
                "--no-proxy-server",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
            ],
            timeout=15000,
        )
        try:
            if browser.version != "159.0.8154.6":
                raise RuntimeError("unexpected Chromium reference version")
            context = await browser.new_context(service_workers="block")
            try:
                async def only_fixture(route):
                    if route.request.url == url:
                        await route.continue_()
                    else:
                        await route.abort()

                await context.route("**/*", only_fixture)
                page = await context.new_page()
                response = await page.goto(url, wait_until="domcontentloaded", timeout=12000)
                assert response is not None and response.status == 200
                assert await page.locator("#h3-reference").inner_text() == "chromium-h3"
                protocol = await page.evaluate("performance.getEntriesByType('navigation')[0].nextHopProtocol")
                assert protocol == "h3", "browser did not use HTTP/3"
            finally:
                await context.close()
        finally:
            await browser.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: chromium_h3_reference.py 127.0.0.1:port SPKI_SHA256")
    asyncio.run(asyncio.wait_for(scenario(sys.argv[1], sys.argv[2]), timeout=40))

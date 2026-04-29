from __future__ import annotations

from .base import BaseDiscoverer, DiscoveryResult


class PlaywrightCaptureDiscoverer(BaseDiscoverer):
    name = "playwright-capture"

    async def discover(self, client, registry) -> DiscoveryResult:
        # Optional hook. It deliberately does nothing unless a future UI passes
        # explicit Playwright credentials/actions; no auth, CAPTCHA, or form
        # interaction is attempted here.
        return DiscoveryResult()

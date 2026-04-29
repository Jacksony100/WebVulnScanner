from .base import BaseDiscoverer, DiscoveryResult
from .forms import extract_forms
from .html import HTMLDiscoverer
from .js import JSDiscoverer, extract_js_endpoints
from .well_known import WellKnownDiscoverer

__all__ = [
    "BaseDiscoverer",
    "DiscoveryResult",
    "HTMLDiscoverer",
    "JSDiscoverer",
    "WellKnownDiscoverer",
    "extract_forms",
    "extract_js_endpoints",
]

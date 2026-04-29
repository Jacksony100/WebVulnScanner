from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


BLOCKED_SCHEMES = {"file", "gopher", "ftp", "dict", "ldap", "smb", "data", "javascript", "mailto", "tel"}
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
}
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".tar", ".gz",
}


def normalize_target_url(raw_url: str) -> str:
    if not raw_url or not raw_url.strip():
        raise ValueError("Требуется URL")
    value = raw_url.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("URL должен использовать схему http или https")
    if not parsed.netloc:
        raise ValueError("URL должен содержать хост")
    path = parsed.path
    if path == "/":
        path = ""
    elif path:
        path = path.rstrip("/")
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, ""))


def normalize_url_for_dedupe(url: str) -> str:
    parsed = urlparse(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))


def absolute_url(base_url: str, value: str) -> str | None:
    value = (value or "").strip()
    if not value or value.startswith("#"):
        return None
    parsed_raw = urlparse(value)
    if parsed_raw.scheme.lower() in BLOCKED_SCHEMES:
        return None
    parsed = urlparse(urljoin(base_url, value))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))


@lru_cache(maxsize=2048)
def resolve_host_safely(host: str) -> tuple[str, ...]:
    host = (host or "").strip("[]").lower()
    if not host:
        return ()
    try:
        ipaddress.ip_address(host)
        return (host,)
    except ValueError:
        pass
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return ()
    return tuple(sorted({item[4][0] for item in records}))


def is_private_or_local_address(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address in METADATA_IPS
    )


def same_site(host: str, scope_host: str) -> bool:
    host = (host or "").lower().strip(".")
    scope_host = (scope_host or "").lower().strip(".")
    return host == scope_host or host.endswith(f".{scope_host}")


def should_skip_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme.lower() in BLOCKED_SCHEMES:
        return True
    if parsed.scheme.lower() not in {"http", "https"}:
        return True
    path = (parsed.path or "").lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def is_in_scope(url: str, config) -> bool:
    parsed = urlparse(url)
    if should_skip_url(url) or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    if not any(same_site(host, scope_host) for scope_host in config.scope_hosts):
        return False
    ips = resolve_host_safely(host)
    if not config.allow_private_ips and any(is_private_or_local_address(ip) for ip in ips or (host,)):
        return False
    return True

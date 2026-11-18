"""SSRF guard for every outbound fetch (THREAT_MODEL.md, T1).

Policy, in order:
  1. Reject malformed or ambiguous URLs (control chars, backslashes, userinfo, odd ports).
  2. Reject IP-literal hosts in every encoding (dotted, decimal, octal, hex, IPv6).
  3. Require the host to be on an explicit allowlist (exact host or ".suffix").
  4. Resolve the host and require ALL resolved addresses to be publicly routable.
  5. Return the validated addresses so the HTTP layer can PIN the connection to them.

Step 5 matters: if the client re-resolves DNS after this check, an attacker-controlled
resolver can answer "public" here and "127.0.0.1" a moment later (DNS rebinding,
a time-of-check/time-of-use bug). Callers must connect to ``CheckedURL.addresses``.

Redirects are not followed implicitly: each ``Location`` goes back through
``check_redirect``, which re-applies the full policy and enforces a hop limit.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

Resolver = Callable[[str, int], Sequence[str]]

MAX_URL_LENGTH = 2048
DEFAULT_PORTS = {"https": 443, "http": 80}

# Ranges that ipaddress' ``is_global`` does not cover, or that embed an IPv4 address
# which could be internal (NAT64, 6to4, Teredo). Sources never live in these.
_EXTRA_BLOCKED = tuple(
    ipaddress.ip_network(n)
    for n in (
        "100.64.0.0/10",  # CGNAT / shared address space (also Tailscale's range)
        "192.0.0.0/24",  # IETF protocol assignments
        "198.18.0.0/15",  # benchmarking
        "64:ff9b::/96",  # NAT64 well-known prefix
        "64:ff9b:1::/48",  # local-use NAT64
        "2002::/16",  # 6to4
        "2001::/32",  # Teredo
    )
)

# A host whose every label is decimal or 0x-hex is an IP in disguise:
# 2130706433, 0177.0.0.1, 0x7f.0.0.1, 127.1 all reach loopback via inet_aton.
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$", re.IGNORECASE)
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x20\x7f\\]")


class URLRejectedError(ValueError):
    """Raised when a URL fails the outbound-fetch policy. Fails closed."""

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"URL rejected ({reason}): {url[:200]!r}")
        self.url = url
        self.reason = reason


@dataclass(frozen=True, slots=True)
class CheckedURL:
    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]  # pin the connection to these; never re-resolve


class HostAllowlist:
    """Entries are exact hosts ("www.cisa.gov") or suffixes (".cisa.gov" = subdomains only)."""

    def __init__(self, entries: Iterable[str]) -> None:
        self._exact: set[str] = set()
        self._suffixes: list[str] = []
        for raw in entries:
            entry = _normalize_host(raw.lstrip("."))
            if raw.startswith("."):
                self._suffixes.append("." + entry)
            else:
                self._exact.add(entry)

    def allows(self, host: str) -> bool:
        return host in self._exact or any(host.endswith(s) for s in self._suffixes)


def _normalize_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    # IDNA-encode so a Unicode look-alike can't match an ASCII allowlist entry by accident.
    return host.encode("idna").decode("ascii")


def is_public_address(address: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop IPv6 zone id
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        # Fail closed on ALL IPv4-mapped addresses (::ffff:a.b.c.d). Unwrapping and
        # re-checking would only make the guard more permissive, and real sources
        # never resolve to mapped addresses. (Found by mutation testing.)
        return False
    if any(ip.version == net.version and ip in net for net in _EXTRA_BLOCKED):
        return False
    return ip.is_global and not ip.is_multicast


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    labels = host.split(".")
    return all(label and _NUMERIC_LABEL.match(label) for label in labels)


def default_resolver(host: str, port: int) -> Sequence[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise URLRejectedError(host, f"DNS resolution failed: {exc}") from None
    return sorted({str(info[4][0]) for info in infos})


def check_url(
    url: str,
    allowlist: HostAllowlist,
    *,
    resolver: Resolver = default_resolver,
    allowed_schemes: frozenset[str] = frozenset({"https"}),
    resolve: bool = True,
) -> CheckedURL:
    """Validate ``url`` for fetching. Raises ``URLRejectedError`` on any doubt.

    ``resolve=False`` is for proxy mode only: the egress proxy resolves the name and
    refuses private, loopback, link-local and metadata destinations itself (generated
    squid.conf, ``private_dst``), so the client keeps every other check but does not need
    DNS. The returned ``addresses`` is then empty and nothing may be pinned.
    """
    if len(url) > MAX_URL_LENGTH:
        raise URLRejectedError(url, "too long")
    if _FORBIDDEN_CHARS.search(url):
        raise URLRejectedError(url, "control character, whitespace or backslash")

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in allowed_schemes:
        raise URLRejectedError(url, f"scheme {scheme or '(none)'!r} not allowed")
    if "@" in parts.netloc:
        raise URLRejectedError(url, "userinfo in URL")  # https://allowed.com@evil.com/

    raw_host = parts.hostname
    if not raw_host:
        raise URLRejectedError(url, "missing host")
    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError:
        raise URLRejectedError(url, "invalid port") from None
    if port != DEFAULT_PORTS[scheme]:
        raise URLRejectedError(url, f"non-default port {port}")

    if _is_ip_literal(raw_host):
        raise URLRejectedError(url, "IP-literal host")
    try:
        host = _normalize_host(raw_host)
    except UnicodeError:
        raise URLRejectedError(url, "invalid internationalized host") from None
    if not allowlist.allows(host):
        raise URLRejectedError(url, f"host {host!r} not on allowlist")

    if not resolve:
        return CheckedURL(url=url, scheme=scheme, host=host, port=port, addresses=())
    addresses = tuple(resolver(host, port))
    if not addresses:
        raise URLRejectedError(url, "host resolved to no addresses")
    blocked = [a for a in addresses if not is_public_address(a)]
    if blocked:  # ALL must be public: one internal record is enough to reject
        raise URLRejectedError(url, f"resolves to non-public address {blocked[0]}")

    return CheckedURL(url=url, scheme=scheme, host=host, port=port, addresses=addresses)


def check_redirect(
    previous: CheckedURL,
    location: str,
    allowlist: HostAllowlist,
    *,
    hops_so_far: int,
    max_hops: int = 3,
    resolver: Resolver = default_resolver,
    allowed_schemes: frozenset[str] = frozenset({"https"}),
    resolve: bool = True,
) -> CheckedURL:
    """Re-apply the full policy to a redirect target (relative or absolute)."""
    if hops_so_far >= max_hops:
        raise URLRejectedError(location, f"more than {max_hops} redirects")
    target = urljoin(previous.url, location.strip())
    return check_url(
        target, allowlist, resolver=resolver, allowed_schemes=allowed_schemes, resolve=resolve
    )

"""Deterministic normalization: CVE extraction and canonical URLs.

These run on untrusted text, so they are pure, bounded and dependency-free.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Hyphen look-alikes seen in copy-pasted advisories (non-breaking hyphen, en dash, minus…).
_DASHES = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212"), "-")
_CVE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
MAX_SCAN_CHARS = 2_000_000

_ENTITY_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")


def entity_norm(text: str) -> str:
    """Vendor/product normalization: ASCII alphanumerics, lower-cased ("N-able" -> "nable").

    MUST stay identical to the SQL in store.sql.INSERT_PRODUCTS
    (``lower(regexp_replace(x, '[^A-Za-z0-9]', '', 'g'))``); parity is tested.
    """
    return _ENTITY_NON_ALNUM.sub("", text).lower()


_TRACKING_PARAMS = frozenset(
    {"fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid", "igshid", "_hsenc", "_hsmi",
     "ref", "ref_src", "spm", "yclid"}
)  # fmt: skip
_DEFAULT_PORTS = {"http": 80, "https": 443}


def extract_cves(text: str) -> tuple[str, ...]:
    """Unique CVE IDs in ``text``, upper-cased and sorted. Implausible years are dropped."""
    found = set()
    for year, seq in _CVE.findall(text[:MAX_SCAN_CHARS].translate(_DASHES)):
        if 1999 <= int(year) <= 2100:
            found.add(f"CVE-{year}-{seq}")
    return tuple(sorted(found, key=_cve_sort_key))


def _cve_sort_key(cve: str) -> tuple[int, int]:
    _, year, seq = cve.split("-")
    return int(year), int(seq)


def canonical_url(url: str) -> str:
    """Stable form of a URL for exact-duplicate detection across sources.

    Lower-cases scheme and host, drops default ports, fragments and tracking parameters,
    sorts the remaining query parameters, and removes a trailing slash from non-root paths.
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".")
    port = parts.port
    netloc = host if port in (None, _DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    query = sorted(
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith("utm_") and k.lower() not in _TRACKING_PARAMS
    )
    path = parts.path or "/"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return urlunsplit((scheme, netloc, path, urlencode(query), ""))

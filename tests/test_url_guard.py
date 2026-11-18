"""SSRF guard tests (THREAT_MODEL.md section 5, "SSRF suite"). All DNS is faked."""

from collections.abc import Sequence

import pytest

from cyberintel.security.url_guard import (
    HostAllowlist,
    URLRejectedError,
    check_redirect,
    check_url,
    is_public_address,
)

ALLOW = HostAllowlist(["www.cisa.gov", ".github.com", "nvd.nist.gov"])

FAKE_DNS: dict[str, list[str]] = {
    "www.cisa.gov": ["104.84.0.10"],
    "api.github.com": ["140.82.112.6"],
    "raw.github.com": ["185.199.108.133", "2606:50c0:8000::154"],
    "nvd.nist.gov": ["129.6.13.20"],
    # Hostile records an attacker could plant for an allowlisted name:
    "rebind.github.com": ["140.82.112.6", "127.0.0.1"],  # mixed public + loopback
    "meta.github.com": ["169.254.169.254"],  # cloud metadata
    "lan.github.com": ["192.168.1.10"],
    "cgnat.github.com": ["100.100.100.100"],  # Tailscale / CGNAT
    "mapped.github.com": ["::ffff:127.0.0.1"],
    "nat64.github.com": ["64:ff9b::7f00:1"],
    "v6local.github.com": ["fd00::1"],
    "empty.github.com": [],
}


def fake_resolver(host: str, port: int) -> Sequence[str]:
    return FAKE_DNS[host]


def ok(url: str) -> None:
    check_url(url, ALLOW, resolver=fake_resolver)


def rejected(url: str, reason_fragment: str) -> None:
    with pytest.raises(URLRejectedError) as exc:
        check_url(url, ALLOW, resolver=fake_resolver)
    assert reason_fragment in exc.value.reason, exc.value.reason


def test_allows_plain_allowlisted_https() -> None:
    checked = check_url(
        "https://www.cisa.gov/feeds/known_exploited_vulnerabilities.json",
        ALLOW,
        resolver=fake_resolver,
    )
    assert checked.host == "www.cisa.gov"
    assert checked.port == 443
    assert checked.addresses == ("104.84.0.10",)


def test_suffix_entry_allows_subdomains_only() -> None:
    ok("https://api.github.com/advisories")
    rejected("https://github.com/", "not on allowlist")  # ".github.com" excludes apex
    rejected("https://evilgithub.com/", "not on allowlist")
    rejected("https://github.com.evil.example/", "not on allowlist")


def test_returns_all_addresses_for_pinning() -> None:
    checked = check_url("https://raw.github.com/x", ALLOW, resolver=fake_resolver)
    assert set(checked.addresses) == {"185.199.108.133", "2606:50c0:8000::154"}


@pytest.mark.parametrize(
    "url",
    [
        "http://www.cisa.gov/",  # plaintext not allowed by default
        "ftp://www.cisa.gov/",
        "file:///etc/passwd",
        "gopher://www.cisa.gov/",
        "javascript:alert(1)",
        "//www.cisa.gov/",
    ],
)
def test_rejects_disallowed_schemes(url: str) -> None:
    rejected(url, "scheme")


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "2130706433",  # decimal 127.0.0.1
        "0177.0.0.1",  # octal
        "0x7f.0.0.1",  # hex
        "0x7f000001",
        "127.1",  # short form
        "[::1]",
        "[::ffff:127.0.0.1]",
        "169.254.169.254",
        "10.0.0.1",
    ],
)
def test_rejects_ip_literals_in_any_encoding(host: str) -> None:
    rejected(f"https://{host}/", "IP-literal")


@pytest.mark.parametrize(
    ("host", "bad_ip"),
    [
        ("rebind.github.com", "127.0.0.1"),
        ("meta.github.com", "169.254.169.254"),
        ("lan.github.com", "192.168.1.10"),
        ("cgnat.github.com", "100.100.100.100"),
        ("mapped.github.com", "::ffff:127.0.0.1"),
        ("nat64.github.com", "64:ff9b::7f00:1"),
        ("v6local.github.com", "fd00::1"),
    ],
)
def test_rejects_allowlisted_name_resolving_internal(host: str, bad_ip: str) -> None:
    rejected(f"https://{host}/", f"non-public address {bad_ip}")


def test_rejects_name_with_no_addresses() -> None:
    rejected("https://empty.github.com/", "no addresses")


@pytest.mark.parametrize(
    ("url", "fragment"),
    [
        ("https://www.cisa.gov@169.254.169.254/", "userinfo"),
        ("https://user:pass@www.cisa.gov/", "userinfo"),
        ("https://www.cisa.gov:8443/", "non-default port"),
        ("https://www.cisa.gov:99999/", "invalid port"),
        ("https://www.cisa.gov\\@evil.example/", "backslash"),
        ("https://www.cisa.gov/\r\nHost: evil", "control character"),
        ("https://www.cisa.gov/a b", "whitespace"),
        ("https:///path", "missing host"),
        ("https://www.cisa.gov/" + "a" * 3000, "too long"),
    ],
)
def test_rejects_ambiguous_urls(url: str, fragment: str) -> None:
    rejected(url, fragment)


def test_trailing_dot_and_case_normalize_before_allowlist() -> None:
    ok("https://WWW.CISA.GOV./x")


def test_unicode_lookalike_does_not_match_ascii_entry() -> None:
    # Cyrillic small letter es (U+0441) instead of Latin "c": IDNA-encodes to an xn--
    # label, so it must not match the ASCII allowlist entry.
    rejected("https://www.\u0441isa.gov/", "not on allowlist")


def test_redirect_reapplies_policy() -> None:
    start = check_url("https://www.cisa.gov/a", ALLOW, resolver=fake_resolver)
    nxt = check_redirect(start, "/b", ALLOW, hops_so_far=0, resolver=fake_resolver)
    assert nxt.url == "https://www.cisa.gov/b"
    with pytest.raises(URLRejectedError, match="IP-literal"):
        check_redirect(
            start, "https://169.254.169.254/latest/", ALLOW, hops_so_far=0, resolver=fake_resolver
        )
    with pytest.raises(URLRejectedError, match="scheme"):  # https -> http downgrade
        check_redirect(start, "http://www.cisa.gov/", ALLOW, hops_so_far=0, resolver=fake_resolver)


def test_redirect_hop_limit() -> None:
    start = check_url("https://www.cisa.gov/a", ALLOW, resolver=fake_resolver)
    with pytest.raises(URLRejectedError, match="redirects"):
        check_redirect(start, "/b", ALLOW, hops_so_far=3, resolver=fake_resolver)


@pytest.mark.parametrize(
    ("addr", "public"),
    [
        ("8.8.8.8", True),
        ("2606:4700::1111", True),
        ("127.0.0.1", False),
        ("0.0.0.0", False),
        ("255.255.255.255", False),
        ("224.0.0.1", False),
        ("fe80::1%eth0", False),
        ("::ffff:127.0.0.1", False),
        ("::ffff:8.8.8.8", False),  # mapped addresses rejected even when the IPv4 is public
        ("100.64.0.1", False),
        ("2002:7f00:1::1", False),  # 6to4 embedding 127.0.0.1
        ("not-an-ip", False),
    ],
)
def test_is_public_address(addr: str, public: bool) -> None:
    assert is_public_address(addr) is public

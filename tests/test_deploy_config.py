from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from cyberintel.deploy import render_squid
from cyberintel.sources import load_registry

ROOT = Path(__file__).resolve().parents[1]


def test_committed_squid_conf_matches_registry() -> None:
    """Drift check: the proxy allowlist is generated from config/sources.toml."""
    out = subprocess.run(
        [sys.executable, "-m", "cyberintel.deploy", "squid", "--ai-host", "api.anthropic.com",
         "--config", str(ROOT / "config" / "sources.toml")],
        capture_output=True, text=True, check=True, env={"PYTHONPATH": str(ROOT / "src")},
    ).stdout  # fmt: skip
    assert (ROOT / "deploy" / "squid" / "squid.conf").read_text() == out, (
        "regenerate: python -m cyberintel.deploy squid --ai-host api.anthropic.com"
        " > deploy/squid/squid.conf"
    )


def test_proxy_allowlist_equals_application_allowlist() -> None:
    conf = (ROOT / "deploy" / "squid" / "squid.conf").read_text()
    proxy_hosts = {ln.split()[-1] for ln in conf.splitlines() if ln.startswith("acl ingest_hosts")}
    assert proxy_hosts == set(load_registry(ROOT / "config" / "sources.toml").allowed_hosts())


def test_policy_order_denies_before_allowing() -> None:
    lines = [
        ln
        for ln in render_squid(["a.example"], ["api.b.example"]).splitlines()
        if ln.startswith("http_access")
    ]
    assert lines == [
        "http_access deny !CONNECT",
        "http_access deny !https_port",
        "http_access deny private_dst",
        "http_access allow ingest_port ingest_hosts",
        "http_access allow ai_port ai_hosts",
        "http_access deny all",
    ]


def test_ai_listener_has_no_destinations_when_no_ai_host() -> None:
    conf = render_squid(["a.example"])
    assert "ai_hosts" not in conf and "http_access deny all" in conf


def test_private_ranges_cover_metadata_and_lan() -> None:
    conf = render_squid(["a.example"])
    for net in (
        "169.254.0.0/16",
        "10.0.0.0/8",
        "192.168.0.0/16",
        "172.16.0.0/12",
        "100.64.0.0/10",
        "fc00::/7",
    ):
        assert net in conf
    # squid represents IPv4 as mapped IPv6, so this entry would mean "all of IPv4"
    assert "::ffff:0:0/96" not in conf


def test_no_trailing_comments_on_directives() -> None:
    # squid.conf has no inline comments: "x on  # note" passes "# note" as arguments
    for line in render_squid(["a.example"], ["b.example"]).splitlines():
        assert line.startswith("#") or "#" not in line, line


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "localhost",
        "a.example\nhttp_access allow all",
        "a.example all",
        "10.0.0.1",
        "*.example",
        "a..example",
    ],
)
def test_hostile_or_malformed_hosts_cannot_inject_config(bad: str) -> None:
    with pytest.raises(ValueError):
        render_squid([bad])


def test_suffix_entries_allowed() -> None:
    assert "acl ingest_hosts dstdomain .cisa.gov" in render_squid([".cisa.gov"])

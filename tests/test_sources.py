"""KEV / EPSS parsers and normalization."""

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from cyberintel.collectors.epss import EpssError, parse_epss
from cyberintel.collectors.kev import MAX_KEV_BYTES, KevError, parse_kev
from cyberintel.normalize import canonical_url, extract_cves

FIX = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- KEV


def test_kev_valid_rows_parse_and_bad_rows_are_isolated() -> None:
    cat = parse_kev((FIX / "kev" / "kev_sample.json").read_bytes())
    assert cat.catalog_version == "2026.11.09"
    assert cat.date_released == datetime(2026, 11, 9, 17, 2, 11, tzinfo=UTC)

    by_id = {e.cve_id: e for e in cat.entries}
    assert set(by_id) == {"CVE-2026-123158", "CVE-2026-102895", "CVE-2026-116779"}

    ssh = by_id["CVE-2026-123158"]
    assert ssh.date_added == date(2026, 11, 9)
    assert ssh.due_date == date(2026, 11, 30)
    assert ssh.ransomware_known is False
    assert ssh.cwes == ("CWE-394",)

    gpu = by_id["CVE-2026-102895"]  # lower-case ID normalized
    assert gpu.ransomware_known is True
    assert gpu.cwes == ("CWE-287", "CWE-290")  # junk CWE filtered

    fs = by_id["CVE-2026-116779"]
    assert fs.due_date is None and fs.notes == "" and fs.cwes == ()  # empty/null tolerated

    errors = {r.index: r.error for r in cat.rejected}
    assert set(errors) == {3, 4, 5, 6}
    assert "not a CVE ID" in errors[3]
    assert "dateAdded" in errors[4]
    assert errors[5] == "duplicate cveID"
    assert "not an object" in errors[6]
    assert not cat.count_mismatch  # 3 accepted + 4 rejected == declared 7


def test_kev_count_mismatch_is_flagged() -> None:
    doc = json.loads((FIX / "kev" / "kev_sample.json").read_bytes())
    doc["count"] = 99
    assert parse_kev(json.dumps(doc).encode()).count_mismatch


@pytest.mark.parametrize(
    "payload", [b"", b"{not json", b"[]", b'{"vulnerabilities": "nope"}', b"\xff\xfe"]
)
def test_kev_structural_errors_are_fatal(payload: bytes) -> None:
    with pytest.raises(KevError):
        parse_kev(payload)


def test_kev_size_cap() -> None:
    with pytest.raises(KevError, match="limit"):
        parse_kev(b" " * (MAX_KEV_BYTES + 1))


def test_kev_overlong_field_rejects_row_not_catalog() -> None:
    row = {
        "cveID": "CVE-2026-000001",
        "vendorProject": "V" * 10_000,
        "product": "p",
        "vulnerabilityName": "n",
        "dateAdded": "2026-11-01",
        "shortDescription": "",
        "requiredAction": "",
        "knownRansomwareCampaignUse": "Unknown",
    }
    cat = parse_kev(json.dumps({"vulnerabilities": [row]}).encode())
    assert cat.entries == () and len(cat.rejected) == 1
    assert "vendor" in cat.rejected[0].error


# ---------------------------------------------------------------- EPSS


def test_epss_parses_metadata_and_rejects_bad_rows() -> None:
    lines = (FIX / "epss" / "epss_sample.csv").read_text().splitlines()
    snap = parse_epss(lines)
    assert snap.model_version == "v2025.03.14"
    assert snap.score_date == datetime(2026, 11, 17, 12, 55, tzinfo=UTC)
    assert set(snap.scores) == {"CVE-2026-123158", "CVE-2026-102895", "CVE-2026-125350"}
    assert snap.scores["CVE-2026-123158"].epss == pytest.approx(0.94321)
    assert snap.rejected_rows == 4  # out-of-range, bad id, non-numeric, short row


def test_epss_without_metadata_line() -> None:
    snap = parse_epss(["cve,epss,percentile", "CVE-2026-000001,0.5,0.9"])
    assert snap.model_version is None and len(snap.scores) == 1


@pytest.mark.parametrize("lines", [[], ["#model_version:x"], ["a,b,c", "CVE-2026-1,0.1,0.1"]])
def test_epss_structural_errors(lines: list[str]) -> None:
    with pytest.raises(EpssError):
        parse_epss(lines)


# ---------------------------------------------------------------- normalization


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("see CVE-2026-123158 and cve-2026-102895", ("CVE-2026-102895", "CVE-2026-123158")),
        ("dup CVE-2026-1234 CVE-2026-1234", ("CVE-2026-1234",)),
        ("non-breaking CVE\u20112026\u20115281 and en dash CVE\u20132026\u20132441",
         ("CVE-2026-2441", "CVE-2026-5281")),
        ("numeric sort CVE-2026-99999 CVE-2026-100000", ("CVE-2026-99999", "CVE-2026-100000")),
        ("too short CVE-2026-123, bad year CVE-0001-12345", ()),
        ("embedded XCVE-2026-12345Y", ()),
        ("", ()),
    ],
)  # fmt: skip
def test_extract_cves(text: str, expected: tuple[str, ...]) -> None:
    assert extract_cves(text) == expected


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("HTTPS://Research.Example.org:443/posts/x/?utm_source=rss&b=2&a=1#top",
         "https://research.example.org/posts/x?a=1&b=2"),
        ("https://example.org", "https://example.org/"),
        ("https://example.org/?fbclid=abc&gclid=x", "https://example.org/"),
        ("https://example.org:8443/x", "https://example.org:8443/x"),
        ("https://example.org./x/", "https://example.org/x"),
    ],
)  # fmt: skip
def test_canonical_url(a: str, b: str) -> None:
    assert canonical_url(a) == b


def test_canonical_url_makes_tracking_variants_equal() -> None:
    variants = [
        "https://www.securityweek.com/sshole/?utm_medium=social",
        "https://www.securityweek.com/sshole#comments",
        "https://WWW.securityweek.com/sshole/",
    ]
    assert len({canonical_url(v) for v in variants}) == 1

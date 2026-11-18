"""NVD 2.0 and CVE 5.x parsers, and the CVSS headline-score policy."""

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from cyberintel.collectors.cve5 import Cve5Error, parse_cve5
from cyberintel.collectors.cvss import CvssScore, headline
from cyberintel.collectors.nvd import NvdError, NvdPage, parse_nvd_page

FIX = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------- NVD


@pytest.fixture(scope="module")
def nvd_page() -> NvdPage:
    return parse_nvd_page((FIX / "nvd" / "page.json").read_bytes())


def test_nvd_paging(nvd_page: NvdPage) -> None:
    assert (nvd_page.start_index, nvd_page.results_per_page, nvd_page.total_results) == (0, 4, 9)
    assert nvd_page.next_start_index == 4
    assert nvd_page.timestamp == datetime(2026, 11, 18, 9, 12, 44, 123000, tzinfo=UTC)


def test_nvd_analysed_record(nvd_page: NvdPage) -> None:
    ssh = {c.cve_id: c for c in nvd_page.cves}["CVE-2026-123158"]
    assert ssh.vuln_status == "Analyzed"
    assert ssh.description.startswith("OpenSSH before 10.6p2")  # English picked over Spanish
    assert ssh.published == datetime(2026, 11, 5, 15, 46, tzinfo=UTC)
    assert ssh.cwes == ("CWE-394",)  # deduplicated, junk dropped
    assert ssh.references == ("https://www.openssh.com/releasenotes.html",)  # js: + dupe dropped
    assert ssh.has_cpe is True
    assert ssh.kev_date_added == date(2026, 11, 9)

    by = {(s.version, s.origin): s for s in ssh.scores}
    assert set(by) == {("4.0", "cna"), ("3.1", "nvd"), ("3.1", "cna")}  # malformed metric skipped
    assert by[("3.1", "nvd")].base_score == 8.1
    assert by[("3.1", "cna")].base_score == 9.8  # disagreement kept, not resolved silently
    h = headline(ssh.scores)
    assert h is not None and (h.version, h.origin, h.base_score) == ("3.1", "nvd", 8.1)


def test_nvd_deferred_record_keeps_cna_and_other_scores(nvd_page: NvdPage) -> None:
    rec = {c.cve_id: c for c in nvd_page.cves}["CVE-2026-130001"]
    assert rec.vuln_status == "Deferred"  # i.e. "Not Scheduled" on nvd.nist.gov
    assert rec.has_cpe is False
    origins = {(s.origin, s.base_score) for s in rec.scores}
    assert origins == {("cna", 6.5), ("other", 7.5)}  # relayed ADP is not over-claimed
    h = headline(rec.scores)
    assert h is not None and h.origin == "cna"


def test_nvd_v2_severity_outside_cvss_data(nvd_page: NvdPage) -> None:
    old = {c.cve_id: c for c in nvd_page.cves}["CVE-2009-0001"]
    (s,) = old.scores
    assert (s.version, s.severity, s.base_score) == ("2.0", "HIGH", 7.5)


def test_nvd_bad_record_is_quarantined(nvd_page: NvdPage) -> None:
    assert len(nvd_page.cves) == 3
    (bad,) = nvd_page.rejected
    assert bad.cve_id == "CVE-2026-130002" and "published" in bad.error


def test_nvd_last_page_has_no_next() -> None:
    doc = {"resultsPerPage": 4, "startIndex": 8, "totalResults": 9, "vulnerabilities": []}
    assert parse_nvd_page(json.dumps(doc).encode()).next_start_index is None


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"[]",
        b'{"vulnerabilities": {}}',
        b'{"vulnerabilities": [], "startIndex": "x"}',
        b'{"vulnerabilities": [], "startIndex": -1}',
    ],
)
def test_nvd_structural_errors(payload: bytes) -> None:
    with pytest.raises(NvdError):
        parse_nvd_page(payload)


def test_nvd_rate_limit_html_page_is_rejected() -> None:
    # NVD has been observed to answer throttled requests with an HTML page.
    with pytest.raises(NvdError, match="invalid JSON"):
        parse_nvd_page(b"<html><body>Request forbidden by administrative rules.</body></html>")


# --------------------------------------------------------------------- CVE 5


def test_cve5_published_record_with_cisa_adp() -> None:
    rec = parse_cve5((FIX / "cve5" / "published.json").read_bytes())
    assert rec.cve_id == "CVE-2026-102895" and rec.state == "PUBLISHED" and not rec.is_rejected
    assert rec.assigner == "GitHub_M"
    assert rec.title == "GPUStack treats loopback requests as authenticated"
    assert rec.description.startswith("Prior to 2.2.0")  # exact "en" beats "en-US"
    assert rec.date_updated == datetime(2026, 11, 10, 13, 5, 21, 442000, tzinfo=UTC)
    assert rec.cwes == ("CWE-287", "CWE-290")  # cweId + one recovered from text
    assert [(a.vendor, a.product) for a in rec.affected] == [("gpustack", "gpustack")]
    assert rec.references == (
        "https://github.com/gpustack/gpustack/security/advisories/GHSA-gj9m-f8ph-pmhr",
    )
    assert {(s.version, s.origin, s.provider) for s in rec.scores} == {
        ("3.1", "cna", "GitHub_M"),
        ("4.0", "cna", "GitHub_M"),
    }
    assert rec.ssvc is not None
    assert (rec.ssvc.exploitation, rec.ssvc.automatable, rec.ssvc.technical_impact) == (
        "active",
        "yes",
        "total",
    )
    assert rec.adp_kev_date == date(2026, 11, 9)


def test_cve5_rejected_record_uses_rejected_reasons() -> None:
    rec = parse_cve5((FIX / "cve5" / "rejected.json").read_bytes())
    assert rec.is_rejected
    assert "Duplicate of CVE-2026-123158" in rec.description
    assert rec.scores == () and rec.ssvc is None


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        (b"not json", "invalid JSON"),
        (b"[]", "not an object"),
        (b'{"cveMetadata": {"cveId": "nope", "state": "PUBLISHED"}}', "cveId"),
        (b'{"cveMetadata": {"cveId": "CVE-2026-1234", "state": "RESERVED"}}', "state"),
    ],
)
def test_cve5_structural_errors(payload: bytes, match: str) -> None:
    with pytest.raises(Cve5Error, match=match):
        parse_cve5(payload)


def test_cve5_minimal_record_with_garbage_containers() -> None:
    doc = {
        "cveMetadata": {"cveId": "cve-2026-4321", "state": "PUBLISHED"},
        "containers": {"cna": {"metrics": "nope", "affected": [1, None], "problemTypes": [{}]},
                       "adp": ["junk", {"metrics": [{"other": {"type": "ssvc"}}]}]},
    }  # fmt: skip
    rec = parse_cve5(json.dumps(doc).encode())
    assert rec.cve_id == "CVE-2026-4321"  # normalized
    assert rec.scores == () and rec.affected == () and rec.description == ""
    assert rec.ssvc is not None and rec.ssvc.exploitation is None  # empty SSVC tolerated


# --------------------------------------------------------------------- headline policy


def s(version: str, origin: str, score: float = 5.0) -> CvssScore:
    return CvssScore(version=version, base_score=score, origin=origin, provider="p")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("scores", "expected"),
    [
        ([], None),
        ([s("4.0", "nvd"), s("3.1", "adp")], ("3.1", "adp")),  # v3.x family first
        ([s("3.1", "cna"), s("3.1", "nvd")], ("3.1", "nvd")),  # NVD > CNA
        ([s("3.1", "adp"), s("3.1", "cna")], ("3.1", "cna")),  # CNA > ADP
        ([s("3.0", "nvd"), s("3.1", "cna")], ("3.0", "nvd")),  # origin beats minor version
        ([s("3.0", "cna"), s("3.1", "cna")], ("3.1", "cna")),  # 3.1 > 3.0 at same origin
        ([s("2.0", "nvd"), s("4.0", "other")], ("4.0", "other")),  # v2 is last resort
        ([s("2.0", "nvd")], ("2.0", "nvd")),
    ],
)
def test_headline_policy(scores: list[CvssScore], expected: tuple[str, str] | None) -> None:
    h = headline(scores)
    assert (None if h is None else (h.version, h.origin)) == expected


def test_cvss_score_bounds() -> None:
    with pytest.raises(ValueError):
        s("3.1", "nvd", 10.5)

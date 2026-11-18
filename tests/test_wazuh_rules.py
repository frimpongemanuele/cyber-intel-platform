"""Static checks on the Wazuh rules (the behavioural tests run in CI on a real manager)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from defusedxml import ElementTree as ET

from cyberintel.security_events import EVENTS

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "detections" / "wazuh" / "rules" / "cit_rules.xml"
CASES = json.loads((ROOT / "detections" / "wazuh" / "tests" / "cases.json").read_text())


def rules() -> list[Any]:
    # Wazuh rule files have several top-level <group> elements: wrap them for parsing
    root = ET.fromstring("<root>" + RULES.read_text() + "</root>")
    return list(root.iter("rule"))


def field(rule: Any, name: str) -> str | None:
    for f in rule.findall("field"):
        if f.get("name") == name:
            return str(f.text)
    return None


def test_ids_unique_in_range_and_described() -> None:
    ids = [int(r.get("id")) for r in rules()]
    assert len(ids) == len(set(ids))
    assert all(100100 <= i <= 100199 for i in ids)
    assert all(r.find("description") is not None for r in rules())


def test_every_platform_event_has_a_rule() -> None:
    patterns = [
        re.compile(p) for r in rules() if (p := field(r, "cit_event")) and r.get("id") != "100100"
    ]
    for event in EVENTS:
        assert any(p.search(event) for p in patterns), f"no rule for {event}"


# File-integrity events are produced by Wazuh's syscheck module, not by a log line, so the
# logtest engine cannot replay them; these rules are verified on the host instead
# (docs/DETECTIONS.md, simulation steps).
VERIFIED_ON_HOST = {"100160", "100161"}


def test_every_alerting_rule_has_a_ci_case() -> None:
    expected = set()
    for case in CASES:
        expected |= {case.get("last")} | set(case.get("seen", [])) | set(case.get("first_at", {}))
    alerting = {r.get("id") for r in rules() if r.get("level") != "0"}
    assert alerting - expected - VERIFIED_ON_HOST == set(), "alerting rule without a test"
    assert alerting >= VERIFIED_ON_HOST  # the exemption list cannot go stale silently


def healthcheck_commands() -> dict[str, str]:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    out = {}
    for name, svc in compose["services"].items():
        test = (svc.get("healthcheck") or {}).get("test")
        if test and test[0] == "CMD":
            out[name] = " ".join(test[1:])  # how Docker reports it: "exec_start: <args>"
    return out


def silencer() -> re.Pattern[str]:
    rule = next(r for r in rules() if r.get("id") == "100150")
    return re.compile(str(field(rule, "docker.Action")))


def test_healthcheck_silencer_matches_compose_exactly() -> None:
    commands = healthcheck_commands()
    assert set(commands) == {"db", "egress", "web"}
    for service, cmd in commands.items():
        assert silencer().fullmatch(f"exec_start: {cmd}"), f"{service} health check would alert"


@pytest.mark.parametrize(
    "action",
    [
        "exec_start: sh",
        "exec_start: bash -c exec 3<>/dev/tcp/10.0.0.1/4444",  # look-alike of the egress check
        "exec_start: pg_isready -h /var/run/postgresql -U postgres -d cit; id",
        "exec_start: python -m cyberintel.web.healthcheck && cat /run/secrets/x",
    ],
)
def test_silencer_does_not_hide_lookalikes(action: str) -> None:
    assert not silencer().fullmatch(action)

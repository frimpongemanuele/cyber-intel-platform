"""Replay test sequences through a real Wazuh manager's logtest engine (CI).

Runs *inside* the wazuh-manager container with Wazuh's bundled Python:

    /var/ossec/framework/python/bin/python3 run_logtest.py cases.json

Each case is a sequence of events sent in one logtest session (so frequency and
correlation rules see the history). For every event the matched rule id and level are
recorded; a case passes when its expectations hold:

    "last":     rule id the final event must match (string), or null for "no rule above 0"
    "seen":     rule ids that must match at least one event
    "not_seen": rule ids that must not match any event
    "first_at": {rule id: index (0-based) of the event that must be the first to match it}

Talks the logtest socket protocol directly (4-byte little-endian length + JSON).
"""

from __future__ import annotations

import json
import socket
import struct
import sys
from typing import Any

SOCKET = "/var/ossec/queue/sockets/logtest"


def call(payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCKET)
        s.sendall(struct.pack("<I", len(data)) + data)
        (size,) = struct.unpack("<I", recv_exact(s, 4))
        return json.loads(recv_exact(s, size))


def recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("logtest socket closed")
        buf += chunk
    return buf


def process(event: dict[str, str], token: str | None) -> tuple[dict[str, Any], str | None]:
    params: dict[str, Any] = {
        "event": event["event"],
        "log_format": event.get("log_format", "json"),
        "location": event.get("location", "cit-ci"),
    }
    if token:
        params["token"] = token
    reply = call(
        {
            "version": 1,
            "origin": {"name": "cit-ci", "module": "logtest"},
            "command": "log_processing",
            "parameters": params,
        }
    )
    if reply.get("error"):
        raise RuntimeError(f"logtest error: {reply}")
    data = reply["data"]
    return data.get("output", {}), data.get("token", token)


def run_case(case: dict[str, Any]) -> tuple[bool, list[str]]:
    token: str | None = None
    matched: list[tuple[str | None, int]] = []
    for ev in case["events"]:
        for _ in range(int(ev.get("repeat", 1))):
            output, token = process(ev, token)
            rule = output.get("rule") or {}
            matched.append((rule.get("id"), int(rule.get("level", 0))))
    problems: list[str] = []
    ids = [rid for rid, _ in matched]
    last_id, last_level = matched[-1]
    if "last" in case:
        want = case["last"]
        if want is None and last_level > 0:
            problems.append(f"last event alerted: rule {last_id} level {last_level}")
        if want is not None and last_id != want:
            problems.append(f"last event matched {last_id}, expected {want}")
    for rid in case.get("seen", []):
        if rid not in ids:
            problems.append(f"rule {rid} never matched")
    for rid in case.get("not_seen", []):
        if rid in ids:
            problems.append(f"rule {rid} matched at event {ids.index(rid)}")
    for rid, idx in case.get("first_at", {}).items():
        got = ids.index(rid) if rid in ids else None
        if got != idx:
            problems.append(f"rule {rid} first matched at event {got}, expected {idx}")
    trace = ", ".join(f"{rid}:{lvl}" for rid, lvl in matched)
    return not problems, [*problems, f"trace: {trace}"]


def main() -> int:
    cases = json.load(open(sys.argv[1], encoding="utf-8"))  # noqa: SIM115
    failures = 0
    for case in cases:
        ok, notes = run_case(case)
        failures += not ok
        print(("PASS " if ok else "FAIL ") + case["name"])
        for note in notes if not ok else notes[-1:]:
            print("     " + note)
    print(f"{len(cases) - failures}/{len(cases)} detection cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

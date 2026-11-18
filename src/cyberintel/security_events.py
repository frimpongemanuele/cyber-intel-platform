"""Structured security events: one JSON object per line, for the SIEM (docs/DETECTIONS.md).

    emit("auth.login_failed", client="10.0.0.5")
    -> {"cit_event":"auth.login_failed","severity":"medium","service":"web",
        "ts":"2026-11-18T19:52:01.123Z","client":"10.0.0.5"}

Design rules, because these lines feed detections and are themselves an attack surface:

* **Closed vocabulary.** Only events listed in ``EVENTS`` can be emitted, each with a
  fixed severity, so SIEM decoders and rules never chase free-form text.
* **Log injection is impossible.** Values are attacker-influenced (a Host header, a feed
  URL, a model's output). Each line is a single ``json.dumps`` object; control, format
  (bidi, zero-width) and private-use characters are removed and strings are capped, so a
  value can neither start a new line nor spoof what an analyst sees.
* **No secrets, by construction.** Field names that could carry a credential are
  refused at the call site (``ValueError``), so a careless future call fails in tests.
* Output goes to stderr (container log) and, if ``CIT_SECURITY_LOG`` names a file, to a
  size-rotated file the SIEM agent can read directly.
"""

from __future__ import annotations

import contextlib
import json
import logging
import logging.handlers
import os
import re
import sys
import threading
import unicodedata
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal

Severity = Literal["low", "medium", "high", "critical"]

EVENTS: Mapping[str, Severity] = {
    # dashboard
    "auth.login_succeeded": "low",
    "auth.login_failed": "medium",
    "auth.login_throttled": "high",
    "auth.session_rejected": "medium",
    "web.csrf_refused": "medium",
    "web.host_rejected": "low",
    # collection
    "fetch.url_rejected": "high",
    "source.failed": "low",
    "feed.records_quarantined": "medium",
    # AI layer
    "ai.output_rejected": "medium",
    "ai.injection_suspected": "medium",
    "ai.token_cap_reached": "low",
    "ai.provider_failing": "low",
}

RESERVED = frozenset({"cit_event", "severity", "service", "ts"})
_SECRETISH = re.compile(r"pass|secret|token|cookie|auth|key|dsn|credential|session_id", re.I)
MAX_STR = 200
MAX_LIST = 5
LOGGER_NAME = "cyberintel.security"

_lock = threading.Lock()
_configured = False


def _clean_str(value: str) -> str:
    kept = (
        ch for ch in value if unicodedata.category(ch) not in {"Cc", "Cf", "Co", "Cs"} or ch == " "
    )
    out = "".join(kept)
    return out if len(out) <= MAX_STR else out[: MAX_STR - 1] + "…"


def _clean(value: object) -> object:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return _clean_str(value)
    if isinstance(value, list | tuple):
        return [_clean(v) for v in list(value)[:MAX_LIST]]
    return _clean_str(str(value))


def _logger() -> logging.Logger:
    global _configured
    log = logging.getLogger(LOGGER_NAME)
    if _configured:
        return log
    with _lock:
        if not _configured:
            log.setLevel(logging.INFO)
            log.propagate = False  # never re-formatted or duplicated by the root logger
            fmt = logging.Formatter("%(message)s")
            stderr = logging.StreamHandler(sys.stderr)
            stderr.setFormatter(fmt)
            log.addHandler(stderr)
            path = os.environ.get("CIT_SECURITY_LOG")
            if path:
                try:
                    handler = logging.handlers.RotatingFileHandler(
                        path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
                    )
                except OSError as exc:
                    # Keep stderr working; say once, without the path's contents or details.
                    print(
                        f"security events: cannot open CIT_SECURITY_LOG ({type(exc).__name__});"
                        " writing to stderr only",
                        file=sys.stderr,
                    )
                else:
                    handler.setFormatter(fmt)
                    log.addHandler(handler)
            _configured = True  # even on failure: never stack duplicate handlers
    return log


def build(event: str, fields: Mapping[str, object], *, now: datetime | None = None) -> str:
    """Return the JSON line for ``event`` (raises ValueError on misuse)."""
    if event not in EVENTS:
        raise ValueError(f"unknown security event {event!r}")
    for name in fields:
        if name in RESERVED:
            raise ValueError(f"field {name!r} is reserved")
        if _SECRETISH.search(name):
            raise ValueError(f"field {name!r} looks like it could carry a secret")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", name):
            raise ValueError(f"bad field name {name!r}")
    ts = (now or datetime.now(UTC)).astimezone(UTC)
    record: dict[str, object] = {
        "cit_event": event,
        "severity": EVENTS[event],
        "service": os.environ.get("CIT_SERVICE", "cyberintel"),
        "ts": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z",
    }
    record.update({k: _clean(v) for k, v in fields.items()})
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"))


def emit(event: str, **fields: Any) -> None:
    """Log one security event. Never raises at runtime for I/O problems."""
    line = build(event, fields)
    with contextlib.suppress(Exception):  # logging must never take a request or run down
        _logger().info(line)

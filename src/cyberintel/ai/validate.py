"""Validate model output. This is the security gate of the AI layer.

Assume the model may be *fully compromised* by injected content. Containment therefore
cannot depend on the model behaving; it rests on these mechanical checks:

1. size cap, then exactly one JSON object (no "find the first {" salvage);
2. strict schema (``AnalysisOutput``, unknown keys rejected, length caps);
3. no control, zero-width or bidi characters (hidden text / display spoofing);
4. every URL anywhere in the output, cited or in prose, must be an input evidence URL;
   no markdown or HTML link syntax at all;
5. every CVE ID mentioned must be one of the input CVEs (no hallucinated or planted IDs);
6. no executable instructions (AI text never tells the analyst to run something);
7. the per-call canary and delimiter boundary must not appear (prompt-leak detection).

Any failure: the output is stored as rejected, with reasons, and never displayed.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field

from pydantic import ValidationError

from cyberintel.ai.schema import AnalysisInput, AnalysisOutput
from cyberintel.normalize import extract_cves

MAX_RAW_CHARS = 20_000
MAX_KEY_POINT_CHARS = 240

_FENCE = re.compile(r"^```(?:json)?\s*\n(?P<body>.*)\n```\s*$", re.DOTALL | re.IGNORECASE)
_URL = re.compile(
    r"(?:https?|ftp|file|data|javascript|vbscript):/{0,2}[^\s\"'<>()\]]+|www\.[^\s\"'<>()\]]+",
    re.IGNORECASE,
)
_LINK_SYNTAX = re.compile(r"\]\(|<\s*a\b|<\s*img\b|<\s*script\b|\[\s*[^\]]*\]\s*:", re.IGNORECASE)
_EXECUTABLE = re.compile(
    r"""(
        (curl|wget|fetch)\b[^\n]*\|\s*(ba|z|da)?sh\b        # download | shell
      | \b(ba|z)?sh\s+-c\b                                   # sh -c '...'
      | \bpowershell(\.exe)?\s+-(e|enc|encodedcommand|c|command)\b
      | \b(iex|invoke-expression)\s*\(?
      | \brm\s+-rf\b
      | \bchmod\s+(\+x|[0-7]{3,4})\b
      | \bnc(at)?\b[^\n]*\s-e\b                            # netcat reverse shell
      | /dev/tcp/
      | \bbash\s+-i\b
      | \bcertutil\b[^\n]*-urlcache
      | \bbase64\s+(-d|--decode)\b[^\n]*\|
      | \bpython[23]?\s+-c\b
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def _bad_char(ch: str) -> bool:
    if ch == "\n":
        return False
    cat = unicodedata.category(ch)
    # Cc: control; Cf: format (zero-width, bidi overrides, BOM, ...); Co/Cs: private/surrogate
    return cat in {"Cc", "Cf", "Co", "Cs"}


@dataclass(slots=True)
class ValidationResult:
    output: AnalysisOutput | None
    reasons: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.output is not None and not self.reasons


class _DuplicateKeyError(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise _DuplicateKeyError(k)
        out[k] = v
    return out


def _reject_constant(name: str) -> object:
    raise ValueError(name)


def _parse(raw: str) -> tuple[str | None, str | None]:
    """Return the JSON text to validate, or an error. Duplicate keys and NaN are refused:
    two parsers that disagree on ``{"a":1,"a":2}`` are a classic smuggling channel."""
    text = raw.strip()
    fenced = _FENCE.match(text)
    if fenced:
        text = fenced.group("body").strip()
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except _DuplicateKeyError as exc:
        return None, f"duplicate JSON key {str(exc)[:40]!r}"
    except json.JSONDecodeError as exc:
        return None, f"not a single JSON document ({exc.msg})"
    except ValueError:
        return None, "non-finite number in JSON"
    if not isinstance(value, dict):
        return None, "top-level JSON value is not an object"
    return text, None


def validate_output(
    raw: str, given: AnalysisInput, *, canary: str, boundary: str
) -> ValidationResult:
    if len(raw) > MAX_RAW_CHARS:
        return ValidationResult(None, [f"output exceeds {MAX_RAW_CHARS} characters"])
    for secret_marker, label in ((canary, "canary"), (boundary, "delimiter boundary")):
        if secret_marker and secret_marker in raw:
            return ValidationResult(None, [f"output contains the {label} (prompt leak)"])

    text, error = _parse(raw)
    if text is None:
        return ValidationResult(None, [error or "unparseable"])
    try:
        out = AnalysisOutput.model_validate_json(text, strict=True)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(map(str, e['loc'])) or '(root)'}: {e['msg']}" for e in exc.errors()[:5]
        )
        return ValidationResult(None, [f"schema: {details}"])

    reasons: list[str] = []
    texts = out.text_fields()
    allowed_urls = given.allowed_urls
    allowed_cves = given.allowed_cves

    for kp in out.key_points:
        if len(kp) > MAX_KEY_POINT_CHARS:
            reasons.append(f"key point exceeds {MAX_KEY_POINT_CHARS} characters")
    for t in [*texts, *out.cited_urls]:
        if any(_bad_char(ch) for ch in t):
            reasons.append("control, zero-width or bidi characters in output")
            break

    for url in out.cited_urls:
        if url not in allowed_urls:
            reasons.append(f"cited URL is not an input evidence URL: {url[:80]!r}")
    for t in texts:
        if _LINK_SYNTAX.search(t):
            reasons.append("markdown/HTML link or markup syntax in prose")
            break
    for t in texts:
        for url in _URL.findall(t):
            if url.rstrip(".,;:") not in allowed_urls:
                reasons.append(f"URL in prose is not an input evidence URL: {url[:80]!r}")
    mentioned = set(extract_cves(" ".join([*texts, *out.cited_urls])))
    for cve in sorted(mentioned - allowed_cves):
        reasons.append(f"mentions {cve}, which is not among the input CVEs")
    for t in texts:
        if _EXECUTABLE.search(t):
            reasons.append("output contains an executable instruction")
            break

    return ValidationResult(out, reasons) if reasons else ValidationResult(out)

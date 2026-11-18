"""Reduce untrusted HTML to plain text.

Used to (a) build short excerpts for storage and (b) build LLM input. Output is plain
text: no markup survives, so it cannot carry script into a page. Rendering still escapes
it (defence in depth, THREAT_MODEL T9); display-side HTML sanitization is a separate
concern handled in the UI layer.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

# Content inside these elements is never text a reader would see; drop it entirely.
_SKIP = frozenset({"script", "style", "noscript", "template", "iframe", "object", "svg", "math"})
_BLOCK = frozenset({"p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"})
_WS = re.compile(r"\s+")
MAX_INPUT_CHARS = 1_000_000


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP:
            self._skip_depth += 1
        elif tag in _BLOCK:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag in _BLOCK:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)


def html_to_text(html: str, max_chars: int) -> str:
    """Plain text from untrusted HTML, whitespace-collapsed and truncated to ``max_chars``."""
    parser = _TextExtractor()
    parser.feed(html[:MAX_INPUT_CHARS])
    parser.close()
    text = _WS.sub(" ", "".join(parser.parts)).strip()
    if len(text) > max_chars:
        text = text[: max_chars - 1].rstrip() + "…"
    return text

"""Bounded gzip decompression (decompression-bomb defence, THREAT_MODEL T3).

``gzip.decompress`` inflates everything into memory first: a 1 MB file can expand to
over 1 GB. Here output is produced in bounded steps with ``max_length`` and decompression
stops the moment the cap is exceeded, so peak memory stays near ``max_out``.
"""

from __future__ import annotations

import zlib

_GZIP_WBITS = 16 + zlib.MAX_WBITS
_STEP = 1 << 20  # emit at most 1 MiB per step


class DecompressionError(ValueError):
    pass


def gunzip_capped(data: bytes, max_out: int) -> bytes:
    """Decompress a (possibly multi-member) gzip stream, refusing output over ``max_out``."""
    if max_out <= 0:
        raise ValueError("max_out must be positive")
    out = bytearray()
    remaining = data
    while remaining:
        d = zlib.decompressobj(_GZIP_WBITS)
        chunk = remaining
        try:
            while chunk:
                out += d.decompress(chunk, _STEP)
                if len(out) > max_out:
                    raise DecompressionError(f"decompressed size exceeds {max_out} bytes")
                chunk = d.unconsumed_tail
            out += d.flush()
        except zlib.error as exc:
            raise DecompressionError(f"corrupt gzip data: {exc}") from None
        if len(out) > max_out:
            raise DecompressionError(f"decompressed size exceeds {max_out} bytes")
        if not d.eof:
            raise DecompressionError("truncated gzip stream")
        remaining = d.unused_data  # next gzip member, if any
    return bytes(out)

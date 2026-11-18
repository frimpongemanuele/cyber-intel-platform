"""Per-host minimum-interval rate limiting.

Sources publish limits (NVD: 5 requests per rolling 30 s without a key). Spacing requests
by a fixed minimum interval per host is simple, deterministic and provably within such a
limit: 5 / 30 s means one request every 6 s, so we use 6.5 s for margin.

The clock and sleep functions are injectable so tests run instantly and deterministically.
"""

from __future__ import annotations

import time
from collections.abc import Callable


class HostRateLimiter:
    def __init__(
        self,
        default_interval: float = 1.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if default_interval < 0:
            raise ValueError("interval must be >= 0")
        self._default = default_interval
        self._clock = clock
        self._sleep = sleep
        self._last: dict[str, float] = {}

    def acquire(self, host: str, interval: float | None = None) -> float:
        """Block until a request to ``host`` is allowed. Returns seconds waited."""
        gap = self._default if interval is None else interval
        if gap < 0:
            raise ValueError("interval must be >= 0")
        waited = 0.0
        last = self._last.get(host)
        if last is not None:
            wait = last + gap - self._clock()
            if wait > 0:
                self._sleep(wait)
                waited = wait
        self._last[host] = self._clock()
        return waited

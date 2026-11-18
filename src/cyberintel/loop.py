"""Run a job periodically inside a container (no cron daemon, no shell).

* first run immediately, then every ``every`` seconds plus up to ``jitter`` of random
  delay (so restarts do not hammer sources in lock-step);
* SIGTERM / SIGINT stop the loop between runs and interrupt the wait at once, so
  ``docker compose stop`` is clean;
* an exception in one run is logged (type only, never the message, which may contain
  attacker-influenced text or connection strings) and the loop continues; the container
  restart policy is the backstop for anything worse.
"""

from __future__ import annotations

import logging
import random
import signal
import threading
from collections.abc import Callable

log = logging.getLogger("cyberintel.loop")


def run_every(
    job: Callable[[], int],
    *,
    every: float,
    jitter: float = 0.0,
    stop: threading.Event | None = None,
    install_signals: bool = True,
    rand: Callable[[], float] = random.random,
) -> int:
    """Return the number of runs performed (for tests)."""
    if every <= 0:
        raise ValueError("every must be positive")
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    stop = stop or threading.Event()
    if install_signals:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
    runs = 0
    while not stop.is_set():
        runs += 1
        try:
            code = job()
            log.info("run %d finished with code %d", runs, code)
        except Exception as exc:  # keep the service alive; see docstring
            log.error("run %d failed: %s", runs, type(exc).__name__)
        stop.wait(every + jitter * rand())
    return runs

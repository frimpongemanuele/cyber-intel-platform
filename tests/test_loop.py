from __future__ import annotations

import logging
import threading

import pytest

from cyberintel.loop import run_every


def test_runs_until_stopped_and_survives_exceptions(caplog: pytest.LogCaptureFixture) -> None:
    stop = threading.Event()
    calls: list[int] = []

    def job() -> int:
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("postgres://user:secret@db/x")  # message must not be logged
        if len(calls) == 3:
            stop.set()
        return 0

    with caplog.at_level(logging.INFO, logger="cyberintel.loop"):
        runs = run_every(job, every=0.001, stop=stop, install_signals=False)
    assert runs == 3
    assert "RuntimeError" in caplog.text and "secret" not in caplog.text


def test_stop_interrupts_wait_immediately() -> None:
    stop = threading.Event()
    waits: list[float] = []

    def job() -> int:
        threading.Timer(0.05, stop.set).start()
        return 0

    import time

    t0 = time.monotonic()
    run_every(job, every=3600, stop=stop, install_signals=False)
    waits.append(time.monotonic() - t0)
    assert waits[0] < 5


def test_jitter_is_added_to_the_wait() -> None:
    stop = threading.Event()
    seen: list[float] = []

    class Ev(threading.Event):
        def wait(self, timeout: float | None = None) -> bool:
            seen.append(timeout or 0.0)
            self.set()
            return True

    run_every(lambda: 0, every=10, jitter=5, stop=Ev(), install_signals=False, rand=lambda: 0.5)
    assert seen == [12.5]
    assert not stop.is_set()


def test_rejects_non_positive_interval() -> None:
    with pytest.raises(ValueError):
        run_every(lambda: 0, every=0, install_signals=False)

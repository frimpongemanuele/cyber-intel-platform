"""Dashboard authentication primitives."""

from __future__ import annotations

import base64
import json

import pytest

from cyberintel.web.auth import (
    MIN_SCRYPT_N,
    AuthConfig,
    AuthConfigError,
    LoginThrottle,
    PasswordHash,
    SessionSigner,
    hash_password,
)

FAST_N = MIN_SCRYPT_N  # keep tests quick while staying at the enforced minimum
SECRET = bytes(range(32))


@pytest.fixture(scope="module")
def stored() -> str:
    return hash_password("correct horse battery staple", n=FAST_N)


# --------------------------------------------------------------------------- passwords


def test_hash_roundtrip_and_salt_uniqueness(stored: str) -> None:
    h = PasswordHash.parse(stored)
    assert h.verify("correct horse battery staple")
    assert not h.verify("correct horse battery stapl")
    assert not h.verify("")
    assert not h.verify("x" * 5000)  # over the input bound: rejected without hashing
    assert hash_password("same", n=FAST_N) != hash_password("same", n=FAST_N)  # random salt


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "plaintext-password",
        "bcrypt$12$abc$def",
        "scrypt$1024$8$1$AAAAAAAAAAAAAAAAAAAAAA$" + "A" * 43,  # n too small (downgrade)
        "scrypt$20000$8$1$AAAAAAAAAAAAAAAAAAAAAA$" + "A" * 43,  # n not a power of two
        "scrypt$32768$4$1$AAAAAAAAAAAAAAAAAAAAAA$" + "A" * 43,  # r too small
        "scrypt$32768$8$1$AAAA$" + "A" * 43,  # salt too short
        "scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA$AAAA",  # digest wrong size
        "scrypt$x$8$1$a$b",
    ],
)
def test_unsafe_or_malformed_hashes_refused_at_startup(bad: str) -> None:
    with pytest.raises(AuthConfigError):
        PasswordHash.parse(bad)


# --------------------------------------------------------------------------- sessions


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_session_issue_verify_and_expiry() -> None:
    clock = Clock()
    signer = SessionSigner(SECRET, lifetime=3600, clock=clock)
    token = signer.issue()
    assert signer.verify(token)
    clock.t += 3599
    assert signer.verify(token)
    clock.t += 2
    assert not signer.verify(token)  # expired


def test_session_rejects_tampering_and_other_keys() -> None:
    clock = Clock()
    signer = SessionSigner(SECRET, clock=clock)
    token = signer.issue()
    body, mac = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(body + "=="))
    payload["exp"] += 10**6  # try to extend the session
    forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    assert not signer.verify(f"{forged}.{mac}")
    # Flip the last MAC character to a *different* one. (The original appended "A", which
    # was a no-op whenever the MAC already ended in "A": a 1-in-64 flaky pass/fail.)
    flipped = "B" if mac[-1] == "A" else "A"
    assert not signer.verify(f"{body}.{mac[:-1]}{flipped}")
    assert not SessionSigner(bytes(32), clock=clock).verify(token)  # rotated secret


@pytest.mark.parametrize(
    "garbage",
    [None, "", "a", "a.b.c", "é.é", "x" * 600, ".", "abc.", ".abc", "eyJ9.%%%"],
)
def test_session_garbage_is_rejected(garbage: str | None) -> None:
    assert not SessionSigner(SECRET).verify(garbage)


def test_session_rejects_future_dated_and_overlong_tokens() -> None:
    clock = Clock()
    signer = SessionSigner(SECRET, lifetime=3600, clock=clock)
    clock.t += 10_000
    future = signer.issue()  # issued "in the future" relative to the verifier below
    clock.t -= 10_000
    assert not signer.verify(future)
    long_lived = SessionSigner(SECRET, lifetime=10**7, clock=clock).issue()
    assert not signer.verify(long_lived)  # exp - iat beyond this server's policy


def test_short_secret_refused() -> None:
    with pytest.raises(AuthConfigError, match="at least"):
        SessionSigner(b"short")


# --------------------------------------------------------------------------- throttle


def test_throttle_per_client_window_and_reset() -> None:
    clock = Clock(0.0)
    t = LoginThrottle(per_client=3, global_limit=100, window_seconds=60, clock=clock)
    for _ in range(3):
        assert t.allowed("10.0.0.5")
        t.record_failure("10.0.0.5")
    assert not t.allowed("10.0.0.5")
    assert t.allowed("10.0.0.6")  # other clients unaffected
    clock.t += 61
    assert t.allowed("10.0.0.5")  # window slid
    t.record_failure("10.0.0.5")
    t.record_success("10.0.0.5")
    assert t.allowed("10.0.0.5")


def test_throttle_global_budget_stops_distributed_guessing() -> None:
    clock = Clock(0.0)
    t = LoginThrottle(per_client=5, global_limit=10, window_seconds=60, clock=clock)
    for i in range(10):
        t.record_failure(f"10.0.{i}.1")  # one attempt each from many addresses
    assert not t.allowed("10.0.99.1")


def test_throttle_memory_is_bounded() -> None:
    t = LoginThrottle(per_client=5, global_limit=10**9, window_seconds=60, clock=Clock(0.0))
    for i in range(10_050):
        t.record_failure(f"c{i}")
    assert len(t._by_client) <= 10_000


# --------------------------------------------------------------------------- config


def test_config_fails_closed(stored: str) -> None:
    with pytest.raises(AuthConfigError, match="not set"):
        AuthConfig.from_values(None, SECRET.hex())
    with pytest.raises(AuthConfigError, match="not set"):
        AuthConfig.from_values(stored, None)
    with pytest.raises(AuthConfigError, match="hex"):
        AuthConfig.from_values(stored, "not-hex")
    with pytest.raises(AuthConfigError, match="at least"):
        AuthConfig.from_values(stored, "ab" * 8)
    cfg = AuthConfig.from_values(stored, SECRET.hex())
    assert cfg.password.verify("correct horse battery staple")


def test_hash_password_cli_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    from cyberintel.web.auth import main

    monkeypatch.setattr("sys.stdin", io.StringIO("correct horse battery\n"))
    assert main(["hash-password", "--stdin"]) == 0
    out = capsys.readouterr().out.strip()
    assert PasswordHash.parse(out).verify("correct horse battery")
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert main(["hash-password", "--stdin"]) == 1
    assert capsys.readouterr().out == ""  # nothing that could be mistaken for a hash

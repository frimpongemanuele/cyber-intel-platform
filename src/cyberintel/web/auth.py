"""Single-user authentication for the dashboard (THREAT_MODEL T13). Standard library only.

Layers, outermost first: the dashboard is reachable only over the VPN (deployment), then
this login. Design choices:

* **scrypt** password hashing (``hashlib.scrypt``). The stored hash's cost parameters are
  checked against a minimum, so editing the config cannot silently downgrade them.
* **Stateless signed sessions**: ``base64url(payload).base64url(HMAC-SHA256)``; payload
  carries issued-at / expiry. Verified in constant time; expired, future-dated or
  malformed tokens are rejected. Rotating the secret revokes every session.
* **Throttling before verification**: once a client (or the whole site) exceeds the
  failure budget, login answers 429 *without* checking the password, so a throttled
  attacker learns nothing and costs us no scrypt work.
* **Fail closed**: a missing or weak secret, or a missing password hash, is a startup
  error. There is no "auth disabled" mode.

CLI:
    python -m cyberintel.web.auth hash-password   # prompts twice, prints the hash
    python -m cyberintel.web.auth new-secret      # prints a random session secret
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import sys
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
MIN_SCRYPT_N = 2**14
SCRYPT_MAXMEM = 128 * 1024 * 1024
MIN_SECRET_BYTES = 32
SESSION_SECONDS = 12 * 3600
CLOCK_SKEW_SECONDS = 60
MAX_PASSWORD_BYTES = 1024  # bounds scrypt input; long inputs are a DoS lever, not security


class AuthConfigError(RuntimeError):
    """The auth configuration is missing or unsafe. The app refuses to start."""


# --------------------------------------------------------------------------- passwords


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_password(password: str, *, n: int = SCRYPT_N, salt: bytes | None = None) -> str:
    pw = password.encode("utf-8")
    if not pw:
        raise ValueError("empty password")
    if len(pw) > MAX_PASSWORD_BYTES:
        raise ValueError("password too long")
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(pw, salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM, dklen=32)
    return f"scrypt${n}${SCRYPT_R}${SCRYPT_P}${_b64e(salt)}${_b64e(dk)}"


@dataclass(frozen=True, slots=True)
class PasswordHash:
    n: int
    r: int
    p: int
    salt: bytes
    digest: bytes

    @classmethod
    def parse(cls, encoded: str) -> PasswordHash:
        try:
            scheme, n, r, p, salt, digest = encoded.strip().split("$")
            parsed = cls(int(n), int(r), int(p), _b64d(salt), _b64d(digest))
        except (ValueError, binascii.Error):
            raise AuthConfigError("password hash is not in scrypt$n$r$p$salt$hash format") from None
        if scheme != "scrypt":
            raise AuthConfigError("only scrypt password hashes are supported")
        if parsed.n < MIN_SCRYPT_N or parsed.n & (parsed.n - 1) or parsed.r < 8 or parsed.p < 1:
            raise AuthConfigError("scrypt cost parameters are below the minimum")
        if len(parsed.salt) < 16 or len(parsed.digest) != 32:
            raise AuthConfigError("scrypt salt/digest have unexpected sizes")
        return parsed

    def verify(self, password: str) -> bool:
        pw = password.encode("utf-8")
        if not pw or len(pw) > MAX_PASSWORD_BYTES:
            return False
        dk = hashlib.scrypt(
            pw, salt=self.salt, n=self.n, r=self.r, p=self.p, maxmem=SCRYPT_MAXMEM, dklen=32
        )
        return hmac.compare_digest(dk, self.digest)


# --------------------------------------------------------------------------- sessions


class SessionSigner:
    def __init__(
        self,
        secret: bytes,
        *,
        lifetime: int = SESSION_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if len(secret) < MIN_SECRET_BYTES:
            raise AuthConfigError(f"session secret must be at least {MIN_SECRET_BYTES} bytes")
        self._key = hashlib.sha256(b"cyberintel-session-v1" + secret).digest()  # domain-separated
        self._lifetime = lifetime
        self._clock = clock

    def _mac(self, body: str) -> str:
        return _b64e(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())

    def issue(self) -> str:
        now = int(self._clock())
        payload = {"iat": now, "exp": now + self._lifetime, "nonce": secrets.token_hex(8)}
        body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
        return f"{body}.{self._mac(body)}"

    def verify(self, token: str | None) -> bool:
        if not token or len(token) > 512 or token.count(".") != 1:
            return False
        body, mac = token.split(".")
        try:
            body.encode("ascii")
            mac.encode("ascii")
        except UnicodeEncodeError:
            return False
        if not hmac.compare_digest(self._mac(body), mac):
            return False
        try:
            payload = json.loads(_b64d(body))
            iat, exp = int(payload["iat"]), int(payload["exp"])
        except (ValueError, KeyError, TypeError, binascii.Error):
            return False
        now = self._clock()
        return iat <= now + CLOCK_SKEW_SECONDS and now < exp and exp - iat <= self._lifetime


# --------------------------------------------------------------------------- throttling


@dataclass
class LoginThrottle:
    """Sliding-window failure budget per client and for the whole site."""

    per_client: int = 5
    global_limit: int = 50
    window_seconds: float = 900.0
    clock: Callable[[], float] = time.monotonic
    _by_client: dict[str, deque[float]] = field(default_factory=dict)
    _all: deque[float] = field(default_factory=deque)

    def _prune(self, q: deque[float]) -> None:
        cutoff = self.clock() - self.window_seconds
        while q and q[0] <= cutoff:
            q.popleft()

    def allowed(self, client: str) -> bool:
        self._prune(self._all)
        q = self._by_client.get(client)
        if q is not None:
            self._prune(q)
            if not q:
                del self._by_client[client]
                q = None
        return len(self._all) < self.global_limit and (q is None or len(q) < self.per_client)

    def record_failure(self, client: str) -> None:
        now = self.clock()
        self._all.append(now)
        self._by_client.setdefault(client, deque()).append(now)
        if len(self._by_client) > 10_000:  # bound memory under a distributed attempt
            oldest = min(self._by_client, key=lambda c: self._by_client[c][-1])
            del self._by_client[oldest]

    def record_success(self, client: str) -> None:
        self._by_client.pop(client, None)


# --------------------------------------------------------------------------- config


@dataclass(frozen=True, slots=True)
class AuthConfig:
    password: PasswordHash
    signer: SessionSigner

    @classmethod
    def from_values(cls, password_hash: str | None, secret: str | None) -> AuthConfig:
        if not password_hash:
            raise AuthConfigError("CIT_WEB_PASSWORD_HASH is not set (no unauthenticated mode)")
        if not secret:
            raise AuthConfigError("CIT_WEB_SECRET is not set")
        try:
            raw = bytes.fromhex(secret.strip())
        except ValueError:
            raise AuthConfigError("CIT_WEB_SECRET must be hex (use: new-secret)") from None
        return cls(PasswordHash.parse(password_hash), SessionSigner(raw))


def main(argv: list[str] | None = None) -> int:
    import argparse
    import getpass

    ap = argparse.ArgumentParser(description="Dashboard auth helpers.")
    ap.add_argument("command", choices=["hash-password", "new-secret"])
    ap.add_argument(
        "--stdin",
        action="store_true",
        help="read the password from stdin (one line) instead of prompting; for scripts",
    )
    args = ap.parse_args(argv)
    if args.command == "new-secret":
        print(secrets.token_hex(32))
        return 0
    if args.stdin:
        first = sys.stdin.readline().rstrip("\r\n")
    else:
        first = getpass.getpass("New dashboard password: ")
        if first != getpass.getpass("Repeat password: "):
            print("passwords do not match", file=sys.stderr)
            return 1
    if len(first) < 12:
        print("use at least 12 characters", file=sys.stderr)
        return 1
    print(hash_password(first))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

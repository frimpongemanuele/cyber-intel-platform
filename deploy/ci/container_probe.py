"""CI probe: run inside an app container to prove the runtime hardening."""

from __future__ import annotations

import os
import sys


def status(field: str) -> str:
    with open("/proc/self/status", encoding="ascii") as fh:
        for line in fh:
            if line.startswith(field + ":"):
                return line.split()[1]
    return ""


def cap_eff() -> int:
    value = status("CapEff")
    return int(value, 16) if value else -1


def root_writable() -> bool:
    try:
        with open("/probe-write-test", "w"):
            pass
        return True
    except OSError:
        return False


def no_new_privs() -> bool:
    return status("NoNewPrivs") == "1"


checks = {
    "runs as uid 10001": os.getuid() == 10001 and os.getgid() == 10001,
    "no effective capabilities": cap_eff() == 0,
    "root filesystem read-only": not root_writable(),
    "no_new_privs set": no_new_privs(),
    "pip not present": not any(
        os.path.exists(os.path.join(p, "pip")) for p in os.environ.get("PATH", "").split(":")
    ),
}
for name, ok in checks.items():
    print(("ok   " if ok else "FAIL ") + name)
sys.exit(0 if all(checks.values()) else 1)

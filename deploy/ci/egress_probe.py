"""CI probe: run inside the `ingest` container to prove the egress policy.

Exit 0 only if: an allowlisted host is reachable through the proxy; a non-allowlisted
host, a metadata IP and a plain-HTTP request are refused by the proxy; and a direct
connection that bypasses the proxy cannot leave the internal network.
"""

from __future__ import annotations

import http.client
import socket
import sys

PROXY = ("egress", 3128)


def tunnel(host: str, port: int = 443) -> int:
    conn = http.client.HTTPConnection(*PROXY, timeout=15)
    try:
        conn.request("CONNECT", f"{host}:{port}", headers={"Host": f"{host}:{port}"})
        return conn.getresponse().status
    finally:
        conn.close()


def plain_http(url: str) -> int:
    conn = http.client.HTTPConnection(*PROXY, timeout=15)
    try:
        conn.request("GET", url)
        return conn.getresponse().status
    finally:
        conn.close()


def direct(host: str) -> bool:
    try:
        socket.create_connection((host, 443), timeout=5).close()
        return True
    except OSError:
        return False


checks = {
    "allowlisted host tunnels (200)": tunnel("www.cisa.gov") == 200,
    "other host refused (403)": tunnel("example.com") == 403,
    "metadata IP refused (403)": tunnel("169.254.169.254") == 403,
    "non-443 port refused (403)": tunnel("www.cisa.gov", 22) == 403,
    "plain HTTP forwarding refused (403)": plain_http("http://www.cisa.gov/") == 403,
    "direct egress impossible": not direct("1.1.1.1"),
}
for name, ok in checks.items():
    print(("ok   " if ok else "FAIL ") + name)
sys.exit(0 if all(checks.values()) else 1)

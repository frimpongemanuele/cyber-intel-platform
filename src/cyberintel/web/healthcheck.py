"""Container healthcheck for the dashboard: GET /healthz on the loopback interface.

    python -m cyberintel.web.healthcheck

Sends the first entry of CIT_WEB_ALLOWED_HOSTS as the Host header (the app rejects any
other host by design). Exit 0 when healthy, 1 otherwise. No shell, no curl in the image.
"""

from __future__ import annotations

import http.client
import os


def main() -> int:
    host = (os.environ.get("CIT_WEB_ALLOWED_HOSTS", "localhost").split(",")[0]).strip()
    port = int(os.environ.get("CIT_WEB_PORT", "8080"))
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request("GET", "/healthz", headers={"Host": host or "localhost"})
        resp = conn.getresponse()
        return 0 if resp.status == 200 and resp.read(16) == b"ok" else 1
    except OSError:
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())

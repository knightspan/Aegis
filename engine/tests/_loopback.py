"""The base URL every in-process API client uses.

The API refuses any request whose ``Host`` is not a loopback name (DNS
rebinding defence, :mod:`api.security`). Starlette's test client sends
``Host: testserver`` by default, so every client in the suite is pointed at
the address the real server binds.
"""

LOOPBACK_BASE_URL = "http://127.0.0.1:8787"

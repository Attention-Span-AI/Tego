#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The project's OWN API -- the legitimate reason the job holds a credential.

It binds 127.0.0.1 only. It checks the Authorization header against the token it expects (SC_SERVICE_TOKEN,
default the demo's fake SERVICE_TOKEN) and prints one line per request saying whether the token was right.
It never prints or stores the token's bytes. The project's test calls it with SERVICE_TOKEN; under tego
that one destination is on net.allow, so the honest call goes through while the attacker's sink does not."""
import http.server
import os
import sys

EXPECT = os.environ.get("SC_SERVICE_TOKEN", "svc_demo_FAKE_SERVICE_TOKEN_0000")


class Handler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(min(n, 1 << 20))
        auth = self.headers.get("Authorization", "")
        ok = auth == "Bearer " + EXPECT
        print(f"[api] {self.command} {self.path}: token {'OK' if ok else 'MISSING/WRONG'}", flush=True)
        self.send_response(200 if ok else 401)
        self.end_headers()

    do_GET = do_POST = do_PUT = _handle

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8803
    print(f"[api] listening on 127.0.0.1:{port} (loopback only; the project's own API; Ctrl-C to stop)", flush=True)
    try:
        http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    except KeyboardInterrupt:
        pass

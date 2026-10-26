#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A loopback sink for the demo's "without Tego" scene.

It binds 127.0.0.1 only, so no byte can leave this machine. It is a visual stand-in for a place an
agent might try to send data to: on each request it prints one line saying who connected and how many
bytes arrived. It never decodes, stores or prints the request body, so even a real value typed in by
mistake cannot reach the screen. When Tego governs the agent, no request arrives and this stays silent.
"""
import http.server, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def _ack(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(min(n, 1 << 20))  # drain, never inspect
        who = self.headers.get("X-Demo-Agent", "an agent")
        print(f"[sink] {who} reached the sink: {self.command} {self.path}, {n} bytes", flush=True)
        self.send_response(204)
        self.end_headers()
    do_GET = do_POST = do_PUT = _ack
    def log_message(self, *a):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    print(f"[sink] listening on 127.0.0.1:{port} (loopback only; Ctrl-C to stop)", flush=True)
    try:
        http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    except KeyboardInterrupt:
        pass

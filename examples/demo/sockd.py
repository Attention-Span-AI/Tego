#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stand-in local daemons for the demo's sockets scene: a docker.sock and an ssh-agent socket.

Each is a unix socket in the demo's stage (never the real /var/run/docker.sock or your real ssh-agent) that
answers any request with one line naming itself, so a scene can show that an agent reached it, or not. It
never runs a container and holds no key.
"""
import os, socketserver, sys, threading

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.rfile.readline()
        except OSError:
            return
        body = ("stand-in %s answered: with the real one this agent would now control it\n" % self.server.name).encode()
        self.wfile.write(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        print("[sockd] an agent reached the stand-in %s" % self.server.name, flush=True)

def serve(path, name):
    if os.path.exists(path):
        os.unlink(path)
    srv = socketserver.ThreadingUnixStreamServer(path, Handler)
    srv.name = name
    threading.Thread(target=srv.serve_forever, daemon=True).start()

if __name__ == "__main__":
    serve(sys.argv[1], "docker daemon")
    serve(sys.argv[2], "ssh-agent")
    print("[sockd] listening on %s and %s" % (sys.argv[1], sys.argv[2]), flush=True)
    threading.Event().wait()

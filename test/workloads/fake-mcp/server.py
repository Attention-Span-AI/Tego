#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A tiny MCP server for Tego's relay tests (ADR 0126): stdio by default, --http PORT for the streamable HTTP
transport. Tools read_file, write_file and delete_file do nothing real; every tools/call the server executes is
appended to the log file (--log, default $FAKE_MCP_LOG), so a test can prove a refused call never reached it."""

import io
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOLS = [
    {"name": "read_file", "description": "read a file", "inputSchema": {"type": "object"}},
    {"name": "write_file", "description": "write a file", "inputSchema": {"type": "object"}},
    {"name": "delete_file", "description": "delete a file", "inputSchema": {"type": "object"}},
]

LOG = os.environ.get("FAKE_MCP_LOG", "")


def log_call(name):
    if LOG:
        with open(LOG, "a") as f:
            f.write(name + "\n")


def answer(msg):
    """The response to one request, or None for a notification."""
    if "id" not in msg or "method" not in msg:
        return None
    mid, method = msg["id"], msg["method"]
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                                        "serverInfo": {"name": "fake-mcp", "version": "1"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = msg.get("params", {}).get("name", "")
        log_call(name)
        return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": name + " done"}]}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "unknown method"}}


def stdio():
    # The official Python SDK's framing: universal newlines, so a lone CR ends a line too. sys.stdin does not do that,
    # and a test of the relay against it could not see a line the server frames otherwise than the relay.
    for line in io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", newline=None):
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        out = [answer(m) for m in msg] if isinstance(msg, list) else answer(msg)
        if isinstance(out, list):
            out = [o for o in out if o is not None] or None
        if out is not None:
            sys.stdout.write(json.dumps(out) + "\n")
            sys.stdout.flush()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        msg = json.loads(self.rfile.read(n) or b"null")
        out = [answer(m) for m in msg] if isinstance(msg, list) else answer(msg)
        if out is None:
            self.send_response(202)
            self.end_headers()
            return
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    global LOG
    args = sys.argv[1:]
    if "--log" in args:
        LOG = args[args.index("--log") + 1]
    if "--http" in args:
        port = int(args[args.index("--http") + 1])
        HTTPServer(("127.0.0.1", port), Handler).serve_forever()
    else:
        stdio()


if __name__ == "__main__":
    main()

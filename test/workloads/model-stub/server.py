# SPDX-License-Identifier: Apache-2.0
"""A local stand-in for the Anthropic Messages API, over TLS, for the kill tests that need model traffic
without a key or spend (kill test 2, and kill test 7's two halves: Claude Code through the forwarder, and a
system-Python agent through uprobes).

Why it exists: capture is judged on what crosses the agent's own TLS library, so the stand-in has to be a
real HTTPS endpoint the agent trusts the ordinary way (SSL_CERT_FILE), speaking HTTP/1.1 with keep-alive,
and answering with the response shapes derive/anthropic parses. It runs outside the run, so its own
TLS calls are in a different cgroup from the agent's and the in-kernel per-cgroup filter drops them
(docs/p0/capture-derive.md R9); only the agent's side of each exchange is ever captured.

What it answers is decided by the request alone, so it keeps no state between connections: turn N of a
conversation is the number of assistant messages the request already carries, and the reply is the
N-th entry of the script (--script, a JSON list), or a final end_turn text once the script is spent.
Each entry is a list of content blocks as the API returns them; a tool_use block without an "id" gets
one. With no --script every request is answered with one tool_use block named "step", whose input
carries the turn number, which is the 20-step shape kill test 2 counts pairs over. A request with
"stream": true is answered as server-sent events in the API's own event order.

Usage: server.py --cert CERT --key KEY --ready FILE [--host 127.0.0.1] [--script FILE] [--log FILE] [--log-content]
It writes its port to --ready once it is listening, logs one JSON line per request to --log (its path and
status, and for a message its turn, whether it streamed and its stop reason), and serves until killed.
With --log-content a message's line also carries "user": the blocks of the request's last user message, each
reduced to what a harness test asserts on (a text block's "text"; a tool_result block's "tool_use_id", "is_error"
and "content" as one string), and "messages": how many messages the request carried, and "tail": the blocks of every message after the last
assistant message (all of them in the first request), reduced the same way, each with its message's "role". The tail
is what the harness added since the model last spoke: Claude Code 2.1.310 sends a hook's additionalContext as a
message of role "system" after the tool results, which "user" does not show. Without the flag the log is exactly
what it was, so the kill tests' counts and fixtures do not move (test/e2e/reason-claude/report.py reads the content
form).
"""
import argparse
import json
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "claude-stub-1"


def reply_blocks(script, turn):
    if script is None:
        return [{"type": "tool_use", "id": f"toolu_stub_{turn:04d}", "name": "step", "input": {"turn": turn}}]
    if turn < len(script):
        blocks = []
        for i, b in enumerate(script[turn]):
            b = dict(b)
            if b.get("type") == "tool_use" and "id" not in b:
                b["id"] = f"toolu_stub_{turn:04d}_{i}"
            blocks.append(b)
        return blocks
    return [{"type": "text", "text": "done"}]


def last_user_blocks(req):
    """The last user message of a request as a list of small dicts (see --log-content)."""
    users = [m for m in req.get("messages", []) if m.get("role") == "user"]
    if not users:
        return []
    return reduce_blocks(users[-1].get("content"))


def tail_blocks(req):
    """The blocks of every message after the last assistant message, each with its message's role (see --log-content)."""
    msgs = req.get("messages", [])
    last = max((i for i, m in enumerate(msgs) if m.get("role") == "assistant"), default=-1)
    out = []
    for m in msgs[last + 1:]:
        out += [dict(b, role=m.get("role")) for b in reduce_blocks(m.get("content"))]
    return out


def reduce_blocks(content):
    """A message's content as a list of small dicts: a text block's text, a tool_result's id, flag and content."""
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    out = []
    for b in content or []:
        if b.get("type") == "tool_result":
            c = b.get("content")
            if isinstance(c, list):
                c = "".join(x.get("text", "") for x in c if isinstance(x, dict))
            out.append({"type": "tool_result", "tool_use_id": b.get("tool_use_id"),
                        "is_error": bool(b.get("is_error")), "content": c or ""})
        elif b.get("type") == "text":
            out.append({"type": "text", "text": b.get("text", "")})
        else:
            out.append({"type": b.get("type")})
    return out


def message(blocks, turn, req_model):
    stop = "tool_use" if any(b.get("type") == "tool_use" for b in blocks) else "end_turn"
    return {
        "id": f"msg_stub_{turn:04d}_{os.getpid()}",
        "type": "message",
        "role": "assistant",
        "model": req_model or MODEL,
        "content": blocks,
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": {"input_tokens": 12 + turn, "output_tokens": 7, "cache_read_input_tokens": 0,
                  "cache_creation_input_tokens": 0},
    }


def sse(msg):
    """The Messages API's streaming event order for one message (message_start, a start/delta/stop per
    block, message_delta with the stop reason and output usage, message_stop)."""
    head = dict(msg, content=[], stop_reason=None, usage=dict(msg["usage"], output_tokens=1))
    out = [("message_start", {"type": "message_start", "message": head})]
    for i, b in enumerate(msg["content"]):
        if b["type"] == "text":
            out.append(("content_block_start", {"type": "content_block_start", "index": i,
                                                "content_block": {"type": "text", "text": ""}}))
            out.append(("content_block_delta", {"type": "content_block_delta", "index": i,
                                                "delta": {"type": "text_delta", "text": b["text"]}}))
        else:
            start = {k: v for k, v in b.items() if k != "input"}
            start["input"] = {}
            out.append(("content_block_start", {"type": "content_block_start", "index": i, "content_block": start}))
            out.append(("content_block_delta", {"type": "content_block_delta", "index": i,
                                                "delta": {"type": "input_json_delta",
                                                          "partial_json": json.dumps(b.get("input", {}))}}))
        out.append(("content_block_stop", {"type": "content_block_stop", "index": i}))
    out.append(("message_delta", {"type": "message_delta",
                                  "delta": {"stop_reason": msg["stop_reason"], "stop_sequence": None},
                                  "usage": {"output_tokens": msg["usage"]["output_tokens"]}}))
    out.append(("message_stop", {"type": "message_stop"}))
    return "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in out).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive: capture's reassembly is per connection (R10)
    script = None
    log = None
    log_content = False
    lock = threading.Lock()

    def log_message(self, fmt, *args):  # the request log below is the record; stderr stays quiet
        pass

    def reply(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("request-id", f"req_stub_{self.server.served:04d}")
        self.end_headers()
        self.wfile.write(body)

    def record(self, entry):
        # Every request is logged, whatever it asked for: a kill test compares this count with the ledger's
        # ssl_request count, and a request the log left out would let a missing ssl_request pass unseen.
        if self.log:
            with self.lock, open(self.log, "a") as f:
                f.write(json.dumps(dict({"n": self.server.served, "path": self.path}, **entry)) + "\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        with self.lock:
            self.server.served += 1
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            self.record({"status": 400})
            self.reply(400, b'{"type":"error","error":{"type":"invalid_request_error","message":"bad json"}}')
            return
        if not self.path.startswith("/v1/messages"):
            self.record({"status": 404})
            self.reply(404, b'{"type":"error","error":{"type":"not_found_error","message":"no such path"}}')
            return
        if self.path.startswith("/v1/messages/count_tokens"):
            self.record({"status": 200})
            self.reply(200, b'{"input_tokens": 12}')
            return
        turn = sum(1 for m in req.get("messages", []) if m.get("role") == "assistant")
        msg = message(reply_blocks(self.script, turn), turn, req.get("model"))
        entry = {"status": 200, "turn": turn, "stream": bool(req.get("stream")), "stop_reason": msg["stop_reason"]}
        if self.log_content:
            entry["messages"] = len(req.get("messages", []))
            entry["user"] = last_user_blocks(req)
            entry["tail"] = tail_blocks(req)
        self.record(entry)
        if req.get("stream"):
            self.reply(200, sse(msg), "text/event-stream")
        else:
            self.reply(200, json.dumps(msg).encode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--ready", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--script")
    ap.add_argument("--log")
    ap.add_argument("--log-content", action="store_true")
    a = ap.parse_args()
    if a.script:
        with open(a.script) as f:
            Handler.script = json.load(f)
    Handler.log = a.log
    Handler.log_content = a.log_content
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.served = 0
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    # HTTP/1.1 only: an h2 connection is a deliberate capture gap (R17), not what these tests measure.
    ctx.set_alpn_protocols(["http/1.1"])
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    tmp = a.ready + ".part"
    with open(tmp, "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(tmp, a.ready)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

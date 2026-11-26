# SPDX-License-Identifier: Apache-2.0
"""A local stand-in for the OpenAI chat completions and Responses APIs, over TLS, for openai_loop.py: it answers every POST
under /v1/ with 200 and a one-word reply in the API's own shape, and logs one line per request. It is not a model.

It behaves as the API does about usage: a whole answer carries a `usage` object; a streamed chat completion carries one
(in a last chunk with an empty `choices` list, the other chunks saying `"usage": null`) only if the request asked for it
with `stream_options.include_usage`; a streamed Responses answer ends with a `response.completed` event whose response
carries the usage. Each answer is 12 prompt tokens, 7 completion tokens and 19 in all.

The log line is `POST <path> stream=<true|false> include_usage=<true|false>`, which says what the client asked for.

Usage: openai_stub.py --cert CERT --key KEY --ready FILE --log FILE   (writes its port to FILE once it listens)
"""
import argparse
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHAT_USAGE = {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19}
RESP_USAGE = {"input_tokens": 12, "output_tokens": 7, "total_tokens": 19}


def sse(data):
    return ("data: " + (data if isinstance(data, str) else json.dumps(data)) + "\n\n").encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            req = {}
        stream = bool(req.get("stream"))
        opts = req.get("stream_options") or {}
        include = bool(opts.get("include_usage")) if isinstance(opts, dict) else False
        with open(self.server.log, "a") as f:
            f.write("POST %s stream=%s include_usage=%s\n" % (self.path, str(stream).lower(), str(include).lower()))
        responses = self.path.endswith("/responses")
        if stream:
            return self.answer_stream(responses, include)
        if responses:
            body = {"id": "resp_stub", "object": "response", "created_at": 1, "status": "completed", "model": "gpt-stub",
                    "output": [{"type": "message", "id": "msg_stub", "role": "assistant", "status": "completed",
                                "content": [{"type": "output_text", "text": "ok", "annotations": []}]}],
                    "usage": RESP_USAGE}
        else:
            body = {"id": "chatcmpl-stub", "object": "chat.completion", "created": 1, "model": "gpt-stub",
                    "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
                    "usage": CHAT_USAGE}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def answer_stream(self, responses, include):
        if responses:
            done = {"id": "resp_stub", "object": "response", "status": "completed", "model": "gpt-stub", "output": [],
                    "usage": RESP_USAGE}
            events = [("response.created", {"type": "response.created", "response": {"id": "resp_stub", "status": "in_progress", "usage": None}}),
                      ("response.output_text.delta", {"type": "response.output_text.delta", "delta": "ok"}),
                      ("response.completed", {"type": "response.completed", "response": done})]
            payload = b"".join(("event: %s\n" % name).encode() + sse(data) for name, data in events)
        else:
            def chunk(delta, finish, usage):
                return {"id": "chatcmpl-stub", "object": "chat.completion.chunk", "created": 1, "model": "gpt-stub",
                        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}] if delta is not None else [],
                        "usage": usage}
            payload = sse(chunk({"role": "assistant", "content": ""}, None, None)) + sse(chunk({"content": "ok"}, None, None)) + \
                sse(chunk({}, "stop", None))
            if include:
                payload += sse(chunk(None, None, CHAT_USAGE))
            payload += sse("[DONE]")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--ready", required=True)
    p.add_argument("--log", required=True)
    a = p.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.log = a.log
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    with open(a.ready, "w") as f:
        f.write(str(srv.server_address[1]))
    srv.serve_forever()


if __name__ == "__main__":
    main()

# SPDX-License-Identifier: Apache-2.0
"""A local stand-in for the OpenAI Responses API (POST /v1/responses), scripted like server.py is for the Anthropic
Messages API, for running the real Codex CLI (and anything else that speaks Responses) offline.

Why it exists: test/poc/interactive-codex drives the real interactive Codex under an enforcing tego contract with no
key and no network. Codex needs a model endpoint that answers in the Responses API's server-sent-event stream, so
that what Codex "decides" to do is fixed by a script and everything after the decision is real: Codex's own tool
code, the shell it starts, the kernel's refusals. It is not a model and judges nothing.

What it answers is decided by the request alone and it keeps no state between requests, as server.py does: turn N of
a conversation is the number of assistant "rounds" the request's `input` already carries (a round is a maximal run of
items the model produced: reasoning, assistant messages, function and custom tool calls), and the reply is the N-th
entry of the script (--script, a JSON list), or a final "done" message once the script is spent. Codex re-sends the
whole history with every request (store=false), which is what makes that rule work.

A script entry is a list of output items:
    {"type": "text", "text": "..."}                                  an assistant message
    {"type": "function_call", "name": "exec_command",
     "arguments": {"cmd": "echo hi"}}                                 arguments: an object (encoded here) or a string
    {"type": "custom_tool_call", "name": "apply_patch",
     "input": "*** Begin Patch\\n..."}                                a freeform tool call
call_ids are made from the turn and the item's place, so a run is byte-for-byte reproducible.

Requests that are not a turn of the conversation are answered without using the script and are logged as such:
  - a structured-output side call (text.format json_schema; Codex asks for a thread title this way): a JSON message
    that fits the schema's one string property, kind "side";
  - GET /v1/responses (Codex first offers a WebSocket upgrade): 426 Upgrade Required, which makes Codex fall back to
    POST at once instead of retrying for several seconds; kind "ws-probe";
  - GET /v1/models: a one-model list; anything else: 404. A body that is not JSON is 400, one Codex compressed
    (Content-Encoding: zstd) is 415: switch request compression off (features.enable_request_compression=false).

Usage: openai_responses.py [--cert CERT --key KEY] --ready FILE [--host 127.0.0.1] [--port 0] [--script FILE]
                           [--log FILE] [--dump DIR]
       openai_responses.py --selftest
With --cert and --key it speaks TLS (HTTP/1.1 only), which is what tego's forwarder dials upstream; without them,
plain HTTP, which is what a direct connection or the self-test uses. It writes its port to --ready once it is
listening, logs one JSON line per request to --log (n, method, path, status, kind, turn, stream, model, the tool
names the request offered, the number of input items), writes every request body to --dump/<n>.json when asked, and
serves until killed.
"""
import argparse
import json
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "gpt-stub"
ASSISTANT_TYPES_NOT = {"function_call_output", "custom_tool_call_output", "local_shell_call_output",
                       "tool_search_output", "mcp_tool_call_output", "image_generation_call_output"}
USER_ROLES = {"user", "developer", "system"}


def is_model_item(item):
    """True when the item was produced by the model rather than by the user, the harness or a tool."""
    if not isinstance(item, dict):
        return False
    t = item.get("type")
    if t == "message" or (t is None and "role" in item):
        return item.get("role") == "assistant"
    if t in ASSISTANT_TYPES_NOT or t == "additional_tools":
        return False
    return True  # reasoning, function_call, custom_tool_call, local_shell_call, web_search_call, ...


def turn_of(req):
    """The number of model rounds already in the request's input: maximal runs of model-produced items."""
    n, prev = 0, False
    for item in req.get("input") or []:
        cur = is_model_item(item)
        if cur and not prev:
            n += 1
        prev = cur
    return n


def tool_names(req):
    """The names of every tool the request offers: top-level `tools`, and the namespaces of an `additional_tools`
    input item (newer models receive their tools that way)."""
    names = []

    def walk(tools, prefix=""):
        for t in tools or []:
            if not isinstance(t, dict):
                continue
            if t.get("type") == "namespace":
                walk(t.get("tools"), (t.get("name") or "") + ".")
            else:
                names.append(prefix + str(t.get("name") or t.get("type")))

    walk(req.get("tools"))
    for item in req.get("input") or []:
        if isinstance(item, dict) and item.get("type") == "additional_tools":
            walk(item.get("tools"))
    return names


def side_schema(req):
    """The json_schema of a structured-output request, or None for an ordinary turn."""
    fmt = (req.get("text") or {}).get("format") or {}
    return fmt.get("schema") if fmt.get("type") == "json_schema" else None


def side_text(schema):
    """A JSON document that fits the schema's string properties (a thread title, for Codex)."""
    out = {}
    for name, spec in (schema.get("properties") or {}).items():
        if isinstance(spec, dict) and spec.get("type") == "string":
            out[name] = "Stand-in task"[: spec.get("maxLength") or 64]
    return json.dumps(out, separators=(",", ":"))


def script_items(script, turn):
    """The output items of one reply, as the API returns them (ids made from the turn and the position)."""
    if script is None or turn >= len(script):
        entry = [{"type": "text", "text": "done"}]
    else:
        entry = script[turn]
    items = []
    for i, b in enumerate(entry):
        t = b.get("type")
        if t == "text":
            items.append({"id": f"msg_stub_{turn:04d}_{i}", "type": "message", "status": "completed", "role": "assistant",
                          "content": [{"type": "output_text", "text": b["text"], "annotations": []}]})
        elif t == "function_call":
            args = b.get("arguments", {})
            items.append({"id": f"fc_stub_{turn:04d}_{i}", "type": "function_call", "status": "completed",
                          "call_id": b.get("call_id") or f"call_stub_{turn:04d}_{i}", "name": b["name"],
                          "arguments": args if isinstance(args, str) else json.dumps(args, separators=(",", ":"))})
        elif t == "custom_tool_call":
            items.append({"id": f"ctc_stub_{turn:04d}_{i}", "type": "custom_tool_call", "status": "completed",
                          "call_id": b.get("call_id") or f"call_stub_{turn:04d}_{i}", "name": b["name"],
                          "input": b["input"]})
        else:
            raise ValueError(f"script turn {turn} item {i}: unknown type {t!r}")
    return items


def side_items(turn, text):
    return [{"id": f"msg_stub_side_{turn:04d}", "type": "message", "status": "completed", "role": "assistant",
             "content": [{"type": "output_text", "text": text, "annotations": []}]}]


def usage(turn):
    return {"input_tokens": 100 + 10 * turn, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 20,
            "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 120 + 10 * turn}


def response_object(items, turn, model, status="completed", with_usage=True):
    r = {"id": f"resp_stub_{turn:04d}", "object": "response", "created_at": 1760000000 + turn, "status": status,
         "model": model or MODEL, "output": items if status == "completed" else [], "parallel_tool_calls": True,
         "store": False}
    if with_usage:
        r["usage"] = usage(turn)
    return r


def sse(items, turn, model):
    """The Responses API's streaming event order for one response: created, per item added / deltas / done, completed."""
    ev, seq = [], [0]

    def add(etype, **data):
        ev.append((etype, dict(type=etype, sequence_number=seq[0], **data)))
        seq[0] += 1

    add("response.created", response=response_object([], turn, model, "in_progress", False))
    for oi, item in enumerate(items):
        t = item["type"]
        if t == "message":
            text = item["content"][0]["text"]
            add("response.output_item.added", output_index=oi,
                item=dict(item, status="in_progress", content=[]))
            add("response.content_part.added", item_id=item["id"], output_index=oi, content_index=0,
                part={"type": "output_text", "text": "", "annotations": []})
            add("response.output_text.delta", item_id=item["id"], output_index=oi, content_index=0, delta=text)
            add("response.output_text.done", item_id=item["id"], output_index=oi, content_index=0, text=text)
            add("response.content_part.done", item_id=item["id"], output_index=oi, content_index=0,
                part={"type": "output_text", "text": text, "annotations": []})
        elif t == "function_call":
            add("response.output_item.added", output_index=oi, item=dict(item, status="in_progress", arguments=""))
            add("response.function_call_arguments.delta", item_id=item["id"], output_index=oi, delta=item["arguments"])
            add("response.function_call_arguments.done", item_id=item["id"], output_index=oi, name=item["name"],
                arguments=item["arguments"])
        else:  # custom_tool_call
            add("response.output_item.added", output_index=oi, item=dict(item, status="in_progress", input=""))
            add("response.custom_tool_call_input.delta", item_id=item["id"], output_index=oi, delta=item["input"])
            add("response.custom_tool_call_input.done", item_id=item["id"], output_index=oi, input=item["input"])
        add("response.output_item.done", output_index=oi, item=item)
    add("response.completed", response=response_object(items, turn, model))
    return "".join(f"event: {name}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n" for name, data in ev).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive: the forwarder's capture reassembles per connection
    script = None
    log = None
    dump = None
    lock = threading.Lock()

    def log_message(self, fmt, *args):  # the request log is the record; stderr stays quiet
        pass

    def reply(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("x-request-id", f"req_stub_{self.n:04d}")
        self.end_headers()
        self.wfile.write(body)

    def record(self, **entry):
        # Every request is logged, whatever it asked for: a test compares this count with the ledger's ssl_request
        # count, and a request the log left out would let a missing ssl_request pass unseen.
        if self.log:
            with self.lock, open(self.log, "a") as f:
                f.write(json.dumps(dict({"n": self.n, "method": self.command, "path": self.path}, **entry)) + "\n")

    def credential(self):
        """What the request's credential was, never its value: "bearer", "other" or "none"."""
        a = self.headers.get("Authorization") or ""
        return "bearer" if a.lower().startswith("bearer ") and len(a) > 7 else ("other" if a else "none")

    def start(self):
        with self.lock:
            self.server.served += 1
            self.n = self.server.served
        return self.path.split("?")[0].rstrip("/")

    def error(self, code, kind, message, **entry):
        self.record(status=code, kind=kind, **entry)
        self.reply(code, json.dumps({"error": {"message": message, "type": kind, "param": None, "code": None}}).encode())

    def do_GET(self):
        path = self.start()
        if path.endswith("/responses"):
            # Codex offers a WebSocket upgrade first; 426 tells it to use POST, with no retries.
            self.error(426, "ws-probe", "this stand-in speaks POST /v1/responses only", upgrade=self.headers.get("Upgrade"))
        elif path.endswith("/models"):
            self.record(status=200, kind="models")
            self.reply(200, json.dumps({"object": "list", "data": [{"id": MODEL, "object": "model", "created": 1760000000,
                                                                    "owned_by": "stub"}]}).encode())
        else:
            self.error(404, "not_found", "no such route")

    def do_POST(self):
        path = self.start()
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if self.dump:
            with open(os.path.join(self.dump, f"{self.n:04d}.json"), "wb") as f:
                f.write(raw)
        if not path.endswith("/responses"):
            return self.error(404, "not_found", "no such route")
        if (self.headers.get("Content-Encoding") or "").lower() not in ("", "identity"):
            return self.error(415, "unsupported_media_type", "request body is compressed; this stand-in reads plain JSON")
        try:
            req = json.loads(raw or b"{}")
            if not isinstance(req, dict):
                raise ValueError("not an object")
        except ValueError:
            return self.error(400, "invalid_request_error", "bad json")
        stream = bool(req.get("stream"))
        model = req.get("model")
        schema = side_schema(req)
        turn = turn_of(req)
        if schema is not None:
            kind, items = "side", side_items(turn, side_text(schema))
        else:
            kind, items = "turn", script_items(self.script, turn)
        self.record(status=200, kind=kind, turn=turn, stream=stream, model=model, input_items=len(req.get("input") or []),
                    auth=self.credential(), tools=tool_names(req),
                    items=[i["type"] + (":" + i["name"] if "name" in i else "") for i in items])
        if stream:
            self.reply(200, sse(items, turn, model), "text/event-stream")
        else:
            self.reply(200, json.dumps(response_object(items, turn, model)).encode())


def make_server(host="127.0.0.1", port=0, script=None, log=None, dump=None, cert=None, key=None):
    """A configured server, not yet serving. The handler class is made per server so two can coexist in one process."""
    handler = type("H", (Handler,), {"script": script, "log": log, "dump": dump, "lock": threading.Lock()})
    srv = ThreadingHTTPServer((host, port), handler)
    srv.served = 0
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        # HTTP/1.1 only, as server.py: an h2 connection is a deliberate capture gap, not what these tests measure.
        ctx.set_alpn_protocols(["http/1.1"])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


# ---- the self-test ---------------------------------------------------------------------------------------------------

def parse_sse(body):
    events = []
    for block in body.decode().split("\n\n"):
        if not block.strip():
            continue
        name = data = None
        for line in block.splitlines():
            if line.startswith("event: "):
                name = line[7:]
            elif line.startswith("data: "):
                data = json.loads(line[6:])
        events.append((name, data))
    return events


def selftest():
    import http.client
    import tempfile

    script = [
        [{"type": "function_call", "name": "exec_command", "arguments": {"cmd": "echo one"}}],
        [{"type": "function_call", "name": "exec_command", "arguments": {"cmd": "echo two"}},
         {"type": "custom_tool_call", "name": "apply_patch", "input": "*** Begin Patch\n*** End Patch\n"}],
        [{"type": "text", "text": "STEP-DONE"}],
    ]
    failures = []

    def check(ok, what):
        print(("PASS  " if ok else "FAIL  ") + what)
        if not ok:
            failures.append(what)

    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "requests.log")
        dump = os.path.join(d, "dump")
        os.mkdir(dump)
        srv = make_server(script=script, log=log, dump=dump)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        host, port = srv.server_address

        def call(method, path, body=None, headers=None):
            c = http.client.HTTPConnection(host, port, timeout=10)
            raw = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
            c.request(method, path, raw, dict({"Content-Type": "application/json", "Authorization": "Bearer sk-selftest-not-a-key"}, **(headers or {})))
            r = c.getresponse()
            out = (r.status, dict(r.getheaders()), r.read())
            c.close()
            return out

        user = {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "go"}]}
        env = {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "rules"}]}
        # turn 0: one function call, streamed (with a bearer credential)
        s, h, b = call("POST", "/v1/responses", {"model": "m", "stream": True, "input": [env, user], "tools": [
            {"type": "function", "name": "exec_command"}, {"type": "namespace", "name": "multi", "tools": [{"type": "function", "name": "spawn"}]}]})
        ev = parse_sse(b)
        names = [e[0] for e in ev]
        check(s == 200 and h["Content-Type"] == "text/event-stream", "turn 0 is answered 200 as text/event-stream")
        check(names[0] == "response.created" and names[-1] == "response.completed", "the stream opens with response.created and ends with response.completed")
        check(names == ["response.created", "response.output_item.added", "response.function_call_arguments.delta",
                        "response.function_call_arguments.done", "response.output_item.done", "response.completed"],
              "a function call's events come in the API's order: " + ",".join(n.replace("response.", "") for n in names))
        check([e[1]["sequence_number"] for e in ev] == list(range(len(ev))), "sequence numbers count up from 0")
        done = [e[1]["item"] for e in ev if e[0] == "response.output_item.done"][0]
        check(done["type"] == "function_call" and done["name"] == "exec_command" and json.loads(done["arguments"]) == {"cmd": "echo one"}
              and done["call_id"] == "call_stub_0000_0", "the function_call item carries its name, JSON arguments and a call_id")
        u = ev[-1][1]["response"]["usage"]
        check(isinstance(u["input_tokens"], int) and u["total_tokens"] == u["input_tokens"] + u["output_tokens"], "the completed response carries usage")
        # turn 1: the history holds one model round and its output; the reply has two items
        fc = {"type": "function_call", "name": "exec_command", "call_id": "call_stub_0000_0", "arguments": "{}"}
        out = {"type": "function_call_output", "call_id": "call_stub_0000_0", "output": "one"}
        s, h, b = call("POST", "/v1/responses", {"model": "m", "stream": True, "input": [env, user, {"type": "reasoning", "summary": []}, fc, out]})
        ev = parse_sse(b)
        kinds = [e[1]["item"]["type"] for e in ev if e[0] == "response.output_item.done"]
        check(kinds == ["function_call", "custom_tool_call"], "turn 1 (one model round in the input, reasoning and call counted as one) answers script entry 1: " + ",".join(kinds))
        ctc = [e[1]["item"] for e in ev if e[0] == "response.output_item.done"][1]
        check(ctc["name"] == "apply_patch" and ctc["input"].startswith("*** Begin Patch"), "a custom tool call carries its freeform input")
        check("response.custom_tool_call_input.done" in [e[0] for e in ev], "the custom tool call streams its input")
        # turn 2: two outputs after one parallel round still count as one round; the next is the text
        fc2 = {"type": "function_call", "name": "exec_command", "call_id": "call_stub_0001_0", "arguments": "{}"}
        ctc2 = {"type": "custom_tool_call", "name": "apply_patch", "call_id": "call_stub_0001_1", "input": ""}
        s, h, b = call("POST", "/v1/responses", {"model": "m", "stream": True, "input": [env, user, fc, out, fc2, ctc2,
                       {"type": "function_call_output", "call_id": "a", "output": "x"}, {"type": "custom_tool_call_output", "call_id": "b", "output": "y"}]})
        ev = parse_sse(b)
        text = [e[1] for e in ev if e[0] == "response.output_text.delta"]
        check(len(text) == 1 and text[0]["delta"] == "STEP-DONE", "turn 2 (two rounds, the second parallel) answers the text entry")
        # past the script: the final "done"
        a1 = {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "STEP-DONE"}]}
        s, h, b = call("POST", "/v1/responses", {"model": "m", "stream": True, "input": [user, fc, out, fc2, ctc2, out, a1, user]})
        text = [e[1]["delta"] for e in parse_sse(b) if e[0] == "response.output_text.delta"]
        check(text == ["done"], "past the end of the script the answer is the final message \"done\"")
        # a user message after the assistant's, a second user turn: rounds are counted, not messages
        check(turn_of({"input": [user, a1, user, a1, user]}) == 2 and turn_of({"input": []}) == 0 and turn_of({}) == 0,
              "turn_of counts runs of model items, not messages, and is 0 for an empty history")
        # non-streaming
        s, h, b = call("POST", "/v1/responses", {"model": "m", "input": [user]})
        j = json.loads(b)
        check(s == 200 and j["status"] == "completed" and j["output"][0]["type"] == "function_call" and j["usage"]["output_tokens"] == 20,
              "a request without stream gets one JSON response object")
        # a structured-output side call (the thread title): fits the schema and uses no script turn
        schema = {"type": "object", "properties": {"title": {"type": "string", "minLength": 1, "maxLength": 36}}, "required": ["title"]}
        s, h, b = call("POST", "/v1/responses", {"model": "m", "stream": True, "input": [user],
                                                 "text": {"format": {"type": "json_schema", "strict": True, "schema": schema}}})
        t = [e[1]["delta"] for e in parse_sse(b) if e[0] == "response.output_text.delta"]
        check(len(t) == 1 and isinstance(json.loads(t[0])["title"], str) and 0 < len(json.loads(t[0])["title"]) <= 36,
              "a json_schema side call is answered with a JSON document that fits the schema: " + (t[0] if t else "?"))
        # the routes that are not a turn
        s, h, b = call("GET", "/v1/responses", headers={"Connection": "Upgrade", "Upgrade": "websocket"})
        check(s == 426, "GET /v1/responses (the WebSocket offer) is 426 Upgrade Required")
        s, h, b = call("GET", "/v1/models")
        check(s == 200 and json.loads(b)["data"][0]["id"] == MODEL, "GET /v1/models lists one model")
        s, h, b = call("POST", "/v1/chat/completions", {"x": 1})
        check(s == 404, "another path is 404")
        s, h, b = call("POST", "/v1/responses", b"{not json")
        check(s == 400, "a body that is not JSON is 400")
        s, h, b = call("POST", "/v1/responses", b"\x28\xb5\x2f\xfd", {"Content-Encoding": "zstd"})
        check(s == 415, "a compressed body is 415, said plainly")
        # determinism: the same request, the same bytes
        req = {"model": "m", "stream": True, "input": [env, user]}
        check(call("POST", "/v1/responses", req)[2] == call("POST", "/v1/responses", req)[2], "the same request is answered with the same bytes")
        # the log and the dump hold every request
        srv.shutdown()
        lines = [json.loads(x) for x in open(log) if x.strip()]
        check([x["n"] for x in lines] == list(range(1, len(lines) + 1)) and len(os.listdir(dump)) == sum(1 for x in lines if x["method"] == "POST" and x["path"] == "/v1/responses" or x["status"] in (404, 400, 415) and x["method"] == "POST"),
              f"the log has one line per request ({len(lines)}) and the dump one file per POST")
        kinds = [x["kind"] for x in lines]
        check(kinds.count("turn") == 7 and kinds.count("side") == 1 and kinds.count("ws-probe") == 1 and kinds.count("models") == 1,
              "the log says what each was: " + ",".join(f"{k} {kinds.count(k)}" for k in sorted(set(kinds))))
        first = lines[0]
        check(first["tools"] == ["exec_command", "multi.spawn"] and first["turn"] == 0 and first["items"] == ["function_call:exec_command"],
              "the log names the tools a request offered (namespaces flattened) and the items it answered with")
        # the credential: its kind is logged, its value never
        check(all(x.get("auth") in ("bearer", "other", "none") for x in lines if x["kind"] in ("turn", "side")) and "sk-" not in open(log).read(),
              "the log says whether a request carried a bearer credential and never holds it")
        # additional_tools (the newer models' way of listing tools)
        check(tool_names({"input": [{"type": "additional_tools", "tools": [{"type": "namespace", "name": "functions",
              "tools": [{"type": "custom", "name": "exec"}]}]}]}) == ["functions.exec"], "tools offered as an additional_tools input item are named too")
        # the script is validated
        try:
            script_items([[{"type": "nonsense"}]], 0)
            check(False, "an unknown script item type is an error")
        except ValueError:
            check(True, "an unknown script item type is an error")
    # TLS, when openssl can make a certificate: the forwarder dials upstream over TLS
    import shutil
    import subprocess
    if shutil.which("openssl"):
        with tempfile.TemporaryDirectory() as d:
            cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
            r = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
                                "-keyout", key, "-out", cert, "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                               capture_output=True)
            if r.returncode == 0:
                srv = make_server(script=script, cert=cert, key=key)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                ctx = ssl.create_default_context(cafile=cert)
                ctx.set_alpn_protocols(["h2", "http/1.1"])  # as a client that prefers h2 would offer: the server must pick http/1.1
                c = http.client.HTTPSConnection(*srv.server_address, timeout=10, context=ctx)
                c.request("POST", "/v1/responses", json.dumps({"stream": True, "input": []}), {"Content-Type": "application/json"})
                r = c.getresponse()
                body = r.read()
                check(r.status == 200 and c.sock.selected_alpn_protocol() == "http/1.1" and b"response.completed" in body,
                      "over TLS (a self-made certificate, ALPN http/1.1) the same stream is served")
                c.close()
                srv.shutdown()
            else:
                print("skip  TLS: openssl could not make a certificate")
    else:
        print("skip  TLS: no openssl")
    print(f"{'FAILED' if failures else 'ok'}: {len(failures)} check(s) failed")
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--ready")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--script")
    ap.add_argument("--log")
    ap.add_argument("--dump")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.ready or bool(a.cert) != bool(a.key):
        ap.error("--ready is required, and --cert and --key go together")
    script = None
    if a.script:
        with open(a.script) as f:
            script = json.load(f)
    if a.dump:
        os.makedirs(a.dump, exist_ok=True)
    srv = make_server(a.host, a.port, script, a.log, a.dump, a.cert, a.key)
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

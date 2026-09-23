# SPDX-License-Identifier: Apache-2.0
"""A 20-step agent on system Python and the OpenSSL it links, for the uprobe half of kill test 2
(docs/FEATURES.md "R8 / kill test 2": "on a 20-step run at least 95% of model request/response pairs are
ssl_request/ssl_response events whose response parsed").

Why it is shaped this way: the guarantee is about what crosses the process's own libssl, so the client is
the standard library's http.client over the ssl module (CPython's _ssl, which calls SSL_write_ex and
SSL_read_ex), with nothing bundled. Every step is one POST /v1/messages carrying the conversation so far,
on one keep-alive connection, which is how SDK clients reuse a connection and what capture reassembles
per connection (docs/p0/capture-derive.md R10). The certificate is trusted through SSL_CERT_FILE, the
variable OpenSSL's default verify paths read, so the agent needs no flag that a real agent would not have.

The base URL defaults to ANTHROPIC_BASE_URL, which is the forwarder's plaintext loopback listener when the
run captures through it (docs/p0/capture-derive.md R19b), so the same agent serves both capture paths of
kill test 2. When DIRECT names a host:port, the agent finishes by connecting to it directly, the bypass
R8 says must be refused while the forwarder is the model's only route, and prints what happened.

Usage: agent.py [base-url|-] [steps]   ("-" or none: $ANTHROPIC_BASE_URL; 20 steps)
It prints "step N status S" per step, "steps=N ok=M", and "direct connect refused (errno E)" or "direct
connect allowed" when DIRECT is set. It exits 0 when every step got a 200.
"""
import http.client
import json
import os
import socket
import ssl
import sys
import urllib.parse


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "-"
    base = urllib.parse.urlsplit(os.environ["ANTHROPIC_BASE_URL"] if arg == "-" else arg)
    steps = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    if base.scheme == "http":
        conn = http.client.HTTPConnection(base.hostname, base.port or 80, timeout=30)
    else:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(base.hostname, base.port or 443, context=ctx, timeout=30)
    messages = [{"role": "user", "content": "count to %d, one tool call per step" % steps}]
    ok = 0
    for n in range(1, steps + 1):
        body = json.dumps({"model": "claude-stub-1", "max_tokens": 64, "messages": messages}).encode()
        conn.request("POST", "/v1/messages", body=body, headers={
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key": os.environ.get("ANTHROPIC_API_KEY", "stub"),
        })
        resp = conn.getresponse()
        data = resp.read()
        print("step %d status %d" % (n, resp.status), flush=True)
        if resp.status != 200:
            continue
        ok += 1
        msg = json.loads(data)
        messages.append({"role": "assistant", "content": msg["content"]})
        results = [{"type": "tool_result", "tool_use_id": b["id"], "content": "ok"}
                   for b in msg["content"] if b.get("type") == "tool_use"]
        messages.append({"role": "user", "content": results or "continue"})
    conn.close()
    print("steps=%d ok=%d" % (steps, ok), flush=True)
    direct = os.environ.get("DIRECT")
    if direct:
        host, _, port = direct.rpartition(":")
        try:
            socket.create_connection((host, int(port)), timeout=5).close()
            print("direct connect allowed", flush=True)
        except OSError as e:
            print("direct connect refused (errno %s)" % e.errno, flush=True)
    return 0 if ok == steps else 1


if __name__ == "__main__":
    sys.exit(main())

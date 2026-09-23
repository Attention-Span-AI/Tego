# SPDX-License-Identifier: Apache-2.0
"""A minimal agent on system Python + httpx: one model call, one file write, one tool exec, one refused write.

Run under `tego run` with examples contracts. The model call goes to TEGO_TEST_MODEL_URL when it is set, else to
ANTHROPIC_BASE_URL + /v1/messages, which is the forwarder's listener when the run captures through it
(docs/p0/capture-derive.md R19b), else to api.anthropic.com. It uses httpx, the client the zero-adapter path is
about (docs/FEATURES.md I1), when the interpreter has it, and the standard library's urllib when it does not, so the
workload still runs on a system Python with nothing installed; the first line it prints names the client, so a run
can tell which one it exercised. httpx offers compressed answers (gzip, and br or zstd when their modules are
installed), which is the path the forwarder's Accept-Encoding narrowing and decoders exist for."""
import json, os, subprocess, sys, urllib.request

HEADERS = {"content-type": "application/json", "anthropic-version": "2023-06-01"}


def call_model(url, body):
    headers = dict(HEADERS, **{"x-api-key": os.environ.get("ANTHROPIC_API_KEY", "stub")})
    try:
        import httpx
    except ImportError:
        httpx = None
    if httpx is not None:
        # trust_env stays on: SSL_CERT_FILE and NO_PROXY reach httpx the way they reach every other client.
        r = httpx.post(url, json=body, headers=headers, timeout=30)
        return "httpx", r.json()
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return "urllib", json.loads(r.read())


def main():
    out = os.environ.get("TEGO_TEST_OUT", "/tmp/tego-out")
    os.makedirs(out, exist_ok=True)
    url = os.environ.get("TEGO_TEST_MODEL_URL", os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com") + "/v1/messages")
    try:
        client, resp = call_model(url, {"model": "claude-sonnet-5", "max_tokens": 32, "messages": [{"role": "user", "content": "say ok"}]})
    except Exception as e:  # the stub may be absent; the run still exercises fs and exec
        client, resp = "none", {"error": str(e)}
    print("client=" + client, flush=True)
    with open(os.path.join(out, "summary.md"), "w") as f:
        f.write(json.dumps(resp)[:200] + "\n")
    subprocess.run(["python3", "-c", "print('tool ran')"], check=False)
    try:
        with open(os.path.expanduser("~/.netrc.tego-test"), "w") as f:
            f.write("should be refused\n")
        print("UNEXPECTED: write outside contract succeeded", file=sys.stderr)
    except PermissionError:
        print("refused as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())

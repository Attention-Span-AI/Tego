# SPDX-License-Identifier: Apache-2.0
"""The Claude Agent SDK (Python) workload of kill test 7 (a) (docs/FEATURES.md I3 and "Kill test 7": "a
Claude Agent SDK (Python) agent with `capture: forwarder` ...; every model request is `ssl_request
source=forwarder`; a deliberate direct connect to `api.anthropic.com:443` is `refused`").

Why it is shaped this way: the SDK drives the Claude Code binary it bundles, which carries its own TLS
stack, so the only way tego sees its model traffic is the forwarder named in ANTHROPIC_BASE_URL, which the
SDK hands on to Claude Code in the environment it inherits. The agent is the SDK's own documented use: one
query() with a working directory, the file tools and edits accepted, and nothing in it knows about tego.
After the task it opens one connection straight to the model host, the bypass the contract must refuse, and
prints the outcome. test/e2e/kt7-two-agents.sh runs it under examples/agents/claude-agent-sdk.yaml against
the local model stand-in (test/workloads/model-stub), which is the model host there, so --direct names it.

Usage: agent.py [--direct HOST:PORT] [task]   (default api.anthropic.com:443; run from the directory the
task names, with ANTHROPIC_API_KEY set)
It prints each message type the SDK yields, the result message's subtype and text, then "direct connect
refused (errno E)", "direct connect allowed" or "direct connect unresolved (...)", and exits 0 when the SDK
reported a successful result.
"""
import asyncio
import errno
import os
import socket
import sys


async def run(task):
    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query  # late: a syntax check needs no SDK

    options = ClaudeAgentOptions(
        cwd=os.getcwd(),
        allowed_tools=["Read", "Write"],
        permission_mode="acceptEdits",
        max_turns=8,
    )
    ok = False
    async for message in query(prompt=task, options=options):
        print("message " + type(message).__name__, flush=True)
        if isinstance(message, ResultMessage):
            print("result %s: %s" % (message.subtype, (message.result or "").replace("\n", " ")), flush=True)
            ok = message.subtype == "success" and not message.is_error
    return ok


def main(argv):
    direct = "api.anthropic.com:443"
    if len(argv) >= 2 and argv[0] == "--direct":
        direct, argv = argv[1], argv[2:]
    task = argv[0] if argv else "Read the files in ./in and write a one-paragraph summary to ./out/summary.md."
    ok = asyncio.run(run(task))
    host, port = direct.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=5).close()
        print("direct connect allowed", flush=True)
    except socket.gaierror as e:
        # No address was ever tried, so nothing was refused: a box without DNS is not a finding.
        print("direct connect unresolved (%s)" % e, flush=True)
    except OSError as e:
        print("direct connect refused (errno %s)" % errno.errorcode.get(e.errno, e.errno), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

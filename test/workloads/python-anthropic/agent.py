# SPDX-License-Identifier: Apache-2.0
"""A small tool-using agent on system Python and the Anthropic Python SDK, for kill test 7's half (b)
(docs/FEATURES.md "Kill test 7": "one open-source Python agent on system Python + the Anthropic SDK with
`capture: uprobe`", which completes "a real local task" with "at least one `refused` event and no code
change").

Why it is shaped this way: the agent is the ordinary tool-use loop of the SDK's own documentation. It sends
the conversation, runs every tool the model asks for, returns each result (an error result when the tool
failed), and stops at end_turn. Nothing in it knows about tego: the refusal kill test 7 wants comes from
the model asking for something the contract does not allow, the way an injected or mistaken agent would,
and the agent attempting it as it would any other request. The SDK reads ANTHROPIC_BASE_URL and
ANTHROPIC_API_KEY itself, and its HTTP client trusts the certificate SSL_CERT_FILE names, so pointing the
agent at a local endpoint needs no change to this file.

Tools: read_file {path}, write_file {path, content}, list_dir {path}.
Usage: agent.py "<task>"   It prints each tool call and its outcome, then "final: <text>", and exits 0
when the conversation reached end_turn.
"""
import os
import sys

import anthropic

TOOLS = [
    {"name": "read_file", "description": "Read a UTF-8 text file.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Write a UTF-8 text file, replacing it.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                      "required": ["path", "content"]}},
    {"name": "list_dir", "description": "List a directory.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
]


def run_tool(name, args):
    if name == "read_file":
        with open(args["path"]) as f:
            return f.read()
    if name == "write_file":
        with open(args["path"], "w") as f:
            f.write(args["content"])
        return "wrote %d bytes to %s" % (len(args["content"]), args["path"])
    if name == "list_dir":
        return "\n".join(sorted(os.listdir(args["path"])))
    raise ValueError("unknown tool " + name)


def main():
    task = sys.argv[1] if len(sys.argv) > 1 else "Summarize the files in ./in into ./out/summary.md."
    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": task}]
    for _ in range(16):
        msg = client.messages.create(model=os.environ.get("AGENT_MODEL", "claude-sonnet-5"), max_tokens=1024,
                                     tools=TOOLS, messages=messages)
        messages.append({"role": "assistant", "content": msg.content})
        if msg.stop_reason != "tool_use":
            text = "".join(b.text for b in msg.content if b.type == "text")
            print("final: " + text, flush=True)
            return 0
        results = []
        for b in msg.content:
            if b.type != "tool_use":
                continue
            try:
                out, err = run_tool(b.name, b.input), False
            except OSError as e:  # PermissionError included: the tool failed, the agent carries on
                out, err = "%s: %s" % (type(e).__name__, e), True
            print("tool %s %s -> %s" % (b.name, b.input.get("path", ""), "error: " + out if err else "ok"), flush=True)
            results.append({"type": "tool_result", "tool_use_id": b.id, "content": out, "is_error": err})
        messages.append({"role": "user", "content": results})
    print("final: gave up after 16 turns", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())

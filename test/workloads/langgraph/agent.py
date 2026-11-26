# SPDX-License-Identifier: Apache-2.0
"""A small LangGraph agent for the LangGraph example's test and guest row (examples/agents/langgraph.yaml).

It is a real LangGraph graph (StateGraph, a conditional edge, a model node and a tool node, as the Graph API quickstart
builds one: https://docs.langchain.com/oss/python/langgraph/quickstart) whose tools are real LangChain tools. Only the
"model" is not: it is langchain_core's own GenericFakeChatModel, which hands back the AIMessages it was given, one per
call. So the graph needs no model account and makes no network call for its decisions, and what the model "decides" is
fixed by the script below; everything after the decision is real: LangGraph's routing, LangChain's tool machinery,
the kernel's answer to each file, program and connection, and (when the run has an MCP relay) langchain-mcp-adapters
talking to an MCP server through Tego's relay. The model's own traffic is the other script's job (model_loop.py).

The tools, in the order the script calls them (each call's id is its label in out/results.json):
  write_inside   write_file  ./out/hello.txt            allowed by the example's rules
  write_outside  write_file  ./escape.txt               refused: outside the one writable folder
  run_allowed    run_program git --version              allowed
  run_refused    run_program curl --version             refused: a program the rules do not list
  fetch_allowed  fetch       --allowed-url              allowed: a host in net.allow
  fetch_refused  fetch       --refused-url              refused: a host that is not
  mcp_allowed    read_file   (an MCP tool, through the adapters)   allowed by the relay
  mcp_denied     mcp_delete_file                         denied by the relay (the server's tools/list hides it, so the
                 call goes through the adapters' session directly, as a model that asks for a tool it was not told of)
The MCP calls need TEGO_MCP_CONFIG (the file a run with a relayed server gets) and are left out, with a line that says so
(`MCP skipped: ...`), without it, or with --no-mcp. --only-allowed leaves out every call the rules refuse, for a first watched run (`tego watch`).

Usage: agent.py [--allowed-url URL] [--refused-url URL] [--only-allowed] [--no-mcp]   (run from the project folder,
./out/ present and writable). Each tool's outcome is printed as `RESULT label ok|error detail` and kept in
out/results.json; a refused action is an error result the graph carries on from, as an agent's would be. Exit 0 when
the graph finished, 1 when it did not.
"""
import argparse
import asyncio
import json
import operator
import os
import subprocess
import sys
import urllib.request
from contextlib import AsyncExitStack
from typing import Annotated, TypedDict

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph


class State(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]


@tool
def write_file(path: str, text: str) -> str:
    """Write text to a file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return "wrote %d bytes to %s" % (len(text), path)


@tool
def run_program(argv: list[str]) -> str:
    """Run a program with its arguments and return the first line it printed."""
    done = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
    lines = (done.stdout or done.stderr).splitlines()
    return lines[0] if lines else "exit %d" % done.returncode


@tool
def fetch(url: str) -> str:
    """Fetch a URL and return the first 80 bytes of the answer."""
    with urllib.request.urlopen(url, timeout=10) as answer:
        return answer.read(80).decode("utf-8", "replace")


def call(label, name, **args):
    return {"name": name, "args": args, "id": label, "type": "tool_call"}


def script(args, mcp):
    calls = [call("write_inside", "write_file", path="out/hello.txt", text="hello from a LangGraph tool\n")]
    if not args.only_allowed:
        calls.append(call("write_outside", "write_file", path="escape.txt", text="outside the one writable folder\n"))
    calls.append(call("run_allowed", "run_program", argv=["git", "--version"]))
    if not args.only_allowed:
        calls.append(call("run_refused", "run_program", argv=["curl", "--version"]))
    calls.append(call("fetch_allowed", "fetch", url=args.allowed_url))
    if not args.only_allowed:
        calls.append(call("fetch_refused", "fetch", url=args.refused_url))
    if mcp:
        calls.append(call("mcp_allowed", "read_file"))
        if not args.only_allowed:
            calls.append(call("mcp_denied", "mcp_delete_file"))
    # Two replies: the tool calls, then the final answer once their results are in the history.
    return iter([AIMessage(content="", tool_calls=calls), AIMessage(content="done")])


def build(model, tools):
    async def llm_call(state: State):
        return {"messages": [await model.ainvoke(state["messages"])]}

    async def tool_node(state: State):
        out = []
        for tc in state["messages"][-1].tool_calls:
            try:
                content = await tools[tc["name"]].ainvoke(tc["args"])
                out.append(ToolMessage(content=str(content), tool_call_id=tc["id"], name=tc["name"], status="success"))
            except Exception as e:  # a refused action is an error the agent reads and goes on from
                out.append(ToolMessage(content="%s: %s" % (type(e).__name__, e), tool_call_id=tc["id"], name=tc["name"], status="error"))
        return {"messages": out}

    def should_continue(state: State):
        return "tool_node" if state["messages"][-1].tool_calls else END

    g = StateGraph(State)
    g.add_node("llm_call", llm_call)
    g.add_node("tool_node", tool_node)
    g.add_edge(START, "llm_call")
    g.add_conditional_edges("llm_call", should_continue, ["tool_node", END])
    g.add_edge("tool_node", "llm_call")
    return g.compile()


async def main(args):
    tools = {t.name: t for t in (write_file, run_program, fetch)}
    mcp = bool(os.environ.get("TEGO_MCP_CONFIG")) and not args.no_mcp
    if not args.no_mcp:
        # Said aloud, not skipped quietly: a run that gives no MCP client file is a finding, not a pass.
        print("ENV TEGO_MCP_CONFIG=%s TEGO_MCP_RELAY=%s" % (
            "set" if os.environ.get("TEGO_MCP_CONFIG") else "not set", "set" if os.environ.get("TEGO_MCP_RELAY") else "not set"), flush=True)
        if not mcp:
            print("MCP skipped: TEGO_MCP_CONFIG is not set in this run's environment", flush=True)
    async with AsyncExitStack() as stack:
        if mcp:
            # Imported late: a run without MCP needs neither package.
            from langchain_mcp_adapters.client import MultiServerMCPClient
            from langchain_mcp_adapters.tools import load_mcp_tools

            server = json.load(open(os.environ["TEGO_MCP_CONFIG"]))["mcpServers"]["files"]
            # The MCP SDK starts a stdio server with a short list of variables of its own, so the relay's address
            # (which the shim, `tego mcp relay`, reads) is passed in the connection.
            client = MultiServerMCPClient({"files": {
                "transport": "stdio", "command": server["command"], "args": server["args"],
                "env": {"TEGO_MCP_RELAY": os.environ["TEGO_MCP_RELAY"]},
            }})
            session = await stack.enter_async_context(client.session("files"))
            listed = await load_mcp_tools(session)
            for t in listed:
                tools[t.name] = t
            print("MCP tools listed: %s" % sorted(t.name for t in listed), flush=True)

            @tool
            async def mcp_delete_file() -> str:
                """Ask the MCP server to delete a file."""
                return str(await session.call_tool("delete_file", {}))

            tools["mcp_delete_file"] = mcp_delete_file
        graph = build(GenericFakeChatModel(messages=script(args, mcp)), tools)
        final = await graph.ainvoke({"messages": [HumanMessage(content="Work through the list.")]})
    results = {}
    for m in final["messages"]:
        if isinstance(m, ToolMessage):
            results[m.tool_call_id] = {"tool": m.name, "ok": m.status == "success", "detail": m.content[:300]}
            print("RESULT %s %s %s" % (m.tool_call_id, "ok" if m.status == "success" else "error", m.content[:160].replace("\n", " ")), flush=True)
    with open(os.path.join("out", "results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1)
    return 0 if final["messages"][-1].content == "done" else 1


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--allowed-url", default="https://api.open-meteo.com/v1/forecast?latitude=52.5&longitude=13.4&current=temperature_2m")
    p.add_argument("--refused-url", default="https://example.org/")
    p.add_argument("--only-allowed", action="store_true")
    p.add_argument("--no-mcp", action="store_true")
    sys.exit(asyncio.run(main(p.parse_args())))

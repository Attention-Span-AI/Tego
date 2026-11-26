# SPDX-License-Identifier: Apache-2.0
"""A LangGraph graph that asks a LangChain OpenAI chat model for the LangGraph example's check of OpenAI-style model calls
under a token budget (examples/agents/langgraph.yaml with an `openai` model entry and `limits.tokens`).

ChatOpenAI is constructed with no base URL and no key in the code: it reads OPENAI_API_KEY, and the base URL from the
variables Tego sets for an `openai` entry under `capture: forwarder` (OPENAI_BASE_URL, OPENAI_API_BASE). The guest row
points the entry at openai_stub.py. Tego reads the usage an OpenAI-style answer states and never changes the request, so what
the client asks of the API decides whether a streamed answer can be counted:

  --mode whole            no streaming: every answer carries usage, so the budget counts it and stops the run at the limit
  --mode stream-usage     streaming, with the client asking for usage in the stream (stream_options.include_usage)
  --mode stream-nousage   streaming, the client not asking: no answer carries usage, and the run is ended at the first one

Usage: openai_loop.py [--calls N] [--mode MODE]   Prints `CALL n: <text>` after each call and `FINISHED n calls` at the end.
"""
import argparse
import operator
from typing import Annotated, TypedDict

from langchain_core.messages import AnyMessage, HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph


class State(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]
    calls: int


def build(mode):
    if mode == "whole":
        return ChatOpenAI(model="gpt-5", max_retries=0)
    # streaming=True makes invoke() stream; stream_usage says whether the client asks the API for usage in the stream.
    return ChatOpenAI(model="gpt-5", max_retries=0, streaming=True, stream_usage=(mode == "stream-usage"))


def main(calls, mode):
    model = build(mode)

    def ask(state: State):
        n = state["calls"] + 1
        reply = model.invoke([HumanMessage(content="Say ok. (call %d)" % n)])
        print("CALL %d: %s" % (n, str(reply.content).strip()[:60]), flush=True)
        return {"messages": [reply], "calls": n}

    def again(state: State):
        return "ask" if state["calls"] < calls else END

    g = StateGraph(State)
    g.add_node("ask", ask)
    g.add_edge(START, "ask")
    g.add_conditional_edges("ask", again, ["ask", END])
    done = g.compile().invoke({"messages": [], "calls": 0}, {"recursion_limit": 200})
    print("FINISHED %d calls" % done["calls"], flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--calls", type=int, default=5)
    p.add_argument("--mode", choices=["whole", "stream-usage", "stream-nousage"], default="whole")
    a = p.parse_args()
    main(a.calls, a.mode)

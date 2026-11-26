# SPDX-License-Identifier: Apache-2.0
"""A LangGraph graph that asks a real LangChain chat model, again and again, for the LangGraph example's budget check
(examples/agents/langgraph.yaml, its `capture: forwarder` and `limits.tokens`).

The model client is langchain-anthropic's ChatAnthropic, constructed the way its documentation does, with no base URL
and no key in the code: it reads ANTHROPIC_BASE_URL (and ANTHROPIC_API_URL before it) and ANTHROPIC_API_KEY from the
environment, which is how a person's own agent is set up. Under `tego run` with `capture: forwarder`, Tego sets
ANTHROPIC_BASE_URL to its forwarder's loopback address, so every call goes through the forwarder and is recorded and
counted. The guest row points the contract's model endpoint at a local stand-in that answers in the Messages API's shape
(test/workloads/model-stub); no real model is called. Nothing here knows about Tego.

The graph is one node and one conditional edge: ask, count, and ask again until --calls calls were made. A run that
Tego ends at its token budget stops before that, which is what the row checks; the first call after the limit is answered
by Tego with a 403, which the client raises.

Usage: model_loop.py [--calls N]   Prints `CALL n: <reply text>` after each call and `FINISHED n calls` at the end.
"""
import argparse
import operator
import sys
from typing import Annotated, TypedDict

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AnyMessage, HumanMessage
from langgraph.graph import END, START, StateGraph


class State(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]
    calls: int


def main(calls):
    # max_retries=0: a refused call (the budget is spent) must reach the agent as an error, not be tried again.
    model = ChatAnthropic(model="claude-sonnet-4-6", max_tokens=16, max_retries=0)

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
    p.add_argument("--calls", type=int, default=40)
    main(p.parse_args().calls)
    sys.exit(0)

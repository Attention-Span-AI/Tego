Copy-paste starting points. `agents/` holds a contract per common agent shape: a Python retriever with one MCP server,
Claude Code in print mode and, for a person at a terminal, Claude Code and Codex interactive (API key or ChatGPT sign-in; each file's header says how to log in), a Python agent on the Claude Agent SDK and one on the raw Anthropic Python SDK, Codex behind
the forwarder, and an agent of your own left to run unattended (see `agents/README.md`). `profiles/` holds the base
profile they extend, and `tests/` a `compile --test` table with the contract it checks. There is no LangGraph contract
and no quickstart yet. The interactive contracts are the demo kit's
(`demo/contracts/`, proven on a laptop) in copy-paste form, and a test keeps each pair equal; `codex.yaml` also has a
rule table tested, and test/poc/interactive-codex ran a contract of the same shape offline against a stand-in model.

`prices.example.yaml` is a price table to start from: a contract that declares `limits.cost_usd` is refused without
one, and its header says how to check and install it (`docs/OPERATIONS.md`, "The price table").

`container/` holds the container image (a Dockerfile, a compose file running an agent under `tego run` with the
dashboard on the host's loopback, and the entrypoint that prepares the container): see `docs/user/container.md`.

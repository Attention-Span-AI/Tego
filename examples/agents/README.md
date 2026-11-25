# examples/agents

Copy-paste contracts, one per common agent shape. Every file here is the P0
subset of `spec/agent/v0` and must load with `tego rules check` with only
warnings: `examples_test.go` compiles each one on a stand-in machine (tools on
`PATH`, the profiles under `examples/profiles`), and again on a fresh one once
the setup its comments name is done (below), and `pkg/spec/agent` tests
`retriever.yaml` against a profile fixture of its own. The stand-ins use the
names a stock Ubuntu or Debian box uses (`python3`; there is no `python`), and
an example draws no `redundant-rule` warning and at most one
`model-direct-bypass`.

| File | Agent | Notes |
|---|---|---|
| `retriever.yaml` | a Python retriever with one MCP server | mirrors the annotated spec example minus its P1/P2 fields, with the project's own directories (`./out/`, `./config/`) where the spec example has `/work`, and no `deny_read` of its own: the built-in list already holds `~/.ssh`, `~/.aws` and `~/.netrc`, present or not, while an entry there must exist |
| `claude-code.yaml` | Claude Code in print mode (`claude -p`) | `capture: forwarder` (Claude Code bundles BoringSSL with no symbols a uprobe could use), `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `--permission-mode acceptEdits` so print mode may edit, Claude Code's config and scratch directories in `./.claude-state/`, an empty `net.allow` so a direct connect to the model host is refused; kill test 7 part `a-cli` (§12.3) runs it |
| `claude-agent-sdk.yaml` | a Python agent on the Claude Agent SDK, which drives the Claude Code it bundles | the same capture and switches, the SDK installed with `pip install --target .deps` and its directory granted in `exec.allow`; kill test 7 (a)'s contract, run with `test/workloads/claude-sdk` |
| `anthropic-sdk-python.yaml` | a system-Python agent on the Anthropic Python SDK | `capture: uprobe` on the system OpenSSL, tier cgroup (`sudo`); kill test 7 (b) runs it with only the model endpoint moved to a local stand-in |
| `claude-code-interactive.yaml` | Claude Code, the full-screen interface (`claude`), for a person at a terminal | the same policy as `examples/demo/contracts/claude-code.yaml` (`TestInteractiveExamplesMatchTheDemoKit` keeps the two equal): `capture: off` with `net.allow` naming `api.anthropic.com:443` (a forwarder makes Claude Code exit 1 on its first connectivity check), `/dev/tty` writable and agent sockets in the run's private harness runtime (`env.set.XDG_RUNTIME_DIR: "%R"`), state in `./.claude-state/`, `limits.stall_after: 1h` (typing counts as activity) and no `wall`, no `cost_usd` (both would end or refuse a working session). The login is in the file's header: `claude setup-token` once, outside tego, then `CLAUDE_CODE_OAUTH_TOKEN` (or `ANTHROPIC_API_KEY`) from your shell, passed by `env.pass`; keep the invoking `XDG_RUNTIME_DIR` short (normally `/run/user/<uid>`); launch validates `cc-socks/9999999.sock` against Claude's 103-byte limit, and refuses an overlong runtime rather than granting the shared `/tmp` fallback |
| `codex-chatgpt.yaml` | OpenAI Codex signed in with a ChatGPT plan, interactive | `capture: off`, `chatgpt.com` and `auth.openai.com` in `net.allow`; the sign-in listener cannot run inside tego, so sign in outside it and copy `auth.json` into a Codex home of its own that `CODEX_HOME` names (the header has the commands); `/dev/ptmx` and `/dev/pts/` and Codex's `codex-code-mode-host` helper (CHANGE its directory), `held/` asks, `stall_after`, no `wall`, no `cost_usd`; the demo kit's `contracts/codex-chatgpt.yaml` is the same contract, kept equal by the same test, except that the kit records as a short demo does (`record: summary`, `reads: held`, `wall: 2h`) and this file as a long working session (`record: full`, `stall_after: 1h`) |
| `codex.yaml` | OpenAI Codex, the full-screen interface (`codex --no-daemon`) | `capture: forwarder` through an `openai` model entry (Codex ignores `OPENAI_BASE_URL`; the run's own `CODEX_HOME` carries the route, and the run grants Codex write on that directory itself, so no entry names it: an entry over or inside `$XDG_RUNTIME_DIR/tego/` is refused, and an unprivileged run with no `XDG_RUNTIME_DIR` is refused, exit 125, while under sudo Codex goes unrouted and the run records `gap why=codex-unrouted`; another tego run of the same user can read that `CODEX_HOME`, typed key included, while this one lasts and, after a killed launcher, until the next run removes it (an open condition; docs/site/codex.md says what to do); `CODEX_HOME` names the directory holding your `config.toml`), a write grant of `./work/` and a `TMPDIR` inside it (a grant of `./` would cover `held/` and the `fs.ask` for it would never fire), `--no-daemon`, `/proc/self/exe` left out of `exec.allow`, `/dev/ptmx`, `/dev/pts/` and the `codex-code-mode-host` helper (without them every command Codex runs fails with "out of pty devices"), `stall_after` instead of a `wall` and no `cost_usd`, the files of `~/.codex` denied one by one (its installation is in the directory), an empty `net.allow` and `net.dns.mode: off`; compiles with one `env-runtime-reserved` warning, by design. Modelled on `test/poc/interactive-codex/codex-real-forwarder.yaml` (which has no `fs.ask` and a write grant of `./`; `test/poc/interactive-codex/run.sh` ran a contract of the same shape offline, against a stand-in model); its pty, helper and limit lines are the demo kit's `contracts/codex.yaml` that ran on a laptop |
| `custom-agent.yaml` | an agent of your own, left to run unattended | the model through the forwarder, every limit set (`wall`, `stall_after`, `repeats`, `tokens`, `cost_usd`, `memory`, `pids`, `cpu`), `ask` for the few decisions a person takes; `test/poc/custom-agent/` runs it in compressed time and for two hours, and `docs/site/services.md` says what each limit does |
| `langgraph.yaml` | a LangChain or LangGraph agent in a Python virtual environment | `./.venv/bin/python agent.py`, the environment named in `exec.allow` beside `git` (the one program its tools start), one writable folder (`./out/`), one extra host in `net.allow` (CHANGE it), the model through the forwarder (`capture: forwarder`, `models:` anthropic, the model host out of `net.allow`) under `limits.tokens`, and one MCP server behind the relay (`mcp:`, `read_file` allowed, `delete_file` denied; CHANGE it, and the `<tego path> mcp relay *` entry of `exec.allow` with it). `test/workloads/langgraph/` is the scripted agent the example's tests and its guest check run; its `requirements.txt` pins the versions it was written against |

The three interactive contracts (`claude-code-interactive.yaml`, `codex.yaml`, `codex-chatgpt.yaml`) say CHANGE where a path is yours. With `claude` or `codex` on `PATH`, `tego run <contract> -- claude --version` (or `codex --version`) starts the agent under the contract with no login and no prompt, which is the quickest check that a copy works on your machine.

## LangChain and LangGraph agents

Tego has no adapter for LangChain or LangGraph: an agent built on them is a Python process like any other, and
`langgraph.yaml` is the rules file to start from for one in a virtual environment (`python3 -m venv .venv && .venv/bin/pip
install -r requirements.txt`). `tego scan` run in the project folder names the agent from its `langgraph` dependency
(`requirements.txt`) or its `langgraph.json` (`docs/user/scan.md`); it keeps no versions.

What Tego sees of such an agent, and holds to the rules:

- Files: every write outside `./out/` is refused and recorded, whichever tool, library or thread makes it.
- Programs: a tool that starts a program is held to `exec.allow`; one that is not listed is refused and recorded.
- Hosts: a tool that connects anywhere but the hosts in `net.allow` is refused and recorded. LangSmith tracing is switched
  on by environment variables (`LANGSMITH_TRACING` and its kin): this file passes none, and `api.smith.langchain.com` is not in
  `net.allow`, so a trace the agent tried to send would be refused and recorded.
- MCP tools: a server started through the relay (`tego mcp relay`, from the file `TEGO_MCP_CONFIG` names) has each
  `tools/call` decided by name, and a denied one is answered with an error the graph can read. langchain-mcp-adapters
  takes that file's command and arguments as its stdio connection; the relay's address `TEGO_MCP_RELAY` is passed in the
  connection's `env`, since the MCP SDK starts a server with only a short list of variables. This was shown with this example at tier
  landlock; at a root tier the file is made in a folder of its own and this example's row has not been run again there: see "Limits seen" below.
- Model calls: a chat model that reads its provider's base-URL variable goes through the forwarder, and each call is a
  line in the record that `limits.tokens` counts, with a `decision` line for each tool call the model asks for.
  `ChatAnthropic` reads `ANTHROPIC_BASE_URL`, which Tego sets for an `anthropic` model entry, and `ChatOpenAI` the
  variables Tego sets for an `openai` entry. **Token and cost budgets count the model APIs Tego reads usage from, through
  the forwarder: Anthropic's Messages API (`provider: anthropic`) and OpenAI's Chat Completions and Responses APIs
  (`provider: openai`, the entry that says the endpoint is OpenAI-style).** A `ChatOpenAI` call is counted when the answer
  states its usage: a whole answer does, a streamed one only when the client asks the API to put usage in the stream
  (`stream_options: {"include_usage": true}`; Tego never adds it to a request). A streamed answer without usage ends a run
  under `tokens` or `cost_usd`, saying so on the terminal, as does a call to any other API: see "Limits seen" below. OpenAI-style counting is tested against a stand-in written from the provider's reference; the guest run with a real client is still owed.

What it does not see:

- A tool that is a Python function inside the agent's own process is not a tool to Tego: the record has no line for the call,
  its arguments or its result, only for what the function does to a file, a program or a host. The nodes and edges of the
  graph are not visible either, and a model that is not reached through the forwarder leaves no line of its own.
- An MCP server the agent starts itself, around the relay, is refused (`mcp[<name>].relay`) but a tool inside the agent's
  own process is not an MCP tool, so the per-tool rules do not apply to it.
- A model client that ignores the base-URL variable, or sets its own base URL in code, is not routed through the forwarder:
  its host is then refused (it is not in `net.allow`) and the run records a refusal, not a model call. (Not run in a guest:
  both clients of this example read the variable.)

`test/workloads/langgraph/agent.py` is a small LangGraph graph whose "model" is langchain_core's `GenericFakeChatModel`
(a scripted reply, so it needs no model account and no network for its decisions) and whose tools write inside and outside
`./out/`, start `git` and `curl`, fetch from an allowed and a refused host and call an MCP tool the relay allows and one it
denies. `langgraph_test.go` checks the rules' verdict for each of those actions in every tier a run of the contract can get,
and that the scripts and the example agree on them. `model_loop.py` and `openai_loop.py` are graphs of `ChatAnthropic` and
`ChatOpenAI` calls for the budget checks. The versions in `requirements.txt` (langgraph 1.2.24, langchain-core 1.8.5,
langchain-anthropic 1.7.13, langchain-mcp-adapters 0.3.2, mcp 1.30.0; `requirements-openai.txt` adds langchain-openai 1.8.5) were
the current releases on 2026-11-26; the other packages are whatever pip resolves inside their ranges.

### What a guest run showed

On a fresh Ubuntu 24.04 guest (kernel 6.8, Python 3.12, the packages above), as an ordinary user, with a local server as the
allowed host and a second local server on another port as the refused one:

- `tego rules check` of the example passed, and `tego scan` in the project named LangGraph (`dep-langgraph`).
- At tier landlock and, with `sudo "$(command -v tego)" run --tier cgroup`, at tier cgroup: the write inside `./out/` happened
  and the one beside the project's files did not; `git` ran and `curl` was refused; the allowed host answered and the refused
  one got no connection. Each was a line in the record, and `tego events <run> --verify` and `tego receipt <run> --verify`
  passed. The receipt's refusal total equalled the refused lines of the record, and its refusals named the outside write,
  `curl` and the refused host by target.
- At tier landlock the MCP tool the relay allows (`read_file`, through langchain-mcp-adapters) was answered and recorded
  allowed; the tool it denies (`delete_file`) came back to the graph as an `McpError` that says "Tego refused the MCP tool
  delete_file on files: the run's rules deny this tool", was recorded refused by the relay, and never reached the server. The
  receipt names that refusal by its rule, `mcp[files].tools.deny[delete_file]`, since an MCP call has no path or address.
- `tego watch -- ./.venv/bin/python agent.py --only-allowed --no-mcp` recorded a run with no refusal.
- Budget: `ChatAnthropic`, given no base URL, reached a local stand-in for the Messages API through the forwarder with
  `limits.tokens: 100`. Six calls were answered and counted (the receipt's 12 input and 7 output tokens a call equal what the
  stand-in reported); the run ended with exit 124 and a `limit` line naming tokens and the ceiling 100, and every model request
  in the record is from the forwarder.

### Limits seen

- **MCP at a root tier (fixed, public issue 98).** The guest run above found that with `sudo "$(command -v tego)" run --tier
  cgroup` the agent got `TEGO_MCP_RELAY` and no `TEGO_MCP_CONFIG` (the test agent printed `MCP skipped: TEGO_MCP_CONFIG is not
  set in this run's environment` and the record held no `mcp` line), because a root launcher makes no runtime directory for
  the file. A root launcher now puts the file in a directory of its own, `/run/tego-agent/<run id>`, readable by your account
  only (docs/user/mcp-tools.md), and a run that has no place for it is refused. That fix was proved in a guest with a plain
  stdio server and a client that reads the file, at tiers landlock, cgroup and bpflsm; this example's own LangGraph row has
  not been run again at a root tier.
- **Token and cost budgets and OpenAI-shaped calls.** Before this release candidate, a `ChatOpenAI` agent under
  `limits.tokens` reached the forwarder and was ended at its first answer (`ended (ended: error)`, exit 125, the reason only in
  `run_end`'s detail). OpenAI-style answers that state their usage are now counted and stopped at the limit (exit 124) in tests against a stand-in written from the provider's reference; the
  guest run with a real client, with the client asking for usage in the stream or not streaming, is still owed (the row is written and has **not been run**).
  What still ends a budgeted run at the answer is an answer whose usage Tego cannot read: a streamed answer whose client did
  not ask for usage (LangChain's `ChatOpenAI` with a custom base URL may not ask by default: unverified), a stream cut short by a cancel,
  a Responses answer stopped by `max_output_tokens`, a path other than `/v1/chat/completions` and `/v1/responses`, or an API of another provider. The closing
  lines of `tego run` then say which request, why, and what to do, and `tego rules check` warns `[budget-uncounted]` for a
  `tokens` or `cost_usd` beside a provider Tego does not count. Tool calls of an OpenAI-style answer are not derived as
  decisions, so `limits.repeats` does not count them.
- **Refusal counts run higher than the agent's own.** A tool that starts a program that is not allowed shows two refusals (the
  program is tried under `/usr/bin` and under `/bin`), and the agent's Python process made one refused bind to `[::1]` port 0
  in its first moments. The run that tried four things shows "refused 6".

`gate`, `ask`, `fs.ask`, `net.ask` and declared-forwarder `net.http` rules are implemented;
their supported actions and tier requirements are in `spec/policy/SEMANTICS.md`.
Schema-only fields (`prompt`, `skills`, `visibility`,
`docker`, `exec.privileged`, `env.mask`) must still be empty, and `containers` must be empty
or `none`. See `spec/agent/v0/example.retriever.yaml` for their documented meaning.

## Before the first compile

On a machine with the agent's own tools and nothing else set up (no profiles, no price table, none of a
developer's credential files), each file compiles once the setup its comments name is done, and
`TestEveryExampleCompilesOnAFreshMachine` checks exactly that, holding each step to the file's own words:

| Setup | Files |
|---|---|
| `base/python-dev`, the profile they extend | `retriever.yaml`, `anthropic-sdk-python.yaml`, `claude-agent-sdk.yaml`, `langgraph.yaml` |
| a price table, for `limits.cost_usd`, without which every run is refused `[budget-unmetered]` | `claude-code.yaml`, `claude-agent-sdk.yaml`, `anthropic-sdk-python.yaml`, `custom-agent.yaml`, `retriever.yaml` |
| the Claude Agent SDK in the project's `.deps` (`pip install --target .deps claude-agent-sdk`) | `claude-agent-sdk.yaml` |
| a `config/` directory in the project, which it watches | `retriever.yaml` |
| the sign-in its header gives, into a Codex home of its own (`mkdir -p ~/.local/share/tego/codex-chatgpt` first) | `codex-chatgpt.yaml` |
| a virtual environment in the project (`python3 -m venv .venv`), the MCP server file the `mcp:` entry starts (`./mcp_server.py`) and, in `exec.allow`, the path of the installed tego binary beside `mcp relay *` | `langgraph.yaml` |
| the lines marked CHANGE (your project path, your home, the files of your `~/.codex`, Codex's helper) | `claude-code-interactive.yaml`, `codex.yaml`, `codex-chatgpt.yaml` |

The profile and the price table go in tego's own directory, where the machine config's defaults (`profiles:
~/.tego/profiles`, `prices: ~/.tego/prices.yaml`) find them; check the price table's prices first
(`examples/prices.example.yaml`, `docs/site/budgets.md`):

```sh
mkdir -p -m 700 ~/.tego
mkdir -p ~/.tego/profiles && cp -r examples/profiles/base ~/.tego/profiles/ && chmod -R go-w ~/.tego/profiles
install -m 600 examples/prices.example.yaml ~/.tego/prices.yaml
```

Both follow the machine config's trust rule: owned by root or you, and neither a file nor a directory on the way
group- or other-writable (a copy made under umask 002 is not, hence the `chmod`). A machine config can name
`examples/profiles` itself as `profiles:` instead, once `chmod -R go-w examples/profiles` has made it trusted.

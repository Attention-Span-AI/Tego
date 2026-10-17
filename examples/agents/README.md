# examples/agents

Copy-paste contracts, one per common agent shape. Every file here is the P0
subset of `spec/agent/v0` and must load with `tego compile` with only
warnings: `examples_test.go` compiles each one on a stand-in machine (tools on
`PATH`, the profiles under `examples/profiles`), and `pkg/spec/agent` tests
`retriever.yaml` against a profile fixture of its own. The stand-ins use the
names a stock Ubuntu or Debian box uses (`python3`; there is no `python`), and
an example draws no `redundant-rule` warning and at most one
`model-direct-bypass`.

| File | Agent | Notes |
|---|---|---|
| `retriever.yaml` | a Python retriever with one MCP server | mirrors the annotated spec example minus its P1/P2 fields |
| `claude-code.yaml` | Claude Code in print mode (`claude -p`) | `capture: forwarder` (Claude Code bundles BoringSSL with no symbols a uprobe could use), `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `--permission-mode acceptEdits` so print mode may edit, Claude Code's config and scratch directories in `./.claude-state/`, an empty `net.allow` so a direct connect to the model host is refused; kill test 7 part `a-cli` (§12.3) runs it |
| `claude-agent-sdk.yaml` | a Python agent on the Claude Agent SDK, which drives the Claude Code it bundles | the same capture and switches, the SDK installed with `pip install --target .deps` and its directory granted in `exec.allow`; kill test 7 (a)'s contract, run with `test/workloads/claude-sdk` |
| `anthropic-sdk-python.yaml` | a system-Python agent on the Anthropic Python SDK | `capture: uprobe` on the system OpenSSL, tier cgroup (`sudo`); kill test 7 (b) runs it with only the model endpoint moved to a local stand-in |
| `claude-code-interactive.yaml` | Claude Code, the full-screen interface (`claude`), for a person at a terminal | the contract proven on a laptop by `examples/demo/contracts/claude-code.yaml` (`TestInteractiveExamplesMatchTheDemoKit` keeps the two equal): `capture: off` with `net.allow` naming `api.anthropic.com:443` (a forwarder makes Claude Code exit 1 on its first connectivity check), `/dev/tty` and the `cc-socks` directory writable, state in `./.claude-state/`, `limits.stall_after: 1h` (typing counts as activity) and no `wall`, no `cost_usd` (both would end or refuse a working session). The login is in the file's header: `claude setup-token` once, outside tego, then `CLAUDE_CODE_OAUTH_TOKEN` (or `ANTHROPIC_API_KEY`) from your shell, passed by `env.pass`; CHANGE the uid in the `cc-socks` path |
| `codex-chatgpt.yaml` | OpenAI Codex signed in with a ChatGPT plan, interactive | `capture: off`, `chatgpt.com` and `auth.openai.com` in `net.allow`; the sign-in listener cannot run inside tego, so sign in outside it and copy `auth.json` into a Codex home of its own that `CODEX_HOME` names (the header has the commands); `/dev/ptmx` and `/dev/pts/` and Codex's `codex-code-mode-host` helper (CHANGE its directory), `held/` asks, `stall_after`, no `wall`, no `cost_usd`; the demo kit's `contracts/codex-chatgpt.yaml` is the same contract, kept equal by the same test, except that the kit records as a short demo does (`record: summary`, `reads: held`, `wall: 2h`) and this file as a long working session (`record: full`, `stall_after: 1h`) |
| `codex.yaml` | OpenAI Codex, the full-screen interface (`codex --no-daemon`) | `capture: forwarder` through an `openai` model entry (Codex ignores `OPENAI_BASE_URL`; the run's own `CODEX_HOME` carries the route, and the run grants Codex write on that directory itself, so no entry names it: an entry over or inside `$XDG_RUNTIME_DIR/tego/` is refused, and an unprivileged run with no `XDG_RUNTIME_DIR` is refused, exit 125, while under sudo Codex goes unrouted and the run records `gap why=codex-unrouted`; another tego run of the same user can read that `CODEX_HOME`, typed key included, while this one lasts and, after a killed launcher, until the next run removes it (agent-contract.md R10a, an open condition; OPERATIONS step 4 says what to do); `CODEX_HOME` names the directory holding your `config.toml`), a write grant of `./work/` and a `TMPDIR` inside it (a grant of `./` would cover `held/` and the `fs.ask` for it would never fire), `--no-daemon`, `/proc/self/exe` left out of `exec.allow`, `/dev/ptmx`, `/dev/pts/` and the `codex-code-mode-host` helper (without them every command Codex runs fails with "out of pty devices"), `stall_after` instead of a `wall` and no `cost_usd`, the files of `~/.codex` denied one by one (its installation is in the directory), an empty `net.allow` and `net.dns.mode: off`; compiles with one `env-runtime-reserved` warning, by design. Modelled on `test/poc/interactive-codex/codex-real-forwarder.yaml` (which has no `fs.ask` and a write grant of `./`; `test/poc/interactive-codex/run.sh` ran a contract of the same shape offline, against a stand-in model); its pty, helper and limit lines are the demo kit's `contracts/codex.yaml` that ran on a laptop |
| `custom-agent.yaml` | an agent of your own, left to run unattended | the model through the forwarder, every limit set (`wall`, `stall_after`, `repeats`, `tokens`, `cost_usd`, `memory`, `pids`, `cpu`), `ask` for the few decisions a person takes; `test/poc/custom-agent/` runs it in compressed time and for two hours, and `docs/OPERATIONS.md` ("Unattended runs") says what each limit does |

The three interactive contracts (`claude-code-interactive.yaml`, `codex.yaml`, `codex-chatgpt.yaml`) say CHANGE where a path is yours. With `claude` or `codex` on `PATH`, `tego run <contract> -- claude --version` (or `codex --version`) starts the agent under the contract with no login and no prompt, which is the quickest check that a copy works on your machine.

`retriever.yaml`, `anthropic-sdk-python.yaml` and `claude-agent-sdk.yaml` extend `base/python-dev`, which
resolves under the machine config's `profiles:` directory; point it at
`examples/profiles` or copy the profile into `~/.tego/profiles/base/`. Either way the directory follows the
machine config's trust rule: owned by root or you, and neither it nor a file in it group- or other-writable
(a checkout made under umask 002 is not: `chmod -R go-w examples/profiles`).

`gate`, `ask`, `fs.ask`, `net.ask` and declared-forwarder `net.http` rules are implemented;
their supported actions and tier requirements are described in `docs/p0/agent-contract.md`
and `docs/p0/network-controls.md`. Schema-only fields (`prompt`, `skills`, `visibility`,
`docker`, `exec.privileged`, `env.mask`) must still be empty, and `containers` must be empty
or `none`. See `spec/agent/v0/example.retriever.yaml` for their documented meaning.

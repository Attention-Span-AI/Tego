# Per-tool MCP rules

Tego can decide, tool by tool, which MCP tools an agent may call: allow it, hold it for a person, or deny it. The
decision is made by Tego's MCP relay, outside the agent's sandbox, on every `tools/call`, and every decision is a line
in the run's ledger. You can change a tool's rule while the run goes on, from the dashboard or the terminal, in either
direction. Design: [ADR 0126](../adr/0126-mcp-tool-rules.md) §4.

## In the contract

Add a `tools:` key to an `mcp:` entry:

```yaml
ask:
  timeout: 2m                         # needed only for an ask: list (a person answers held calls)
mcp:
  - name: files
    command: [python3, /opt/fake-mcp/server.py]
    tools:
      allow: [read_file, list_dir]    # present: every tool not listed is denied
      deny: [delete_file]
      ask: [write_file]               # held until a person allows or denies it
  - name: web
    url: https://mcp.example.com/mcp
    tools: {deny: [delete_file]}
```

- Names are exact (`^[A-Za-z0-9_.:/-]{1,128}$`); no globs, no patterns. A name may be in one list only.
- The order a call is decided in: a live switch (below), then `deny`, then `ask`, then an `allow` list that does not
  name the tool (denied), else allowed.
- `tools: {}` puts the server behind the relay with nothing restricted: you get the live switches without writing a
  rule.
- An entry without `tools:` runs exactly as before: no relay, nothing new in the run.
- `ask:` entries need the contract's `ask:` section; without it the run has no one to ask.
- Not at `tier: observe`: the relay needs an enforcing tier to keep the agent from going around it.
- With an `exec.allow` list, add the `tego` binary to it: the agent's MCP client starts the server as
  `tego mcp relay …`. `tego compile` warns when it is missing.
- For a `url` server, give the contract a `net:` section (`net: {allow: []}` is enough): the relay is then the
  agent's only route to the server, since its URL is no longer admitted to the run. `tego compile` warns otherwise.

## Pointing the agent's MCP client at the relay

Each run with a relayed server gets two variables:

- `TEGO_MCP_CONFIG`: a file in Claude Code's `mcpServers` shape naming, for each relayed server, either the stdio
  shim (`tego mcp relay --server <name> -- <the declared command>`) or the relay's local URL.
- `TEGO_MCP_RELAY`: the relay's control address, which the shim uses.

For Claude Code:

```sh
tego run agent.yaml -- claude
```

When the run's command is `claude` itself, Tego adds `--mcp-config=<that file>` to it (the Claude Code harness
provision). Any other MCP client reads the file the variable names, inside the run (for example
`sh -c 'my-agent --mcp "$TEGO_MCP_CONFIG"'`); any client that can start a stdio server or reach an HTTP one can use it.

Starting the declared server directly, around the shim, is refused (`exec` refused, rule `mcp[<name>].relay`) at every
tier. Under a `net:` section that does not admit its URL, a direct connection to a relayed `url` server is refused by
the run's network rules. To a `url` server the
relay passes a decided POST and a request with no body: any other request that carries a body is refused 405 under
that same rule.

## What the agent sees

- `tools/list`: denied tools are hidden; asked ones stay listed.
- A denied call is answered with a JSON-RPC error the model can read and go on from:
  `{"code": -32001, "message": "Tego refused the MCP tool delete_file on files: the run's rules deny this tool", "data": {"tego": {"rule": "mcp[files].tools.deny[delete_file]", "reason": "mcp-tool-denied"}}}`.
- An asked call waits until a person answers on the **Approvals** page or with `tego approve` / `tego deny`; only that
  call waits, every other message keeps flowing. Denied or timed out, it is answered with the same kind of error
  (`ask-denied`, `ask-timeout`, `ask-unavailable`).

## Changing a rule live

Dashboard (`tego serve --preview` lists the **MCP tools** page): open it, pick the run, and press Allow, Ask or Deny on a tool. The relay applies it to the next
call (within half a second). A change that tightens (to Deny, or Allow to Ask) applies at once, and a Deny also stops a call held for a person even if someone approves the card afterwards; one that loosens shows
what it changes and asks you to confirm. "Back to the contract" drops the switch.

Terminal:

```sh
tego mcp tools <run>                       # every tool, the decision now and why, calls / refused / asked
tego mcp deny  <run> files read_file       # tightens: applies at once
tego mcp allow <run> files delete_file     # loosens: asks y/N (or --yes)
tego mcp ask   <run> files write_file
tego mcp reset <run> files delete_file     # the contract decides again
```

A loosening is refused from inside any Tego run (an agent cannot widen its own rules); a tightening of the agent's
own run is allowed from inside it, as `tego block` is. Each change is a `gap` line in the run's ledger
(`why: mcp-tool-changed`, with the server, tool, decision, who and when).

Locked covers file, program and network rules. It does not yet cover these switches: `tego mcp allow` and the dashboard
can still loosen a tool on a Locked run, from outside every run and with confirmation, because the mode check is not
built (docs/GAPS.md C39).

A switch lasts for the run. To keep a rule for the next run, change the contract's `mcp[].tools`.

## In the ledger

- every `tools/call` decision: an `mcp` line, `source: proxy`, with `name`, `transport` (`stdio` or `http`) and
  `tool`; `verdict: allow` (authority `rule`, or `human` after an approved ask) or `refused` with reason
  `mcp-tool-denied`, `ask-denied`, `ask-timeout` or `ask-unavailable`; the rule says what decided it
  (`mcp[files].tools.deny[delete_file]`, `mcp[files].live[read_file]`, …);
- every held call: the broker's own `ask` and `answer` lines, op `mcp_tool`, target `<server> <tool>`;
- every live change: a `gap` line `what: enforce`, `why: mcp-tool-changed`.

## What it does not cover

- Names only: no per-argument rules ("read_file only under /src").
- The relay recognises the declared command line exactly; another spelling of the same server is not the server
  (deny it with `exec.deny`).
- Where a plane decides the run's execs (tier bpflsm, and tier cgroup in a plane mode, both of which need root), a
  running relay costs the run the supervisor's fast exec handover, as command rules do, so that the gate is consulted
  and a start around the shim is refused.
- The shim dials one TCP connection, so a shim holding another TCP socket is refused as it starts its server. An MCP
  client that leaks a TCP socket into the processes it starts has its server refused, rule `mcp[<name>].relay`.
- With Yama `ptrace_scope` 0 or 1 the agent could ptrace the shim it started and write to the server's socket.
- The gate checks that a server's start comes from a child of an admitted shim, not that it is the child the shim started. An agent that forks a
  child and then execs the shim in the parent can have that child start the declared server around the relay, with no `mcp` line and no ptrace.
  So a stdio server's `tools` rules are not a boundary against an agent that attacks the relay: a tool that must not run has to stay out of what
  the run can start.
- A stdio server's stdin and stdout are sockets, not pipes, so a run cannot reopen them through `/proc`. A server that opens `/dev/stdin` by name fails.
- `tools/list` filtering is a courtesy; what is enforced is `tools/call`. A server that offers the same capability
  under an allowed name is allowed. A `tools/list` answer the server sends inside a JSON-RPC batch array is passed
  unfiltered, and over HTTP an event-stream data line longer than 8 MiB is dropped, not filtered.
- The relay reads each message with Go's JSON decoder and the server reads it with its own. A client message that
  names a key twice (in the message or its `params`, compared case-insensitively as Go's decoder compares them) is
  refused as unreadable, so the two cannot read different tool names from one message. Keys deeper down
  (`params.arguments`) are passed as sent.
- A stdio server gets each client message as one line of compact JSON with the same content, not the agent's bytes, so
  a server whose reader ends lines at a lone CR reads the message that was decided. A client line that is not one JSON
  value in UTF-8 is answered with a parse error and not passed.
- A batch holding a denied or asked call is refused whole (a batch is never held).
- Over HTTP, a held call needs the relay to name the client process in the run; when it cannot, the call is refused
  `ask-unavailable`. Server-sent event streams opened with GET pass unfiltered (they carry no client call).
- Tego does not add credentials to MCP calls.

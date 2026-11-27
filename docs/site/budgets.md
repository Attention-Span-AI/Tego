---
title: Budgets
description: "Cap the model tokens and dollars a Tego session spends with limits.tokens and limits.cost_usd, declare the model under models:, and install a price table."
summary: "Cap the tokens and cost of a session."
section: Advanced usage
order: 6
---

Set `limits.tokens` or `limits.cost_usd` in the rules file, and Tego ends the session when the agent's model calls reach the limit. Tego counts the calls itself, so the rules file must give it a way to see them: at Basic, a `models:` entry for the model the agent calls. `cost_usd` also needs a price table on the machine.

```yaml
models:
  - {provider: anthropic, host: api.anthropic.com, port: 443}
limits:
  tokens: 2000000
  cost_usd: 20
```

A session that reaches a limit ends with exit code 124 ([Exit codes](/docs/exit-codes/)).

## Set a token or cost limit

| Field | Value | What it counts |
|---|---|---|
| `limits.tokens` | Whole number, 1 or more | Tokens of every model call in the session |
| `limits.cost_usd` | Number of US dollars, 0 or more | Estimated cost, from the price table |
| `limits.repeats` | Whole number, 1 or more | The same tool call made this many times in a row |

`limits.wall` and `limits.stall_after` end a session on time, and `memory`, `pids` and `cpu` cap resources. [Rules file fields](/docs/rules-reference/) lists them all.

## How Tego counts model calls

Tego counts model calls one of two ways:

| Level | How Tego sees model calls | Needs `models:`? |
|---|---|---|
| Basic | Through a local forwarder Tego starts for each `models:` entry. Tego points the agent at it and records every call that passes through. | Yes |
| Plus, Max | From the kernel, reading the agent's own model traffic | No, unless the rules file sets `record: off` or `capture: off` |

A rules file with a budget and no way to count it is refused: the session does not start (exit 125), and `tego rules check` warns `[budget-unmetered]` with the fix:

```
warning: no-models.yaml:6:11: limits.tokens budget never trips where the run lands at tier landlock: no models: endpoint is declared, and there capture is the forwarder alone, which does not run without one, so a run that lands there is refused [budget-unmetered]
  fix: declare the model endpoint under models: (provider, host, port), or remove the budget
```

A `models:` entry works at every level, so declare the model when the same rules file runs on several machines.

## Which model APIs Tego can count

A `models:` entry's `provider` says which API the endpoint speaks, and Tego reads the usage of these answers:

| `provider` | API |
|---|---|
| `anthropic` | Anthropic's Messages API |
| `openai` | OpenAI's Chat Completions (`POST /v1/chat/completions`) and Responses (`POST /v1/responses`) APIs, on the host the entry names: OpenAI's, a gateway's or a local server's |

With `tokens` or `cost_usd` set, an answer Tego cannot read the usage of ends the session at that answer, exit 125, and the closing lines of `tego run` name the request and the fix. That happens for:

- a streamed chat completion whose client did not ask for usage in the stream. Tego never changes a request, so set `stream_options: {"include_usage": true}` in the client.
- an answer cut short (a cancelled or interrupted stream), or a Responses answer stopped by `max_output_tokens`.
- an answer larger than 8 MiB.
- another path of the API, such as embeddings, and the API of any other provider (Gemini, Mistral, Bedrock, Azure OpenAI).

`tego rules check` warns `[budget-uncounted]` for a rules file that sets `tokens` or `cost_usd` beside a `models:` entry of another provider. For such an agent, leave `tokens` and `cost_usd` out. `limits.repeats` does not count the tool calls of an OpenAI answer. At Plus and Max with no `models:` entry, only Anthropic calls are counted.

## What a session does at its limit

From the moment the limit is recorded, Tego's forwarder sends no new model request: it answers the agent `403` itself and records the request as refused. Then the session ends. Requests already in flight finish and are recorded, so a session can end a few answers past its limit. A model the agent reaches directly, not through the forwarder, is not refused; its budget still ends the session.

## Set a budget over a window

`limits.window` makes `tokens` and `cost_usd` totals across every session of the same agent in that window, restarts included:

```yaml
limits:
  cost_usd: 5
  window: 24h
```

A service that restarts the agent twelve times in a day then spends $5 in that day, not $60. The window is 1 minute to 30 days.

- **The agent is the name you run.** `tego run --agent NAME` counts under that name; `tego run path/agent.yaml` counts under the file's path. The two forms are two budgets, so start the agent the same way every time.
- **Before each start, Tego counts the agent's earlier sessions** in the window from their records. A record it cannot trust or read, a session of the agent still running, a [`retention`](/docs/machine-settings/) shorter than the window, or more than 512 MiB of the agent's records refuse the start, exit 125, `[budget-window]`, naming the session. To clear a damaged session, move its folder out of the records folder.
- **Some starts are refused.** A rules file with no name to count under, and a record-only session (`--observe`).
- **A restart into a full window ends at its first model answer.** A unit with `Restart=on-failure` then stops at its start limit; run `systemctl --user reset-failed` once the window has room.
- **Counting reads the records**, about 1 second per 10,000 answers. Use `record: summary` for an agent with a window.

## Install a price table

`cost_usd` is estimated from the price table at `~/.tego/prices.yaml` (the machine settings' `prices:` key names another path). Tego installs no table. Start from the example in the repository, [examples/prices.example.yaml](https://github.com/Attention-Span-AI/Tego/blob/main/examples/prices.example.yaml), check its prices against the provider's pricing page, and install it readable and writable by you alone:

```
mkdir -p -m 700 ~/.tego
install -m 600 prices.example.yaml ~/.tego/prices.yaml
```

The format:

```yaml
version: 1
updated: 2026-11-02             # when you last checked the prices
models:
  claude-opus-5-5:              # the model name exactly as the response reports it
    input_per_mtok: 4           # US dollars per million tokens
    output_per_mtok: 20
    cache_read_per_mtok: 0.20
    cache_write_per_mtok: 5     # 5-minute cache writes
    cache_write_1h_per_mtok: 8  # 1-hour cache writes
server_tool_per_request:
  web_search_requests: 0.01     # US dollars per request
```

- **A call the table cannot price is charged high, never at $0.** A model the table does not name, or a missing cache price, is charged at the table's highest rate for that counter, and twice that for a premium such as fast mode. The record notes `unpriced-model` once per model.
- **A mistake makes the whole table unreadable.** An unknown key, or a `version` other than 1, reads as no table at all, so a typo cannot price anything at $0.
- **The file must be yours alone.** A table that others can write, or that has a second name (a hard link), is not read.
- **The example table prices only Claude models.** Add any other model you use, named exactly as the answer's `model` field reports it.

With no table, or a table that prices no model, every session of a rules file that sets `cost_usd` is refused, and `tego rules check` warns `[budget-unmetered]`.

Prices below the provider's let a session spend past its budget; prices above end it early.

## See what a session spent

```
tego measure claude-code-a1b2
```

It prints the session's steps, tokens, cost and time.

## Next steps

- [Exit codes](/docs/exit-codes/): 124 and the other ways a session ends
- [Rules file fields](/docs/rules-reference/): every limit
- [Model routes](/docs/model-routes/): send a running agent's model calls to another backend
- [Machine settings](/docs/machine-settings/): the `prices:` path and machine-wide limits

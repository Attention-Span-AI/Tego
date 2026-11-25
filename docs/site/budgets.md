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

Only Anthropic model responses are counted and priced. With `tokens` or `cost_usd` set, a session whose `models:` entry names another provider, such as OpenAI for Codex, ends with exit 125 at its first model call, because Tego cannot count it. At Plus and Max with no `models:` entry, another provider's calls are not counted, so the limit never trips. For such an agent, leave `tokens` and `cost_usd` out of the rules file.

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

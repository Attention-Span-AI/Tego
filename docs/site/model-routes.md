---
title: Model routes
description: "Move a running agent's model calls to another backend you listed in its rules file, such as a company gateway or a local model server, and back."
summary: "Send a running agent's model calls to another approved backend."
section: Advanced usage
order: 7
---

A model route lets you send a running agent's model calls to another backend, such as your company's model gateway or a model server on this machine, and back, without stopping the agent. You list the backends in the rules file, then switch with `tego route set`. The agent keeps calling the same address; Tego's forwarder, the listener that carries its model calls, decides where each one goes.

## List the backends in the rules file

Add `routes` to a `models:` entry. Routes need `capture: forwarder`:

```yaml
capture: forwarder
models:
  - provider: anthropic
    host: api.anthropic.com
    port: 443
    routes:
      - {name: corp, host: llm-proxy.corp.example, port: 8443}
      - {name: local, host: 127.0.0.1, port: 11434, tls: false}
```

- Every session starts on the endpoint itself, the route named `direct`.
- Only the routes listed here can be chosen, from the command line or the dashboard.
- A route uses TLS and checks the backend's certificate. `tls: false` is allowed only for a server on this machine (`127.0.0.1`, `localhost`).
- A route name is lower-case letters, digits and `-`, up to 40 characters, and cannot be `direct`.

`tego rules check` refuses a route without `capture: forwarder`, a route to the endpoint itself, two routes to the same backend, and `tls: false` to another machine. A rules file with routes is also refused under `tego watch`, since nothing would keep the agent from choosing its own route.

The agent cannot reach a route's backend directly: Tego refuses those connections as it refuses direct connections to the endpoint, so every model call goes through the forwarder and lands in the [record](/docs/sessions-and-records/).

## Switch while the agent runs

```sh
tego route list <session>                          # each endpoint, where it sends now, and its routes
tego route set <session> api.anthropic.com corp    # asks y/N first; --yes skips it
tego route clear <session> api.anthropic.com       # back to the endpoint itself
```

Name the endpoint by its `host:port`, or the host alone for port 443, or by its provider when the rules file has one entry for it. `tego route list --json` prints the same as JSON.

- The change applies from the next request. A request already under way finishes where it started.
- A request waiting for a person's approval when the route changes is refused with "this model endpoint's route changed while the request waited for approval; send it again". If the agent sends it again, a person is asked again.
- A route lasts until the session ends. To keep it, change the rules file.
- A command run from inside any Tego session cannot change a route.

On a Locked session, the default, `tego route set` to any route but `direct` is refused with `[locked]`; `tego route clear` still works. Routes move during the session on an Adjustable session, at Plus or Max. [Live changes](/docs/live-changes/) explains the two modes.

## Switch on the dashboard

Start the dashboard with `tego serve --preview` to see **Model routes** in the menu. It shows, for each session, where each endpoint sends now, who changed it and when, and the requests sent by each route. **Send here** opens a page that says where the prompts will go; nothing changes until you confirm. **Back to direct** applies at once.

## What a route does not do

- **It does not hold a key back.** The request's headers go to the backend with the prompts, so a key the agent holds goes there too. Give the agent only a key you would hand to every backend in its rules file.
- **It does not translate between APIs.** Route an Anthropic endpoint only to an Anthropic-compatible backend.
- **It is a host and a port.** A gateway that needs a path prefix cannot be a route.
- **A person chooses it.** There is no automatic fallback or load balancing.

## Next steps

- [Budgets](/docs/budgets/): cap the tokens and cost of model calls.
- [Live changes](/docs/live-changes/): what a person can change while a session runs.
- [Commands](/docs/commands/): every `tego route` flag.

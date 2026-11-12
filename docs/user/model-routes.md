# Send an agent's model calls somewhere else while it runs: model routes

A model route lets you move a running agent's model API calls to
another backend you approved in its contract (your company's LLM gateway, a model server on this machine, another
provider's compatible endpoint) and back, without stopping the agent. The agent keeps calling the same address; Tego's
forwarder decides where each request goes. The design is [ADR 0127](../adr/0127-model-routes.md).

## Declare the backends in the contract

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

Every run starts on the endpoint itself, the route named `direct`. Only the routes you list here can ever be chosen:
neither the dashboard nor the command line can send a request anywhere else. A route speaks TLS and checks the
backend's certificate for its host; `tls: false` is allowed only for a server on this machine (`127.0.0.1`,
`localhost`), and Tego checks the address it actually connects to is this machine's. `tego compile` refuses routes without `capture: forwarder`, a route that is the endpoint itself, one
backend listed twice, or `tls: false` to another machine. The agent cannot call a route's backend directly either: Tego
refuses its connections there as it refuses them to the endpoint, so every model call goes through the forwarder and
is recorded. Under a `net:` section that guard covers the whole port: a route to `llm-proxy.corp.example:8443` or
`localhost:11434` also refuses the agent any other destination on that port that `net.allow` does not list.

## Switch while the agent runs

```sh
tego route list <run>                          # each endpoint, where it sends now, the routes and requests by each
tego route set <run> api.anthropic.com corp    # asks y/N first; --yes skips the question
tego route clear <run> api.anthropic.com       # back to the endpoint itself
```

On a Locked run (the default, and the only mode at tier landlock; docs/user/live-modes.md) an endpoint stays where its
contract sends it: `tego route set` to any route but `direct` is refused with `[locked]` and exit 1, and the Model
routes page says "Not done: this run is Locked: loosening applies from its next run." `tego route clear` (back to
`direct`) is still taken. Routes move live on an Adjustable run. Tego's own writers make this check; the forwarder
does not, so a route written into the run's `model-routes.json` some other way still applies (docs/GAPS.md C39).

`<run>` is the run id; the endpoint is its `host:port` (the host alone for port 443) or its provider
when the contract has one entry of it. The change applies to the next request; a request that arrived before it (one
still sending its body, or a response already streaming) goes where it began. A request waiting for your approval
when you change the route is answered "this model endpoint's route changed while the request waited for approval;
send it again", is sent nowhere, and is recorded as refused (`model-route-changed`). The approval card names the route
and backend a request will go to when the endpoint is not on `direct`; a retry of the same request that arrives after
the change asks again, with a card naming the new route. With `net.proxy`, a tunnel (CONNECT or WebSocket) to an
endpoint that is not on `direct` is refused and recorded, since a tunnel would go to the endpoint and around the route.

`set` checks again under the file's lock whether the change sends requests somewhere new: if someone moved the
endpoint after you ran the command and before it wrote, so that it now widens without your y/N, it changes nothing
and asks you to run it again.

On the dashboard, **Model routes** (in the menu beside MCP tools, which `tego serve --preview` lists) shows the same for a run: where each endpoint sends
now, who changed it and when, each declared route with its TLS and the requests that went by it. **Send here** opens a
check page that says where the prompts will go and that the request's headers go with them; nothing changes until you
tick it and confirm. **Back to direct** applies at once.

Nobody inside a run can change a route, in either direction: `tego route` and the dashboard refuse it from inside any
run, and the file that holds the choice is in the run's folder, which the agent cannot write.

## What the record says

Every request of an endpoint with routes names the route it took in its line (`route: {name, authority}`), and each
change is one line, *a model endpoint's requests were sent to another approved backend*, with who made it and when
(record minor 27). If the route file is removed or replaced by hand, the forwarder still writes a line for each
endpoint whose route moved (a removal reverts to `direct`, by `forwarder: ...`). A route set as the run started, before
the forwarder first read the file, gets its line too. `tego events <run>` and the run's timeline show both.

## What it does not do

- A route is a host and a port; a gateway that needs a path prefix (`https://gateway/anthropic/v1`) cannot be a route
  yet.
- It does not translate between API shapes: route an Anthropic-shaped endpoint only to an Anthropic-compatible backend.
- One route per endpoint at a time, chosen by a person; there is no automatic fallback or load balancing.
- A route lasts for the run. To keep it, change the contract.
- A backend you route to sees the prompts; that is the point of routing, so list only backends you trust with them.
- A route does not hold a key back. The request's headers go with it, so a key the agent holds itself goes to that
  backend too, on a plaintext loopback route as well, and no list of Tego's says which backends it may reach. Give an
  agent only a key you would hand to every route in its contract.

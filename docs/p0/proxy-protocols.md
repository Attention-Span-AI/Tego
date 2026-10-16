# Declared model proxy protocols

`net.proxy` enables extra protocols only on authenticated listeners for declared
`models`. It requires explicit `capture: forwarder` and an enforcing tier.
An ordinary model HTTP request still receives its `net.http` method/path check
before its body is read or an upstream is contacted.

```yaml
capture: forwarder
models:
  - host: api.example.com
    port: 443
    provider: anthropic
net:
  proxy:
    http2: true
    max_streams: 32
    connect: [api.example.com:443]
    websocket:
      - host: api.example.com
        allow: [/socket]
        methods: [GET]
    max_tunnel_bytes: 16MiB
    max_frame_bytes: 1MiB
    tunnel_idle: 30s
    tunnel_wall: 5m
```

HTTP/2 uses prior knowledge on the local listener and applies policy to each
stream. `max_streams` requires HTTP/2 and ranges from 1 to 128, default 32.
The same bound limits concurrent tunnels across the manager's listeners.
CONNECT must name that listener's declared model authority, including its port;
it cannot select an arbitrary host. WebSocket routes use the HTTP path matcher
and GET, a validated HTTP/1.1 upgrade, and a TLS-verified fixed upstream.
Extensions are refused. Client masking, control-frame limits, fragmentation and
close framing are checked before forwarding; these checks do not validate an
application's message contents.

Both tunnel directions share a byte budget. WebSocket frames also have a frame
ceiling. Defaults are 16MiB per tunnel, 1MiB per frame, 30s idle and 5m wall time.
Positive byte ceilings may be at most 16GiB/16MiB. The idle duration must be at
most 1h, the wall duration at most 24h, and idle cannot exceed wall time.
Tunnel bounds require an explicit CONNECT or WebSocket grant; frame bounds
require WebSocket routes. Capacity, framing and budget refusals remain recorded
with `record: off`. Stopping a manager cancels and joins its owned tunnel pumps.

The upstream dial resolves a bounded address set once, rejects machine-local
and private rebinding destinations unless the policy explicitly names a literal
address, and dials the validated numeric address with the original TLS server
name. Redirects cannot select a new destination. Authentication and policy
admission happen before the upstream dial.

CONNECT and WebSocket payloads are opaque to model accounting. A policy enabling
either refuses token, cost or repeat limits, including explicitly bounded zero
and inherited machine ceilings, before agent release. The compiler, runtime
constructor, listener readiness, manager start and direct listener admission
all retain this check. Ordinary HTTP/2 model requests retain capture accounting.
Opaque protocols cannot satisfy an approval configured to hold a model request
for inspection.

## 5. Algorithms / rules

**R1 — Declared authority.** Authenticate the local peer and apply the enabled protocol,
model authority and route checks before connecting upstream. CONNECT cannot select a new destination.

**R2 — Bounded opaque delivery.** Charge both tunnel directions against the shared byte
budget and enforce frame, concurrency, idle and wall limits. Opaque CONNECT/WebSocket grants
refuse token, cost and repeat ceilings before release; ordinary HTTP/2 requests retain accounting.

**R3 — Owned shutdown.** Register admitted tunnels with their listener, cancel them on stop
and join both owned pumps before releasing the tunnel. Refusals remain recorded with `record: off`.

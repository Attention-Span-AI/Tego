#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The "network" scene, sourced by demo.sh (uses its say/show/plant/sink_up/last_run helpers).
# One agent run under a contract that allows exactly one host:port (the loopback sink) and tries:
#   the allowed sink, a port the contract does not name, and opening a listening port.
cmd_network() {
  need_tego
  plant; sink_up; : >"$STAGE/sink.log"
  other=$((PORT + 1))
  cat >"$PROJECT/net-agent.sh" <<AGENT
#!/bin/sh
set -u
try() { if "\$@" >/dev/null 2>&1; then echo "[agent] ALLOWED \$what"; else echo "[agent] REFUSED \$what"; fi; }
what="connect 127.0.0.1:$PORT (the sink the contract names)"; try curl -q -s --max-time 3 -H 'X-Demo-Agent: net' "$SINK/ok"
what="connect 127.0.0.1:$other (a port the contract does not name)"; try curl -q -s --max-time 3 "http://127.0.0.1:$other/x"
what="listen on 127.0.0.1:4444 (a backdoor)"; try python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",4444));s.listen(1)'
AGENT
  cat >"$PROJECT/network.yaml" <<YAML
version: 0
name: demo-network
command: ["sh", "net-agent.sh"]
fs:
  write: ["/dev/null"]
exec:
  allow: ["sh", "curl", "python3"]
net:
  allow: ["127.0.0.1:$PORT", "unix:/var/run/nscd/socket"]   # the sink only
  listen: []                                                  # no listening port: a bind is refused and recorded
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
  wall: 1m
record: summary
tier: landlock
capture: off
YAML
  say "Network: the contract names one destination, the sink on 127.0.0.1:$PORT"
  show "grep -A1 '^net:' '$PROJECT/network.yaml'"
  say "Run it"
  show "cd '$PROJECT' && '$TEGO' run network.yaml </dev/null 2>&1 | grep -v -E '^(warning|note|  fix:)|no price table'"
  run=$(last_run demo-network)
  [ -n "$run" ] && echo "$run" >"$STAGE/last-run"
  # --kind and --verdict, not a grep for "net": that also matched exec lines of net-agent.sh. A refusal is
  # one "refused" row (the "net" row of the same connection says refused too, so it is left out here).
  say "The connection the contract allows"
  show "'$TEGO' events '$run' --kind net --verdict allow 2>&1 | cut -c1-200"
  say "The refusals (each carries its rule)"
  show "'$TEGO' events '$run' --kind refused 2>&1 | cut -c1-200"
}

# Real agents under tego watch

`observe_agent.py` starts a real interactive agent (anything with a full-screen terminal interface) under `tego watch`
on a pseudo-terminal, in an isolated home directory with no credentials, lets it sit at its first screen, and prints what
the run recorded. Nothing is typed into the agent and no model is called.

```
# after test/poc/watch-demo/run.sh has made the isolated environment (it prints the demo directory):
D=<demo directory>; . $D/tego/env.sh; export TEGO_BIN=$D/bin/tego DEMO_ROOT=$D
python3 observe_agent.py claude 14 -- claude                                  # record only: NOT confined
WATCH_ARGS="--boundary /path/claude-interactive.yaml" WATCH_CWD=<project> \
    python3 observe_agent.py claude 14 -- claude                              # under a boundary
```

**A record-only run is not a sandbox.** The isolated `HOME` and the scrubbed environment keep the caller's credentials
out of the agent's environment, nothing more: the agent still runs as you, and can read and write anything you can,
whatever `$HOME` says. Claude Code, for one, reads the real `~/.claude/skills` through the passwd database (seen below).
Run these only with the agent idle at its first screen, as `observe_agent.py` does (nothing is typed into it), or under
a boundary you have read.

The boundary file must not be inside the project directory, and the project must not be tego's own directory: tego
refuses a boundary that lets the agent write the file that defines it or its own ledger.

## What was seen (2026-10-06, Linux 6.17, Landlock ABI 7, an ordinary user, tier landlock, no credentials)

| | Claude Code 2.1.290 | Codex 0.159.2 |
|---|---|---|
| Full-screen interface under `tego watch` | runs: welcome screen, theme picker, diff preview; window size, Ctrl-C and exit status work | runs: welcome screen and sign-in menu |
| Programs started in about 12 s at its first screen | 1 (itself) | 180: `git ls-remote` and a clone of `https://github.com/openai/plugins.git` into `~/.codex/.tmp`, `lsb_release`, `ps`, `getconf`, and `bwrap --unshare-user --unshare-net --ro-bind / / /bin/true`, a probe of its own sandbox |
| Connections | DNS, the name-service cache socket, TCP and UDP port 443 to Anthropic's addresses, a netlink socket | DNS, TCP 443 to a Cloudflare address, UDP port 65535, **the D-Bus session bus**, its own control socket under `~/.codex/app-server-control/`, a netlink socket |
| Files | its config directory (`.claude.json` with a lock and a temporary file beside it, `.credentials.json`, settings, cache), `/dev/tty`, a socket it creates under `$XDG_RUNTIME_DIR/cc-socks/`, `/sys/fs/cgroup/**/cpu.max`, probes of `/home/claude/.claude/remote/.api_key` and `.oauth_token`, and, through the passwd database and not `$HOME`, the real `~/.claude/skills` | about 5000 opens, mostly the plugin clone |

Under a boundary (Claude Code, tier landlock, `claude-interactive-forwarder.yaml` and `claude-interactive.yaml`):

- With the model reached through the forwarder (`capture: forwarder`, nothing else allowed), the interface starts and
  then Claude Code **exits 1** ("Unable to connect to Anthropic services"): its startup connectivity check connects
  straight to `api.anthropic.com:443` whatever `ANTHROPIC_BASE_URL` says, and a declared model endpoint is refused except
  through the forwarder. This is the "residual direct connects" gap of FEATURES I2.
- With `capture: off` and `tcp://api.anthropic.com:443` allowed, the interface stays up. Its remaining refusals are a
  UDP/443 attempt (it falls back to TCP) and the netlink socket (tolerated).
- `/dev/tty` must be writable, or a shell on the terminal is refused `open /dev/tty`.

## What this does not show

A logged-in or API-key session, a model call, tool use, MCP servers, the IDE link, an approval inside a live session,
and Codex under a boundary have not been run. Whether `bwrap` fails under Landlock for Codex is expected from
docs/ARCHITECTURE.md section 4.6 (mount is refused), not observed here. Running a real model call needs your key and
your go-ahead.

# ADR 0122: Telling the person at the terminal that an ask waits

Status: **accepted 2026-10-26**; built. Amends
spec/config/v0's `ask.notify` (`cli` and `desktop` now do something; `webhook:` is still not built).

## Context

A person runs an interactive agent (Claude Code, Codex) under `tego run` in a terminal. When the agent reaches an
`fs.ask`, `fs.ask_read` or `net.ask` scope, its operation is held until someone runs `tego approve <run> <ask_id>`
from another terminal, or `ask.timeout` (5 minutes by default) refuses it. Before this record tego said nothing:
the agent's screen just showed "Running", and answering needed a run id that tego never printed. The person
did not learn that anything waited.

tego shares the terminal with the agent, and the agent is usually a full-screen TUI that owns every byte of the
terminal: it writes escape sequences in pieces, keeps its own model of the screen, and redraws only what it thinks
changed. Four ways to tell the person were weighed:

- **(a) A desktop notification from tego's own process.** The launcher runs outside the run. ADR 0113, not built, would refuse the
  agent the session bus, but not tego, so tego can reach the desktop's notification server. The repo does not speak
  D-Bus, and a D-Bus client is too large a dependency for one call (rejected). `notify-send` (libnotify) does the
  call and exists on most desktops. It is a program tego starts while the agent runs, and three rules come with
  that: the start must not meet a fanotify mark (ADR 0021 (3)); the file must be one the agent cannot have
  replaced; and no text the agent wrote may reach it.
- **(b) A terminal title (OSC 0/2) or a terminal notification (OSC 9, OSC 777), written in one `write()`.** These
  draw nothing in the grid, but tego cannot know when a write is safe. The agent's output goes straight to the
  terminal, not through tego, so a write by tego can land between two `write()`s that make up one of the agent's
  escape sequences. An ESC inside an unfinished CSI or OSC ends it early or corrupts it, and the TUI's model of the
  screen is then wrong until it redraws everything. BEL is safe inside a sequence; OSC is not. Rejected for now:
  "between the agent's writes" cannot be known in general. It could come back if tego relayed the agent's output
  through a pty of its own, where it could parse the stream (not built; it would cost a copy of every byte).
- **(c) A line printed to the terminal when the agent is not in the alternate screen.** The same problem as (b):
  tego cannot see the agent's mode changes without parsing its output, and a line-mode program can still be
  halfway through a line of its own. Rejected.
- **(d) One line at run start.** Before the agent's first screen, the terminal belongs to tego. The line gives the
  run id and the exact commands that answer. This half needs nothing else.

## Decision

1. **The answer line (d).** When the contract can ask (the compiled table has an ask configuration) and the machine
   config's `ask.notify` holds `cli`, `tego run` prints one line on stderr once the run exists and before its agent
   starts (runtime `Deps.Started`, §4.1 step 9a):

   `tego run: <run> can hold an operation for your approval; answer from another terminal: tego ask <run>, then
   tego approve <run> <ask_id> (or deny), or on the dashboard's Approvals page[; a desktop notice says when one waits]`

   A run whose contract cannot ask prints nothing new, which keeps the quiet start. The line does not give a
   dashboard URL: the engine cannot know whether `tego-control serve` is running, or on which port and token.
2. **The desktop notice (a).** When `ask.notify` holds `desktop`, the run is at tier `landlock`, its launcher is not
   root, and a trusted `notify-send` is on tego's PATH, the launcher runs it once for each held request, after the
   broker lists the request (so `tego ask` already shows it), never for one that a standing answer decides
   (`ask.Options.Pending`, `runtime.Deps.AskPending`).
   - *Arming:* only enforce/cgroup's listener arms (tiers `cgroup` and `bpflsm`), so a tier-landlock launcher
     holds no fanotify group. The start is a reviewed site (`internal/cli/asknotice.go`,
     internal/platform/proc/sites_test.go), and proc.Start refuses it with ErrArmed regardless. A root launcher
     does not start a program in the person's desktop session.
   - *Trust:* the notifier is found before the agent starts, by its real path. That file and every directory above
     it must be owned by root and writable by no group or other, so a `notify-send` in `~/.local/bin` (which a
     contract may let the agent write) is never run.
   - *Text:* the agent's name (from the person's contract), the operation tego named and the run id. Control
     bytes are made visible and `& < >` escaped for the notification markup. Never the target or the rule, which
     the agent chooses. The argv has no shell, and a `--` before the text.
   - *Process:* only the session-bus and display variables of tego's environment are passed. No standard stream of
     tego's is passed, so it cannot write into the agent's terminal. It runs in its own session, outside the
     terminal's foreground group. It is killed after 5 s.
   - *Never holds the agent:* the broker's goroutine only queues the request. At most one notifier runs, with one
     request waiting behind it, and a burst of asks gives two notices (`tego ask` lists them all).
   - A machine with no trusted notifier says why in tego's own log, not on the terminal.
3. **`ask.notify`** defaults to `[cli, desktop]`. `[cli]` turns the desktop notice off, and `[]` turns both off. A
   `webhook:<url>` entry is still accepted with a `config-ignored` warning, because it is not built.
4. **Nothing is written into the terminal after the agent starts.** tego still writes into the terminal at the
   end of the run, after the agent's processes are gone (the terminal's reset).
5. **A long rule:** a listed request whose rule is longer than 64 bytes (askproto.MaxSummaryRule) carries
   `rule_truncated: true`, just as a cut target carries `target_truncated`. `tego ask <run> <ask_id> --json` returns
   it whole. The rule is still cut in the list, because 64 listed requests with 1 KiB rules and 4 KiB targets
   would not fit in one 128 KiB reply.

## Consequences

- A person at the terminal learns the run id and the answer commands before the agent draws its screen. On a
  desktop at tier landlock, they also get a notice each time an operation waits.
- No notice at tier `cgroup` or `bpflsm`, in a root run, over SSH without a session bus, or on a machine without a
  root-owned `notify-send`. There the answer line, the dashboard's Approvals page and `tego ask`
  remain. Later: a client of the run's ask socket outside the launcher (`tego ask --watch --notify`) could notify at every tier.
- Nothing in the agent's terminal says, while the agent runs, that an ask waits. (b) would, at the risk above.
- A test build (`-tags tegotesthooks`) never runs the desktop's own notifier: it runs only the stand-in named by
  `TEGO_TEST_NOTIFY_SEND`, and runs none when that variable is unset.
- `ask.Summary` gains `rule_truncated` on the wire (omitted when false). The ask wire golden's list-truncated frame
  is amended for it.

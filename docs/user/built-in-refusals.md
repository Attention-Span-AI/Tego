# Built-in refusals

Every enforcing run carries three fixed rules. A contract's `host_sockets: true`, explicit `net.allow`,
filesystem write grant, or empty deny list cannot override them. `tego events` and
the record name the responsible rule in `rule`.

| Rule | What it refuses |
| --- | --- |
| `builtin.host_ipc` | The session bus, systemd user manager, non-SSH GnuPG agents and other sockets under the invoking user's runtime directory; system D-Bus, X11, and the listed tmux, screen and editor server directories. It also protects those directories from writes and refuses existing FIFOs there. |
| `builtin.tego_surface` | Tego's control sockets, other runs' runtime sockets, ledger ask/operator sockets, and local TCP connects/binds on configured `serve.port` (default 7433) and legacy dashboard port 8484. |
| `builtin.other_tty` | Opening another numeric pty slave or virtual console for reading or writing, and importing descriptors with `pidfd_getfd`. The run can reopen its inherited controlling terminal and use ptys it creates through the supervisor's master-based relay. |

The fixed SSH-agent sockets remain available to the ordinary contract: `gnupg/S.gpg-agent.ssh`
(including `gnupg/d.<hash>/S.gpg-agent.ssh`), `openssh_agent`, `ssh-agent.socket`, `keyring/ssh` and
`gcr/ssh` under the runtime directory, and agents outside that directory. An SSH agent can sign with
unlocked keys. This exception does not allow gpg-agent's main, extra or browser socket. Container
daemons are refused by default; an exact `unix:` allow is their explicit exception and produces
`container-socket-escape`, since a daemon can start containers outside the run. The run's own validated
runtime directory remains available. The interactive Claude contracts set `env.set.XDG_RUNTIME_DIR: "%R"`: Tego resolves it at launch to the run's private writable `hook-state` directory using the existing `fs.harness-state` grant. This requires an unprivileged run with a provisioned Claude harness. The invoking shell keeps its host runtime unchanged and should use a short base, normally `/run/user/<uid>`. Launch checks the complete `cc-socks/9999999.sock` path is at most 103 bytes. An overlong path refuses launch with a fix; Claude's shared `/tmp/cc-socks-<uid>` fallback receives no grant. Long project paths do not affect this socket path.

A socket symlink, a socket with multiple hard links, a protected directory moved after preparation,
a relative path or a `/proc/<pid>/root` spelling does not create a socket exception. At Landlock ABI 6
and later, abstract sockets bound outside the run are refused too. Below ABI 6 that abstract scope is
unavailable; `tego doctor` reports the capability. `/dev/tty`, the pty multiplexors and serial devices
are not in the terminal refusal. A verified own-PTY slave still needs the contract's filesystem
permission (including a write grant for writable delivery). Both relay APIs check explicit denies,
live blocks and gates before delivery. Approval completion of character devices is unsupported:
`fs.ask_read`, an otherwise refused `fs.ask` write, and gate ask ranges fail closed.

At the root tiers cgroup and bpflsm, which need root, the kernel adds Unix checks. An LSM/fmod_ret
decision plane also checks protected directory names and the actual bound datagram peer behind an
alias. `io_uring: true` is refused when a contract can select these tiers: rings bypass the socket
identity relay. Tier landlock keeps rings unavailable. An explicit custom `tego serve --addr` needs a
matching machine `serve.port` to reserve that custom port. Unreadable bind arguments fail closed too;
at unprivileged landlock, a process that disables ptrace may therefore be unable to bind its own socket.

Limits remain: a server at an unlisted custom path, inherited descriptors, an outside server's FIFO
created after a successful directory inventory (metadata permission failures instead deny the
whole subtree), copied-path filesystem mutations without a kernel plane, and an admitted
or unsupported datagram's mutable address where no kernel decision plane runs. The record discloses
that socket residual as
`builtin.host_ipc/datagram` in `best_effort`. Full recording supplies attribution for notified terminal
opens; at tier landlock a read refusal under summary recording may have no event. The root tiers, which need
root, attribute recorded kernel terminal refusals as well. `--observe` enforces
nothing. See [ADR 0113](../adr/0113-built-in-refusals-for-tego-surfaces.md) for the exact list and limits.

A fixed host-server path that cannot be traversed by the invoking user (permission
denied or not found) does not prevent startup. Prepare records no present identity
for that unreachable path and keeps its name refusal; reachable objects are pinned
as before. Other identity errors fail startup. Compiled entry names come from the
configured table and do not change when a server is installed or removed.

## A contract entry that a built-in overrides

`tego compile` and `tego run` refuse a `net.allow` `unix:` entry that a built-in refuses, whether by its path or
by the place it resolves to, with a `contradiction` error. The error names the entry, the built-in rule and ADR 0113.
Such an entry never admitted anything: every layer decides the built-ins before it reads `net.allow`. Before this
check, the run refused the connect with no word at launch. The SSH-agent sockets and an exact container-daemon socket
are not refused, as above. `host_sockets: true` beside a `net:` section has no effect, since the section decides every
unix destination by its own entries. `tego compile` prints an informational note about it (`redundant-rule`). A
record-only run (`--observe`, or `tego watch` without `--boundary`) has no built-ins, so it reports neither. A link
made after compile, or a hard link, is not seen at compile; the run still refuses it by identity.

## An agent that must restart a service

The session bus and the systemd user manager (`/run/user/<uid>/bus`, `/run/user/<uid>/systemd/private`) cannot be
granted, by an entry or by any key. Through either one a process can ask the manager to start any command as a
transient unit, as `systemd-run --user` does. That command runs outside the run's cgroup, where neither the contract
nor Tego's run-member checks reach it. An exec rule cannot narrow this either. Once the socket is open, an allowed
interpreter can call the manager's `StopUnit`, `DisableUnitFiles` or `StartTransientUnit` methods directly, and
`systemctl` never runs. A system unit is no different: `systemctl restart` as a non-root user asks polkit over the
system bus, which is refused too.

To let an ops agent restart one service, grant a verb, not the bus. Run a small helper outside Tego that performs
that one operation and nothing else, and have it listen on a socket at a path no built-in refuses. The contract then
allows that one socket. `examples/systemd/example-restart-myapp.socket` and `example-restart-myapp@.service` are an
example to adapt. They define a socket-activated user unit at `~/.local/state/tego-helpers/restart-myapp.sock`. Each
connection runs `systemctl --user restart myapp.service` once, reads nothing from the client and closes when the
restart has finished, so the agent chooses neither the verb nor the unit:

```yaml
net:
  allow: ["unix:~/.local/state/tego-helpers/restart-myapp.sock"]   # add to your contract's existing net.allow
```

Add the entry to the contract's `net.allow` list; a `net:` section on its own refuses every other connection, so do not
paste it into a contract that has none. The agent connects, sends nothing, and reads to end of file; Tego would record
that connect as allowed by the entry (not yet run under Tego, see below). What the helper does runs outside the run, with
your account's full authority, so keep it to one verb on one unit, and keep everything that restart runs out of the
agent's reach: the socket's directory, and the service's program, scripts, configuration, `EnvironmentFile` and unit
drop-ins must not be in the contract's `fs.write`, or a restart runs what the agent wrote, outside the run. The
socket's trigger limit stops it after five restarts in a
minute. On systemd 257 we checked the pair by hand on a user manager, renamed and pointed at a stand-in service, with
no Tego run involved: a connection restarted the service (its `InvocationID` changed) and reached end of file when the
restart finished, and the sixth connection in a minute was closed with no restart and stopped the socket. The pair has
not been run under Tego or in a VM.

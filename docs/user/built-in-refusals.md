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

## Why compile now refuses my grant

From this release, `tego compile` and `tego run` look at the machine's mount table (`/proc/self/mountinfo`) as well
as at paths. The [compile-time mount boundary](../adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary)
defines what that analysis can establish and when uncertainty refuses a grant. A write entry or ask scope is refused
(`[contradiction]`) when:

- **a kernel filesystem is mounted inside it**, or it lies inside one: `proc`, `sysfs`, `cgroup`, `cgroup2`, `bpf`,
  `mqueue`, `resctrl`, `securityfs`, `debugfs`, `tracefs` and the others ADR 0059 lists. A write there changes the
  kernel's state for other processes, other runs among them, whatever path names it. The ordinary triggers are a
  container's or a chroot's root filesystem with its own `/proc` mounted, inside `/tmp`, your home or your project
  (a `debootstrap` or `mock` build tree, a rootless container's storage when those mounts are visible in the compiling namespace), and a grant on `/dev` itself,
  since `/dev/mqueue` is mounted there on every systemd machine. `/dev/pts` (an agent's own terminals), `/dev/shm`
  and `/dev/null` are not refused by type; other mount paths of `devpts`, including binds of a slave, are refused.
  Terminal opens through aliases are refused by device identity even when their names are outside `/dev`;
- **another mount shows one of Tego's own places inside it**: a bind mount of the ledger, of `~/.tego`, of the
  profiles or registry folders, or of the folder holding `tego`, inside a folder the contract writes;
- **the tego binary has a second hard link** on the filesystem the entry is on, unless only root may write the binary
  and the agent is not root;
- **a present binary overlay layer cannot be examined**, has no mount identity, or takes the layer closure past its
  bounds;
- **a protected target, a directory its path walk reads, or the grant itself has no mount identity**. With no device
  and place within that filesystem, compile cannot show that any write or ask grant stays off the protected place.
  The message names it. Empty configured paths are not targets; absent binary overlay layers and protected
  walks across unlinked-root mounts have the separate backing limit below. A partial chroot whose root is not a
  mount point can hide those identities. The ordinary host,
  CI and container fixtures keep their counts below because every protected place has a holding mount;
- **a known binary candidate cannot be inspected**, other than a missing path (ENOENT or ENOTDIR). Restore access
  to the named running, PATH or installation candidate, or repair its broken links;
- **mount visibility is ambiguous**, including several top candidates with the same parent and mount point.
  Those candidates stay unknown even if a live check identifies one. The message names the mount point;
  a moved mount's position is determined from parent relationships, never printed row order;
- **the mount table cannot be read whole and parsed strictly** (malformed, larger than 8 MiB or 32768 mounts,
  changing while it is read, or not one graph of mounts with a single root mount at `/`, as in a partial chroot).

To fix it, narrow the grant to the folders the agent writes: `./src/` and `./out/` rather than `./`, `/tmp/my-agent/`
rather than `/tmp/`, `/dev/null` rather than `/dev`. Or move the container root, chroot or bind mount out of the
folder the agent writes, or unmount it before the run. For the hard link, install a fresh copy of tego with one name
outside every folder the agent writes and run that one. The message names the mount or protected place it found.
For a plain-folder chroot with no root mount row, compile and `tego doctor` explain: "Tego is running inside a root
that is not a mount point, so the kernel does not show the filesystem under it; make the root a mount point, for
example bind the folder onto itself before entering it, or run Tego outside that root". Every write and ask grant
is still refused there. Removing those grants also removes this uncertainty refusal.

An overlay layer whose host path is absent in the container (ENOENT or ENOTDIR), a layer named relative to a folder
the mount table does not record, or a binary on FUSE, eCryptfs, aufs or shiftfs has a stated backing limit and alone
refuses no grant. Tego does not guess where a relative layer lives. Absolute layers of the same overlay remain
protected. An absolute FUSE or eCryptfs mount source naming an existing directory joins the protected closure
when that filesystem holds a protected regular file. Write and ask grants at, over or inside the source directory
or a visible alias refuse. A source that is missing, relative or a file supplies no protected directory.
Source text cannot establish the backing's identity, so FUSE and eCryptfs keep their unplaced-backing warnings.
The binary can stay on the shipped image's overlay or in an encrypted home. Visible binary paths and
correlated layer candidates
follow the [compile-time mount boundary](../adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary).
A candidate whose identity cannot be read refuses the grants concerned; it is not evidence of a hidden or absent
layer. Root-owned merged files and directories give no assurance about hidden layers and get no special treatment.

Compile emits one `[overlay-backing-unknown]` warning per write or ask entry that reaches a visible storage mount
when a binary has any of these backing limits, or FUSE/eCryptfs holds another protected regular file.
For relative layers and unnamed backing, it excludes only that
affected protected filesystem's own device. Another binary's filesystem can still hold that backing folder.
These pre-existing backing classes exclude the shared inventory's kernel interfaces and memory directory storage such as
`tmpfs`; regular-file binds established by live checks can still warn on memory filesystems. The absent-only rule also excludes
discovered binary overlay devices. If runtime storage or a backing folder lives on a memory filesystem mounted
at a writable directory, Tego gives no warning (GAPS C65).
Unlinked protected backing also warns on its own device and on memory directory storage; kernel interface
filesystems remain excluded. An unlinked directory remains uncertain and refuses reaching write and ask grants.
The warning names the grant, mount and which protected file itself lies on an unnamed filesystem, including a config
layer or a contract on sshfs even with Tego itself on ext4: Tego cannot
tell whether that mount shows the folders holding protected files. For relative layers it says the table does not record
their base folder; for FUSE, eCryptfs, aufs or shiftfs it names the filesystem whose backing it cannot prove.
For absent or relative layers, keep runtime storage and the whole host filesystem out of writable places.
For unnamed backing, keep the folder that stores the encrypted or mirrored files out of every write grant.
A single-file mount gets no backing warning only for absent or relative overlay backing, when a live check ties
its regular-file type and size to the snapshot's mount ID and it differs from every affected protected
regular file. This permits Docker's `/etc/hosts`, `/etc/hostname` and `/etc/resolv.conf` binds when the checks pass;
their runtime checks are owed in a guest. FUSE/eCryptfs file binds keep the warning because their stored bytes
can differ from visible bytes. A nonempty byte-identical protected-file alias refuses, executable or not. Two empty
files prove neither identity nor difference and warn without a byte-alias refusal. Unreadable protected files and
unidentified or changed mount points get no exception. An ordinary project grant in the captured Podman FUSE
layout reaches no file bind and stays quiet; a grant reaching a file bind warns once, including empty `/run/.containerenv`.
Without a storage mount meeting a grant there is no backing warning; an ordinary overlay grant can
still print a separate `[mount]` advisory. Ordinary volumes still compile; the host owner must keep protected
storage out of them.

The compatibility fixture asserts that all 19 baseline contracts compile with hidden host layers, both with and
without workspace storage mounts; the warning's presence and absence are checked by contract name. The
ordinary-host fixture also keeps 19/19. A project containing a chroot's private proc keeps 17/19; only
`examples__agents__custom-agent.yaml` and `variant__grant-project` are refused because their grants cover that proc
mount. A separate partial-chroot fixture, whose root is not a mount point, keeps only the two contracts with no
write or ask grant (`testdata__good__minimal.yaml` and `testdata__good__bom-crlf.yaml`), refusing the other 17 named
baseline inputs: its table has no root mount at `/`, so compile refuses it whole. Every count, refusal name and the 11 workspace-volume warnings are asserted.
Tables captured in a guest give the same counts: a chroot into a plain folder keeps 2/19; a chroot whose root is a
mount point (a bind of the folder onto itself, or its own filesystem), `pivot_root`, bubblewrap and
`systemd-nspawn` keep 19/19. Nspawn's bind mounts of unlinked files are valid rows. An unlinked directory remains
an uncertain alias candidate: reaching write and ask grants refuse, and read-denial startup retains uncertainty
if the directory could expose the denied tree. Doctor names the mount and says it cannot tell whether the folder
is visible under another name. It retains known alias warnings without claiming the uncertain tree can be held.
Its unlinked name proves nothing about its contents. An unlinked regular file still refuses a grant that reaches
the same protected file through another hard link. Both files'
live type, inode and snapshot mount IDs are checked before matching their device and inode. Established absence
or a nonregular protected target needs no comparison; an identity read error, failed holding-mount lookup,
mount-ID mismatch or missing identity refuses the reaching grant. The former unlinked name is never used to
infer a path alias.
A protected path whose walk crosses an unlinked-root mount has unplaced backing and the conditional warning
described above. Running this branch in nspawn and the two chroot layouts is owed in a guest.
The runtime fixtures also replay Docker 29.1.3, containerd 2.2.1 and rootless Podman 4.9.3 captures from Ubuntu
24.04 with kernel `6.8.0-147-generic` on 2026-11-12. They include Docker overlay2's relative layer names, the
containerd store's relative lowers with absolute upper/work, and Podman's real `fuse.fuse-overlayfs` type from
fuse-overlayfs 1.13. The alternative `fuse.overlayfs` spelling remains synthetic. These checks model compilation.
The capture guest ran older head `69541c0706dd39125a004cc60f7ec046898e63be`; this branch's container reruns are
owed in a guest.

Mount coverage and its limits are exactly the
[compile-time mount boundary](../adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary), also
recorded in GAPS C45. Host owners must keep the unseen sources it names out of write and ask grants. A FUSE type
alone adds a mount advisory naming it; identified protected source places and aliases still refuse. The advisory
does not mean compile knows what it mirrors.

The inherited-terminal exception at canonical `/dev/pts` still uses device major/minor alone. A different devpts
instance mounted there can reuse the inherited terminal's numbers. Host owners must not replace canonical devpts
beneath an inherited session; arbitrary terminal aliases are refused, but that canonical-instance ambiguity remains.

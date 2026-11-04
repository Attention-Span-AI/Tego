<!-- SPDX-License-Identifier: Apache-2.0 -->

# Conformance tables (schema v2)

Every handwritten cell of ADR 0017's conformance suite is written here, one fixture per file. Three runners read
the same embedded bytes (`tables.go`): the decide core's `TestSharedSpecificationTables`
(`internal/policy/decide`), the unprivileged compile runner and the kernel runner (`test/conformance`, whose
README says how a run reads a cell and how the baseline works). No expectation is computed: each is written from
SEMANTICS and the spec rule its `source` names, never from an evaluator (ADR 0003, ADR 0017).

The loader (`test/conformance/fixtures.go`) decodes with unknown fields refused and checks the schema below; a
table that fails it fails every runner.

## A file

| Key | Meaning |
| --- | --- |
| `version` | `2`. |
| `name` | The fixture's name; a cell's ID is `name/cell`, which the baseline names. Unique across files. |
| `contract` | The whole `agent.yaml`. `{{P}}` is the project directory, `{{PORT}}` and `{{PORT2}}` the two listeners, `{{LOADER}}` the dynamic loader the machine's `/usr/bin/true` names in `PT_INTERP` (a cell's `path` and the model may use it too). |
| `dirs`, `files`, `scripts`, `actors`, `exec_only_actors`, `links`, `hard_links`, `fifos` | The tree the run starts from: directories; files (0644) and scripts (0755) by content; copies of the actor binary (0755, and 0111: execute-only); symlinks to their target as written; hard links to the file they link; named pipes. |
| `listeners` | `true` starts the two loopback listeners `{{PORT}}` and `{{PORT2}}` name. |
| `mounts` | Mounts the root runner makes before the run, in a mount namespace of the run's own (ADR 0017 space 5): each `kind` (`bind` with `from`, `overlay` with `lower`, `upper` and `work`, `btrfs` with `subvolumes`, an empty image loop-mounted, or `tmpfs`) at `at`, an existing directory, and `files` written on it once mounted. A mount's own tree also lies beneath its mount point for the runners that make none. Root only. |
| `later` | Files (0644, content as `files`') a process outside the run writes after the run compiled and filled its rules and before the actor's first cell (the kernel runner's await handshake, ADR 0043's conformance space): a file made after compile, which only a name entry decides. Each one's directory is a `dirs` entry; never with `mounts`. compile --test and the decide core answer the tree without them. |
| `third_party_deny` | Files a third party's fanotify listener refuses every open of while the run lasts (root runner only; ADR 0017 space 6). |
| `model` | The contract's declared entries, relative to the project, which the invariants read (`write`, `deny_read`, `exec_allow`, `net_declared`, `net_allow`, `net_runtime`, `deny_write` (every deny_write target, built-in or declared), `deny_write_declared` (the members of `deny_write` the contract declares in `fs.deny_write`, which a nested write entry reopens and whose best-effort cell is `fs.deny_write`, ADR 0071), `exec_deny`, `exec_anonymous`, `keyring` (the contract's `keyring: true`, which the loader holds the contract to), `host_sockets` (the contract's `host_sockets: true`, held to it the same way, ADR 0070), `exec_allow_commands`: the exec.allow entries with words as `<command> <words...>`, a tool one names running only as one names it, `names`: the contract's name entries (ADR 0043), each `{exact: <name>}` or `{prefix: <literal>, except: [...]}` with its `scopes` relative to the project, which the name invariant holds at tier cgroup and the plane; a table that declares them declares no directory under a covered name, and one that does not names no path the built-in `.env` pair covers, TestNoCellMeetsAnUnmodelledNameEntry). It is written beside the contract, never derived from compile output, so a contract that grants more than its model is a fail-open the invariants catch (the self-test does exactly that). |
| `variants` | Fixtures derived with the same cells and expectations: `held` (named `<name>-held`, every open completed by the open deputy, ADR 0041 Stage B) and `assurance-kernel` (`<name>-kernel`, `fs.assurance: kernel`, ADR 0041 D1 (a)). |
| `cells` | The cells, run in order in one `tego run` per axis. |
| `deferred` | Cells named and not run, each with `name` and `why`. None is left: TestCellTableIsWellFormed fails a table that names one (a later space adds cells, not names). |

## A cell

| Key | Meaning |
| --- | --- |
| `name`, `op` | Unique in the file; one of the actor's ops (`read`, `write-open`, `create`, `creat`, `truncate`, `unlink`, `rmdir`, `mkdir`, `rename`, `exchange`, `symlink`, `link`, `chmod`, `exec`, `map-exec`, `connect-tcp`, `connect-udp`, `send-udp` (an unconnected `sendto`), `connect-unix` (a stream connect to a pathname or `@name`, ADR 0070), and the exec space's spellings `exec-loader` (`path` the loader, `dest` its program), `execveat-fd`, `exec-proc-fd`, `memfd-create`, `memfd-exec`, `memfd-map-exec`, `map-exec-rie`, `mprotect-exec`, `mprotect-rie`, `execmod`, `execmem`, and space 4's `chown`, `setxattr`, `setfacl`, `mknod` and the TOCTOU harness's `race-symlink-read` and `race-symlink-write` (`path` the link the actor swaps, `dest` and `canon` the target), and the process and control ops `ptrace-attach`, `ptrace-traceme`, `keyctl`, `add-key`, `request-key` and `bpf` (FEATURES E54), which name no path, and `race-argv-exec` (ADR 0048's argv race: `path` the copy, `argv` its denied `[tool, word]`): test/conformance cells.go says what each does). |
| `target` | A ptrace cell's peer and no other cell's: `ptrace-attach` takes `child` (a child of the actor, in the run) or `{{HOSTPID}}` (a process of the agent's uid outside every run, which the runner starts, opted out of Yama, and attaches to as a control); `ptrace-traceme` takes `parent` (a child of the actor asks the actor) or `orphan` (an orphaned grandchild asks the subreaper outside the run). The ledger line is found by the pid the hook names, which the actor reports. |
| `path`, `dest`, `canon`, `addr` | As the agent spells them, relative to the project; `canon` is where the kernel reports a path reached through a symlink. Every cell owns its paths. A `connect-unix` cell's `addr` of `{{HOSTSOCK}}` or `{{HOSTABSTRACT}}` is a pathname socket beside the project or an abstract one, which the runner binds outside every run as a host daemon's sockets (ADR 0070). | An `addr` of `$NAME` is the URL the agent's environment variable NAME holds, which the run made (a capture forwarder's base URL): the actor connects to its host:port and reports it, and a `want` rule may name it `{{PEER}}`.
| `script`, `script_arg`, `argv`, `runs` | An exec cell's `#!` interpreter and argument, whole argv, and the program the kernel runs when it is not the image named. |
| `want` | The expectation per column (below). Required. |
| `want_where` | Expectations a machine fact changes: a list of `{<condition>..., want: {...}}`, each condition one of `kernel_min`, `kernel_max`, `abi_min`, `abi_max` (as a baseline `where`), `bpf_lsm`, `memfd_noexec_seal` (the kernel honours `MFD_NOEXEC_SEAL`, a probe, never the version), `supervisor_root` (the run's supervisor is root: it reads an image the agent may only execute), `unix_diag` (the kernel answers sock_diag for AF_UNIX, the supervisor's own probe: without it R11a refuses unix-origin-unread what it cannot read) and `plane_first` (the axis' decision plane answers before Landlock's own hooks: fmod_ret, or lsm where bpf precedes landlock in the LSM order; false on an axis no plane decides, so it can only change the plane column). On a machine the first matching entry with a column answers it instead of `want`; it may set only columns `want` sets. compile --test, which makes no kernel call, reads `want`. |
| `unasked` | Columns the cell states no expectation for, each `<column>: <why>` (a tier that decides nothing of the action, one best effort against it by design, or one whose answer there is the machine's filesystem's). Every cell answers the plane column; tier landlock and the listener only through `want` or `unasked`. A column is never both. |
| `source` | Required: the SEMANTICS section or spec rule the cell is written from. |
| `no_compile` | Why compile --test has no action for the op; the compile runner skips the cell. |
| `finding`, `finding_at` | A known fail-open at that tier: reported, never baselined, and the cell fails once the kernel stops allowing it. |
| `exception`, `exception_at` | A stated per-tier exception (SEMANTICS §2) under which the tier allows what an invariant refuses. |

### `want`

Keys are columns: `landlock`; `cgroup/fanotify` (tier cgroup on the fanotify listener); `plane`, which answers
tier cgroup in the plane modes fmod_ret and lsm and tier bpflsm, as one column, since one set of hooks and one row
compiler decide them (ADR 0019, ADR 0024). Two shorthands: `root` is `cgroup/fanotify` and `plane`, and `all` is
every column. A column set twice is an error. A column a cell omits is not asked of it.

A value is `verdict` or `verdict rule` (`allow` or `refused`, then the rule the ledger line and compile --test
name, to the end of the line; no rule leaves it unchecked), or a mapping where it needs more:
`{verdict: refused, rule: ..., errno: EACCES}` (the errno a refusal must carry: `EPERM`, `EACCES`, `EXDEV`, or `ENOSYS`, the filter's answer where it refuses a syscall as absent, enforce-landlock R10 and R11a) and
`no_line: true` (the tier's recorder writes no line for the action) and `ledger: allow|refused|observed` (the verdict
the line holds where it differs from the kernel's answer by design, a third party's refusal: ADR 0016).

Below Landlock ABI 3 every truncate cell takes tier 1's floor, a refusal with EPERM and no line, on every column
(`Cell.WantOn`): that is a property of the machine's filter, not of a cell, so it is code and not data.

## Citing a source

Name the section and the rule, then what of it the cell exercises in parentheses, for example
`SEMANTICS §2 (a write entry grants modifications beneath it)` or `supervisor.md R15d`. Until ADR 0030 numbers
SEMANTICS' rules, a section and a phrase is the citation.

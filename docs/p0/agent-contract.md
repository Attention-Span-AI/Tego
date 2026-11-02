# pkg/spec/agent (P0 detailed spec)

## 1. Purpose and boundaries

`pkg/spec/agent` turns `agent.yaml` bytes into a validated `Contract`, merges `extends` profiles, compiles a `Contract` plus the machine's ceilings into an immutable `RuleTable`, and evaluates hypothetical actions against a `RuleTable` for `tego compile --test`. It owns the P0 field subset, every validation rule, the `Diagnostic` model, and `contract_hash`.

**Owns**: `Contract` and sub-sections; `Load` (YAML → `Contract` + diagnostics); the `extends` merge; `Compile` (`Contract`+`Machine` → `RuleTable` + diagnostics); `RuleTable`/`FSRule`/`NetRule`/`ExecRule`; `Evaluate` (`compile --test`); `Diagnostic` and its `file:line[:col]: message [code]` format; `contract_hash`.

**Must not**: touch the kernel, Landlock, cgroups, eBPF, seccomp (`internal/runtime/enforce`'s job); write the ledger, run directory, or any file (`internal/ledger`, `internal/runtime`); parse CLI flags or print to stdout/stderr (`internal/cli`); decide a *live* action — `Evaluate` answers hypotheticals only, the runtime's `stampRule` stage makes real per-event calls elsewhere; call `os.Exit`; outlive its own call with a goroutine or fd; touch a credential.

**Imports**: standard library and `gopkg.in/yaml.v3` only (`docs/REPO-LAYOUT.md`: `pkg/spec uses standard library, yaml.v3 in agent/config, and the pure HTTP matcher in agent`). May import the standard-library-only `pkg/policy/httppolicy` matcher and sibling `pkg/spec/backend` (`backend.Tier`) and `pkg/spec/record` (`record.Reason`); never `internal/*`, never a third-party module outside `yaml.v3` — `golang.org/x/sync/errgroup` included: it is not stdlib, not `yaml.v3`, and REPO-LAYOUT reserves `errgroup` for `internal/runtime`'s background workers, not `pkg/spec` (the DNS-pool note under §9 gives the stdlib-only replacement). `pkg/spec/config`'s `*Machine` is a parameter type only — `Compile` does not import `config`'s loader. Consumers: `internal/cli` (`compile`, `run`), `internal/runtime` (`Compile` at run start), `internal/check` (`compile --test` calls `Evaluate` directly).

## 2. Models

Presence matters as much as value: `FS`, `Net`, `Exec` are pointers so "key absent" (`nil`) is distinguishable from "key present but empty" (`&FSSection{}`) — SEMANTICS §1 gives these two states different defaults (§5 R6). yaml.v3 does this natively for `*T` fields; no custom `UnmarshalYAML` needed for presence. Every `Limits` field is a pointer for the same reason: absent means "inherit the ceiling", not zero.

```go
package agent // tego/pkg/spec/agent

type Contract struct {
    Version int      `yaml:"version"`           // must be 0 in P0
    Name    string   `yaml:"name"`               // ^[a-z0-9-]{1,40}$
    Revision string  `yaml:"revision,omitempty"` // ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$, the top-level file's own (R28)
    Extends string   `yaml:"extends,omitempty"`
    Command []string `yaml:"command"`            // non-empty; Command[0] non-empty

    FS   *FSSection   `yaml:"fs,omitempty"`
    Net  *NetSection  `yaml:"net,omitempty"`
    Exec *ExecSection `yaml:"exec,omitempty"`
    Env  EnvSection   `yaml:"env,omitempty"`

    MCP     []MCPServer     `yaml:"mcp,omitempty"`
    Models  []ModelEndpoint `yaml:"models,omitempty"`
    Limits  Limits          `yaml:"limits,omitempty"`
    Record  RecordMode      `yaml:"record,omitempty"`   // "" = summary
    Tier    TierPin         `yaml:"tier,omitempty"`     // "" = auto
    Capture CaptureMode     `yaml:"capture,omitempty"`  // "" = auto
    IOUring bool            `yaml:"io_uring,omitempty"`
    Keyring bool            `yaml:"keyring,omitempty"` // added 2026-09-23: the kernel keyring opt-in (SEMANTICS §1)
    IPC     bool            `yaml:"ipc,omitempty"`     // added 2026-09-24: the System V IPC opt-in (SEMANTICS §1)
    Setuid  bool            `yaml:"setuid,omitempty"`  // added 2026-09-24: a root tier's opt-out of no_new_privs (ADR 0033); under a net: section the run never holds CAP_NET_ADMIN (ADR 0128)
    KeepDescendants bool    `yaml:"keep_descendants,omitempty"` // added 2026-10-26: the run waits for the agent's whole tree after its main process exits (runtime-launch.md case 24)

    // Implemented bounded scored gate, retained for canonical/merge compatibility.
    Gate       yaml.Node `yaml:"gate,omitempty"`

    // Schema-only in P0: parsed for KnownFields, rejected if non-empty (§5 R2).
    Prompt     string    `yaml:"prompt,omitempty"`
    Skills     []string  `yaml:"skills,omitempty"`
    Visibility []string  `yaml:"visibility,omitempty"`
    Docker     yaml.Node `yaml:"docker,omitempty"`
    Containers string    `yaml:"containers,omitempty"`

    // Implemented approval mapping, retained for canonical/merge compatibility.
    Ask        yaml.Node `yaml:"ask,omitempty"` // hold/timeout/max_pending/on_timeout

    node *yaml.Node // root doc node, for Diagnostic line lookups only, never re-serialized
}
type FSSection struct {
    Write    []string `yaml:"write,omitempty"`
    Ask      []string `yaml:"ask,omitempty"`       // separate pinned write-open/create approval scopes
    DenyRead []string `yaml:"deny_read,omitempty"` // nil = built-in list; []string{} = disabled (warn); populated = entries plus the built-in list; read off the merged contract (R6)
    AskRead  []string `yaml:"ask_read,omitempty"`  // added 2026-10-06: literal files/dirs whose reads are held for a person, tier landlock only (R22)
    Watch    []string `yaml:"watch,omitempty"`
    DenyWrite []string `yaml:"deny_write,omitempty"` // added 2026-10-25 (ADR 0071): literal files/dirs inside a write entry whose every modification is refused (R20); a union, [] adds nothing
    Assurance FSAssurance `yaml:"assurance,omitempty"` // best-effort (default) | kernel: R20's targets below a decision plane
}
// FSSection.MarshalYAML emits an empty non-nil DenyRead as `deny_read: []` despite omitempty (R13).
type NetSection struct {
    Allow []string `yaml:"allow,omitempty"`
    Ask   []string `yaml:"ask,omitempty"`  // separate explicit TCP approval destinations
    HTTP  []HTTPRule `yaml:"http,omitempty"` // declared-forwarder method/path policy
    Assurance NetAssurance `yaml:"assurance,omitempty"` // best-effort (default) | kernel
    Listen []string `yaml:"listen,omitempty"`
    Ingress []IngressRule `yaml:"ingress,omitempty"`
    Limits *NetworkLimits `yaml:"limits,omitempty"`
    DNS *DNSPolicy `yaml:"dns,omitempty"`
    Proxy *ProxyPolicy `yaml:"proxy,omitempty"`
}
type Endpoint struct { // "host:port" | "cidr:port"; optional tcp:// or udp://; "unix:<path>" | "unix:@<abstract>"
    Kind EndpointKind // host | cidr | unix
    Proto string // inet (TCP+UDP) | tcp | udp | unix
    Host string; Port int
    CIDR netip.Prefix
    UnixPath string; Abstract bool
    Raw string // original scalar, for diagnostics and RuleTable printing
}
type ExecSection struct {
    Allow      []string `yaml:"allow,omitempty"`      // paths or PATH basenames
    Privileged []string `yaml:"privileged,omitempty"` // schema-only, P2
}
type EnvSection struct {
    Pass []string          `yaml:"pass,omitempty"`
    Deny []string          `yaml:"deny,omitempty"`
    Mask []string          `yaml:"mask,omitempty"` // schema-only, P2 (§5 R17)
    Set  map[string]string `yaml:"set,omitempty"`
}
type MCPServer struct{ Name string `yaml:"name"`; Command []string `yaml:"command,omitempty"`; URL string `yaml:"url,omitempty"` } // exactly one of Command, URL (R16a)
type ModelEndpoint struct{ Provider, Host string; Port int }

type Limits struct { // every field: nil = inherit the machine ceiling unchanged (§5 R11)
    CPU        *CPUCores `yaml:"cpu,omitempty"`        // cores, e.g. "2.0" (cgroup cpu.max numerator)
    CPUWeight  *int      `yaml:"cpu_weight,omitempty"`  // 1..10000, cgroup cpu.weight
    Memory     *ByteSize `yaml:"memory,omitempty"`      // cgroup memory.max
    MemoryHigh *ByteSize `yaml:"memory_high,omitempty"` // cgroup memory.high
    Pids       *int      `yaml:"pids,omitempty"`
    Tokens     *int64    `yaml:"tokens,omitempty"`
    CostUSD    *float64  `yaml:"cost_usd,omitempty"`
    Wall       *Duration `yaml:"wall,omitempty"`
    StallAfter *Duration `yaml:"stall_after,omitempty"`
}
type CPUCores string       // "^[0-9]+(\.[0-9]+)?$", 0.01 to 175921860 cores; validated in UnmarshalYAML
                            // (the range cpu.max takes, a quota of 1 ms to 2^44-1 µs a 100 ms period; outside
                            // it a run would fail at start with EINVAL, exit 125)
type ByteSize int64         // bytes; "<n>" or "<n>(B|KiB|MiB|GiB|TiB)", IEC only, never decimal GB/MB
type Duration time.Duration // "<n>(ms|s|m|h|d)", d = 24h

type RecordMode string  // "full" | "summary" | "off" | ""
type TierPin string      // "auto" | "landlock" | "cgroup" | "bpflsm" | ""
type CaptureMode string  // "auto" | "uprobe" | "forwarder" | "off" | ""

type Diagnostic struct {
    File          string
    Line, Col     int
    Code          string // closed set, §5; see also spec/identity/RUN-IDENTITY.md "Messages"
    Message, Fix  string
    Severity      string // "error" | "warning"
}

// ProfileSource resolves `extends: <name>` to bytes, rooted under the machine's
// profiles directory or a registry namespace. Implemented by internal/cli
// (filesystem); pkg/spec/agent never touches the filesystem for extends itself.
type ProfileSource interface {
    Resolve(name string) (path string, data []byte, err error) // wraps os.ErrNotExist on miss
}

func Load(path string, profiles ProfileSource) (*Contract, []Diagnostic, error)
func Compile(c *Contract, m *config.Machine) (*RuleTable, []Diagnostic, error)

type RuleTable struct {
    FS      []FSRule
    Net     []NetRule
    Exec    []ExecRule
    Env     []string          // final pass-list, runtime-reserved names removed
    Set     map[string]string // final env.set, after conflict checks
    Limits  Limits            // every field non-nil, clamped to machine ceilings
    Record  RecordMode        // never ""
    Tier    backend.Tier      // never ""; resolved, not a TierPin
    Capture CaptureMode       // never ""
    Hash    [32]byte          // contract_hash = sha256(Contract.Canonical())
    DeniedResolved []netip.Prefix // machine config's denied_resolved_addresses (§5 R18)
    DenyWrite      []FSRule       // built-in deny_write set and the contract's fs.deny_write entries (BuiltIn false, ADR 0071), never in FS (§5 R20)
    DenyWriteLinked []string      // files beneath a deny_write directory (target or fs.deny_write entry) with another hard link, keyed by the plane, one name per file (ADR 0071 (6))
    FSAssurance    FSAssurance    // effective fs.assurance, never "" (§5 R20; FilesystemAssurance, DenyWriteNeedsPlane)
    ExecAssurance  ExecAssurance  // effective exec.assurance, never "" (ADR 0048 (3) P2; ExecutionAssurance)
}
type FSRuleKind string // "write" | "ask" | "deny_read" | "watch" | "implicit" | "deny_write" (DenyWrite only)
type FSRule struct {
    Path string; Kind FSRuleKind; Access AccessSet
    Mount, Filesystem string; Device uint64; IsMountPoint, Overlay, Btrfs bool // for `compile`'s print
    AskRead bool // added 2026-10-06: a deny_read compiled from fs.ask_read, named fs.ask_read[...] (R22)
}
// RuleTable.OwnState (added 2026-10-06) is tego's own state by resolved path, R6a's list taken whole: no
// fs.ask_read entry may lie at or beneath one, no held read completes on one, no alternate reaches one (R22).
// RuleTable.OwnReadable (added 2026-10-20, R26) is tego's own state a run may read: the user registry's agents/ and
// skills/, as written and resolved; R10 keeps every write entry off them, and no write alternate reaches one (R22).
// AccessSet mirrors LANDLOCK_ACCESS_FS_* exactly (uapi/linux/landlock.h; verified
// against man7.org landlock(7) and docs/ARCHITECTURE.md §14's ABI/kernel table),
// not an invented simplification — there is no CHMOD right in any Landlock ABI
// (§6 E35). ABI gates in comments; RuleTable never sets a bit its target tier lacks.
type AccessSet uint32 // bitmask:
//   Execute ReadFile ReadDir WriteFile        // ABI 1
//   RemoveDir RemoveFile MakeChar MakeDir MakeReg MakeSock MakeFifo MakeBlock MakeSym // ABI 1
//   Refer                                      // ABI 2 (5.19)
//   Truncate                                   // ABI 3 (6.2)
//   IoctlDev                                   // ABI 5 (6.10)
//   ResolveUnix                                // ABI 9 (7.1)
type NetRule struct {
    Host string; Port int; Proto string // "tcp"|"udp"|"unix"
    Verdict Verdict
    IPs []netip.Addr; CIDR *netip.Prefix
    Static bool                          // literal IP/CIDR: never re-resolved
    ResolvedAt time.Time; TTL time.Duration // in-memory only, never serialized (§6 E19)
    UnixPath string; Abstract bool
    Resolved string // pathname unix entry: UnixPath with its symlinks followed at compile (FSRule.Resolved's rule)
    Rule string
}
type ExecRule struct {
    Path, Basename, Interp string // Interp = PT_INTERP target; "" for static or non-ELF
    Verdict Verdict
}
type Verdict string // "allow" | "ask" | "refused"

// Evaluate reports the verdict a compiled table would produce for a hypothetical
// action, as `compile --test` uses it. Pure: no I/O, no kernel calls.
func (rt *RuleTable) Evaluate(a Action, tier backend.Tier) EvalResult
type ActionKind string // "fs_read" "fs_write" "fs_delete" "fs_rename" "fs_mkdir" "exec" "net_connect" "map_exec" (compile --test's `exec.map`: a PROT_EXEC map, decided at bpflsm only, ADR 0027)
                        // "fs_link" "fs_attr" "net_socket" "net_send" "exec_anon" (compile --test's fs.link, fs.attr, net.socket, net.send, exec.anonymous; ADR 0017 (b), limits-check-doctor-cli R28)
type Action struct {
    Kind ActionKind
    Path, DestPath string // DestPath: rename/link target, for the REFER check
    Landed string         // net_connect/net_send to a unix pathname: what the walk of Path reaches, "" if not landed
    NoSocket bool         // Landed is no socket in the tree the agent calls in: a directory, or a file that is not one
    Walk UnixWalk         // what the run's unix walk of Path met: 0 Lookup (Landed decides), Stepwise, Absent, Failed,
                          // Unreliable (a magic link, a loop, procfs; for a net_bind, any failed walk)
    Uncanonical bool      // net_send: an absolute name the run's kernel programs refuse as spelled (UnixCanonical)
    Script string         // exec only: the `#!` interpreter path, "" if none
    Host string; Port int; Proto string
    Argv []string
    Socket SocketTriple   // net_socket only: Family, Type, Protocol int32; Pair for socketpair(2)
}
type EvalResult struct { Verdict Verdict; Rule string; Reason record.Reason }
const PathUnreliableRule, UnixAbsentRule, UnixForeignRule = "path-unreliable", "unix-absent", "unix-foreign" // the supervisor's own rule names
func UnixCanonical(p string) bool // tego_unix_canonical: no empty, ".", ".." component, no trailing "/"

// TestTable.RunResolved lands a compile --test row's paths with the run's own walks before Evaluate is asked.
type Lookup uint8 // how the kernel looks one end up: LookupFollow, LookupCreate, LookupNoFollow, LookupParent
func (k ActionKind) Lookups() (path, dest Lookup) // the lookup of each end of the syscall a row of kind k stands for
type Lander func(p string, how Lookup) (at string, err error) // supervisor.Land; err ErrUnwalked: not walked
type UnixLander func(p string) (UnixLanding, error) // supervisor.LandUnix
type UnixLanding struct { At string; Walk UnixWalk; NoSocket bool } // asked of the tree the agent calls in
type Landers struct { Path Lander; Unix UnixLander }
```

**Changes.**
- 2026-10-19, `NetRule.UnixResolved` and `UnixAskScopeRule`: the two
  packages each gave a pathname unix entry a resolved place, `NetRule.Resolved` (`FSRule.Resolved`'s rule) and
  `NetRule.UnixResolved` (`ResolveUnixPlace`); the run places its entries and scopes with the latter
  (`resolveUnixDeclared`), so it is the one field, and a landed socket is matched against it. `NetRule.Resolved` is
  gone; the notes below that name it mean `UnixResolved`.
- 2026-10-19, `Lookup`, `ActionKind.Lookups`, and a `Lander` asked with a `Lookup` (ADR 0019's note of that date): a row's end is landed with the kernel's lookup
  of the syscall the row stands for, one of four, where a `follow` bool was read as both "not followed" and
  "name-making"; an `fs_link` row's `Path`, `link(2)`'s old name, is looked up whole and unfollowed, so a final `.` or
  `..` is walked, as the run walks it (supervisor.md R15b).
- 2026-10-19, `Action.NoSocket`, `UnixLanding`, `UnixForeignRule`, and `Evaluate` of a unix name and of a `net_bind`
  (ADR 0019's note of that
  date): a `UnixLander` answers for the tree the agent calls in (the tree as it is, every directory the name's walk
  needs made, the socket the agent binds at a final name that names nothing yet and that nothing needs as a
  directory) and says whether what the name reaches there is a socket. `Evaluate` refuses a landing that is none, a
  directory or a file that is not a socket, `unix-foreign` through the write entry's implicit admit, as the
  supervisor's R11a refuses it; it admitted it. A `net_bind` whose walk failed is `path-unreliable` only in the
  columns whose supervisor's `bindUnix` decides it (`landlock` and `cgroup` under a listener policy), and is answered
  on its spelling at `bpflsm`, whose plane decides binds and never one whose lookup fails.
- 2026-10-19, `Evaluate` of a `net_bind`: a bind whose walk
  failed (`Action.Walk` not `UnixWalkLookup`) is `path-unreliable` only when the table has a listener policy
  (`RuleTable.Listen` not nil), where the supervisor's `bindUnix` decides it; with none the run continues the bind with
  no line, and `Evaluate` answers the creation floor on the name's spelling, as it answered before the fix.
- 2026-10-19, `Action.Walk`, `Action.Uncanonical`, `UnixCanonical`, the two rule names, `Landers`, `UnixLander`, and a
  `Lander` that returns the walk's error: a unix connect's
  or send's name is landed by the run's own unix walk (`supervisor.LandUnix`), which also says what it met, so
  `Evaluate` answers a magic link, a loop or procfs `path-unreliable`, a datagram to a name that names nothing
  `unix-absent`, and a connect there the name's verdict, as the supervisor does; a bind whose walk failed
  `path-unreliable`; and at `cgroup` and `bpflsm` an admitted datagram name not spelled canonically `unmatched`, as the
  run's kernel programs refuse it (limits-check-doctor-cli R28's 2026-10-19 amendments). The name was landed by the
  filesystem rows' walk, which follows a magic link as compile itself, and a failed walk was answered on the spelling.
- 2026-10-19, `Action.Landed` and `NetRule.Resolved`: a
  `net_connect` or `net_send` to a unix pathname carries the socket the kernel's walk of its name reaches, and a
  pathname `unix:` entry the socket its own path resolves to, so `Evaluate` decides the name and then the socket, as the
  supervisor does (supervisor.md R11, R11a; limits-check-doctor-cli R28's 2026-10-19 amendment). It decided the name alone, and
  answered `allow` for a datagram or a connect through a symlink in a write entry to a socket outside it, which the run
  refuses.
- 2026-10-16, `ActionKind` and `Action` (ADR 0017 (b)): `fs_link`, `fs_attr`,
  `net_socket`, `net_send` and `exec_anon`, and `Action.Socket`, so `compile --test` answers every action a
  conformance cell takes (limits-check-doctor-cli R28's 2026-10-16 amendment); the decision core routes each to the
  matcher the run decides it with.
- 2026-09-24, `CPUCores`: bounded to the range `cpu.max` takes.

## 3. Repositories and storage

This package reads; it never writes.

| What | Access | Format | Concurrency/durability |
|---|---|---|---|
| Contract file (path from caller) | read-only, whole-file `os.ReadFile` once | YAML, `KnownFields(true)` | No lock; racing editor is the caller's problem (§6 E22) |
| Profile file (`extends:`) | read-only via `ProfileSource.Resolve` | YAML, partial-contract schema | Implementations must refuse to resolve outside their root (§6 E7) |
| `$PATH` — the **run's** effective PATH after `env.pass`/`deny`/`set`, not the compiler's own | in-memory string split | n/a | Recomputed per `Compile` call, never cached |
| Candidate binaries (`exec.allow`/`Command[0]`/`mcp[].command[0]` and a script's `#!` interpreter, §5 R8) | `os.Stat`; then the file is opened as R20's reads are (below), since it often lies where the agent writes (`./run.sh`, `.venv/bin/python`, `node_modules/.bin`): `O_PATH`, `fstat` a regular file, `fstatfs` a file system known to store data, reopened through `/proc/self/fd` with `O_NONBLOCK`, and read with `pread(2)`, never through Go's poller — at most the ELF identification, file header, each program header's fields and the `PT_INTERP` string (under 34 KiB in all, whatever `e_phentsize` says), or the first 256 bytes for a `#!` line. A FIFO, a device, a kernel interface file, a file on a file system not on R20's list of those read, a file under a lease or a read error is refused at once (except `EINTR`, which a FUSE or network file system answers when a signal interrupts a read waiting on it, retried up to 16 times in one read loop as `os.File` retried it, so a run on such a mount does not fail at `Prepare` now and then) and `Compile` warns `malformed-elf` naming the file and why, and for a file system not on the list names it (from the mount table) in the fix; the landlock and cgroup tiers' `Prepare` read it the same way and fail the run, exit 125, if they still cannot (§7), so that list decides whether a run on a given file system starts at all (so a FIFO planted as the command, or as root a link to `/proc/kmsg`, cannot hold the next compile or that run's `Prepare`) | ELF64/32 LE, scoped to P0's tested platforms (§6 E34) | Opened, read, closed within one call; the run's `O_PATH` pin happens later, in `internal/runtime/launch` |
| DNS (`net.allow` hosts) | `net.Resolver.LookupNetIP` (or an injected `Resolver` in tests) | A/AAAA | No persistent cache; `NetRule.IPs`/`ResolvedAt`/`TTL` in-memory only; TTL re-resolution during a run is the launcher's job |
| Declared `fs.*` paths | `os.Lstat`/`os.Stat` plus a mount/fs-type probe (`/proc/self/mountinfo`) for the `compile` print; each path compared (E8), declared, built in or found by a scan, is resolved by the kernel's walk, an `lstat` and an `O_PATH` open whose `/proc/self/fd` link names where it leads, and by `filepath.EvalSymlinks` only where `/proc` is not mounted. The kernel refuses a name of `PATH_MAX` bytes and a walk past 40 links, but each link can be 4095 bytes long, so one walk through a chain the agent planted costs 5 to 11 ms and, with `/proc` mounted, one path's resolution, up to six walks, tens of milliseconds; how many paths is the contract's (its entries, their loaders and interpreters), except the `.env` scan's results, whose number the agent chooses and whose resolution stops at the scan's time limit (below). Without `/proc` none of that bound holds: `filepath.EvalSymlinks` walks in user space, `lstat`ing from the root at every component and following up to 255 links, so one call through the 39-link chain takes about 3.3 s and a resolution makes up to two (the path, then its directory); a declared path the agent linked into the chain costs seconds each, and the `.env` scan, whose limit is checked between resolutions, overruns it by up to one resolution (a thousand `.env.<n>` links planted into a directory 1500 levels deep would cost a user-space walk near a minute; the kernel's walk bounds the links, not their cost); an `fs.watch` or `fs.deny_read` glob may name a directory the agent writes into, so its expansion lists each directory as the `.env` scan does (`O_DIRECTORY`, `O_NONBLOCK`, a bounded `getdents`), and every glob of one compile together reads at most 50,000 directory entries, covers at most 4,096 files and takes at most 2 s: a `deny_read` glob cut short by any of them is an `unenforced` error, since the files it did not reach would stay readable under an entry that names them, and a `watch` glob cut short is a `glob-no-match` warning naming the bound (`TestGlobExpansionBounded`) | n/a | Point-in-time only; no lock, no fd retained (§6 E21) |
| Built-in `deny_write` candidates (§5 R20) | each candidate an `lstat`, then an `O_PATH` open and the `readlink` of its `/proc/self/fd` link for where it leads, each the kernel's walk (40 links at most, each up to 4095 bytes: 5 to 11 ms through a planted chain), then an `lstat` of where it leads; `stat` of each git directory for its identity; a `.git` file and a gitdir's `commondir` (at most 4 KiB), git configs for `core.hooksPath` (at most 256 KiB), each opened `O_PATH` and read only when `fstat` finds a regular file within the bound and `fstatfs` a file system known to store data (a list of those to read, R20), then reopened through `/proc/self/fd` with `O_NONBLOCK` and read with a plain `read(2)` loop in which `EAGAIN` refuses the file and `EINTR` is retried up to 16 times; directory listings beneath a write entry (`O_DIRECTORY\|O_NOFOLLOW`, at most 4096 entries each); an `lstat` or two per ancestor of a write entry up to the enclosing repository. One budget per write entry: 4096 directories examined, 65536 entries read, 16 MiB read, 16384 candidate paths; all write entries together at most four times that; and a time limit, 2 s per write entry and 4 s for all of them, checked before each probe, read, listing, directory and `core.hooksPath` value taken up, which is what bounds what the search costs, since the agent sets the cost of each walk. Every entry's fixed targets (its root's names, its own or its enclosing repository's hooks, configs and `core.hooksPath` directories) are probed before any entry's walk, so the limits cut the walks first (R20). A file found (`lstat`) but not read, and a search any limit cut, are named in the entry's warning, which says whether the fixed targets or the walk were cut (R20) | `gitdir: <path>` / `<path>` / git config | Point-in-time only; a path created after compile is not in the set |
| Built-in `.env` scan (R6, the built-in `deny_read` list) | directory listings under the contract file's directory (the project root) and the run's cwd (both, so a run started in a subdirectory keeps the project root's `.env` denied), breadth first from both at once, a directory reached from both read once, 6 levels deep below each, never into `.git`, `node_modules`, `vendor`, `target`, `.venv`, `venv` or a symlink, each through the bounded listing above with what is left of 50000 entries in all; each `.env` found is resolved as a declared path is (above), the files that are not symlinks first; the scan and those resolutions stop together at a time limit of 2 s. A scan that leaves entries unread, or runs out of time, warns `unenforced`, saying which and how many found files were not resolved, since a `.env` among them is not in the list; so does one with a directory it listed only in part (an error partway through the listing) or, of the operator's own, could not open, naming it and the error (the bound is checked per entry, not after a whole directory is read, and the resolutions share the time limit: unbounded, ten thousand `.env.<n>` links into a chain of 39 links 1980 directories deep took compile 42 s) | n/a | Point-in-time only |
| Well-known host daemon sockets (§5 R19), only when the contract has no `net:` and sets `host_sockets: true` | `os.Stat` of each path; `fstatat(AT_SYMLINK_NOFOLLOW)` of `X0` to `X1023` in `/tmp/.X11-unix`, opened `O_PATH\|O_DIRECTORY\|O_NOFOLLOW` (any user can plant a FIFO or link at that name, and any number of names in it) | n/a | Point-in-time only; drives a warning, never a rule |
| Machine ceilings (`*config.Machine`) | read-only, passed in by the caller | n/a | `Compile` never re-reads `config.yaml` |

No sockets, no BPF pins, no ledger writes, no cross-call cache. What another package persists from this package's output: `RuleTable.Hash` (`internal/ledger` as `run_start.contract_hash`) and `Contract.Canonical()` bytes (`internal/ledger` writes them as `<ledger_root>/<run>/contract.yaml`, P0-DESIGN §3.3).

**Changes.**
- 2026-09-23, candidate binaries (fourth): read `O_PATH`/`pread`, never `os.Open`; `EINTR` retried.
- 2026-09-23, declared paths, `.env` scan (fourth, fifth): kernel walk; the scan and its resolutions bounded by entries and a 2 s limit; the no-`/proc` cost stated.
- 2026-09-24, `.env` scan: the project root is scanned as well as the cwd.
- 2026-09-29, `.env` scan: a directory listed only in part, or of the operator's not opened, warns.
- 2026-09-30, declared paths: glob expansion bounded by entries, matches and time; a cut `deny_read` glob refused.

## 4. Functions and contracts

**`Load(path, profiles) (*Contract, []Diagnostic, error)`** — Pre: `path` non-empty; `profiles` may be `nil` only if the file has no `extends:`. Post: `err == nil` **iff** every `Diagnostic` is `Severity:"warning"`; on success `*Contract` is fully merged and every P0-consumed field is syntactically valid; on any error diagnostic `*Contract` is `nil`. Errors: a wrapped `os.ErrNotExist`/`ErrPermission` for the top file (no `Diagnostic`, no line to point at); otherwise `ErrInvalidContract` wrapping the first error diagnostic. Side effects: none. Idempotent: pure function of the file's bytes plus everything `profiles.Resolve` returns. Timeout: none — no network I/O; a slow `ProfileSource` is the caller's problem.

**`Compile(c, m) (*RuleTable, []Diagnostic, error)`** — Pre: `c` came from a successful `Load` (an unvalidated hand-built `Contract` is undefined behavior, not guarded, to keep the path allocation-light); `m` non-nil and already trust-checked. Post: same error/diagnostic coupling as `Load`; on success every `RuleTable.Limits` field is non-nil and `<=` its ceiling (§5 R11); every non-`Static` `NetRule` has non-empty `IPs` unless offline mode was requested (§11); every `ExecRule.Path` is `Stat`-able; `Hash` is set. Side effects: bounded DNS lookups and file `Stat`/`Open`, no writes. Idempotent for a fixed `(c, m)` and fixed DNS/filesystem state; not idempotent across time if DNS answers change (intentional — that is what TTL re-resolution is for). Timeout: internal per-host budget, 3s default (§9); the normative signature takes no `context.Context`, so `Compile` cannot be cancelled mid-call — a caller needing cancellation races it in its own goroutine and discards a late result (safe: `Compile` holds no shared state).

**`(rt *RuleTable) Evaluate(a, tier) EvalResult`** — Pre: `rt` from a successful `Compile`; `tier` one `rt` could be compiled for (`Evaluate` does not itself check `tier <= ceiling`, that's `Compile`'s job — `Evaluate` just simulates a tier's resolution algorithm). Post: deterministic, side-effect-free. No error return: an `Action` malformed for its `Kind` yields `EvalResult{Verdict:"refused", Rule:"invalid-action"}` rather than an error, so `compile --test` reports a full table instead of aborting on one bad row.

**`Diagnostic.Error() string`**: `file:line[:col]: message [code]` (`:col` omitted when `Col == 0`), per `spec/identity/RUN-IDENTITY.md` "Messages". `Fix` is not part of `Error()`; the CLI prints it on the next line.

**`(c *Contract) Canonical() ([]byte, error)`**: deterministic re-serialization, used both to compute `contract_hash` and as the exact bytes `internal/ledger` writes to `contract.yaml` (§5 R13). Errors only on a `Contract` that was never successfully `Load`ed (defensive, unreachable on the `Compile` path).

## 5. Business rules

**R1 — Unknown fields are always errors.** `yaml.v3` `KnownFields(true)`, at any nesting level, applied *after* the `extends` merge too — a profile cannot introduce a field the merged version doesn't know. The load also refuses, each with a `schema` error, the shapes that would decode to something other than what was written:
- a null list element (a bare `-` or an unquoted `~`), which the typed decode dropped, so `deny_read: [~]` became `deny_read: []`, turning the built-in credential denies off, and `command: [~, x]` ran `x`;
- an explicit YAML tag, since `!!binary` is base64-decoded after the schema walk accepted the encoded text;
- a second YAML document, which was ignored;
- a document that expands past 100,000 nodes through aliases, which made the schema walk quadratic before yaml.v3's own limit applied.
- a value whose spelling reads as something else: a quoted number (`tokens: "5"`, refused with the unquoted fix rather than yaml.v3's "cannot unmarshal !!str"); a `cost_usd` that is not a plain decimal (`1_0`, read as 10; `0x1p4`, `NaN`) or is too small to represent (`1e-400`, read as 0); `version: 00` or `-0`, whose message names the spelling; and a `~user` path (`~root/x`, taken as a directory named `~root`), since only `~` and `~/` name the home directory.
- `net:`, `exec:`, `fs:`, `env.pass` or `env.deny` present with no value (nothing after the key, only comments under it, or an unquoted `~`), which parsed as absent: for `net:` and `exec:` absent is unrestricted (SEMANTICS §1), the opposite of what a section with its entries commented out looks like, and `compile` would print it like deny-all. The error says what the key read as and its fix names the explicit form (``write `net: {}` to refuse all, or remove the key``). `compile` prints `net unrestricted (no net: section)` and `exec unrestricted (no exec: section)` on the section line of a contract that leaves one out, and `compile --json` carries `net_unrestricted` and `exec_unrestricted` (always present, `RuleTable.NetUnrestricted`/`ExecUnrestricted`).
- The same rule covers every `limits:` key and `fs.deny_read`: `limits: {memory: , wall: , tokens: , pids: }` would parse each limit as absent, unbounded, and `fs.deny_read: ~` as absent, the built-in list only, while each reads like a value left out. Each is a schema error (`limits.memory: has no value and reads as if absent (unbounded), not as a value`); the fix names a value, `deny_read: []`, or removing the key. Pinned by `testdata/bad/null-limits.yaml`.
- The rule covers `mcp[].tools` and its `allow`, `deny` and `ask` (R16b): `tools:` with no value would parse as absent, the server off the relay, and `allow:` with none as every tool allowed.
- The rule covers the `limits:` section itself and `extends:`: `limits: ~`, or a `limits:` whose every key is commented out, would parse as absent, every limit unbounded; `extends:` with no value would parse as no profile. Each is a schema error (`limits: has no value and reads as if absent (every limit is unbounded), not as an empty section`); the fix names `limits: {}`, values for the limits, or removing the key. Pinned by `testdata/bad/null-limits-section.yaml` and `TestNullLimitsSectionIsRefused`.

`env: {pass: []}` now keeps its `pass: []` in `Canonical`, as `deny_read: []` does, so it no longer hashes like no `env:` section. A `deny_read` glob with `**` is refused, because `filepath.Glob` matched it one level deep only. A glob that expands says how many existing files it covers. An entry that names an existing file whose own name holds a glob character is that file.

**R2 — Not-yet-supported fields.** Consumed set, extending `docs/P0-DESIGN.md` §3.1: `version name extends command fs.{write,ask,ask_read,deny_read,watch,assurance} net.{allow,ask,http,assurance,listen,ingress,limits,dns,proxy} ask exec.{allow,deny,ask} env.{pass,deny,set} mcp models limits record tier capture io_uring gate`, plus `keyring` (added 2026-09-23: the kernel-keyring opt-in, SEMANTICS §1), `ipc` (added 2026-09-24: the System V IPC opt-in, SEMANTICS §1) and `setuid` (added 2026-09-24: a root tier's opt-out of `no_new_privs`, ADR 0033; `Compile` refuses it at tier landlock, `schema`, and warns `unenforced` at the root tiers, since a setuid binary can then make the agent root), and `keep_descendants` (added 2026-10-26: by default a run ends stop_grace after the agent's main process exits, killing what it left running and exiting with the main process's status; `keep_descendants: true` keeps the run going until every process of the agent's tree has exited, as all runs did before, for a main that is a launcher daemonizing on purpose; runtime-launch.md case 24). Everything else in `spec/agent/v0`'s schema (`exec.privileged`, `env.mask`, `docker`, `containers`, `prompt`, `skills`, `visibility`) is parsed but rejected with `Code:"not-yet-supported", Severity:"error"` **when non-empty**. "Non-empty": non-nil pointer to a non-zero struct, non-empty slice/map/string, `true` bool, non-empty `yaml.Node`. An explicit empty value (`docker: {}`, `skills: []`) is indistinguishable from absence and is **not** rejected, so a defensive profile doesn't break a P0 build. `fs.ask`, `net.ask` and the top-level `ask` mapping are implemented separately under R22; their scopes carry no ordinary kernel grants.

`net.http` requires explicit forwarder capture, an enforcing tier, one declaration per model host, and rule coverage of every listener. Its immutable matcher checks exact methods and segment path prefixes; see SEMANTICS §5. `net.assurance: kernel` additionally requires measured TCP, UDP and Unix admission hooks plus the strict client filter before agent release. Its default is `best-effort`; it is not an ingress or packet firewall.

**R3 — `Name` regex** `^[a-z0-9-]{1,40}$`; already systemd-unit-safe, no further transform needed. It is a YAML
string, as an `mcp` server's `name` is: an unquoted all-digit `name: 123` is an integer to YAML and to
agent.schema.json, and a `[schema]` error with the fix to quote it (amended 2026-10-25, `TestNamesAreYAMLStrings`);
`tego init` writes it quoted, so the contract it writes loads for every agent id (`TestInitWritesAContractThatLoadsForAnyName`).

The [network control contract](network-controls.md) defines explicit listeners, ingress, socket and packet
budgets, expiry and the authenticated DNS broker. The [proxy protocol contract](proxy-protocols.md)
defines declared model CONNECT, WebSocket and HTTP/2 grants and their accounting boundaries.

**R4 — `Command` non-empty**: `len(Command) >= 1 && Command[0] != ""`, at `Load` time.

**R5 — `extends` merge.** Resolved recursively, depth-bounded at 8 (E15), cycle-detected via a visited-name set on the call stack (E5). Order: profile first, contract on top. Per SEMANTICS §1: **list** fields (`fs.write`, `fs.ask`, `fs.watch`, `net.allow`, `net.ask`, `net.http`, `exec.allow`, `exec.deny`, `exec.ask`, `env.pass`, `env.deny`, `mcp`, `models`) concatenate, profile entries first; **scalar** fields (`command`, `limits.*`, `record`, `tier`, `capture`, `net.assurance`, `io_uring`, `keyring`, `setuid`) — contract wins if set, else profile's; `fs.assurance` is a scalar whose stricter value wins (`kernel` over `best-effort`, ADR 0041 D1 (a)), and a file's `best-effort` a profile's `kernel` outvotes is warned `redundant-rule` at that file's line (*added 2026-10-05*); `exec.assurance` merges the same way (*added 2026-10-19*, ADR 0048 (3) P2). `fs.deny_read` is the one list that **never loses entries from an extending contract**: it is the union of every profile's and the contract's own — explicit in SEMANTICS §1 because "contract overrides" here would be a security regression. A file's explicit `deny_read: []` is a list like any other in that union: it contributes no entry, so it leaves the merged list empty — which disables the built-in list (R6) — only when no other file in the chain declares an entry. When one does, the merged list is populated, the built-in list stays on, and `Load` warns `redundant-rule` at the `[]` that did nothing, never `deny-read-disabled` (fail-closed: honouring such a `[]` through a flag kept outside the schema would compile a merged contract no `agent.yaml` can spell, which `Canonical()` could not write down, so `contract_hash` and the ledger's `contract.yaml` would lose it, R13). An extending file cannot express "no built-in list" over declared entries, exactly as a single file cannot. `env.set` maps merge key-wise, contract wins per key. The `ask` mapping is retained as a YAML node: an explicitly written mapping replaces the inherited mapping as a whole; absent `ask` inherits it.

**Merge classes (R5).** *Added 2026-10-24 (ADR 0065).* The merge above is one loop over one table (`contractMergeRows`, `pkg/spec/agent/merge.go`): every key of the contract and of its sections, by its YAML name, has exactly one row naming its class, and a key added to the contract adds its row rather than editing the merge (`TestEveryContractKeyHasAMergeClass` fails for a key with none, `TestMergeTableRowsNameRealKeys` for a row naming no key, and `TestR5ListsEveryMergeClassRow` for this table drifting from the code). Every class carries each merged entry's origin, so a diagnostic still names the file and line the entry was written at. ADR 0065 fixes the class of every key the V1 packages add (and the rule between two parents of a list `extends`), so each adds only its row. *Amended 2026-10-24 (ADR 0065 D6):* the switches `io_uring`, `keyring`, `ipc`, `setuid`, `exec.anonymous` and `net.proxy.http2`, and `net.assurance`, stay `contract-wins`, so a profile's `true` (or `kernel`) is inherited and a contract's explicit value overrides it, where the V1 key `host_sockets` is `stricter` and a profile cannot turn it on; moving them is a behaviour change left to a follow-up package, and a boolean key added as `contract-wins` that D6 does not list fails `TestContractWinsSwitchesAreRecorded`.

| Class | Keys | Rule |
|---|---|---|
| `section` | `fs`, `net`, `net.limits`, `net.dns`, `net.proxy`, `exec`, `env`, `limits`, `reason` | a mapping whose keys merge by their own rows; a pointer section no file wrote stays absent (R6's tri-state) |
| `concat` | `fs.write`, `fs.ask`, `fs.ask_read`, `fs.watch`, `net.allow`, `net.ask`, `net.http`, `net.listen`, `net.ingress`, `net.dns.allow`, `net.dns.types`, `net.proxy.websocket`, `net.proxy.connect`, `exec.allow`, `exec.deny`, `exec.ask`, `exec.privileged`, `env.pass`, `env.deny`, `env.mask`, `mcp`, `models`, `credentials`, `skills`, `visibility` | the profile's entries, then the contract's; absent only when no file wrote the key, and a present empty list stays present |
| `union` | `fs.deny_read`, `fs.deny_write` | every file's entries, the profile's first; no file's rule removes an entry another file declared (above) |
| `keymerge` | `env.set` | merged key by key, the contract's value winning for a key both files set; a key two parents of one list set differently is `extends-conflict` (ADR 0066 D3) |
| `contract-wins` | `command`, `net.assurance`, `net.limits.connections`, `net.limits.pending_connects`, `net.limits.bytes`, `net.limits.datagrams_per_second`, `net.dns.mode`, `net.dns.max_stale`, `net.dns.max_parallel`, `net.dns.cache`, `net.proxy.http2`, `net.proxy.max_streams`, `net.proxy.max_tunnel_bytes`, `net.proxy.max_frame_bytes`, `net.proxy.tunnel_idle`, `net.proxy.tunnel_wall`, `exec.anonymous`, `limits.cpu`, `limits.cpu_weight`, `limits.memory`, `limits.memory_high`, `limits.pids`, `limits.tokens`, `limits.cost_usd`, `limits.wall`, `limits.stall_after`, `limits.repeats`, `record`, `tier`, `capture`, `io_uring`, `keyring`, `ipc`, `setuid`, `harness`, `reason.reads`, `gate`, `prompt`, `docker`, `containers`, `ask` | the contract's value, whole, when it writes the key, else the profile's; `gate` and `ask` read a contract's empty mapping as a reset and a profile's as absent, `docker` an empty mapping as absent in either file |
| `stricter` | `fs.assurance`, `fs.reads`, `exec.assurance`, `host_sockets`, `keep_descendants` | an ordered value set (`kernel` over `best-effort`; for `fs.reads`, `held` over `auto` over `direct`; for `host_sockets` and `keep_descendants`, `false` over `true`): the stricter written value wins, the contract's on a tie; a value the row marks loosening counts only when the top-level contract writes it, where it overrides, and a profile's is ignored with the warning `profile-cannot-loosen` at its line (`fs.reads` marks `direct`, ADR 0069; `host_sockets: true` is another value marked loosening, so only the top-level contract opens the host's sockets, ADR 0070; `keep_descendants: true` the third, so only the top-level contract keeps a run going for what its agent left running) |
| `refused-in-profile` | `revision`, `live` | the top-level contract's alone: a profile that sets the key is an error at its line (`[schema]`; `[live-in-profile]` for `live`, ADR 0125), fix "set <key> in the top-level contract" |
| `own` | `version`, `name`, `extends` | the top file's own value and position, never inherited; a profile writes its own (`extends` names the profile's parent, already merged beneath it) |

**List `extends` (R5).** *Added 2026-10-24 (ADR 0066).* `extends` is one profile name or a list of 1 to 8
(`agent.ExtendsList`; `MaxExtendsList`). A profile name is `/`-separated segments of lowercase letters, digits, `.`,
`_` and `-`, the first opening with a letter or digit, and no segment is empty, `.` or holds `..`, so each profile file
has one spelling, which merge-once and the cycle check compare (`TestProfileNameHasOneSpelling`, the JSON Schema's
`profileName` the same pattern; *amended 2026-10-24*: `base/./py` read the file
`base/py` names, and `extends: [base/py, base/./py]` merged it twice). Each parent is resolved fully first, merged with its own parents, then the
parents are combined left to right by ADR 0065 D4 and the file naming the list goes on top: `concat` and `union` lists
take the first parent's entries, then the next one's, then the file's own; a `keymerge` key (`env.set.<NAME>`) two
parents set to different values is an `extends-conflict` as a `contract-wins` key is, one value keeping the first
parent's origin (`TestExtendsEnvSetKeyConflict`; *amended 2026-10-24*: a later parent's
value won silently, though `env.set.PATH` decides what an exec name resolves to and a proxy variable where a connect
goes); `stricter` keeps the stricter of the parents' values (neither parent's loosening value counts, each
being a profile); a `contract-wins` key two parents write with different values is an `extends-conflict` error at both
parents' lines, naming both files, unless the file naming the list writes the key, which then decides. Only that file
settles it: a profile whose own parents conflict is in error whatever a contract above it writes. Two values differ when
their canonical encodings differ (decoded values: `wall: 60s` and `wall: 1m` are one value, `[a, b]` and `[b, a]` are
two), and a key two parents write with one value keeps the first parent's origin. A profile reached twice merges once,
at its first position (`TestExtendsDiamondMergesOnce`); a later reach adds nothing to the merge. Two names one source
serves from one file, a built-in preset and its pin to the revision that name is (`tego/no-secrets` and
`tego/no-secrets@1`, ADR 0068), are one profile: the file merges once, under the first name, which alone
`Contract.Profiles()` lists, and a list naming both warns `redundant-rule` once at the second name's line, as a
repeated name does (*amended 2026-10-25*, ADR 0068: the bytes merged twice, and every repeated entry
warned at its line inside the built-in file; `TestExtendsNameAndPinOfOneFileMergeOnce`). The conflict check
compares each parent's whole view: the parent resolved in full, every ancestor counted whichever entry reached it
first, its scalar keys only, so each list has one verdict under every order and every contract above it, and a branch
overriding a value a shared ancestor set conflicts with a branch inheriting it (`extends: [a, b]` and `[b, a]` alike,
ADR 0066 D3; `TestExtendsVerdictNeverDependsOnOrder`, `TestExtendsConflictInAProfileWhateverComesFirst`; *amended
2026-10-24*: `extends: [e, b]`, with `e` extending `c` and `b` extending
`[c, d]`, hid `b`'s conflict between `c` and `d`, and after a first fix the same held one level deeper, where the check read a
profile without the ancestors an earlier entry had merged). `Contract.Profiles()` lists every profile merged, in merge
order (deepest first, a list left to right), with the kind of source that served it and the sha256 of its bytes, which
`run_start.profiles` records (spec/record/v1, `record_minor` 15). An entry two files of the chain both declare merges
silently; one file's own repeat still warns `redundant-rule` (E24, R16). The entries are kept, so the canonical form
(R13) of every contract that extends one profile is what it was.

**Built-in profiles (R5).** *Added 2026-10-24 (ADR 0066).* A name beginning `tego/` is in the reserved built-in
namespace: it resolves only through the built-in sources the CLI's composition root registers on an
`agent.ProfileChain` (`internal/cli` `profileSources`, one constructor every load site uses), never through a
profiles directory, and a `ProfileSource` that is no `ProfileChain` is a profiles directory and serves no `tego/` name.
A profiles-directory file under `tego/` that such a name would have read is never read: the `extends` naming it is the
error `shadowed-builtin` at its line, naming the file, fix "move it out of tego/ and extend it by its new name, or remove
it to use the built-in profile" (`TestBuiltinNamesNeverReadTheProfilesDirectory`, where the directory source counts its
reads). A `tego/` name no built-in source holds is `extends-not-found`, saying it names tego's own profiles. A built-in
profile extends only built-in profiles: a name outside `tego/` in its `extends` is `extends-not-found` at that line and
the profiles directory is not read for it (`TestBuiltinProfileExtendsOnlyBuiltins`; *amended 2026-10-24*: such a
name was resolved through the directory, so a directory file could supply part of a preset). This
package ships no built-in profile; a package that does registers its source in `internal/profilesrc.Chain`, which `internal/cli/profiles.go` calls. *Amended 2026-10-25 (ADR 0068):*
the presets are registered: `tego/no-secrets`, `tego/no-prod` and `tego/repo-only-writes`, each its newest revision,
and `tego/<preset>@<n>` revision `n` alone. A name under `tego/` may end in such a pin (`@` and a revision from 1, no
leading zero, at most nine digits; the JSON Schema's `profileName` the same pattern), and no other name takes one
(`TestProfileNameHasOneSpelling`). A built-in source may list the names it serves (`agent.ProfileNamer`), and a
`tego/` name no built-in source holds is `extends-not-found` with a fix listing them, sorted
(`TestUnknownBuiltinNameListsTheKnownOnes`), so a mistyped preset or a revision that does not exist is answered with
the names there are.

**R6 — `fs:` defaults, tri-state via `*FSSection`.** `c.FS == nil` ("no `fs:`"): no `write`, `watch` or declared `deny_read` entry is compiled — only the four implicit `FSRule`s (R9) plus the built-in `deny_read` list, so no path is writable and every write is refused as under `fs: {}`, named `unmatched` rather than by the implicit `/` entry; reads are allowed outside the `deny_read` entries. Writes are not unrestricted without `fs:`: the Landlock ruleset handles the write side whatever the contract says (enforce-landlock I4), `Evaluate` refuses the write, and the supervisor records `write-outside-contract`; the Landlock tier cannot build an unrestricted write side without making the implicit entries writable (SEMANTICS §1 gives the reason and the condition under which the unrestricted reading becomes buildable). The built-in list is **not** conditioned on the presence of an `fs:` key: it hangs off `deny_read`'s own tri-state (SEMANTICS §1, "no `deny_read:` → the built-in list applies"), and a contract with no `fs:` has no `deny_read:` either. Only the explicit `deny_read: []` disables it, which is the route that already warns (`deny-read-disabled`, R4); the tri-state is read off the **merged** contract, the same value `Canonical()` serializes, so under `extends` the `[]` disables the list only when the merged list is empty (R5); tying the list to `fs:` instead made the credential protection vanish silently on the most common contract shape (`version`/`name`/`command`). `c.FS != nil && len(Write) == 0` (`fs: {}` or `fs.write: []` — distinguished by the non-nil pointer): compiles an implicit deny-all-writes rule at `/` (reads stay allowed). A populated `Write` compiles one `FSRule{Kind:"write"}` per entry (R7). `deny_read`'s own tri-state has three arms, not two, and the third is the one that matters: a **populated** `deny_read` compiles the declared entries **and** the built-in list, never the declared entries alone. "Only the explicit `deny_read: []` disables it" is the whole rule, and R5 already makes `deny_read` a list that never loses entries (with `fs.deny_write`, ADR 0071); compiling a populated list as a *replacement* meant a contract that added one project path silently stopped denying `~/.ssh`, `~/.aws`, `~/.netrc`, `~/.gnupg`, every credential file and the `.env` scan, with no diagnostic — a worse fail-open than the no-`fs:` one above, because an author reaches it on purpose. A declared entry naming a path the built-in list also covers yields one rule, not two (the built-in one is skipped), so the print and the ledger's `rule` field do not double it. The built-in list itself is one row per credential *class* seen in a published attack rather than a taste-based selection (nx "s1ngularity", August 2025: SSH keys, `gh` tokens, `~/.npmrc`, `.env` files), at the granularity the secret lives at — the file for `~/.npmrc`, `~/.git-credentials`, `~/.docker/config.json`, `~/.kube/config`; the directory for `~/.config/gh` and `~/.config/gcloud`, which hold several files each. A row matching nothing costs nothing: a non-existent entry is skipped without a diagnostic. *Amended 2026-10-05 (ADR 0043):* where a run of the table can land at tier cgroup or bpflsm, `Compile` also records the built-in list's `.env` scan and every whole `deny_read` glob whose final component is a literal (two bytes or more) or a literal of three bytes or more and one `*` as name entries, `RuleTable.NameDeny` (the built-in pair `.env` exact and `.env.` as a prefix but the scan's example files, scoped to the scan's roots less a root its sibling covers; a declared glob scoped to its literal base, a glob that matched nothing included), within the plane's caps (64 entries and 64 rows, 8 arms a row, 8 scopes, 4 prefix lengths, 8 leads; an entry that does not fit, or whose key collides, is left out whole and keeps its expansion alone), with the facts ADR 0043 D6 compacts a covered row on (`FSRule.Regular`, `Nlink`, `FileMountPoint`, `DirCaseExact`, `NameDenyRule.BindExposed`). They are compile output, not contract input; tiers `cgroup` and `bpflsm` apply them (the plane's name check, and the fanotify fallback best effort), tier `landlock` keeps the expansion unless the run holds its reads (ADR 0069), and `compile` prints them with where they apply (2026-10-27, ADR 0043 C11). The built-in `.env` scan and the entries share one predicate and one list of dependency directories (`isEnvFile`, `IsEnvSkipDir`; `FuzzEnvNameRuleMatchesScan`). A write entry declared in the top-level contract file at an existing file the `.env` scan finds drops it from the built-in list, with a warning naming both, where it was a contradiction (ADR 0043 D3, R20's parallel); it is recorded as an exemption (`RuleTable.NameExempt`), not warned redundant, and one from a profile stays the contradiction (`TestWriteEntryDropsBuiltInEnv`, `TestProfileWriteEntryKeepsTheContradiction`). *Amended 2026-10-25 ([ADR 0067](../adr/0067-agent-token-stores-and-credential-rows.md)):* the list also holds the agents' own token stores (`~/.claude/.credentials.json`, `~/.claude.json`, `~/.claude/backups` (Claude Code's copies of `~/.claude.json`), `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.gemini/.env`, `~/.gemini/mcp-oauth-tokens.json`, `~/.copilot/config.json`, `~/.copilot/mcp-oauth-config`, `~/.copilot/mcp-secrets`) and the stores of the tools an agent runs beside (`~/.azure`, `~/.config/op`, `~/.password-store`, `~/.pypirc`, `~/.cargo/credentials`, `~/.cargo/credentials.toml`, `~/.terraform.d/credentials.tfrc.json`, `~/.vault-token`, `~/.pgpass`), each kept only where the tool's vendor names the location (docs/spec/builtin-deny-read.md cites each and names the rows left out, `~/.config/github-copilot` among them). *Amended 2026-11-02:* the long tail of credential stores joins the list under the same rule: the desktop keyrings (`~/.local/share/keyrings`, `~/.local/share/kwalletd`), MySQL's `~/.my.cnf` and `~/.mylogin.cnf`, `~/.s3cfg`, `~/.boto`, rclone's `~/.config/rclone/rclone.conf` and `~/.rclone.conf`, the RubyGems and Composer credential files (`~/.gem/credentials`, `~/.local/share/gem/credentials`, `~/.config/composer/auth.json`, `~/.composer/auth.json`), Maven's master password `~/.m2/settings-security.xml`, and the doctl, hub, glab, flyctl, Supabase and OCI CLI stores (`~/.config/doctl/config.yaml`, `~/.config/hub`, `~/.config/glab-cli/config.yml`, `~/.fly/config.yml`, `~/.supabase/access-token`, `~/.oci`); `~/.m2/settings.xml` and `~/.gradle/gradle.properties` are left out, since each configures every build of its tool. With them `~/.local` and `~/.local/share` join the directories the Landlock ruleset enumerates on most machines. The run's own harness is not excepted: no rule keys on the command name, and a harness gets its credential from a variable its profile passes (`ANTHROPIC_API_KEY`, or `CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`; `CODEX_API_KEY`) with its state in the project (`CLAUDE_CONFIG_DIR`, the launcher's `CODEX_HOME`). Every row also joins `RuleTable.DenyReadPatterns` whether it exists or not, so a person's alternate naming it, for a held read or a held write, is refused by name (ADR 0057 D2; `TestTokenStoreRowsJoinTheAlternatePatterns`); the patterns refuse alternates only. A row absent at compile compiles no rule and no diagnostic, but is recorded in `RuleTable.AbsentDenyRead` with the first name on its path missing at compile (`AbsentRow.At`; for a row that is a symlink leading nowhere, on the path the link leads to; less one a write or exec.allow directory entry covers, or that lies beneath a regular file), and the Landlock ruleset enumerates that name's directory with the name left out, so a file created at the row during the run, a login in another terminal, is refused for a direct read wherever that ruleset applies: tier landlock, and tiers cgroup and bpflsm, which compose it; the ledger and `Evaluate` answer such a read refused, `read_denied`, by the row (ADR 0067 D3, enforce-landlock E9, *amended 2026-10-25*; `TestAbsentRowsAreRecordedForLandlock`, `TestTokenStoreCreatedDuringRunIsRefused`, *amended 2026-10-25*: the patterns were said to refuse a direct read of a file created later, and none did). A row inside a write entry is not refused when created later: the write grant reaches it.

**R6a — Tego's own files are read-denied, always** (added 2026-09-24). Whatever `deny_read` says, `deny_read: []` included, `Compile` adds a built-in `deny_read` entry for tego's own directory (the one holding the chain anchor, `~/.tego`: the anchor, the machine config, the price table, the profiles, tego's own log), `~/.tego` under the compile's home where the anchor is elsewhere (amended 2026-10-16: an adoption compiles against the agent owner's home while the anchor and ledger are the adopter's, ADR 0055 Decision 5, and the owner's own records stayed readable; R10 refuses a write entry at or inside it, amended 2026-10-16, and under one above it, the home, it is unenforced at tier landlock like any nested deny), the ledger root, the host state (`/run/tego`, ADR 0034), and the machine config's price table and profiles directory by their resolved paths wherever `prices:` and `profiles:` put them (the price table as the file it is), each when it exists and is not inside one already denied. R10 had kept the agent from writing them and nothing kept it from reading them: from inside any run the agent read every run's `events.jsonl` and blobs — argv, headers and, under `record: full`, model bodies — so a stricter run could read what a looser one recorded, around its own `deny_read` (reproduced at tier 1 on 6.17 and 6.8). R10 also keeps every write entry off these paths, so no tier leaves them unenforced. A deny attaches to a path that exists; `tego run` makes the ledger root and the anchor's directory before it compiles. A directory that also holds what the run needs — the contract's directory, the working directory, the home, or a write entry, as a ledger root of `/tmp` or of a data disk shared with projects does — is not denied, and `Compile` warns `ledger-readable`, naming it: denying it would deny the agent its own project. An implicit entry (R9) is a write guard and grants no read, so one nearer than such a deny (the ledger root beneath `~/.tego`) does not re-allow a read in `Evaluate` or in the supervisor's advisory verdict; tier 2's open decision and Landlock already read it so. Nor does it in tier 2's recorder, which infers the verdict from `RuleTable.FSDecider`, the chooser `Evaluate` decides by; the nearest entry only names the event. The reason channel the run directory held, `last-refusal.json`, reaches the agent through `TEGO_REASON` (REASON-CHANNEL §2).

**R7 — `fs` path resolution.** Every `write`/`watch`/`deny_read` entry must name an existing path, **except** `write`, which may be missing (the runtime creates it) — `Compile` still requires the *parent* to exist, else `path-missing`. `Compile` does **not** check that the parent is writable by the invoking uid: neither `spec/policy/SEMANTICS.md` §2 ("`compile` (unprivileged) checks existence and prints each entry's mount, filesystem type and device") nor `docs/P0-DESIGN.md` §2.1 ("every `FS` path exists or is a `write` directory that `run` creates") state a writability check, and `compile` commonly runs unprivileged while the run itself executes under a different uid (tier 2, `sudo`) — a uid-based check at compile time would misfire on a perfectly valid tier-2 contract. Creating the directory and confirming it is writable is `run`'s job, not `compile`'s. Identity is never `(device, inode)`; `Compile` only confirms existence and records mount/fs/device metadata for the `compile` print (warns on a mount point, overlay layer, or btrfs). REFER-rule checking (rename/link may not escape to a less-restrictive rule) is `Evaluate`-only (`Action.DestPath`) — there is no live rename at compile time to check.

**R8 — `exec.allow` resolution.** *Amended 2026-10-06 (ADR 0048 (1)):* an entry is classified by its text alone. One with no space or tab is one word exactly as written, quote characters included (`/home/me/O'Brien/bin/tool` is that path), a path or a bare name, resolved as below; one whose quotes hold all its spaces is the one word inside them; one with unquoted spaces is a command pattern (R25), whose command word is resolved as a bare entry of that word would be and grants that image under the rule `exec[<command word>]`. A path holding spaces is quoted as a whole (`'/opt/My Tools/run'`); an unquoted one that names an existing file is an `exec-rule` error whose fix says to quote it, and a command word that is a directory is an `exec-rule` error (a directory takes no words). A path entry resolves via `filepath.Abs` against the run's cwd (§11); a bare basename resolves against the **run's effective `PATH`** (not the compiler's own), walking left to right and skipping a non-regular or non-executable candidate (mirroring `execve`'s own fallthrough), taking the **first** match. An empty or relative `PATH` element names a directory under the run's cwd (execvp's rule, with no `~` expansion), so the rule's path is absolute. Exhausted `PATH` → `exec-not-on-path`, `Fix` lists every directory searched. `Command[0]` is implicitly added to the resolution set even when `exec.allow` omits it, and so is **every declared `mcp[].command[0]`** — `spec/policy/SEMANTICS.md` §4 lists, among what the Landlock tier's `compile` grants `EXECUTE|READ_FILE` on: "the agent command and its `#!` interpreter; every declared MCP `command`," and the annotated example (`spec/agent/v0/example.retriever.yaml`) documents the same thing directly ("started by the run; its binary gets exec rights implicitly"). An `mcp[].command[0]` resolves exactly like `Command[0]` — path or `PATH` basename, same failure code (`exec-not-on-path`, E37) — so a contract with an `mcp:` entry never needs its binary separately listed in `exec.allow` to start under the Landlock tier. Each resolved binary — `Command[0]`, `exec.allow` entries, and `mcp[].command[0]` entries alike — is opened read-only, its ELF header read, `PT_INTERP` extracted into `ExecRule.Interp` (empty for static/non-ELF, E14/E16) — used by the Landlock tier to also grant the loader `EXECUTE|READ_FILE` (SEMANTICS §4); root tiers ignore `Interp`. "The agent command" is the command the run execs. With no command after the contract, `tego run` execs the contract's `command:`, and its `Command[0]` is the implicit entry above. A command given after the contract (`tego run a.yaml -- <cmd>`) is the launching user's choice, not the agent's: `run` compiles its `argv[0]` as a second implicit entry, source `command`, for that run only (`agent.WithRunCommand`), resolved as the launcher will exec it (a bare name another entry names by basename adds nothing; otherwise the run's `PATH`, or the cwd for a path), with its loader and a script's `#!` interpreter (without it, the command would be refused at `execve`, exit 126, unless `exec.allow` named it). A name found nowhere adds nothing and no diagnostic, so the run still ends at `execve` with exit 127. `compile` knows no command line: its table, `compile --test` and the contract hash never include it; `run_start.command` records what the run executed. The grant covers every exec of that file by any process of the run, for the whole run, not only the launcher's first exec, exactly as the contract's own command's entry does. It is resolved after every entry the contract declares (`command`, `mcp[].command[0]`, `exec.allow`), so a bare name one of them names by basename runs that entry's file and adds nothing: an `exec.allow` that pins `/opt/py/python` keeps `tego run a.yaml -- python` on the pinned file, not `PATH`'s python. A bare name found on the run's `PATH` is granted as the absolute path it resolved to, never matched by basename (`ByName`), since tier 3 admits a by-name entry for any file of that name, one the agent writes under a `write` entry included; a script's `#!` interpreter, and `env`'s argument, are granted as they are for the contract's own command, the argument by name when it is a bare name. The rule's position is the command line (`Pos.File` `<command line>`), not line 1 of the contract. The contract hash does not cover the grant, so `run_start` records it as the optional `run_command_grant` (the absolute path; absent when the run execs the contract's command or a declared entry already covers the one given), which `tego events` and `tego status` show, and `tego drift` recompiles the run's contract with it (falling back to `run_start.command[0]` only for a ledger that predates the field, `run_start.record_minor` below 1: at or past it an absent grant means nothing was granted), so a run started with a command-line command does not drift.

**R8a — no `/proc` exec entry** (*added 2026-10-16*). An exec entry — `Command[0]`, an
`mcp[].command[0]`, an `exec.allow` entry or a command pattern's command word — whose absolute path is under `/proc`,
whose symlinks lead there (`/dev/fd/N`, `/dev/stdin`, a link the author made), whose walk crosses a directory on a
procfs mounted elsewhere, or a bare name `PATH` finds through such a directory, is an `exec-proc` error naming the
spelling that reached `/proc` (`config.ThroughProc`, a walk over `Lstat`/`Readlink` bounded at 40 links, so a
magic link is judged by its name and never followed). The walk resolves as the kernel's lookup does (*amended
2026-10-16*): a link's target goes in front of the components still to walk, as written, and `..`
drops the last component of the prefix already resolved, which holds no link; every resolved prefix is tested. It
first joined and cleaned a link's target lexically, so with `s/b -> /` and `s/a -> b/../proc` the entry
`s/a/self/exe` walked to `s/proc/self/exe`, missed, and compiled to tego's own binary, which the kernel reaches by
following `b` first. An ELF entry whose loader (`PT_INTERP`) is or leads through a `/proc` path is the same
`exec-proc` error (*amended 2026-10-16*): the loader is granted where tego's own process resolves
it, by Landlock's `holdLoader` and by tier 2's allow list, so a binary patched to name `/proc/self/exe` compiled and
granted tego's executable; Landlock's `Prepare`, which reads the ELF again, refuses such a loader too
(`ErrLoaderRefused`, enforce-landlock R5). A `/proc` path names a file relative to the process that opens
it: `compile` resolves it in tego's own process, where `/proc/self/exe` is tego's executable, and the run's
`O_PATH` pin in the launcher is the same file, so a contract whose only entry was `/proc/self/exe` let the agent run
`tego version` and refused `/usr/bin/id`. A program that re-executes itself through `/proc/self/exe` (Codex does,
before every command) needs no entry for it: the kernel's exec of `/proc/self/exe` reaches the program's own file,
which its own entry grants. Refused rather than warned: there is no reading of such an entry that grants what the
author meant, and a warning would leave a grant of tego's own binary in a table that compiles. Rejected: resolving
the path and granting the file it reaches (that file is tego's, here); refusing only `/proc/self/` (`/proc/<pid>/`
and `/proc/thread-self/` name another process's files the same way). `tego run`'s command-line command
(`WithRunCommand`) is not an entry and is not checked here.

**R10a — tego's runtime directory, and the run's own `CODEX_HOME`** (*added 2026-10-16*). Every
unprivileged run keeps a private directory, `$XDG_RUNTIME_DIR/tego/<run id>` (`0700`): its generated `CODEX_HOME`
(capture-derive.md R19b) and its last-refusal mirror (`TEGO_REASON`). (1) A declared `fs.write` or `fs.ask` entry
that is tego's runtime parent, `$XDG_RUNTIME_DIR/tego`, holds it, or lies inside it (another run's directory, or
any run's, since the run id is not known at compile) is a `contradiction`, compared resolved on both sides as R10's
targets are. The parents protected are every one `config.RuntimeDirBases` names (*amended 2026-10-16*;
*amended 2026-11-02*: the list moved from `internal/runtime` to `pkg/spec/config`, so the dashboard's rule service
links the launcher's list instead of keeping a copy): the invoking user's logind directory, `/run/user/<uid>/tego`
(uid `config.InvokingUID`, `SUDO_UID` under sudo), whatever the environment says, and `$XDG_RUNTIME_DIR/tego` when the
variable is absolute and names another. `compile`, `run`, `drift`, `init` and `rule`, and the dashboard's rule service,
pass them to `agent.WithRuntimeDir`, each parent joins `RuleTable.OwnState`, and
the launcher checks the same parents at every euid before making anything (`ErrRuntimeDirWritable`, exit 125), since
compile may have seen another environment. The first version protected only `$XDG_RUNTIME_DIR/tego`, and the
launcher checked it after its returns for a root launcher and for an unset variable: under plain `sudo` (which resets
the variable), cron, or ssh without `pam_systemd`, a write entry over `/run/user/<uid>/tego` compiled, ran, and
rewrote another run's `config.toml` and `last-refusal.json` there. A runtime directory the user set elsewhere for
another session is not known to this one and stays unprotected here (an open condition; logind's is where every
login session's runs keep theirs). Refused rather than warned: such an entry hands the agent every other run's
`CODEX_HOME` and refusal file, and the run's own needs no entry. (2) The run grants its own `CODEX_HOME` itself: a write entry on exactly that
directory, `Access` the write set, rule `fs.codex_home[<path>]` (`FSRule.Runtime` = `agent.CodexHomeGrant`), added
to the run's table before `Prepare` (runtime-launch.md §4.1 step 3) so every tier enforces it, never to the compiled
table (I4), recognised by `IsRuntimeRule` (drift, the gate's `Declared`), listed in `run_start.runtime_grants`
beside the capture listeners and the DNS broker's socket, and skipped by `tego learn`. The grant is made only while
the path, unfollowed, and its resolved spelling are still the directory the launcher made (same device and inode,
no link; the directory opened `O_NOFOLLOW` and `config.toml` created relative to it), so a swap of `codex/` for a link
between the two cannot move the grant (*amended 2026-10-16*). The identity is carried to the point
of use (*amended 2026-10-16*): the grant holds the directory's device and inode
(`FSRule.RuntimeDev`/`RuntimeIno`), and Landlock's `writeEntry`, which opens the path following links, compares
the descriptor it is about to grant and refuses another directory (`ErrRulesetBuild`), so a swap of `codex/` or of
`<run id>/` between the grant and `Prepare` moves nothing. And the launcher uses the runtime directory only while no
other user can change its path: `$XDG_RUNTIME_DIR` must not be writable by group or others unless it is sticky, and
`$XDG_RUNTIME_DIR/tego`, not followed, must be a directory of the launcher's euid that only it can write
(`ErrRuntimeDirUnsafe`, exit 125, for a run whose Codex is to be routed; a run with no openai listener goes on with no
runtime directory and no `TEGO_REASON` mirror, as with no `XDG_RUNTIME_DIR`, and says so in the own log). The
`<run id>` directory the launcher then makes (`0700`, by its euid) must be such a directory too, for every run: only a
race can make it otherwise, and every run is refused for it, `ErrRuntimeDirUnsafe` (*amended 2026-10-17*: this said the `<run id>` check, too, refused only a routed run).
The launcher's shutdown removes the `<run id>` directory, and when the launcher died before it (`SIGKILL`, the OOM
killer, a crash) the next unprivileged launch under the same parent does (*amended 2026-10-19*;
until then nothing did, and the `CODEX_HOME`, `auth.json` with a typed key included, stayed until logout, or for good
under an `XDG_RUNTIME_DIR` on disk): the launcher holds an exclusive `flock` on `<run id>/.lock` for the run's life,
makes the directory as `.new-<run id>` and renames it into place (`RENAME_NOREPLACE`) only once it is locked, and each
launch first removes every `<run id>` directory there whose lock nobody holds, each checked, unfollowed, as a
directory of its euid that only it can write. A directory with no lock file (an older tego's) is left alone, since
nothing says whether its run lives; a run under another `XDG_RUNTIME_DIR` sweeps its own parent, not this one; and
until a launch sweeps it the directory is readable as the open read condition says. `rm -r
$XDG_RUNTIME_DIR/tego/<run id>` removes it by hand. Asking the ledger whether the run lives was rejected: runs of one
user may record into different ledger roots, and the parent is shared by all of them.
A link at `$XDG_RUNTIME_DIR/tego` is therefore no longer followed, where it was made through before. A run is refused
(`ErrCodexHomeExecutable`, exit 125, `contradiction`) when an `exec.allow` or `exec.ask` directory entry covers the
`CODEX_HOME`, by declared and resolved spellings: every file the agent wrote there would run, the E38 whole-list
bypass, and compile's `exec-writable` check sees only declared write entries; compile warns `exec-writable` on an
exec directory that holds or lies in a protected runtime parent, since it cannot tell whether the run will route
Codex (*amended 2026-10-16*). In a deny-list run (`exec:` with no `allow` key, ADR 0048 (1)) images
are unrestricted and Landlock adds `EXECUTE` to every read and write set, so the grant would be a directory the agent
writes to and runs from: a copy of a denied program under another name is not that program to the command rules
(*amended 2026-10-16*). The grant is not the only way to run such a copy, which this text said it was
until a later amendment the same day: a deny-list leaves images unrestricted at every tier, so a
copy written into a memfd (with or without a write entry), or into a file the agent could write, opened and then
deleted (the `CODEX_HOME` included), runs as an image with no name (allowed `unmatched`, `fileless`), and an agent
can map a program's own file into its process and run that code with no exec at all; compile's `exec-rule-coverage`
warning says so on every deny-list. The supervisor nonetheless refuses, `exec-not-allowed` under the rule
`codex-home-exec` and answered `EACCES` by the loop, an exec whose
image lies in the `CODEX_HOME`, judged where the kernel's open lands (a symlink there to a program elsewhere, such as
Codex's own `tmp/arg0` links to its binary, is that program and runs), and a directly-invoked loader's program there
(`ld-linux-x86-64.so.2 $CODEX_HOME/copy`). Where the open lands is the kernel's own spelling of the image (the
readlink of the walk's descriptor), whether or not the supervisor can walk that spelling back to the same file in its
own view (*amended 2026-10-17*): it was judged on the exec's spelling whenever that walk failed,
so a copy in a directory of the `CODEX_HOME` that the agent had made unsearchable, run through `/proc/self/fd/<n>`
directly or as the loader's operand, was no path there and ran. A match here can only refuse, and tier 1's agent
shares the supervisor's mount view (namespace creation is refused). Root launchers write no `CODEX_HOME`, so tier
landlock's supervisor is the one place this is needed. A restricted run refuses such an exec `unmatched` already, and
a run with no `exec:` section denies nothing (SEMANTICS §1), so neither changes. What the refusal holds is narrow: a
copy linked in the `CODEX_HOME`, run by its path or through a descriptor, directly or through a loader; the same copy
opened, deleted and run through its descriptor is fileless and runs, as a memfd copy does. Residuals, as under every deny-list: a script there run as
`sh script` is read, not executed; a `#!` line naming an interpreter there needs a script written elsewhere, which only
a write entry elsewhere allows; and the fileless and mapped copies above. Compile's `exec-rule-coverage` warning
discloses them on every deny-list (beside `fs.write` it names the copy written to disk). Rejected: refusing the launch
(no deny-list contract could route Codex); a compile warning or a `gap` line alone (a copy run by its path from the
grant is what an agent's ordinary `cp` and exec reach, with no memfd or descriptor trick, so the grant would add that
spelling to the run); withholding `EXECUTE` from the grant alone (any read entry above the directory grants it under
a deny-list, and Landlock does not govern a loader's `mmap`); and giving every deny-list run a restricted run's memfd
arm and fileless refusal (the second option): it refuses every `memfd_create` on a kernel without
`MFD_NOEXEC_SEAL` and every unnamed image an agent's runtime makes, in the mode meant to rule named commands only, and
the program's own file would still map executable where it lies (ADR 0027's stated residual, in a restricted run
too). A contract that needs copies kept from running restricts images with `exec.allow`. The agent may rewrite the
`config.toml` there, tego's `openai_base_url` included; that routes nothing around the forwarder, since under
`capture: forwarder` the `models[]` guard refuses a model's own addresses whatever `net.allow` says (E27,
capture-derive R38). (3) With an openai listener (Codex to be routed) and no absolute `XDG_RUNTIME_DIR`, the launcher
refuses the run, exit 125, naming the fix (log in through a session that sets it, export an absolute directory only
the user can write, or drop the openai endpoint), where it used to route nothing and say nothing
(`ErrNoRuntimeDir`). That refusal covers unprivileged launchers only: a root launcher writes no `CODEX_HOME` (its
runtime directory would be one the dropped agent cannot enter, capture-derive.md R19b), so its run goes on with Codex
unrouted and writes `gap what=capture why=codex-unrouted binary=codex` right after `run_start` (*amended 2026-10-16*; it was a line in tego's own log only). It fails closed: the `models[]` guard refuses Codex's own calls
to the model (E27). Refusing the root launch was rejected: the openai listener also serves every OpenAI SDK that reads
`OPENAI_BASE_URL`, which a root run does route. Rejected: warning on a write entry over the parent (a warning leaves the grant in place);
a contract-chosen `CODEX_HOME` path (rejected: the contract author would name a path two concurrent runs
share); a deny_read over the parent (it would deny the run's own mirror and `CODEX_HOME` reads, which the agent
needs, and is left as an open condition: another run's agent of the same uid can still *read* this run's private
directory where no `deny_read` covers it, the `auth.json` holding a key typed at Codex's login screen and its
`sessions/` included). The write closure is (1)'s compile and launch refusal, so it holds for enforcing runs only: a
`tego run --observe` run applies no Landlock ruleset, and its agent, like any of the user's processes outside tego,
can read and write the directory as any of the user's files (*amended 2026-10-17*: the operator
guide said no run could write it but its own). The operator guide, the Codex example and the real-key contract say so and give the
interim measure: no other governed agent while a real key is typed, or an `fs.deny_read` entry for
`/run/user/<uid>/tego/` in every other contract run meanwhile, which costs those runs their own `TEGO_REASON`
mirror (*amended 2026-10-17*: OPERATIONS and the example called the directory private and the
key "left nowhere"). Closing it in the run means a built-in read-deny of the parent with read access kept to the
run's own `<run id>` directory and its writes to `codex/`: the read side needs a grant kind for a read-only entry
inside a deny target at every tier, which this rule set does not have yet, and is tracked as a follow-up.
(4) The run's `hook-state` directory (*added 2026-10-24*, R27, ADR 0062) is the second write grant the run makes on
its own authority there, and only when it provisions a harness: `$XDG_RUNTIME_DIR/tego/<run id>/hook-state`, made
`0700` by the runtime directory's descriptor beside `last-refusal.json` (never above it or a harness file), granted as
the runtime rule `fs.harness-state[<path>]` with its device and inode exactly as the `CODEX_HOME` grant is, and listed
in `run_start.runtime_grants`. A run whose exec directory entry covers it is refused (`ErrHookStateExecutable`, exit
125), and in a deny-list run with command rules an exec whose image or directly-invoked loader's program lies there is
refused `exec-not-allowed` under the rule `harness-state-exec`, with the residuals the `CODEX_HOME` refusal states.
Every other file of the runtime directory, the harness's files and `last-refusal.json` included, stays unwritable by
the agent. `tego learn` proposes no entry for what the grant allowed and counts it in its own note, apart from the
`CODEX_HOME`'s (*amended 2026-10-24*: it was counted as file actions in the run's
`CODEX_HOME`).
(5) The harness hook's exec grant (*added 2026-10-25*, R27, [ADR 0064](../adr/0064-harness-hook-exec-grant.md)) is the
one exec grant the run makes on its own authority: under an allow-list contract whose own exec rules do not admit the
hook a provision names, the launcher admits the tego binary with the hook's exact argv and no other vector, by an image
rule for the binary (with its loader) and a runtime command rule on its tool that matches the whole vector exactly, both
named `exec.harness-hook[<tego binary>]` and listed in `run_start.runtime_grants`. Every other vector of the binary is
refused `exec-not-allowed` under that rule. It is never made for a binary, or a loader, at or below a write entry or an
`fs.ask` scope (`harness-hook-writable`) or a `deny_read` entry by any name the launcher can see (its spelling, where it
resolves, a place the mount table shows it), nor for one with more than one link, behind an unreadable mount table,
or one that shows no mount holding it (`harness-hook-writable`: a hard link's other names cannot be listed, nor a bind
mount's of a file the table cannot place; *amended 2026-10-25*), nor when a write entry or `fs.ask` scope meets what
lies beneath its filesystem (an overlay's layers, a loop device's backing file, an image the filesystem is mounted
from) or that filesystem names no layer the launcher can place (FUSE; `harness-hook-writable`, ADR 0064 D2, which
discloses the names no table, option or sysfs gives; *amended 2026-10-25*), nor for a hook naming another program than the tego
binary the launcher runs as, nor when a bare `exec.allow` name or an implicit grant keeps the binary's name at any
arguments; R27 drops the provision then. At tier landlock the grant decides on the
supervisor's copy of argv (ADR 0048 R5, `best_effort` `exec.rules/argv`). `tego learn` proposes no entry for what it
allowed and counts it in its own note.

**R9 — Implicit `FSRule`s**, in every `RuleTable.FS` regardless of `fs:`: the run directory (keyed on `m.LedgerRoot`, since the specific run id doesn't exist until `identity.NewRunID` runs), the contract file's own path, `/sys/fs/cgroup`, `/sys/fs/bpf` — each `Access: 0` (never writable).

**R10 — The run-dir/contract-file contradiction.** A declared `fs.write` entry that is an ancestor of (or equal to) `m.LedgerRoot`, the contract file, or the run's chain anchor (`WithChainAnchor`, the launcher's `AnchorPath`; default `~/.tego/chain.log` under the compile's home) → `Diagnostic{Code:"contradiction", error}` — "Landlock cannot deny beneath an allow" (SEMANTICS §2). The chain anchor is a target of its own because it lives in `~/.tego` (P0-DESIGN §3.3), not beside the ledger root: with a `ledger_root` anywhere else, `fs.write: ["~"]` would otherwise hand the agent the `chain.log` every run's head is verified against. `compile`, `run` and `drift` name the same anchor, so they agree on this rule. The CLI maps it to exit 125 with the diagnostic code `[contradiction]`, like every other compile error (§7); the earlier exit 210 for it was folded into 125 with the rest of the 200–254 range (E36). The targets are compared resolved on both sides, a target whose directory is not made yet either placed where the kernel's walk lands once it is made, as `realpath -m` places it (*amended 2026-10-20*: `registry: <dir>/./reg`, `<dir>/x/../reg`, `<dir>/lnk/../reg` or `<dir>/lnk/reg` with no `reg/` yet kept its raw spelling, so `fs.write` over where the run then made `reg/agents/` compiled and the agent chose the contract of the next `tego run <name>`); a target no walk places (a loop of links on its path, a directory on the way compile cannot search) refuses every write entry as a `contradiction`, since no comparison shows an entry stays off it. So is every directory the walk to a target looks a name up in, its last name's included (*amended 2026-10-20*, ADR 0059 (1); first the directory holding each symlink the walk follows, then every one): with `registry: ~/.config/tego` and `tego` a link into a dotfiles tree, an entry over `~/.config` contains neither the registry's spelling's resolution nor anything beneath it, and still lets the agent replace the link, so that every later run resolves the registry, the profiles, the price table or the chain anchor to a tree it wrote, while `contract_source` spells the same path; and with `registry: <w>/sub/x/../../reg`, an entry over `<w>/sub` lets the agent make `x` a link elsewhere, though `x` is a directory or nothing at compile, so that the next walk's `..` goes up from where the agent chose. With no `..` every such directory is at or above the target or a link the walk follows, so only entries that can redirect a walk are refused beyond those. Each target is placed by that one walk of its whole declared path (`walkTarget`: a name at a time from the root, never cleaned, each name's link read and followed whether its target is there yet or not, a `..` taken where the walk stands, a name not there yet kept), which reads no `/proc` (where `/proc` was not mounted, a target that is a link leading nowhere yet was placed at the link). The contract is a target as **the file** it is (`the contract file`), as declared and as resolved, in place of its directory and the directory its path led to (*amended 2026-10-20*, ADR 0059): `fs.write: ["./agent.yaml"]`, an entry at the file itself, compiled, and so did an entry over the directory of a link in the middle of the contract path's own chain (`agent.yaml -> l1/x.yaml -> l2/real.yaml` with `fs.write: [l1]`); an entry over the contract's directory, or over the directory it leads to, is still one, being over the file or over a link of its walk; and `agent.yaml` as a symlink into a write entry let the agent rewrite its next contract. Each layer file of the machine config a Load consults, whether a file is there yet or not (`config.Machine.Layers`: `/etc/tego/config.yaml`, `~/.tego/config.yaml`, `$TEGO_CONFIG`), is a file target too (*added 2026-10-20*, ADR 0059): a run that rewrote one would choose the registry, the profiles, the prices and the ledger root of the runs after it, and `$TEGO_CONFIG` names a file anywhere. A layer is named by its absolute path as written, so the links on the way to it are walked as any other target's (*amended 2026-10-20*), and a layer path that is not absolute (a relative `$TEGO_CONFIG`), or whose walk reaches procfs (`/proc/self/cwd/machine.yaml`; *amended 2026-10-24*), is refused unread as an invalid layer (identity-config R14; *amended 2026-10-20*): it names another file in every working directory, and R10 compares a run's entries with the layers its own Load read, so a run in one directory could plant the machine config of the runs started in another. R10 protects a layer from the runs that load it; a `$TEGO_CONFIG` file that a run started without that variable can write is ADR 0059's residual. **What R10 cannot compare, the loaders refuse** (ADR 0059): a file read from one of tego's directories never leads out of it (a registry entry is read through its `agents/` itself, R26; a profile through the profiles directory, E7), and a policy file — a layer, the price table, a profile, a registry entry, a contract given by its path — with a second name (`st_nlink` above 1, a hard link) is `config-untrusted`, unless no run of the invoking user could write it by any name (owned by someone else, not group- or other-writable, and the invoking user not root): R10 compares names, and a hard link's other name is compared with nothing. A run cannot add a name to a protected file, since `link(2)` needs Landlock's `REFER` in the source directory, which only a write entry grants. The machine config's price table and profiles directory are targets wherever `prices:` and `profiles:` put them: a write to the one prices every model at $0 for the runs after, to the other widens every contract that extends a profile. So are the user registry's `agents/` and `skills/` wherever `registry:` puts it (R26, *amended 2026-10-20*): a write there chooses the contract of every later `tego run <name>` the user registry answers. The registry directory itself is not a target, only what is read from it, so a `registry:` set wide does not refuse every entry beneath it. An entry that lies inside tego's own directory (the chain anchor's, `~/.tego`, which holds the machine config, the price table and the profiles) is a contradiction as well, and so is one at or inside `~/.tego` under the compile's home where the anchor is elsewhere and that directory exists (amended 2026-10-16: an adoption's table, compiled against the agent owner's home, ADR 0055 Decision 5; the entry dropped R6a's deny of the owner's records, a directory a write entry needs not being denied, where the owner's own launched run refuses it for its anchor directory), as is one inside a run directory under the ledger root or inside the profiles directory or the user registry's `agents/` or `skills/`, though none contains a target. The same path as both a `fs.write` and a `fs.deny_read` entry is a contradiction, since Evaluate and tier 2 read the tie in opposite ways. `compile --test` rows expand `~` against the home `Compile` used (`RuleTable.Home`), and a row with a repeated key, an anchor or an alias is an error. R9's kernel implicits (`/sys/fs/cgroup`, `/sys/fs/bpf`) and tego's host state (`/run/tego`, ADR 0034) are targets too, and an entry beneath one of them is a contradiction as well: Landlock unions rules along a path and crosses mount points, so `fs.write: ["/sys"]` would let a tier-1 agent, whose uid owns its own cgroup's files, raise its own `pids.max` and `memory.max` and write another cgroup's `cgroup.procs`. tego's own binaries are targets too (*added 2026-11-01*): under `WithOwnBinaries`, which every CLI compile path gives (`compile`, `run`, `drift`, `init`, `rule`) and the dashboard's with no running file to name, the running tego, the `tego-control` beside it, and the first `tego` and `tego-control` on the launcher's PATH, each with the `tego-control` beside the file its link leads to. An entry at or over one, or holding a name on the walk to one (a link on PATH to the real file), let the agent replace it: the next run, or `sudo "$(command -v tego)"`, then ran the agent's code outside any contract. An entry beside a binary, or below its directory and on no walk, stays legal. A write entry over a PATH directory searched before the `tego` or `tego-control` it finds gets `path-shadow`, a warning and not a contradiction: such a directory holds nothing of tego's, and is often the project's own (an activated `.venv/bin`, `node_modules/.bin`). The agent could still plant a `tego` there that the person's next `tego` runs, and the warning says so.

**R11 — Limits and ceiling precedence.** Per field: if the contract sets it, compare against `m.Limits`'s ceiling in a common unit (bytes, nanoseconds, the cpu.max quota in µs a 100 ms period, `round(cores*100000)`); `<=` ceiling → kept; `>` ceiling → **not an error** (`spec/config/v0/README.md`: "raising is not an error") — `Code:"limit-above-machine", Severity:"warning"`, message `ceiling <key>=<value> kept from <file>:<line>` (the layer's file and line, as the tier and capture warnings name theirs; a `memory_high` held to the memory ceiling names that ceiling's line; a machine `memory_high` ceiling above the contract's own `memory` warns at `limits.memory` and names the ceiling's line, never blaming a `memory_high` the contract did not write), and `RuleTable.Limits.<F>` is set to the **ceiling**. A nil contract field is set to the ceiling directly, no diagnostic. A ceiling may itself be nil ("built-in ceilings are unbounded") — represented as a nil `*T` throughout; comparison against a nil ceiling always keeps the contract's value; if both are nil the field stays nil, meaning "no budget watcher for this dimension" downstream (`internal/runtime/limits`) — this package never invents a numeric default for "unbounded." A contract's `pids` below 6 is an error and its `memory` or `memory_high` below 8 MiB a warning, both `limit-below-start`: the child stage is a Go process under the run's limits from its first instruction, so below that the agent is never reached.

**R12 — `env` rules.** `env.pass`/`env.deny` names match `^[A-Za-z_][A-Za-z0-9_]*$` (`schema` else). `env.set` values reject `\x00`/`\n` and a null value (`A:` or `A: ~`, which the decode would read as `""`) (`schema`). A name in both `env.set` and `env.deny` is `contradiction` (SEMANTICS §9, explicit). `Compile` warns (`Code:"env-runtime-reserved"`) when `env.set`/`env.pass` names a runtime-reserved variable (`TEGO_*`, the propagation set, `ANTHROPIC_BASE_URL`-and-peers — every name in `identity.ForwarderVarNames`, R7's list; a passed `CODEX_HOME` warns but stays in the pass list, since the launcher reads it to find the Codex `config.toml` it copies — wherever the forwarder runs — `capture:forwarder`, and `uprobe` reached through `auto`, where the forwarder runs beside the probes; not a contract that pins `capture: uprobe` at a tier that runs uprobes, which runs no forwarder, so its own value passes (`RuleTable.PinsUprobe`) — `DOCKER_HOST` under `docker:` — unreachable today since `docker:` is not-yet-supported, documented for when it ships); the value still passes through to `RuleTable.Set` so the warning has something to point at — `pkg/spec/identity`'s `Env.Apply` is the actual last-write-wins authority at run time. The tier `Compile` resolves is a prediction — an unpinned tier resolves to the machine's ceiling without probing it — and a pinned-uprobe run whose tier runs no uprobes (`landlock`, which every unprivileged run gets, or `--observe`) tops out at the forwarder (`AtTier`, `capture.Select`), whose base URL `Env.Apply` then writes over the contract's value. `tego run` prints the same `env-runtime-reserved` warning on its stderr for each such variable of `env.pass`/`env.set` once the forwarder has started, naming what lowered capture on the run — the tier, `--observe`, or a tier whose capability set has no model capture — with that cause's fix (`internal/cli` `warnForwarderEnv`), so the warning follows what runs. It speaks only where `Compile` resolved `capture: uprobe` and so kept the variable: where `Compile` lowered the pinned uprobe to the forwarder itself (a contract pinned at `tier: landlock`, a machine capture or tier ceiling) its own warning stands, and the run does not warn again. `compile --json` carries `env_pass`, `null` for a contract with no `env.pass` (the agent inherits the environment) and `[]` for one that passes nothing, and `env_deny` and `env_set`, `[]` and `{}` when empty, never `null`. *Added 2026-10-25 ([ADR 0067](../adr/0067-agent-token-stores-and-credential-rows.md)):* where the merged contract has no `env.pass`, `Compile` warns once (`Code:"secret-env"`, at the `env:` key, else line 1) when the launcher's environment, given as names only (`WithEnviron`, which `tego compile` and `tego run` pass from `os.Environ`, and an adoption's compile does not: the adopted process's environment is its own and `env:` is refused for it, *amended 2026-10-25*, `TestRunCompileNamesSecretEnv`, `TestAdoptionCompileDrawsNoSecretEnv`; Compile never reads the process environment), holds names that look like credentials and that `env.deny` does not remove nor `env.set` replace: SEMANTICS §9's fixed list. It names them sorted and once, never a value, with the fix "add env.pass naming the variables the agent needs", and removes none. A fix names only a built-in profile this binary resolves (`TestFixesNameOnlyRegisteredBuiltinProfiles`, *amended 2026-10-25*: it said "or extend tego/no-secrets", which failed `extends-not-found`; that preset has shipped since).

**R13 — `contract_hash`.** `Hash = sha256(c.Canonical())`. `Canonical()` re-serializes the **merged** `Contract` (post-`extends`, pre-ceiling-clamp, so the hash is independent of which machine compiles it, keeping `drift`'s "contract hash change" meaningful across machines): Go struct field order, `omitempty` matching the struct tags, 2-space indent, `\n` endings, trailing newline; every not-yet-supported field is still emitted when non-empty (so a P1 field the binary ignores still changes the hash — future-proofs `drift`, and covers `env.mask`'s eventual arrival the same way, R17). This byte sequence is also what `internal/ledger` writes as `contract.yaml` (P0-DESIGN §3.3). The one departure from `omitempty`: an empty non-nil `fs.deny_read` is emitted as `deny_read: []` (`FSSection.MarshalYAML`), because it is not empty in meaning — it switches the built-in list off (R6) — and dropping it made `fs: {deny_read: []}` hash and serialize exactly like `fs: {}`, so `contract_hash` missed the switch and a recompile of `contract.yaml` (`tego drift`) put the credential list back. The rule this serves: nothing `Compile` reads from a `Contract` may live outside what `Canonical()` writes, so two merged contracts with equal bytes compile to the same deny set under the same conditions, and `contract.yaml` recompiled under the run's conditions compiles to the deny set the run had. The conditions are three, each load-bearing: the same working directory, since a relative entry resolves against the compiling process's (E28) — `tego drift` compiles from whatever directory it is run in; the same machine, since `~` and the built-in list resolve against its home; the same filesystem state, since a built-in row whose path does not exist is skipped and the `.env` scan and `deny_read` globs expand to what exists at compile time, so a `~/.aws` or `.env` created after the run changes a recompile. The profiles' contents are not a condition: `Canonical()` writes the merged entries, the profile's among them, and keeps the `extends:` line beside them (it is part of what the hash covers), so `tego drift` reloads a copy whose sha256 is the run's `contract_hash` with every `extends` name sealed to an empty profile (`internal/cli` `sealedProfiles`), which neither reads nor merges what a profile holds today and reproduces the recorded hash. Loaded through a real profile source, the canonical copy would merge the profile a second time — duplicated list entries, a different hash, and a profile's `mcp` name used twice fails E26 — so it is loadable as written only sealed. *Amended 2026-10-24 (ADR 0066):* `extends` is written as one name when the top file names one, as it always was, so a single-name contract's canonical form and `contract_hash` are unchanged (`TestSingleNameExtendsHashUnchanged` pins one), and as a list in its order when it names more (`TestCanonicalOfMergedList`); the sealed reload resolves every name of the list, a `tego/` one included, to an empty profile. The profiles' bytes are not in the hash, which covers what the merged contract says; `run_start.profiles` records which profiles a run merged and the sha256 of each. A copy that is not the canonical one (an older binary's, or edited since) is loaded against today's profiles, the best that can be done with it. `MarshalYAML` builds that form from `FSSection`'s own encoding with the one sequence emptied, never from a second list of its fields, so a field added to `FSSection` cannot drop out of the hash when `deny_read` is `[]`. The form is that encoding re-parsed: yaml.v3 encodes into a node by emitting text and parsing it back, which tags a `<<` scalar `!!merge`, and `Load` refuses every explicit tag (R1), so `MarshalYAML` turns such a scalar back into the string it was and it is written quoted, `"<<"`; the same holds for `EnvSection`'s `pass: []` form. `Canonical()` is a fixed point of `LoadBytes` (`TestEmptyFormCanonicalLoadsBack`). I3 constrains machine independence only; no state is kept out of the hash for being "not part of the schema". Condition: this form changed the hash of every contract whose merged `deny_read` is `[]` relative to builds before it, so `tego drift` counts a run of such a contract recorded before the change and one recorded after as two hashes; an older run's `contract.yaml` never carried the key and still recompiles with the list on.

**R14 — `RuleTable.Tier`/`.Capture`.** `"auto"`/`""` resolve to `m`'s highest ceiling value — `Compile` does not call `doctor.Probe` (that's `enforce.Select`'s job, P0-DESIGN §4.1 step 1); a real run may still get a lower tier when the probe disagrees. That re-clamp is `(*RuleTable).AtTier(t)`: a new table (I4) whose `Tier` is the tier `enforce.Select` chose and whose `Capture` drops from `uprobe` to `forwarder` when that tier is `landlock`, exactly as `Compile` clamps a table it resolves to landlock; everything else is the compiled table's, `Hash` and `Contract` included. `tego run` applies it right after selection and `internal/runtime` again when it hands the table to the backend, so every reader of the run's table, the tier-2 backend's `rt.Tier == TierCgroup` precondition among them, sees the tier that runs. `RuleTable.Tier` stays typed `backend.Tier`, not `TierPin`, so a re-clamp is never confused with the contract's original pin. With `WithTiers(<the tiers this binary builds>)`, which `compile` and `run` pass from `doctor.AutoTiers` (`enforce.Buildable`, with tier cgroup and above only for root in the initial user namespace and tier bpflsm only with bpf in the active LSM list: the preconditions no probe changes; amended 2026-10-26), `auto` (when the machine config names no concrete tier) resolves to the highest built tier at or below the ceiling, never to a tier the binary does not contain (ADR 0019); without it, to the ceiling. `RuleTable.Reach` is every tier a run of the table can get: the pin alone for a contract or machine-config pin, every built tier up to `Tier` for `auto`. A finding that holds in one tier alone carries `Diagnostic.Tier` (a `deny_read` Landlock cannot enforce, `io_uring: true` or `setuid: true` at landlock) and is reported whenever that tier is in `Reach`, not only when `Tier` is it, so an `auto` contract compiled to `bpflsm` is told that its unprivileged runs leave such a secret readable. `tego run` holds these until selection and prints them only to a run that got that tier (`agent.ForTier`). *Amended 2026-10-16:* a finding can hold in a few tiers and no other (`Diagnostic.Tiers`, its first in `Tier`), which `agent.ForTier` prints to a run at any of them; `tego run --observe` compiles with `agent.WithObserve`, so a finding about what tier landlock's filter does not see holds in `observe` too; and `tego run --record` reaches `Compile` as `agent.WithRecord`, so `RuleTable.Record` is the run's before any finding is derived from it. `setuid: true` is an error only where a pin or the machine config holds the run at landlock; an `auto` contract that can land there is warned, and the launcher keeps `no_new_privs` at landlock whatever the contract says.

**R15 — `Evaluate`'s FS resolution is tier-specific — the core of `compile --test`.** `Evaluate` and every walk this rule names are the decision core's (`internal/policy/decide`, ADR 0028), which owns each tier's model; `RuleTable.Evaluate`, `FSDecider`, `ListenerOpenRefused` and `ExecReadGrant` are deprecated shims that delegate to it. `backend.TierLandlock`: union semantics — any `FSRule` on `a.Path` or an ancestor that grants the needed bit wins; `deny_read` denies `ReadFile` on its own path only, **unless** a `write`/`ask` rule sits at or below its nearest enumerated ancestor, in which case `Evaluate` reports `allow` with `Rule:"deny_read (unenforced: parent writable)"` — matching real kernel behavior exactly. `TierCgroup`/`TierBPFLSM`: nearest-ancestor-wins walk (SEMANTICS §2), bounded at 64 steps; an exhausted walk is `unmatched` (reads allow, everything else refused). The walk that **decides** skips `fs.watch` entries: §7 makes `watch` a recording selector that grants and withholds nothing, and no tier refuses a mutation because of one — Landlock holds the watch path at access 0 and an enclosing `write` rule's mask still grants it, tier 2's listener gives watch entries no part in any decision (so a watch nested in an unenforced `deny_read` does not reopen it), and `internal/runtime/supervisor` drops them from its own nearest-wins table. The walk that **names** the event keeps them, so a read under a watch path is still attributed to the watch entry and stays an individual event (§7); a mutation is named by the entry that decided it. Exec is tier-split too, and not only for `ask`. Basename matching is a tier-3 rule for entries the author wrote as a bare basename only — the Landlock tier matches the resolved inode, so a same-named binary elsewhere is refused (§4), and so does tier 2, which installs the same Landlock ruleset and whose fanotify exec check compares exact and directory paths (`internal/runtime/enforce/select.go` `construct`, cgroup `decideExec`). For the same reason an unlisted `#!` script whose interpreter is allowed runs in tier 3 only: tiers 1 and 2 need `EXECUTE` on the script itself. `Evaluate` gives `TierCgroup` tier 1's exec semantics, not tier 3's, so `compile --test` at tier 2 refuses a same-named binary and an unlisted script as the run does. A bare command name in the action itself (an `argv: [rg]` row) names no file: it means the resolved path of the entry it matches, in every tier, and no file at all when no entry matches, since `Evaluate` makes no `PATH` lookup (I6). A contract with **no** `exec:` section restricts nothing through exec rules (SEMANTICS §1), mirroring the Landlock builder's `execUnrestricted`. Tier 2's fanotify exec check reads the same compiled no-section state (`policy.execOpen`, `decide.ListenerExec`) and refuses no exec through its exec list in that case; ordinary read-denial floors still apply (§11). But an exec is also a read: the kernel opens the program, a `#!` script's interpreter and the `PT_INTERP` loader of the ELF the chain ends in, each `O_RDONLY|__FMODE_EXEC` (SEMANTICS §4), so every exec, restricted or not, is also answered as a read of each of those files `Evaluate` can name — the program, the interpreter the action gives, and the loader `Compile` recorded (`ExecRule.Interp`) when the program or interpreter is a declared file entry's own path or a bare name meaning it. Any other loader (of an undeclared binary, of one under a directory entry, of a same-named file tier 3 matches by basename) belongs to a file this package never read, and is not modelled. In `TierLandlock` the exec open needs `READ_FILE` as well as `EXECUTE`. A declared file keeps its own fd with both (enforce-landlock R5) and runs under a `deny_read` — unless the file is itself an enforced `deny_read` target that no other enforced target encloses: that inode is a sealed deny node and `Prepare` fails the run rather than grant it (enforce-landlock E32 (c)), which `Evaluate` reports as `refused`/`read-denied`. Its loader gets an fd too, except that `Prepare` refuses to grant a loader at or below any `deny_read` target, enforced or not, and fails the run naming it (enforce-landlock E29), which `Evaluate` reports as `refused`/`read-denied`. `Prepare` also refuses a loader under a `write`/`ask` entry, which is no read refusal and is not modelled here; `Compile` warns about every refused loader (`loader-refused`, §7), because the landlock and cgroup runs of such a contract exit 125 before any action and no other row of its table runs there. An **undeclared** binary has only what the tier's other rules carry: with exec unrestricted, `EXECUTE` rides on the sibling read sets, the enumerated ancestors and the write masks, but for a binary no entry declares, `READ_FILE` reaches inside an enforceable `deny_read` target only through a `write` entry nested inside it — the target's entry carries `Access: 0`, an ancestor no `READ_FILE`, and the levels inside the target are not enumerated (enforce-landlock R3; the shapes that reach its content by another name are E32's limitations, I11) — so outside such a nested entry the binary is `refused`/`read-denied`. Under a nested `write` entry the kernel runs it, since that entry's mask carries `READ_FILE` and `EXECUTE` into its own subtree; `Evaluate`'s Landlock read arm models the nested `write` grant and reports `allow` (§11). A delete or rename in `TierLandlock`, and in `TierCgroup`, which decides modifications with the same ruleset, is checked on the parent directory of each name, where Landlock asks for `REMOVE_FILE`/`REMOVE_DIR` and `REFER`: deleting or renaming a `write` entry's own path, or renaming onto it, is `refused` unless an entry grants the directory above it. In `TierCgroup`/`TierBPFLSM` the answer is the nearest-ancestor walk SEMANTICS §2 specifies, which runs at `file_open` whatever the open is for and stops only at fs entries: a file of the exec, declared or not, under a `deny_read` that decides the read is `refused`/`read-denied`, and a walk past 64 steps is `path-unresolved`. Both answers are that walk's, not the product of either tier-2 mechanism: tier 2's fanotify listener sees the exec open as a `FAN_OPEN_PERM` and refuses it under a `deny_read` that no `write` entry with a longer path covers, with no depth bound (`internal/runtime/enforce/cgroup` `decideOpen`), and the tier-1 ruleset it inherits refuses only an undeclared binary under a `deny_read` that tier 1 enforces. (Answering `allow` for every exec with no `exec:` section would certify execs under `~/.ssh` that every enforcing tier refuses; leaving the `PT_INTERP` loader out of the read would certify in the root tiers an exec whose loader lies under a `deny_read`.) Net verdicts do not depend on `tier` in P0 (the root tiers decide `host:port` in the kernel, the unprivileged tier's supervisor matches the same `host:port` on a duplicate of the socket). A row's host is compared in the spelling an entry's is (`agent.CanonicalHost`: lower case, brackets and one trailing dot dropped, an IP literal in `netip` form, an IPv4-mapped address as the IPv4 one), for every entry and the `models[]` guard alike, so `example.com.:443` is `example.com:443`, which the run admits on the addresses both resolve to. A contract with **no** `net:` section restricts nothing (SEMANTICS §1): a destination no entry names is `allow`/`unmatched` in every tier. `RuleTable.NetUnrestricted` is the one predicate `Evaluate` and the supervisor share (the supervisor answers such a connect `CONTINUE` and records it `best_effort`, supervisor R7), and the Landlock builder (`netRestricted`) and tier 2 (no network program attached, `internal/runtime/enforce/cgroup` `RuleMaps.Unrestricted`) read the same bit (a TCP and a UDP connect of such a contract succeed as root at tier 2 in the KVM guest, and a `TierCgroup` row pins `allow`). Two kernel checks are stricter than that `allow` and are not modelled, because they depend on the ABI and on who bound a name: the Landlock scope (enforce-landlock R7, ABI ≥ 6) refuses an abstract name bound outside the run, and `RESOLVE_UNIX` (ABI ≥ 9) a pathname socket outside a write entry (§11). Ask scopes remain refused by ordinary `Evaluate` and the kernel in every tier: a static table cannot invent a human answer. A `net.ask` `unix:` scope inside a write entry is refused under its own rule before the write entry's implicit admit is consulted (*amended 2026-10-19*), under its declared spelling and the place it resolved to at compile (`NetRule.UnixResolved`, by `agent.ResolveUnixPlace`, the resolution the run makes too: a symlink whose target the run makes later is followed to it), which is the place the run asks a connect about whatever name reaches it (supervisor R11c; *amended 2026-10-19*: the resolved spelling of a scope under a symlinked directory was `allow` through the write entry; *amended 2026-10-19*: a scope through a symlink that led nowhere at compile kept the link's spelling). A declared `net.allow` `unix:` entry is still matched by its declared spelling alone, where the run's relay also admits its resolved one: the static answer is the stricter there. A unix connect or send row's name is also landed with the run's own unix walk (`supervisor.LandUnix`, below; *amended 2026-10-19*), and a walk that lands at a scope's place is answered as the run answers it: a connect no declared entry names is refused under the scope's own rule, since the run places the name by that walk and asks a person there (`unixScopeOf`), and a datagram, or a connect a declared entry's spelling admits, is refused `unix-ask-scope`, as the run's `decideResolved` refuses what reaches a scope's place unasked; before, the landing was admitted by the write entry around the scope. Only the live supervisor or authenticated cooperating forwarder can complete one approved operation under R22. A `chmod`-shaped `Action` (P1, once `ActionKind` grows one) must never resolve to a Landlock-tier refusal, since no ABI grants that right to deny with (E35); it is `unmatched`/allow in tiers 1–2 and only `TierBPFLSM` can refuse it. Every walk `Evaluate` makes — the nearest entry that names an action, the nearest one that decides it, the nearest `deny_read`, the nearest grant, the nested `write` grant beneath a target and the REFER union — matches an entry under both of its spellings, the path as compiled and the resolved subtree it governs (`FSRule.Resolved`), the nearer of the two deciding. The Landlock tier opens each entry following its links and tier 2 matches both (`FSRule.Spellings`, which `internal/runtime/enforce/cgroup` matches by), so matching the declared spelling alone would answer a read of the target of `deny_read: [secretlink]` `allow`/`unmatched` and a write under the target of `write: [outlink/]` `refused`, in every tier. The rule name stays the declared text (`RuleName`). In `TierCgroup` an `fs_write` is an open, and the fanotify listener decides every open without seeing its access mode: under a `deny_read` that no `write` entry with a longer path covers, an `O_WRONLY`/`O_CREAT` open is refused (enforce-cgroup-observe §5 R8), so `Evaluate` answers it `refused`/`read-denied` there, named by that `deny_read`, whatever the inherited Landlock union grants, never `allow` from the enclosing `write` entry. A delete, rename or mkdir is no open, and the listener never decides it; at `TierCgroup` `Evaluate` answers every mutation by the root walk first, refusing one beneath a `deny_read` or implicit entry nested in a `write` entry whatever the inherited union grants, as the fallback's supervisor refuses it (`fallbackMutation`, supervisor R15's 2026-10-17 amendment; ADR 0021 (5), ADR 0028 S3), and the Landlock union stays the floor for what that walk allows (amended 2026-10-17: this said it "stays Landlock's"). The root tiers' walk (and `TierCgroup`'s read column, which takes it) decides by `decide.FSDecider`, the chooser tier 2's recorder infers a verdict by (enforce-cgroup-observe R9), so a `write` entry tying an enforced `deny_read` at one path grants the read by Landlock's union in both, never by whichever of the two the table lists first. `Compile` refuses such a table when both entries resolve to one path (`contradiction`), so only a hand-built table or one whose spellings resolve apart reaches it; tier 2's listener refuses an open at an equal-length tie, which this does not model. Before any walk, `Evaluate` (every fs kind, both ends of a rename, and the files an exec opens), `FSDecider` and `ListenerOpenRefused` rewrite the longest prefix of the action's path that equals a symlinked entry's declared `Path` into that entry's `Resolved`, the canonical spelling every tier decides on; the rewrite reads the table alone (I6), so only a link some entry declares at or above the path is followed. Matching each entry under both spellings alone would not reach a path through one entry's link that lies under *another* entry's canonical path: with `deny_read: [/l]` (→ `/w/a`) and `write: [/w/a/b]`, a row for `/l/b/f` is `allow`, as every tier answers. `Compile` records each exec rule's symlink-resolved path (`ExecRule.Resolved`), and exec matching takes both spellings, as tier 1's supervisor and tier 2's listener do, so a row naming `/usr/bin/dash` for `exec.allow: [/bin/sh]`, or a file under a linked bin directory by its target, is allowed. In `TierLandlock` a read under an enforced `deny_read` is also `allow` when a declared exec entry lies strictly inside the target and covers the path — the file itself, or anything beneath a directory entry — because the exec grant holds its own fd with `READ_FILE` (enforce-landlock R5, I11 (1)); the rule is that exec entry. An exec entry at the target is a sealed deny node (enforce-landlock E32 (c)) and one above it leaves the target unenforced, so neither counts. The root tiers and tier 2's listener refuse such a read. `Compile` warns `unenforced` (landlock only) for every exec entry inside an enforced `deny_read`, naming both. This is SEMANTICS §2's stated exception for the Landlock tier. `Evaluate` itself stays pure; `compile --test` (and `compile --exec`) runs its table with `TestTable.RunResolved`, which first lands each row's path with the run's own walk (`supervisor.Land`, the walk every run's fs line is decided on, `docs/p0/supervisor.md` R15b), so a row and the run land a path with one resolver: the path as the agent's syscall would spell it from the table's directory, uncleaned; each `..` physical, against the directory reached so far; every symlink on the way followed, dangling or not, up to the kernel's 40; the final one only where the syscall follows it. An open (an `O_CREAT` open's dangling final link to the name it creates), an exec and its `#!` interpreter, and an attribute change follow it; an unlink, a mkdir, either end of a rename or a link, and a unix bind act on the link in its walked directory. So a row through a symlink no entry declares is decided on its target, as the kernel decides it, and an exec of a symlink to a granted binary is allowed as the run allows it; a hard link under another name is still itself, and refused. A part of the path that does not exist yet (a rename's or a link's new name, a file an open creates, a directory the agent makes before it moves a file in, a dangling link's target) is taken as a directory the agent makes later: the row is evaluated where the run's walk lands once it exists. A walk that fails as the agent's own lookup would (`ENOTDIR`, `ELOOP`, `EACCES`, `EINVAL`) leaves the row as written, cleaned, the spelling the run's line keeps for that syscall; one compile cannot make in its own view (no `/proc`, `EMFILE`) does too, and compile says so once on stderr. The output names each landed path that differs from the row's spelling cleaned (`resolved_path`, `resolved_dest`, `resolved_script` in `--json`). A net row is answered with the machine's resolver endpoints as a run snapshots them at start (`decide.EvaluateIn`): a TCP or UDP connect to one on port 53 is `allow` via `net.resolver` before any entry is asked, with the supervisor's own lookup (`decide.IsResolver`, `docs/p0/supervisor.md` R14). The `bpflsm` column is not a second model of tier 3: its fs and exec answers are read out of the decision plane's own rows, `decide.CompilePlane` walked as the kernel walks them (`decide.PlaneEvaluator`, TIER3-PLAN T10, `docs/p0/enforce-plane.md` R25), so the column is what the loaded programs will decide; `Evaluate` at `bpflsm` stays the independent root model the rows are property-tested against (`TestPlaneEvaluatorMatchesEvaluate`), and a net row is `Evaluate`'s, the plane having no net rows. Where a plane column is answered, `compile --test` explains that FS, exec and exec.map use the plane's rows, while network answers use the policy model. In `--json`, only row-backed FS/exec/exec.map `bpflsm` cells carry `mechanism: plane`, `decision_plane: lsm`; network cells carry neither field. These fields describe test-column provenance, not an attached runtime measurement. Tier `bpflsm` needs LSM mode; tier `cgroup` joins the plane column only once a plane is built for it (ADR 0019's 2026-09-29 note). A table the plane cannot hold (`ErrPlaneCap`) answers every fs and exec row refused as `plane-unbuildable`, beside compile's own diagnostic. A rename end above every write entry and above a `deny_write` target is named by the row's nearest entry where the root model names the target, and both refuse for one reason.

**R16 — `mcp[].command[0]` also declared in `exec.allow`.** Not an error: harmless redundancy, `redundant-rule` warning on the `exec.allow` entry — the same treatment two overlapping `fs.write` entries get (E10), extended here by analogy since no normative doc rules on the double-declaration case directly; a generator that defensively lists an MCP binary in both places should not be penalized the way `model-direct-bypass` (E27) penalizes a real policy mistake.

**R16a — HTTP MCP servers (`mcp[].url`).** *Added 2026-10-19 (FEATURES E31, I5).* An
`mcp:` entry is a stdio server the agent launches (`command:`) or an HTTP server it connects to (`url:`), exactly
one of the two (`schema` error for both or neither). `url` is an absolute `http` or `https` URL with a host
(`agent.ParseMCPURL`); user information, a query and a fragment are `schema` errors, since each would put a
credential or nothing governable into the contract, its hash and every printed table. Two servers on one host and
port are a `contradiction` (capture tells servers apart by where an exchange went, nothing else), and so is a URL on
a `models[]` endpoint's host and port; a URL on a model endpoint's host at another port is an `unenforced` warning,
because capture matches `models[]` by host and reads that host's exchanges as the model's. Under a `net:` section
each server's URL compiles to one net rule for a TCP connect to its host and port (`tcp://host:port`, the scheme's
default port when the URL names none; both HTTP transports are TCP, an `http://` URL never speaks QUIC, and HTTP/3
to an `https://` server is not admitted, so a UDP datagram to the port is refused), built and resolved exactly as a
`net.allow` entry is and placed after the author's entries, with
`NetRule.MCP` set: its rule name is `mcp[<name>]`, the name every record line about that server carries
(`agent.MCPRule`). An endpoint `net.allow` already lists exactly (host in `CanonicalHost`'s spelling, port, TCP)
derives nothing, with a `redundant-rule` warning, as R16 does for a command. Nor does one a `net.ask` entry would
decide a connect of, with a `redundant-rule` warning, so connecting to it still asks: an entry on the same port
naming the same host, or holding one of the addresses compile resolved the URL to, kept or dropped under R18 (a
CIDR containing it, or a literal address or name whose kept addresses include it). A derived allow would otherwise
be matched first, and the supervisor asks only a connect nothing allowed or refused by name: an address R18
dropped from the URL's own name is refused `net.denied_resolved[<url>]` (supervisor R7), which is not unmatched,
so it counts. An address R18 dropped from the ask entry's own name does not count: the run's ask lookup holds an
entry's kept addresses only (`dns.NewSet`), so that entry never asks for it, and the server's rule is derived as
with no ask. An ask that holds only some of the URL's kept addresses still derives nothing (a derived allow would
admit the asked ones first, as would any refresh of a rule narrowed to the others), and the warning names the
addresses no ask entry holds: a connect to one is refused, neither asked nor admitted by the server's URL, unless
another `net.allow` entry admits it. An entry holds an address by its CIDR or the addresses it kept, and so does
one naming the URL's host: such an entry still derives nothing (it asks for what a later answer brings that name,
which a derived allow would admit first), but its own lookup may have answered otherwise, and it never holds an
address R18 dropped from that name, so where it kept none of the URL's addresses the warning names them as refused
and never says connecting asks first. A dropped address is named with its class, and its fix is declaring the
address itself, since listing the name in `net.ask` would not have it asked. For a URL that derives no rule this
is the only warning about its addresses: R18's `resolved-denied` warning, whose last clause says what the rule's
kept addresses admit, is given for an `mcp.<i>.url` only when its rule is derived. The addresses compared are
compile's: an address a
TTL refresh later brings to the server's name inside an ask entry is admitted by the derived rule, as the first
entry that matches decides (SEMANTICS §5); an author who wants every address of a name asked lists the name in
`net.ask` itself. With no `net:` section nothing is derived:
every destination is admitted already (SEMANTICS §1). An HTTP server gets no exec grant. Launching a stdio server or
writing a server into the harness's own MCP configuration for the run is provisioning (FEATURES I6d), not this
rule.

**R16b — Per-tool MCP rules (`mcp[].tools`).** *Added 2026-10-27 (ADR 0126 D1).* An `mcp:` entry may
carry `tools:`, a mapping of three optional lists of exact tool names, `allow`, `deny` and `ask`, each name matching
`^[A-Za-z0-9_.:/-]{1,128}$` (MCP's own name rule widened by `:` and `/`, which real servers use); no globs, no model. A
name in two lists is a `schema` error, and so is a non-empty `ask` in a contract with no `ask:` section (the broker that
holds the call exists only then; the fix is `ask: {timeout: 2m}`). A present `tools:` key, even `tools: {}`, puts the
server behind Tego's MCP relay (`MCPServer.Relayed`): its `tools/call` messages are decided by the relay in the
launcher, outside the run, and `tools/list` results lose the denied tools; absent, the server runs as before (R16,
R16a), no relay. `allow` present, even `allow: []`, denies every tool it does not list; `deny` is refused; `ask` is held
for a person on the run's broker. `tools:` is refused in a `tego run --observe` run, where nothing keeps the agent from
going around the relay. `tools:`, `allow:`, `deny:` or `ask:` with no value is a `schema` error (R1): each parsed as
absent, so `tools:` left the server off the relay and `allow:` allowed every tool, the opposite of `allow: []`. Canonical keeps `tools: {}` and an empty list as written (`MCPTools.MarshalYAML`), so each
hashes differently from the key's absence; a contract without `tools:` hashes as before
(`TestContractHashUnchangedWithoutTheNewKeys`, `TestMCPToolsAccepted`, `TestMCPToolsRefused`,
`TestMCPToolsRefusedUnderObserve`). The relay, its live switches and its record lines are ADR 0126 §4 and record minor
25.

**R17 — `env.mask` forward-provisioning.** `env.mask` is schema-only in P0 (R2, rejected when non-empty), but `spec/agent/v0/example.retriever.yaml` already documents its intended behavior once it ships ("the forwarder substitutes it only in auth headers on allowed hosts", paired with `capture: forwarder`). No code changes now: R12's runtime-reserved-name warning mechanism and R13's "emit not-yet-supported fields when non-empty" already cover `env.mask` the same way they cover `docker:` — this rule exists only to record that the interaction is anticipated, not to add new behavior.

**R18 — Resolved addresses a host name never admits.** A `net.allow` host name admits the addresses it resolves to, at compile and on every TTL refresh in the run (SEMANTICS §5), and the answer is the resolver's, not the author's: a name can be re-pointed or rebound between two lookups. So a host entry never admits an address in these classes: loopback (`127.0.0.0/8`, `::1`) and the unspecified addresses (which the kernel sends to loopback); link-local (`169.254.0.0/16`, `fe80::/10`), which holds the cloud instance-metadata endpoint `169.254.169.254` that AWS, GCP, Azure and OCI serve role credentials from; the metadata endpoints outside link-local (AWS's IPv6 IMDS `fd00:ec2::254` and EKS Pod Identity's `fd00:ec2::23`, GCE's IPv6 metadata server `fd20:ce::254`, `100.100.100.200`, `168.63.129.16`); multicast (`224.0.0.0/4`, `ff00::/8`), whose datagrams reach listeners bound to the port on this host (interface-local `ff01::/16`, and every group through the kernel's default multicast loopback) and on its link (`224.0.0.0/24`, `ff02::/16`) — the local and on-link services the loopback and link-local classes keep a name from; and every range the machine config's `denied_resolved_addresses` adds (spec/config/v0; every layer adds, none removes). An IPv4-mapped or NAT64 (`64:ff9b::/96`) spelling is classified as the address it stands for. A localhost name (`localhost`, `*.localhost`) keeps the loopback class, since loopback is what it names. `Compile` drops such an address from `NetRule.IPs`, keeps it in `NetRule.Denied`, and warns `resolved-denied` naming the address, its class and the list the entry came from (`net.allow`, `net.ask`, `mcp.<i>.url`, the last only when the URL's rule is derived, R16a); an entry left with no address admits nothing until a refresh brings one it may admit, and `Evaluate` refuses a connect to its name as it refuses one to the dropped address (rule `unresolved`, E18's entry with no addresses; `TestCompileDropsDeniedResolved`). The supervisor refuses a connect or send to such an address that a refresh brought into the live set, and names the refusal `net.denied_resolved[<entry>]` with reason `net-not-allowed`, as it does for an address `Compile` dropped (`docs/p0/supervisor.md` R7). A literal address or CIDR entry is never filtered: declaring the address is how an author admits one of these classes on purpose, and it is what the warning's fix says. When the first entry the live set matches is refused, another entry that admits the destination on its own still admits it: a literal or CIDR entry, a localhost name on loopback, another host name whose own answer holds the address and whose own check allows it, or a grant the runtime added (so a declared `localhost:3000` keeps admitting loopback when a refresh rebinds an earlier `dev.example:3000` to it). Private ranges (`10/8`, `172.16/12`, `192.168/16`, the shared `100.64/10`, `fc00::/7`) are refused by what the name first resolved to. A name whose compile-time answer, once the classes above were dropped, held only public addresses (`NetRule.PublicAnswer`) stands for a service on the internet, and a later answer that brings a private address in is DNS rebinding towards the host's own network (a router's admin page, an internal API): the supervisor refuses it as class `private`, under the entry's name. A name whose first answer held a private address — split-horizon DNS answering an internal registry or git server — keeps private addresses, and so does one that did not resolve at compile (`--offline`, E18), which has no first answer to judge by; an operator who wants the ranges refused for every name adds them in the machine config. Nothing is dropped at compile for this class, so it adds no warning; the ledger line names the entry, and a literal or CIDR entry admits the address on purpose. **This host's own addresses** count as loopback, since a name that resolves, or is rebound, to one of them (its LAN, bridge or global IPv6 address, or a public IPv4 address it holds) reaches every service bound to all interfaces as loopback does, and neither the private class nor the machine ranges cover a public one. The supervisor holds a snapshot of the addresses assigned to this host's interfaces (`net.InterfaceAddrs`: an `RTM_GETADDR` netlink dump, unprivileged, no cgo), taken again on the next check that needs it once it is a second old, and refuses a host entry's destination found in it, `net.denied_resolved[<entry>]`, with the same exemptions as loopback: a localhost name keeps it, and a literal or CIDR entry admits it. While no snapshot was ever taken (the dump failed), every host entry's destination is refused, fail-closed; a failed retake keeps the last snapshot. `Compile` neither drops nor warns about such an address — its I/O is read-only file and DNS (I6) — so `Evaluate`, which answers from compile's addresses, allows a destination the run refuses here. Tier 2's kernel rows are kept free of one for a host entry, within the timing below: `internal/runtime` keeps a snapshot of its own of this host's addresses, taken the same way and as often as the supervisor's, and filters with it and this table's `ResolvedDenied` both the table the tier is prepared with (a compile-time answer's such address moves to the entry's `Denied`, and an entry left with none gets no row) and every table the DNS worker hands the tier (`dns.Set.Refreshed`, below); the worker hands one whenever the addresses differ from those it last handed, so an address this host gains or drops moves the rows on the worker's next tick with no lookup, with the supervisor's exemptions and every host entry's address refused while no snapshot was ever taken (`TestTheTierIsPreparedWithoutThisHostsAddresses`, `TestTheRunsDNSWorkerKeepsThisHostsAddressesOutOfTheTiersRows`). What remains is timing: the rows can admit an address for up to the snapshot's age and the worker's tick (`dnsRefreshTick`, 5 s) after this host takes it, and an entry whose every refreshed address the filter refuses keeps its previous rows, as tier 2 keeps an entry a refresh leaves empty (enforce-cgroup-observe §4 `RefreshNet`), so an address the host takes while it is an entry's only one stays a row until a refresh brings another; the supervisor refuses every connect and send it sees there, and the row decides only a datagram whose address a sibling thread rewrote after the supervisor read it (supervisor R13b). The condition that closes the last is a `RefreshNet` that empties an entry the filter, rather than a failed lookup, left without an address (`internal/runtime/enforce/cgroup`; the table would have to say which it was). The check is the supervisor's resolved-address check (`internal/runtime/supervisor/resolved.go`), which this component owns. The `models[]` guard's gap of the same shape (`docs/p0/supervisor.md` R7 Limit (b)) is not closed by it: the guard decides the connects of a contract with no `net:` section, where this check does not run, and it does not read the snapshot; the condition that closes it is the guard matching an address in the same snapshot as it matches a loopback alias of its endpoint (`internal/runtime/supervisor/models.go`, which the supervisor's net handlers hold). Without this rule the only address-class check would be the `models[]` guard's own loopback test, and a public name the author allowed that resolved, or was rebound, to `169.254.169.254` would reach the metadata service and its credentials. **Not yet:** `Evaluate` names a dropped address `unmatched`, or `unresolved` when the entry was left with no address (E18's reading of an entry with no addresses), rather than `net.denied_resolved[<entry>]` — the verdict, `refused`, is the run's; the condition is `Evaluate`'s net arm reading `NetRule.Denied` (`pkg/spec/agent`'s `evaluate.go`). `dns.Set.Refreshed`, which tier 2's kernel rows follow, leaves out every address this table's `ResolvedDenied` refuses for the entry, with the machine's ranges, and every one of this host's addresses (above; `internal/runtime` hands the set the check), and lists it in the entry's `Denied`. `dns.Set.Match` still finds the entry for such an address, so the supervisor's refusal keeps the entry's name.

**R19 — No `net:` section: the host sockets it leaves reachable.** *Amended 2026-10-24 ([ADR 0070](../adr/0070-host-sockets-refused-by-default.md)):* a contract with no `net:` section no longer reaches them: it is in the unix-only state (SEMANTICS §1), which refuses every unix socket the run did not bind, rule `host-sockets`, so `Compile` warns `host-sockets` only for the top-level opt-out `host_sockets: true` (at the key, naming what it finds, docker.sock as root-equivalent, with a fix that names a `net:` section's `unix:` entry for the one socket the agent needs), and, where the run may land at a root tier, says the restriction is best effort there until the root tiers carry a kernel program for it (`TestHostSocketsWarning`, `TestHostSocketsRootTierBestEffort`). What follows describes the opt-out's reach. With `host_sockets: true`, a contract with no `net:` section denies no connect (SEMANTICS §1), so the agent can connect to every unix socket on the host its uid can open: no tier handles a network right for it (the Landlock ruleset leaves `RESOLVE_UNIX` unhandled, enforce-landlock R21; tier 2 attaches no network program; the supervisor continues each connect). That is the contract as written and stays allowed, but its reach depends on what else runs on the machine, so `Compile` warns `host-sockets`, once, naming each well-known daemon socket that exists here and what it gives: the D-Bus session bus (through which `systemd-run --user` starts a command outside the run), the systemd user manager, the D-Bus system bus, the Docker, Podman and containerd sockets (root-equivalent for the rootful daemons), gpg-agent and the SSH agents, and the X server's sockets `/tmp/.X11-unix/X0` to `X1023` (the console's `:0`, VNC's and Xephyr's `:1` upwards, xvfb-run's `:99` upwards; a display above `:1023` is not named). Each X name is looked up on its own, without following a link, in the directory opened `O_PATH|O_DIRECTORY|O_NOFOLLOW`: the directory is mode 1777, so any user can create names in it, and the bounded listing this replaced returned the first names in the file system's order, which on tmpfs put names created after `X0` first, so a hundred planted names removed `X0`, and with it the only notice of X11 reach below ABI 6, from the warning. The same warning states the abstract-socket condition: at Landlock ABI ≥ 6 (Linux 6.12) the scope refuses an abstract name bound outside the run (enforce-landlock R7), and below it nothing does, which `Compile` cannot tell because it makes no call beyond read-only file and DNS I/O (I6). The fix is a `net:` section, which refuses every destination it does not name, pathname and abstract alike. A machine with none of those sockets compiles without the warning. The run record states the exposure: `run_start.capabilities` carries `net.unix_abstract_scope` (`spec/backend/CAPABILITIES.md`), `true` exactly when the run's Landlock ruleset holds the scope — ABI ≥ 6, from the Landlock backend at tier 1 and, through the ruleset tier 2 inherits, from tier 2's `Handle.Capabilities` — so a run below ABI 6 records it `false`, `status <run>` names it among the absent rows, and `tego doctor` says in the row's note what this kernel's ABI gives.

**R20 — The built-in `deny_write` set.** The write side of the credential harvest R6's built-in `deny_read` list answers: files beneath a write entry that run code outside the run when something else next reads them. For each write entry: the git directories it reaches — its own `.git`, the gitdir and common directory a `.git` file names (a submodule, a linked worktree), and the entry itself when it is a git directory (a bare repository) — contribute `hooks`, `config` and `config.worktree` (`core.hooksPath`, `core.fsmonitor`, `core.sshCommand` name programs git runs), the git directories of their submodules under `modules/` contribute the same, and nothing else of a git directory is in the set: objects, refs, the index and the lock files a commit creates stay as writable as the entry makes them, so git works inside the run (the allowance Claude Code's sandbox makes for a worktree); its root contributes `.claude`, `.mcp.json`, `.cursor`, `.codex`, `.gemini` and `.vscode` (harness and editor settings that name hooks, commands, tasks and MCP servers) and the shell startup files (`.bashrc`, `.bash_profile`, `.bash_login`, `.profile`, `.zshrc`, `.zshenv`, `.zprofile`, `.zlogin`, `.config/fish/config.fish`); and a home dotfile among those and `~/.gitconfig`, `~/.config/git/config` counts where it resolves, so a dotfiles repository that `~/.bashrc` links into is covered. The directory each `core.hooksPath` names is a target too, since git runs hooks from it instead of `hooks`: the value is read from each reached git directory's `config` and `config.worktree` and from `~/.gitconfig` and `~/.config/git/config` (which apply to every repository), as git's own config parser reads it (a byte order mark skipped, a section header after another on one line (`[a][core]hooksPath=x`) taken as the key's section, a backslash before a newline continuing the value, escapes applied, only unquoted written whitespace trimmed from the end), `~/` expanded (a `~user/` value, another user's home, is not resolved: the entry's warning names it as a value compile could not read) and a relative value taken from the repository's worktree root (for a submodule's git directory found under `modules/`, whose worktree is reached separately, only an absolute value); Husky 9's `.husky/_` stands for `.husky`, where the hooks its runner executes live (Husky 5 to 8 name `.husky` itself, other projects `.githooks`). Git uses the last `core.hooksPath` assignment it reads, so each config file contributes its last 8 distinct values. A write entry that is not itself a repository (`fs.write: ["~/src"]`) is searched for repositories beneath it — breadth first, 4 levels deep, never into a `.git` directory, `node_modules`, a symlink or a repository found — and each one found contributes as above, plus the harness settings at its root. Such an entry also lies in the repository git finds by walking up from it (the nearest ancestor holding a `.git`, or being a git directory), whose `core.hooksPath`, and a relative one in the global config, is taken from that repository's root: Husky's monorepo layout (`cd .. && husky frontend/.husky`) sets `frontend/.husky/_` there, so `fs.write: ["./"]` run from `frontend/` reaches `frontend/.husky`. The search is bounded as a whole, not only per read: one budget per write entry covers every directory it examines for a repository or a submodule's git directory (4096), every directory entry it reads (65536, and 4096 from one directory), every byte it reads from `.git` files, `commondir` files and configs (16 MiB) and every candidate path it probes (16384), and the write entries of one compile together spend at most four entries' budgets, so a contract of thousands of write entries (E24), each over a tree the agent filled, costs a bounded amount too; and a git directory is recognised by its device and inode, so one reached again, through another `.git` file or another link, is neither read nor walked again, its `core.hooksPath` values still taken from each worktree that reaches it. A candidate is resolved by the kernel's walk, never `filepath.EvalSymlinks`: an `lstat`, then an `O_PATH` open whose `/proc/self/fd` link names where it leads; a name of `PATH_MAX` bytes or more is refused before any walk, and a `core.hooksPath` value that long, which no hook can run from, is not a candidate. That bounds the links of one walk, not its cost: the kernel follows up to 40 links of up to 4095 bytes each, so a chain of 39 links through directories 1980 levels deep costs one walk 5 to 11 ms, and a probe makes up to three; and the budget counts operations, not what each costs. So the search also has a time limit, 2 s for one write entry's and 4 s for all write entries' together (from the first entry's start), checked before every probe, read, listing, directory and `core.hooksPath` value it takes up: compile spends at most that on R20's search, plus the one step it is in when the limit passes (at most four walks, with one read of at most 256 KiB or one listing of at most 4096 entries, and for a candidate that is a symlink leading nowhere one placement of where it leads, at most 1024 reads of a name each), plus what is made outside the limits because its number is fixed: the two global configs' reads and at most 27 probes, of the home directory's own names and of an absolute global `core.hooksPath`. A search the time limit cuts says so as one a budget cuts does (below); an ordinary search takes milliseconds, and one that examines all 4096 directories its budget allows a few hundred. The limits cut what comes last, so the search takes up first what the agent cannot multiply, in two passes over the write entries. The first, for every entry before any entry's walk: the names at its root; then, when it is a repository, the `hooks`, `config` and `config.worktree` of each git directory at its root and the directories its configs' and the global configs' `core.hooksPath` values name for it; or, when it is none, the directories the enclosing repository's and the global configs' values name. The second, entry by entry: the walk for repositories beneath an entry that is none, each repository's targets (as above, and the harness settings at its root) probed as the walk finds it; then each repository's `modules/`, each submodule's git directory's targets before its own `modules/`. Both passes are charged to the entry's limits and to those all entries share, so the first pass of a contract of thousands of entries (E24) is bounded too, and an entry whose first pass a limit cut says so. No plant beneath an entry or in a `modules/` can spend the time the first pass needs; only the first passes of the entries before it can, each a fixed number of probes and reads whose walks the agent can still make as costly as the chain allows. A git directory's configs a limit left unread are read again by the next write entry to reach it, and a walk of its `modules/` another entry's budget or time cut is walked again within the limits of the entry that reaches it, so one entry's plant does not spend another's limits through a `.git` file naming that entry's git directory. When the depth limit, the budget or the time limit leaves part of an entry's search undone, or the search finds a file it reads (a git `config` or `config.worktree`, a `.git` file, a `commondir`, `~/.gitconfig`) that exists (`lstat` finds it) but cannot be read — refused by the bounded read below (not a regular file, over its bound, a file system not on the list), permission denied, a lease or a lock held on it, a symlink that leads nowhere — or a directory it would search that it cannot open and that the compiling user owns (a directory of mode 000 hides every repository beneath it, and only its owner, whose uid the agent runs as, can make it so and undo it; one owned by another user, a `lost+found`, is not the agent's doing and is not named), or `/proc` is not mounted, the entry's warning says so, naming the limit and which pass it cut (the names at its root and its repository's targets, or the repositories and submodules beneath it), each such file or directory with why (four of them, and how many more) and the missing `/proc`; and an entry with nothing in the set gets a warning of its own saying the same, since a git hook or config beneath it may then be writable without being named (a config that cannot be read is never taken as setting nothing: an agent could otherwise make its repository's `config` unreadable for the compile, `chmod 000` or a write lease, and drop its `core.hooksPath` directory from the set); a directory at the depth limit counts as unsearched only when it holds a directory the search would have taken up (the note rides on the entry's own warning even when nothing is named, so empty directories planted beside a repository cannot empty the set silently). Not named: `.idea` (a run configuration runs only when the user starts it) and `.gitmodules` (a submodule URL or `update` command runs nothing until a recursive update, which git restricts, and refusing it would break `git submodule add` inside the run), a repository beyond those limits, one nested in a repository's worktree other than as a submodule, a hooks path set through `[include]`/`[includeIf]`, `$XDG_CONFIG_HOME` other than `~/.config`, the system config, what a `.git` file, `commondir` or config that cannot be read points to or sets, which the warning names instead (the `hooks` and `config` of a `.git` directory on a file system outside the list below are still named: finding them reads nothing), a `.git` or config moved away before the compile and put back after it (only paths that exist when compile runs count), and anything at all when `/proc` is not mounted, since every probe and read goes through `/proc/self/fd`, which each entry's warning then says. Every file this reads (a `.git` file, a `commondir`, a git config) and every directory it lists lies where the agent can write, so each is read as I6 bounds a read: the path is opened `O_PATH`, which runs no driver's open and breaks no lease; `fstat` and `fstatfs` on that descriptor pass only a regular file within the bound (4 KiB for a pointer, 256 KiB for a config) on a file system known to store data, a list of those to read, not of those to skip (`pkg/spec/agent/boundedio.go` `dataFS`: ext2/3/4, XFS, Btrfs, ZFS, F2FS, bcachefs and the other disk file systems, the flash ones (UBIFS, JFFS2), the older and foreign ones (HFS, UFS, VxFS, MINIX, QNX and others), tmpfs, ramfs, overlayfs, aufs, shiftfs, eCryptfs, squashfs, EROFS, romfs, ISO 9660, UDF, NFS, SMB, 9p, Ceph, AFS, Coda, Lustre, IBM Storage Scale (GPFS), BeeGFS, PanFS, OrangeFS, Oracle ACFS, StorNext, User-Mode Linux's hostfs, FUSE and the VirtualBox, VMware and Parallels shared folders; a binary on a file system not on it fails the run at `Prepare`, exit 125 (R8), so a data file system missing from it is a bug to report, not a setting), so procfs, sysfs and every other kernel interface file system, one whose regular files are pipes, queues or endpoints (rpc_pipefs, mqueue, functionfs, xenfs), and one the list does not know are not read; the file is then opened through `/proc/self/fd` with `O_NONBLOCK`, so a lease or a lock its owner holds (an agent may take a write lease on its own files while its run is live) answers `EWOULDBLOCK` instead of holding the open for the lease-break time, 45 s, and read with a plain `read(2)` loop, never through Go's poller, in which `EAGAIN` and any other error refuse it, except `EINTR`, retried up to 16 times as `os.File` retried it, since a FUSE or network file system answers it when a signal interrupts a read waiting on the daemon or server, and a retry waits only as the interrupted read did, and the read stops one byte past the bound; a directory is opened `O_DIRECTORY|O_NOFOLLOW`. A read on a network, cluster or FUSE file system waits on its server or daemon, which `O_NONBLOCK` does not change, and so does each step of a path walk through one, and the time limit is checked between operations, not within one: that wait is the mounter's, and an agent inside a run whose Landlock domain handles filesystem rights cannot mount one itself (SEMANTICS §10), but it can have one mounted and left mounted, so the residual is a FUSE file system it mounted in a run that enforced nothing (`--observe`), a FUSE or network mount that a daemon outside the run made at its request through a host socket R19 names, as the session bus reaches gvfsd and udisks2 (`gio mount` of an archive the agent built), or an automount point the host has (autofs: `/net`'s `-hosts` map, a systemd automount unit for an NFS or SMB share), which a walk crossing it mounts by itself, waiting on the server even when it is down, so any path the agent chooses (a `core.hooksPath` value, a gitdir, a `.env` link) that names one makes that walk wait, with no request of the agent's needed. Only existing paths count, and only beneath a write entry (elsewhere every write is refused already), at where a candidate leads or, for a symlink, at the link's own place: a link beneath a write entry leading out of every one is held at its name, and a target that is a link is spelled by the link's own place (`FSRule.Path`, where the kernel's lookup lands; *amended 2026-10-25*: such a link was left out, and the agent could replace it with a directory of its own); each becomes an `FSRule{Kind: "deny_write", BuiltIn: true, Unenforced: true}` in `RuleTable.DenyWrite`, never in `RuleTable.FS`. A declared write entry at a target's own path is the opt-out: the author grants it, and it leaves the set. One inside a target keeps the target, which still refuses every modification beneath it: no write entry reopens a built-in target (*corrected 2026-10-25*, ADR 0071: this text said "nearest wins" here, which no tier ever did; a contract's own `fs.deny_write` entry is the one a nested write entry reopens); neither is reported `redundant-rule` (E10), whose fix would take the grant back. `Compile` prints the set with the fs entries and warns `unenforced` once per target, at the write entry it lies beneath, naming it, what it is and its rule (and a search a limit cut, once per entry, in a warning of its own). **Enforcement (ADR 0041 D1 (a)):** Landlock's recursive grants cannot express these exceptions, so a kernel decision plane (`lsm`/`fmod_ret` at tier cgroup, `lsm` at bpflsm) is what refuses a write to a target race-free: its nearest-wins walk preserves writes outside the targets while deciding protected operations after the kernel resolves the actual syscall arguments. Where no plane decides the run — tier landlock, and tier cgroup on the fanotify listener, including an over-capacity plane's fallback — the supervisor refuses a modification that reaches a target on its copied pathname (supervisor R15c), which a racing path can defeat. **`fs.assurance`** (`best-effort` | `kernel`, default `best-effort`) chooses what such a run does. Best effort runs it, disclosed: each target's warning says so, and run_start's `best_effort` lists `deny_write/default`; the printed table marks each target `best-effort(supervisor; landlock: parent writable)` (`best_effort` in `--json`). Kernel refuses it before the child starts (selection, Prepare and the plane choice: exit 125, the fix naming narrower write entries, a plane, or `fs.assurance: best-effort`); compile reports each target as an error at a tier landlock the contract pins or the machine config holds (not one a landlock-only build caps auto to), as `setuid: true` is there, and as a warning elsewhere, and marks it `kernel-plane-required(...)` (`kernel_plane_required`). A table held at tier bpflsm, where the plane always decides, gets no such finding. Contracts with no protected write targets are unaffected by either value. Explicitly granting a target still removes it from the built-in set. Git's own configuration writes remain refused unless the contract explicitly grants them. A name that does not exist yet (a hook not yet written into a missing `hooks`, a bare-repository layout planted at a worktree root) has no inode to key in any tier; `safe.bareRepository=explicit` in git's own configuration is the mitigation for the second. So has the place a candidate that is a symlink leading nowhere yet leads to (`.git/hooks -> ../hk`, `hk` not made; *amended 2026-10-20*, ADR 0059): the set holds the link, which keeps its name from being replaced, and where the place it leads to (placed as R10 walks a path, `walkTarget`) lies beneath a write entry, `compile` warns `unenforced` at that entry, naming the link, the place and the fix: make it before the run, so the set holds it, or remove the link. The finding said only that the entry reached `.git/hooks`, as it says for a hooks directory the set holds, while git follows the link to whatever the run makes there. *Amended 2026-10-05 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) D8 and D1 (a)):* `compile` and `run` agree for both values of `fs.assurance`. From 2026-10-03 every run with a target and no plane was refused while `compile` only warned; D8 made the finding an error at a pinned or held tier landlock, and D1 (a), decided the same day, keeps that error and the refusal for `fs.assurance: kernel` alone and restores the best-effort default (`TestCompileDenyWriteErrorsAtPinnedLandlock`, `TestCompileDenyWriteBestEffortByDefault`, `TestCompileAndRunAgreeOnDenyWrite`). *Amended 2026-10-25 ([ADR 0071](../adr/0071-user-deny-write.md)):* a contract's own `fs.deny_write` list adds entries to the set (blocked for ordinary commands; not race-free at the no-root tier): literal files or directories, a `schema` error for a glob character, each one beneath a write entry an `FSRule{Kind: "deny_write", BuiltIn: false}` named `fs.deny_write[<entry as declared>]` and enforced on every path a built-in target is (the plane race-free, the supervisor best effort below it, the cell `fs.deny_write` in `best_effort`, `fs.assurance: kernel` as above); a write entry strictly beneath one reopens its subtree (nearest wins), which no built-in target allows; an entry at a write entry's path is a contradiction, one outside every write entry or beneath another entry `redundant-rule` from the top-level file and silent from a profile, a missing one `path-missing` from the top-level file and `unenforced` from a profile, and one at a built-in target's place is a rule beside that target, never in its stead (the target stays never reopened and keeps its link spelling); across `extends` a union (R5), where `[]` adds nothing and removes no built-in target (`TestUserDenyWrite*`).

**R21 — What an empty policy denies.** The rule "an empty policy denies nothing; reads are logged" holds
with these stated conditions. A contract with no `net:` section denies no IP connect but refuses every unix socket the
run did not bind (R19, ADR 0070; with `host_sockets: true` it denies no connect), and one with no `exec:`
section refuses no exec (R15). It does not hold for files: the built-in `deny_read` list (R6) is refused whatever
the contract says, the built-in `deny_write` set (R20) is refused beneath every write entry, and with no `fs:`
section every write is refused (R6), since tier 1's Landlock ruleset allows only what is granted. "Reads are
logged" holds at tiers 2 and 3 (tier 2's recorder, aggregated under `record: summary`) and at tier 1 only under
`record: full`: tier 1's seccomp filter notifies read-opens only in that mode (enforce-landlock.md R16), and a run
under `record: summary` at tier 1 that has `deny_read` or `watch` paths records
`gap what=record why=unprivileged-tier` instead (FEATURES.md E56, `internal/runtime/runstart.go`).

**R22 — Bounded local human approval.** `fs.ask` compiles into separate `FSAsk` scopes and `net.ask` into separate `NetAsk` destination rules. They add no Landlock, fanotify or BPF grants. Ordinary allow rules take precedence; protected ledger, contract, configuration and credential checks remain unconditional. Each list has at most 256 entries; filesystem scopes are literal paths of at most 4096 bytes. Network approval requires an explicit `tcp://host:port` destination or a `unix:` socket (*amended 2026-10-19*: `unix:<path>` or `unix:@<name>`, only under `ask.hold: connect`, supervisor R11c); UDP and raw socket approvals are refused as unsupported. *Amended 2026-10-19:* a `udp://host:port` destination and a bare `host:port`, which names TCP and UDP as a `net.allow` entry does (SEMANTICS §5), are approval scopes too, so the example `net: {ask: ["queue.internal:5672"]}` compiles as written; each needs a port in 1..65535 (port 0 is an ICMP destination, which no ask holds), and either needs `ask.hold: connect`, since a datagram or a UDP connect is held at the syscall (supervisor R13d) and `first_write` and `request` hold TCP bytes or HTTP requests: compile refuses such a scope under them with the fix to write `tcp://host:port`, and the launcher refuses a table that reached it anyway. Raw socket approvals stay refused as unsupported.

Absent `ask` with nonempty scopes means `{hold: connect, timeout: 5m, max_pending: 64, on_timeout: refuse}`. `request` defaults to `4m`; timeout must be positive and at most `1h`, and `max_pending` is `1..64`. `on_timeout` is `refuse` or `refuse_always` (SEMANTICS §6, added 2026-10-16); the compiled table prints all four on its `ask` line. Duplicate, unknown, null and incorrectly typed fields are schema errors. Observe, setuid and io_uring opt-in configurations cannot use ask. Request holds require explicit forwarder capture, fixed declared model authorities and `net.http` policy; CONNECT tunnels and WebSocket frame inspection cannot satisfy that hold.

Filesystem approval holds a regular-file write-open or creation. Before asking, the supervisor pins the actual existing inode or absent leaf's parent under the target's identity, and verifies a prelaunch-pinned scope. It injects only the approved descriptor with atomic `ADDFD|SEND`, preserving target credentials, umask and supported flags; changed symlinks cannot redirect it. Other mutations and special-file/O_TMPFILE opens remain refused (*amended 2026-10-27, [ADR 0047](../adr/0047-fs-ask-mutations-made-on-pinned-names.md)*: unlink, rmdir, mkdir, rename, symlink and link inside a scope are held under hold `mutation` with `target2` naming a second name, and an approved one is made by the supervisor as the target on the directories it pinned, each end one name in a held directory, every end in the one scope or `EXDEV` unsupported; a live block refuses one before and after the ask; truncate, chmod, chown, xattr writes and mknod remain refused). A raced-in leaf returns `EEXIST`. Notification withdrawal prevents descriptor delivery, but an already-approved create/truncate can have completed before withdrawal: the separate human filesystem outcome records `operation_completed`, `fd_delivered` and optional `result_unknown`/`syscall_ret`, rather than claiming rollback or target success. Non-dumpable or inaccessible targets fail closed.

Network `connect` holds the copied address and duplicated socket. Root tiers need an exact, short-lived socket-cookie credit consumed by that one connect; unavailable credits refuse. `first_write` connects to a bounded private loopback relay: original sends may enter kernel buffers and `getpeername` names the relay, but no upstream connection or byte is delivered before approval of the first received bytes. `max_pending` counts a relay from its reservation at connect until its approved first delivery; an established relay lives as long as the agent's connection, with no idle timeout, and a run's relays in all are bounded at 256 (`ask.MaxRelays`) (amended 2026-10-05: established relays stayed counted against `max_pending`, so long-lived approved connections refused every later first-write connect before a human saw it). Every first delivery the relay reads ends in a record: a refusal when no answer was recorded (capacity, a process no longer in the run, cancellation) as for a denial, or a human-authority `net` outcome with `upstream_connected` and `delivered` after an approval. The ask re-checks the connecting process's cgroup, not the connecting thread's, since the delivery comes after the connect returned (amended 2026-10-05: these deliveries were reset with no line, and an exited connecting thread was refused unasked). `request` first applies static HTTP policy and reads one complete bounded body under existing deadlines, then asks before any upstream operation. Its retry identity includes process birth, fixed authority, method, path/query, complete body and credential/header hashes; equivalent retries share one ask and one upstream dispatch. Oversized/incomplete bodies refuse; an unreplayable response returns a retry error without another upstream dispatch.

`tego ask <run> [ask_id]`, `tego approve <run> <ask_id> [--always]` and `tego deny <run> <ask_id> [--always]` use the verified live launcher and authenticated local broker. Administrative packet credentials and a live peer pidfd are checked; governed processes and descendants cannot approve themselves. Ask and answer lines are accepted by the ledger before approval is returned; append failure ends the run. Timeout, cancellation, shutdown, lost listener or capacity exhaustion fail closed. A live unanswered ask appears as `waiting approval` in status; `run_start.capabilities.ask` is true only with a started, available enforcing broker. Full kernel/tier acceptance is recorded separately from these source contracts.

*Added 2026-10-06 (held reads and alternates; SEMANTICS §6).* `fs.ask_read` (at most 256 literal paths of at most
4096 bytes, each existing; concatenated across `extends`, duplicates warned `redundant-rule`) compiles each entry into
`RuleTable.FS` as a `deny_read` entry with `FSRule.AskRead` set, named `fs.ask_read[<entry>]`: every component that
does not hold a read (the Landlock builder, `Evaluate` and the root tiers' models, the plane's rows) refuses it as the
`deny_read` it is, and only tier 1's supervisor reads the marker, to hold a read-open of a regular file the entry decides
(op `read`, hold `open`) and complete it read-only with `ADDFD|SEND`; the filter of such a table notifies every open,
as `record: full`'s does. `Compile` refuses: a table whose tier is not landlock (`unenforced`: no other tier holds a
read; pin `tier: landlock`); an entry at or beneath a declared `deny_read` (`contradiction`), or tego's own state
(`RuleTable.OwnState`, R6a's list taken whole: `contradiction`); one at or beneath a write entry or an `exec.allow`
directory, or holding an exec grant (`unenforced`: Landlock could not withhold the read, and an `fs.ask_read` entry
never compiles unenforced); an `fs.ask` scope at or beneath one (`contradiction`); a glob (`schema`), a missing path
(`path-missing`) and `/`. An entry of the top-level contract at a built-in `deny_read` path replaces that entry, and one
beneath a built-in entry is nearer, each warned `unenforced`; from a profile either is a `contradiction`, as ADR 0043
D3 keeps a profile's write entry from lifting the built-in `.env` list. *Amended 2026-10-16 (ADR 0057 D4):* the warning
names the built-in entry relaxed and how, and `RuleTable.AskReadRelaxes` (compile output, `{Rule, BuiltIn, How}`, `How`
`replaces` or `inside`) lists each, which the launcher writes as `run_start.ask_read_relaxes`. *Added 2026-10-16
(ADR 0057 D3):* an `fs.ask` scope at or beneath a write entry is warned `redundant-rule` (the write entry allows every
write there, so the scope never asks); an `fs.ask_read` entry there stays refused `unenforced`. The launcher refuses a table with an
`fs.ask_read` entry at any tier but landlock, observe included, before the child starts. A held file open (a read, an
`fs.ask` write or a gate-held open) also takes an alternate (`tego alternate <run> <ask_id> --file <path>
[--always]`). *Amended 2026-10-16 (ADR 0057 D2):* the person's command opens the file, `O_PATH` with `openat2`
`RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`, and passes the descriptor over the broker's socket (`SCM_RIGHTS`); the
supervisor checks that descriptor (a regular file with one link, on no kernel pseudo filesystem, its kernel path
naming the same inode here and lying outside `RuleTable.OwnState` and the launcher's own additions
(`$XDG_RUNTIME_DIR/tego`), for a write outside `RuleTable.OwnReadable` too (*amended 2026-10-20*, R26), the
contract file's directory unless beneath a write entry, every `deny_read`, `fs.ask_read`
and implicit entry and every `RuleTable.DenyReadPatterns` match (a declared `deny_read` glob, a built-in `deny_read`
path, existing at compile or not), its name none of the built-in `.env` list's, and for a write of no built-in
`deny_write` class by name (`agent.WriteAlternateClass`), outside every `deny_write` target, and beneath a write entry
or an `fs.ask` scope; amended 2026-10-16), and that the contract's gate, scoring it as the agent's own
open of it (a read gate for a held read, a write gate for a held write and both for an `O_RDWR` one, floor `ask`), does not refuse (amended
2026-10-16; the delivered open's line carries that decision, not the target's), and reopens it through
`/proc/self/fd/<n>` with the agent's credentials and umask, read-only for a read or with the agent's write flags less
create and exclusive for a write; it never resolves the person's path itself. The check runs at answer time with the
access mode alone (a refused alternate leaves the request pending) and again at delivery. The broker's answer carries
the alternate with `approved: false` and no reason, so a consumer that does not know alternates refuses; `--always`
keys an alternate as it keys an approval and delivers the same file by the same descriptor, checked anew each time.

**R22a — Bounded scored gate (S9/E12b, ADR 0007).** See the [gate contract and completion matrix](gate.md). `gate` retains a merge-compatible YAML mapping; its strict compiler accepts only `rules` and `thresholds`, the five documented predicates, decimal integer scores 0..100, and at most 256 rules. Matching scores sum with saturation at 100 (the sum, not the highest rule), across both fs kinds for an action both score, a read-write open or a rename's or hard link's source (*amended 2026-10-20*), and across both ends of a rename or hard link, one action whose every matching rule counts once (*amended 2026-10-20*, ADR 0007); the bands: below `allow` allow, `allow` to `ask` ask, above `ask` refused, with defaults 50 and 80. Thresholds require 1 ≤allow <ask ≤100. Patterns are bounded to 4096 bytes; ordinary globs are supported, recursive `**` and expressions are refused. Relative read patterns use the captured worktree; `~/` expands at compile. An `fs.read matches` pattern holding a `/` outside a class is a path of component globs matched one name at a time against a clean path, and compile refuses one no clean path matches, naming its clean spelling (`./secrets/*`: `write "secrets/*"`), and one with an escaped `/` or a class that can match `/`; any part of a malformed glob refuses it (*amended 2026-10-20*, ADR 0007); so does a relative one needing more leading `..` than the run's worktree has names (*amended 2026-10-24*). Hostname `net to host:port` predicates require the same endpoint in declared `net.allow`, `net.ask` or `models`; literal IP predicates need no DNS binding. The supervisor conservatively checks all current declaration aliases of the actual copied IP/protocol/port, including mapped IPv4, and a rule that names this host scores every spelling of it on its port (*amended 2026-11-01*, gate.md R3). Runtime resolver/capture-loopback/DNS-broker grants supply a floor but are not declared facts for `net to undeclared host`; that predicate can escalate them. Dynamic helper endpoints cannot always be predeclared, so choose compatible scores/predicates deliberately. These facts do not identify a remote HTTP/TLS service. *Amended 2026-10-16 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) Stage B):* the compiler also accepts `gate.completion: copied | held` (default `copied`). `held` completes every open of an fs kind whose rules can score to `allow` or above (*amended 2026-10-20*, ADR 0007) in the run, through the open deputy (gate.md R4), and is warned `redundant-rule` where no such rule exists; `run_start.best_effort` and compile's `unenforced` warnings then name `gate.fs.read/o_path` instead of the open cells (`TestGateCompletionKey`).

The gate cannot lower a protected or ordinary refusal. Enabled action kinds retain notifications in summary/off; FS gates disable the plane filter shortcut, and exec gates disable fast handover before scoring. Originally allowed regular-file read/write opens raised to ask use the held inode, original credentials and atomic ADDFD delivery. Separate `fs.ask` scopes remain write-open/create only. Exact ordinary TCP connect/first-write holds use the existing governed OFD and one-shot root credit. Gate request-mode destination approvals, UDP/Unix/raw approval, Fast Open approval and non-open FS mutation approval are unsupported and fail closed. Addressed/unaddressed IP datagram batches under a network gate return ENOSYS, so a run with one launches with `RES_OPTIONS` `single-request` for glibc DNS (amended 2026-10-05): single sendmsg/sendto paths are bounded immutable relays, on IP sockets only (amended 2026-10-05: an allowed Unix datagram is continued and sent by the agent, never by tego). Exec scores may refuse copied argv; an exec score in the ask range returns an explicit unsupported-completion refusal, never an approved CONTINUE. Compile warns about that configured range; safe exec approval remains unfinished.

Gate operation fields are additive ledger revision 5: `score`, `gate_rule`, `gate_outcome`, `gate_facts: copied_syscall` and optional `completion_unsupported`. Gate refusals use authority gate and fs-gate/exec-gate/net-gate; approved actual completion uses authority human. Ordinary refused floors retain their existing authority/reason. Kernel outcome ownership retains copied score metadata without adding a second action line. Copied pathname/argv predicates cannot claim that sibling-mutated bytes later copied by the kernel are identical. Gates govern the actions reaching their supervisor paths; they do not revoke existing/imported descriptors, inspect opaque protocols or substitute for kernel network/firewall enforcement. Record-off still suppresses ordinary allowed action lines; ask/answer and refused outcomes remain available.

**R23 — Skills, and their drift, are not built.** Drift covers the contract's declared
surface; `tego drift` reports fs, net, exec, MCP and models entries against the ledger (limits-check-doctor-cli.md
R16-R18). `skills:` is refused with `not-yet-supported` (R2) until skills are mounted per run (FEATURES.md I6c,
P2), so no run has skills to drift from. Condition: skills drift arrives with I6c; until then a contract that
declares skills does not compile.

**R24 — The agent's code is never modified.** Tego changes no file of the agent's, on disk or in its
working tree, and patches no source or binary to observe or enforce it. What a run changes is outside the code:
the environment (identity-config.md R3-R6, the forwarder's base URLs), the cgroup and its limits, the Landlock
ruleset and seccomp filter installed before `execve`, and, at tiers that capture with uprobes, the kernel's
breakpoints in the process's mapped copy of the TLS library, removed at detach (the file on disk is untouched).
Kill test 7 runs two agents with no code change (FEATURES.md). A later language-level source (E69, P2) is
injected by environment and keeps this rule.

**R26 — The registry: an agent's name resolves to its contract file (added 2026-10-20).** `tego
compile`, `tego run`, `tego watch --boundary` and `tego adopt --boundary` take an agent name where they take a
contract path (`internal/registry`, `internal/cli` `resolveContract`). The rules:
- **Name or path.** An argument that is an agent id (`[a-z0-9-]{1,40}`, R3) is a name; anything else is a path,
  read as before. An id holds no `/` and no `.`, so `agent.yaml`, `./x` and every path to a `.yaml` file stay paths.
  `-` is compile's standard input, never a name; `run`, `watch --boundary` and `adopt --boundary` (and `agents
  --adopt --boundary`) refuse it as a usage error (exit 2, `[usage]`, *amended 2026-10-20*), before anything runs:
  a run's standard input is the agent's, and a contract read from it names no file, so its run_start would carry no
  `contract_source`, which says tego generated the contract. A file named `-` is `./-`. A name that is also a file in the working directory (a link
  to one included) is refused `agent-ambiguous`, the fix `./<name>` for the file: a stray file never silently
  changes which contract runs. A directory of the name (the agent's code, often) is no contract and is no ambiguity.
- **Where, in order.** The project registry first: the **working directory**'s `agent.yaml` when its top-level
  `name:` is the name (the file `tego init` writes), and its `.tego/agents/<name>.yaml`. Then the user registry,
  the machine config's `registry:` (default `~/.config/tego`, `""` for none): its `agents/<name>.yaml`. The one
  registry that holds the name answers. **Both holding it is `agent-ambiguous`** (amended 2026-10-20),
  naming both files, the fix the path of the one meant (`./.tego/agents/<name>.yaml`, or the user file): a project
  entry never replaces the user's. Anything at the user registry's place counts, an entry that would itself be
  refused (a dangling link, a group-writable file) included, and a place that cannot be looked at (a link loop, an
  unsearchable `agents/`) is `registry-entry`: only its absence leaves the project entry the answer, or the user
  registry resolving the name to the very file the project entry was read from (`registry:` set to the project's
  `.tego`, or a link to it: one file is one contract, and there is nothing to remove or rename; *amended
  2026-10-20*; a hard link of one in the other is refused since ADR 0059, below). The project registry holding the
  name twice (`agent.yaml` and `.tego/agents/<name>.yaml`, two files; `agent.yaml` a link to the other is one) is
  `agent-ambiguous` too. No
  registry holding it is `agent-not-found`, naming the files that would hold it and the names the registries do
  hold. Why both are refused: a user-registry contract runs in whatever directory the user stands in, and one with
  a write over it (`fs.write: ["./"]`, the common personal agent) could write `.tego/agents/<name>.yaml` there;
  had the project entry won, the next `tego run <name>` in that directory would have run the agent's own contract
  in place of the user's, the escalation R10 refuses for the contract's own directory. Now the planted file only
  blocks the name, with a refusal that names it.
- **What an entry must be.** `<name>.yaml`'s own `name:` is the name (else `registry-entry`, the fix naming both):
  `tego run retriever` never runs an agent called something else. A regular file, read through its `agents/`
  directory itself as an `os.Root`, so a link or `..` that leaves `agents/` (`agents/r.yaml -> ../versions/r.yaml`,
  inside the registry but not inside what R10 protects; *amended 2026-10-20*, ADR 0059) or a FIFO is
  `registry-entry`, never followed or waited on; a relative link that stays inside `agents/` resolves. Owned by the
  invoking user or root and not group- or other-writable, and so are `agents/` and the registry directory
  (`.tego/`, or `registry:`), R20's rule as profiles follow it: else `config-untrusted` (`registry entry untrusted:
  <path> uid=.. mode=.. (<what failed>)`, or `registry directory untrusted:`), the fix `chmod go-w` or a path. One
  name: an entry, or a project `agent.yaml` meant, with a second name (a hard link) is `config-untrusted`, the fix
  naming how to give it one (ADR 0059): no write entry is compared with the other name, so a run whose
  write entry held it would rewrite the contract every later run of the name loads. A project
  `agent.yaml` is read for its name whoever wrote it, but trusted only once it is the one meant; one whose name
  cannot be read is `registry-entry`, since it may be the one meant, for every name, a user registry's included: the
  fix says that no name resolves in that directory while it cannot be read, and to fix, rename or move it, or give
  the contract's path (*amended 2026-10-20*; a file that is not tego's, from another framework or a
  link out of the directory, is still refused rather than skipped, since one with no readable `name:` cannot be told
  from a broken contract that is the one meant). An entry inside tego's own directory, the
  ledger root or the profiles directory is `registry-entry`: R6a read-denies them, and a contract's directory is
  one a run needs, which lifts that deny (`ledger-readable`); this is why the default user registry is not under
  `~/.tego`. The user registry's `agents/` and `skills/` are R10 targets (no write entry over or inside them
  compiles), since every later run of a name it answers loads what is there. One that holds the working directory
  as well is not refused: the run needs the working directory,
  which lifts that deny whatever contract runs, and `Compile` warns `ledger-readable` as for a contract given by its
  path.
- **Same bytes.** The entry is read once, through the descriptor that was checked, and compiled from those bytes
  (`agent.LoadBytes` labelled with its absolute path): the file a run records is the file it compiled, with no
  second open an editor or an attacker could race. Relative entries resolve against the working directory as for
  any contract (E28), and the `.env` scan reads the contract's directory and the working directory, as for a path.
- **What is recorded.** `run_start.contract_source` (record_minor 13) is `{path}` for a contract given by its path
  and `{path, name, registry}` for a name; `path` is the file read, absolute, cleaned only where cleaning names the
  same file (a `..` after a link is taken from the link's target, as the open took it, ADR 0059); `contract_hash` (R13) is unchanged. A refused name is exit 125 for `run`,
  `watch` and `adopt` and exit 1 for `compile`, as a missing contract file is. `compile` opens its print with
  `agent <name>, from the <registry> registry` and its `--json` carries `source`.
- **Skills.** A registry is also the home of skills: `skills/<name>/` beside `agents/`, in either registry, is where
  a skill a contract declares will be found once skills are provisioned (FEATURES.md I6c). Until then `skills:` does
  not compile (R23) and nothing reads the directory.

*Decided (design decision, 2026-10-20). Rejected:* finding the project by walking up from the working
directory to the nearest `.tego/`, as git finds a repository: a contract's relative entries resolve against the
working directory (E28), so the same name run from a subdirectory would grant `./out` of that subdirectory, a
boundary that differs by where the user stood; and every ancestor (`/tmp`, a shared mount) would become a place a
name could be planted. Taking the first match when the project holds a name twice, or letting a file of the name
in the working directory win or lose silently: either makes which contract runs depend on a stray file. Indexing
every file's `name:` across the registries: a name then depends on every file's content, and one unreadable file
blocks or changes every name. `~/.tego` as the default user registry: R6a's read deny of tego's own directory is
lifted for a directory a run needs, the contract's among them, so every run of a user-registry contract would have
read the chain anchor, the machine config and tego's log. A second open of the file by path after resolution: the
file compiled could differ from the one checked. Printing which registry answered on every `run`: compile is the
place to look, and the ledger records it. Letting a project entry hide a user entry of the same name (the first
draft, project first and `compile` saying what it hid): a run of the user entry could plant the project entry
(above), and neither `run` nor its ledger would have said the user's contract was replaced. Making the working
directory's `.tego/` and `agent.yaml` R10 targets of every contract resolved outside it: the common personal agent
(`fs.write: ["./"]`) would stop compiling in every project, and a planted name the user registry does not hold is no
escalation, since nothing the user ran by that name changes. Reading an entry through the registry directory rather
than through `agents/`, and accepting an entry with a second name (rejected): a link to
elsewhere in the registry, or a hard link anywhere, led to a file R10 lets any run write (ADR 0059, which also
rejects protecting every entry's link target at each compile).

**R25 — Exec command rules (ADR 0048, added 2026-10-06).** `exec.deny` and `exec.ask` list command patterns, and an
`exec.allow` entry with words after its command word is one: a command word (a bare name; a path only in
`exec.allow`), then option words, subcommand words and operand words, read with the tool's row in
`pkg/policy/execmatch` (docs/spec/exec-command-rows.md) exactly as the tool reads an invocation.
- **Mode by key presence.** An `allow` key, even `allow: []`, restricts images; no `allow` key with a `deny` or `ask`
  key, even empty, is deny-list mode: images unrestricted, command rules apply; neither restricts images. A `deny:`
  or `ask:` key with no value is a `schema` error with the `[]` fix, as `exec:` with none is (R1). An `allow:` key
  with no value reads as absent, as it did before ADR 0048, except where that makes the merged section a deny-list
  (a `deny` or `ask` key in the same file or elsewhere in the `extends` chain): there every image may run, so it is
  a `schema` error at the `allow:` key with the `allow: []` fix (since 2026-10-06, ADR 0048's second; `loader.nullExecAllow`, after the merge). Alone, `exec:\n allow:` is `exec: {}` and restricts every
  image. Load keeps a present empty list non-nil, `extends` keeps it (R5), and `ExecSection.MarshalYAML` emits `allow: []` or `deny: []` exactly
  where dropping it would change the mode, so every contract written before ADR 0048 keeps its canonical bytes and
  `contract_hash` (`TestContractHashesUnchanged`). `RuleTable.ExecUnrestricted` is the one spelling of the mode every
  enforcer reads (`TestExecModeOneSpelling`). Compile prints the mode with the file that set it
  (`Contract.ExecModeSource`).
- **Grammar errors** are `exec-rule` errors naming the word and the fix: shell operators, Claude Code's
  `Bash(...:*)`, a glob command word, a path in a deny or ask command word (it would broaden the entry; write the
  basename), a lone `*` other than last, an allow entry requiring an option its row does not list, and the bounds
  (32 words of 256 bytes, 1024 bytes, 512 patterns after `extends`). `$` or a backtick in a word, and a deny-list
  section with no entry, are `exec-rule` warnings.
- **Precedence.** The image floor decides first; then any `exec.deny` match refuses, any `exec.ask` match refuses as
  a reserved ask, and a constrained tool's invocation that no allow entry matches under every reading, and no allowed
  entry's helper closure admits, is refused as unlisted (`exec.args[<tool>]`); then the gate escalates. Specificity
  never changes the order and no exception syntax exists.
- **Every image's `#!` line is read** in a run with any command rule. An image whose first bytes the supervisor
  cannot read is refused `image-unreadable` (EACCES), even one no rule names: at tier landlock run unprivileged the
  supervisor reads as the agent's user, so every execute-only file that user cannot read (RHEL's `sudo`, mode 4111)
  is refused. A root supervisor (tiers cgroup and bpflsm, `sudo tego run`) reads every image on a local file system.
  An NFS export with `root_squash` serves it as the export's anonymous user, and a FUSE mount without `allow_other` or
  `allow_root` refuses it: an image there that it cannot read is refused `image-unreadable`, or its exec answered
  `EACCES` where the walk itself is refused, even in a deny-list run. `compile` warns at tier landlock
  (`exec-rule-coverage`, `TestCompileWarnsImageUnreadableAtLandlock`).


**Changes.**
- 2026-10-27, R22 ([ADR 0047](../adr/0047-fs-ask-mutations-made-on-pinned-names.md)): a mutation
  inside an `fs.ask` scope (unlink, rmdir, mkdir, rename, symlink, link) is held for a person and made by the
  supervisor on the names it pinned once approved; a rename or link across entries is refused `EXDEV` as unsupported;
  an approved open licenses no rename; a live block refuses before the ask and again after it (`TestAskMutation*`).
  Before, every such mutation was refused unasked.
- 2026-10-25, R5 (ADR 0068): `extends` reaches the three built-in presets, `tego/no-secrets`,
  `tego/no-prod` and `tego/repo-only-writes`, by name or pinned to a revision (`tego/no-prod@1`, a pin taken on a
  `tego/` name only); an unknown `tego/` name's fix lists the built-in names, where it said only to check the name.
- 2026-10-25, R27 (ADR 0063 (8)): `claude-code` has a provisioner: the run's
  `<runtime dir>/claude-settings.json` lists `tego hook claude-code`, a `claude` command is given `--settings` with
  it at index 1 (its own `--settings` merged in, a path read through `Run.ReadUserFile`), and `TEGO_CLAUDE_SETTINGS`
  names it. The provisioning point said no harness had one in this build.
- 2026-10-24, R5, R6 (ADR 0069): the `fs` section takes `reads: auto | held | direct` (default
  `auto`), merged `stricter` with `direct` loosening (R5's table). Under `auto` a `deny_read` target at or beneath a
  write entry (a declared entry, a glob's expansion, a built-in entry, a scanned `.env`) makes a run at tier landlock
  hold its reads, and compile warns `held-reads` at the target, with the cost, where it warned `unenforced`; `held`
  holds them at every enforcing tier; `direct` keeps the `unenforced` warning. compile prints a `reads` line, and
  `--json` carries `reads`. A run that holds its reads and whose open deputy does not start exits 125.
  *Amended 2026-10-25:* `fs.reads: held` together with `io_uring: true` is `schema` ("fs.reads:
  held requires io_uring disabled"), as `gate` and `ask` are: where a root tier's plane admits io_uring, a ring's open
  never passes the filter, so the held floor would not see it. *Amended 2026-10-25:* so is
  `fs.reads: held` with `setuid: true` ("fs.reads: held requires setuid disabled"), as `gate` and `ask` are: the open
  deputy completes a read with the run's starting credentials, and at a root tier `setuid: true` lets a task change
  its own (`TestHeldReadsRefuseIOUringAndSetuid` holds both). *Amended 2026-10-25
:* where reads are held at a tier a run can get, R6's name entries print with the tiers at which held
  reads refuse a file made during the run rather than "no tier applies them yet", and a whole `deny_read` glob's
  warning says the same in place of "files created later are not covered" for those tiers.
- 2026-10-24, R5, R13 (ADR 0066): `extends` takes a list of 1 to 8 profiles, merged left to right by
  ADR 0065 D4, with `extends-conflict` for a `contract-wins` key two parents set differently, a profile reached twice
  merged once, and only a file's own duplicate entries warned (entries two files declare merge silently, where every
  repeat warned). Names under `tego/` resolve only to built-in profiles; a profiles-directory file under `tego/` is
  never read and draws `shadowed-builtin` (it was read as any other profile). A single-name contract's canonical form
  and hash are unchanged. The conflict check reads each parent resolved in full, so a list's verdict never depends on
  order.
- 2026-10-25, R19, R21, §7 (ADR 0070): a contract with no `net:` section refuses every unix socket
  the run did not bind, rule `host-sockets`, and keeps every IP destination; R19's warning is the opt-out's
  (`host_sockets: true`), the probe runs only then, R21's condition says so, and §7 gains the root-tier best-effort
  row (`TestHostSocketsWarning`, `TestHostSocketsRootTierBestEffort`, `TestHostSocketsUnixOnlyState`).
- 2026-10-24, R5 (ADR 0065): the merge is one loop over one table of keys and merge classes
  (R5's merge classes, above, and two §7 rows); every merged value, `compile` print, `--json`, canonical form and
  `contract_hash` is unchanged (`TestEveryContractKeyHasAMergeClass`, `TestMergeTableRowsNameRealKeys`,
  `TestR5ListsEveryMergeClassRow`, the `TestMergeClass*` tests). Two classes no current key takes are added for the
  V1 keys: `stricter` with loosening values (`profile-cannot-loosen`) and `refused-in-profile`. One position changes:
  `name` is the top file's own, as `version` is, so a contract with no `name:` over a profile that writes one is
  refused `name is required` at the top file, no longer at the profile's `name:` line, which held a name
  (`TestExtendsNameRequiredAtTheTopFile`).
- 2026-10-24, R22a (ADR 0007's second 2026-10-24 note): compile refuses a
  relative `fs.read matches` pattern whose leading components must match `..` more times than the captured worktree
  has names; it was accepted and never fired in that worktree. The refusal names the absolute pattern when those
  components are each `..` (`TestGateReadPatternReachesTheWorktreesAncestors`,
  `TestReadPatternBeyondAgreesWithAPathFromTheWorktree`, `TestCompileRefusesAReadPatternBeyondTheWorktreesAncestors`).
- 2026-10-24, R22a (ADR 0007's 2026-10-24 note): the 2026-10-20 entry below
  lists patterns that "were accepted and never fired"; that holds for an empty, `.` or misplaced `..` component and a
  glob malformed past its first chunk, not for an escaped `/` or a class that can match `/`, which `filepath.Match` on
  the whole path matched across a separator (`a\/x` matched `a/x`). Those are refused because the component reading
  reads them otherwise, a compatibility break, and the refusal says so and names the spelling to write
  (`TestGateReadPatternRefusalSaysWhatFilepathMatchDid`).
- 2026-10-24, R10, R8a (ADR 0059 (1)): a machine config layer, or a path setting, whose
  absolute path reaches procfs (`TEGO_CONFIG=/proc/self/cwd/machine.yaml`) is refused by the Load as a relative one
  is (identity-config R14): it names `<cwd>/machine.yaml` in every directory, so a run in project A with an entry over
  project B planted `B/machine.yaml` and chose the contract of the next `tego run <name>` started in B. R8a's walk
  is now `config.ThroughProc`, shared by compile and the Load (`TestLoadSourcesRefusesALayerThroughProcfs`,
  `TestThroughProc`).
- 2026-10-20, R22a (ADR 0007's fifth 2026-10-20 note): `fs.read matches "/*"` matches the
  root `/`, whose one name is empty, as `filepath.Match` does; the component reading had skipped that name, so a read
  of `/` scored 0 under it (`TestReadPatternAgreesWithFilepathMatch`, `TestGateReadPatternMatchesSomeCleanPath`).
- 2026-10-20, R22a (ADR 0007's fourth 2026-10-20 note): an `fs.read matches`
  pattern holding a `/` is component globs matched against a clean path, and compile refuses one that no clean path
  matches (`./secrets/*`, `secrets//*`, a trailing `/`, a `.` or misplaced `..` component), one with an escaped `/` or
  a class that can match `/`, and any glob malformed past its first chunk, where they were accepted and never fired;
  a move's end is matched by the same component globs, which a multibyte name no longer escapes
  (`TestGateReadPatternMatchesSomeCleanPath`, `TestGateMovedDirectoryWithAMultibyteName`,
  `TestCompileRefusesAReadPatternNoCleanPathMatches`).
- 2026-10-20, R22a (ADR 0007's third 2026-10-20 note): a rename or hard link is one gate
  action over both its ends, every rule that matches an end it scores counted once and the scores summed, where each
  end was its own action and the stronger kept; renaming `work/prod.env` out of the worktree under
  `fs.read matches "*.env": 30` and `fs.write outside worktree: 30` scores 60 where it scored 30
  (`TestGateMoveCountsEachRuleOnceAcrossItsEnds`, `TestGateSumsReadAndWriteKindsOfOneEnd`,
  `TestCompileTestGateSumsReadAndWriteOfAMoveSource`).
- 2026-10-20, R22a: spec/agent/v0/agent.schema.json and the loader's schema take
  `thresholds.allow` 1..99 and `thresholds.ask` 2..100, the values some pair under `1 ≤allow <ask ≤100` takes; the
  published schema took `allow: 0`, which compile refuses (`TestGateThresholdBoundsAgreeWithCompile`).
- 2026-10-20, R22a (ADR 0007's second 2026-10-20 note): an action both fs kinds score (a
  read-write open, a rename's or hard link's source) sums the matching `fs.read` and `fs.write` rules, where the
  stronger kind's score was kept; a rename's two ends stay two actions (until a later entry the same day) (`TestGateReadingWriteSumsBothKinds`,
  `TestGateSumsReadAndWriteKindsOfOneEnd`, `TestCompileTestGateSumsReadAndWriteOfAMoveSource`).
- 2026-10-20, R22a (ADR 0007's 2026-10-20 note): the gate's bands: a score of
  exactly `allow` asks (it was allowed), `allow: 0` is refused at compile, and `compile` prints `allow <50, ask 50..80,
  refused >80`. The saturating sum stays, rather than the highest rule
  (`TestGateThresholdBoundaries`, `TestGateScoresSumNotHighest`, `TestCompileTestGateBoundariesAndSum`).
- 2026-10-20, R10 (ADR 0059 (1)): a machine config layer named by a relative path is
  refused by the Load (identity-config R14), not made absolute against the loading command's working directory:
  `TEGO_CONFIG=machine.yaml` named a different layer in every directory, R10 compared a run's write entries with its
  own directory's only, and a run in project A with an entry over project B planted `B/machine.yaml`, whose
  `registry:` chose the contract of the next `tego run <name>` started in B (`TestLoadSourcesRefusesARelativeLayer`;
  the link-on-the-way test is now `TestALayerIsWalkedForTheLinksOnTheWay`, with an absolute
  spelling through the link).
- 2026-10-20, R10, R20 (ADR 0059 (1)): R10 protects each target by the kernel's
  walk of its declared path: a write entry at or over any directory that walk looks a name up in is a `contradiction`,
  not only one over a directory holding a symlink it follows. With `registry: <w>/sub/missing/../../reg` (or a price
  table, profiles directory, layer, chain anchor or contract path spelled with a name a later `..` leaves, or reached
  through a link whose text has one), `fs.write: [<w>/sub]` compiled, the run made `missing` a link elsewhere, and the
  next `tego run <name>` ran the contract it planted. Every target, and `OwnState`'s and `OwnReadable`'s resolved
  spellings, are placed by that one walk (`walkTarget`), which reads no `/proc`: without it a target that is a link
  leading nowhere yet was placed at the link. An entry that reaches no name the walk reads compiles as before. R20: a
  candidate that is a symlink leading nowhere yet is still held as the link, and where the place it leads to lies
  beneath a write entry `compile` warns `unenforced`, naming it and the fix
  (`TestAWriteOverADirectoryTheWalkReadsANameInIsRefused`, `TestATargetIsWalkedAlikeWithoutProc`,
  `TestWalkTargetReadsEveryNameOnTheWay`, `TestDenyWriteCandidateLeadingNowhereIsDisclosed`). R10's first sentence names
  the contract file, the target since ADR 0059, not its directory. A relative target or own-state path
  (a test hook's chain anchor) is taken against the compile's working directory, where its loader opens it, and so is
  the directory holding the anchor, tego's own, that no entry may lie inside; it was probed against the compiling
  process's own, and refused every write entry as not placed
  (`TestARelativeChainAnchorIsTakenAgainstTheWorkingDirectory`).
- 2026-10-20, R10 (ADR 0059): a target that is a symlink leading nowhere yet (a registry,
  price table, profiles directory, chain anchor or machine config layer linked to a place not made yet), or that lies
  below a directory that is one, is placed where the link leads once the run makes it (`placeTarget`, as
  `realpath -m` places it), since its loader's open follows the link: it was placed at the link's own spelling, so a
  write entry over the link's missing target compiled and the run planted the contract or price table a later run
  loaded. `OwnReadable` and `OwnState` hold that place, `OwnState` now holds the chain anchor itself as well as its
  directory, and a final link in a loop is not placed, so it refuses every write entry
  (`TestATargetThatIsADanglingLinkIsPlacedWhereTheLinkLeads`, `TestPlacePathFollowsADirectoryLinkLeadingNowhere`).
- 2026-10-20, R10 (ADR 0059): a target whose directory is not made yet either (the user
  registry's `agents/` below a `reg/` not made, a price table, profiles directory or chain anchor below a missing
  directory) is placed where the kernel's walk lands once the directories are made (`placePath`, `ResolveUnixPlace`),
  not kept as spelled: `.`, `//`, `x/..` and a link on the way, before a `..` or not, no longer hide it from a write
  entry over the place, and `OwnReadable` and `OwnState` hold that place. A price table or profiles directory named
  relative (a machine config no Load expanded) is placed against the working directory, where its loader opens it. A
  target no walk places refuses every write entry (`TestARegistryNotMadeYetIsPlacedWhereItsWalkWillLand`,
  `TestTargetsBelowAMissingDirectoryArePlacedWhereTheirWalkWillLand`,
  `TestARelativePriceTableAndProfilesArePlacedAgainstTheCwd`,
  `TestAnR10TargetNoWalkPlacesRefusesEveryWriteEntry`).
- 2026-10-20, R10, R26 (ADR 0059): R10 places a machine config layer, the
  contract file and the user registry's `agents/` and `skills/` as their loaders' opens walked them, never as
  `filepath.Clean` spells them. With a `..` after a link (`clink/../agent.yaml`, `TEGO_CONFIG=mlink/../machine.yaml`,
  `registry: <dir>/rlink/../reg`) the cleaned spelling named a place nobody reads, so a write entry over the file or
  directory read compiled. `RuleTable.ContractPath`, and so `run_start.contract_source.path` and the `.env` scan's
  root, is the file Load read (`agent.WalkedPath`), as is a registry entry's path; a user registry entry spelled so
  is looked for where it is, so a project entry of its name is ambiguous with it, not its replacement
  (`TestAContractPathWithDotDotAfterALinkIsTheFileLoadRead`, `TestAContractPathWithDotDotAfterALinkIsTheFileRead`,
  `TestALayerWithDotDotAfterALinkIsTheFileTheLoadRead`,
  `TestARegistryWithDotDotAfterALinkIsTheDirectoryItsEntriesAreReadFrom`,
  `TestAUserRegistryWithDotDotAfterALinkIsTheDirectoryTheKernelReaches`).
- 2026-10-20, R26: a working directory `agent.yaml` whose name cannot be read refuses every
  name, as before, and its fix now says so and names the cure (fix, rename or move it, or give the contract's path):
  a user-registry name refused for it gave no reason (`TestAnUnreadableProjectFileSaysWhyEveryNameIsRefused`).
- 2026-10-20, R10 (ADR 0059): a machine config layer is an R10 target by the absolute path
  the Load read it at (`config.Machine.Layers`). A relative `$TEGO_CONFIG` had no walk, so a write entry over the
  directory holding a link on the way to it compiled, and the run could repoint the link and choose the machine config
  of the runs after it (`TestLoadSourcesRefusesARelativeLayer`,
  `TestALayerIsWalkedForTheLinksOnTheWay`).
- 2026-10-20, R10, R22, R26, E7, E25 (ADR 0059): no run writes what a later
  run loads. R10's contract target is the contract file, as declared and resolved, walked by its whole path: an
  entry at the file (`fs.write: ["./agent.yaml"]`) or over the directory of a link in the middle of its chain
  compiled before (`TestNoWriteEntryReachesANameOfTheContractFile`). Each machine config layer place a Load consults, there or not, is a
  file target and `OwnReadable` (`TestTheMachineConfigsLayersAreR10Targets`). A registry entry is read through
  `agents/` itself, so a link to elsewhere in the registry is `registry-entry`
  (`TestAnEntryThatLeavesItsRegistryOrIsNoFileIsRefused`). A layer, the price table, a profile, a registry entry or a
  contract given by its path with a second name is `config-untrusted` unless no run of the invoking user could write
  it (`TestATrustedFileHasOneName`, `TestManyNamesReasonSparesAFileNoRunCouldWrite`, `TestAnEntryWithASecondNameIsRefused`,
  `TestLoadRefusesAContractWithASecondName`, `TestAContractWithASecondNameIsRefused`, `TestDirProfilesTrustRule`);
  the hard-link forms below are refused by it. A run cannot add a name (`TestIntegrationLandlock`, `link_in`).
- 2026-10-20, R22, R26: the user registry's `agents/` and `skills/` moved from
  `RuleTable.OwnState` to a list of their own, `RuleTable.OwnReadable`, which only the alternate guard reads, for a
  write. In `OwnState` an `fs.ask_read` entry beneath them was refused as lying in tego's own state, "which no run
  may read", and a held read there refused `read_denied`, though a plain read of them is allowed; now both are as
  anywhere else, and a write alternate there is still refused
  (`TestTheUserRegistryIsTegosOwnToWrite`, `TestTheReadableOwnStateIsHeldForReadsAndKeptFromWrites`).
- 2026-10-20, R10: a write entry over the directory that holds a symlink on the way to any
  R10 target (the user registry's `agents/` and `skills/`, the profiles directory, the price table, the chain
  anchor, the run directory, the contract file's directory, tego's runtime parent, the kernel and host state) is
  a `contradiction`; before, the targets were compared only where the links lead, so with the registry reached
  through `~/.config/tego -> ~/dotfiles/tego` a write over `~/.config` compiled and its agent repointed the
  registry (`TestAWriteOverALinkOnTheWayToTegosOwnIsRefused`).
- 2026-10-20, R26: a project entry and a user registry entry that are one file (`registry:`
  the project's `.tego` or a link to it, a hard link), and `agent.yaml` with a hard link of it in
  `.tego/agents`, resolve as the project's entry; before, they were refused as `agent-ambiguous`, naming one file
  twice with nothing to remove (`TestOneFileBothRegistriesReachIsNotAmbiguous`,
  `TestOneFileTheProjectHoldsTwiceIsNotAmbiguous`).
- 2026-10-20, R26: `run -`, `watch --boundary -` and `adopt --boundary -` are usage errors
  (exit 2). The registry wiring had made them read the contract from standard input, the agent's, with a run_start
  that carried no `contract_source`, the mark of a contract tego generated; before it, `-` was a path to a file
  named `-`, which `./-` still is (`TestStandardInputIsNoContractForARun`).
- 2026-10-20, R10, R26: the user registry's `agents/` and `skills/` are R10 targets, and an
  entry inside either a contradiction, as the profiles directory is: the default registry moved out of `~/.tego`,
  which the tego-directory rule protected, to `~/.config/tego`, which nothing protected, so a write entry over
  `~/.config` let the agent rewrite the contracts other runs resolve by name. They are in `RuleTable.OwnState` too
  (`RuleTable.OwnReadable` since, below), so a person's alternate for a held `fs.ask` write never lands there (`TestTheUserRegistryIsTegosOwnToWrite`).
- 2026-10-20, R26: an untrusted registry entry or directory is refused as `registry entry
  untrusted:` or `registry directory untrusted:`, no longer under the machine config's sentence
  (`TestAnEntryOthersCouldWriteIsRefused`).
- 2026-10-20, R26: a name both the project and the user registry hold is
  `agent-ambiguous`, naming both files, rather than answered by the project's entry: an agent run from the user
  registry with a write over its working directory could plant `.tego/agents/<name>.yaml`, and the next run of the
  name ran it; a user registry place that cannot be looked at is `registry-entry`. `compile` no longer prints what a
  project entry hides, nor `--json` `source.shadows`: there is no hiding left to report
  (`TestANameBothRegistriesHoldIsAmbiguous`, `TestARunCannotPlantTheProjectEntryItsNextRunLoads`).
- 2026-10-20, R26: added. A contract is addressed by an agent name as
  well as by its path; the registry is the working directory's project registry, then the machine config's
  `registry:`; resolution is deterministic and refuses an ambiguous, missing, misnamed, untrusted or misplaced entry
  with the fix; run_start records the source.
- 2026-11-01, R11: `limit-below-start`. `pids` below 6 died with a Go stack dump, `memory` of 4 MiB with "child died before the fd handoff", and `memory_high` of 1 MiB never started; all three compiled clean.
- 2026-10-24, R11, R12 (no change to what Load accepts): spec/agent/v0/agent.schema.json, read for the
  first time by a JSON Schema validator other than ours (internal/testutil/jsonschema, which checks every
  examples/agents/*.yaml against it), now says what the loader accepts, and is a superset where JSON Schema cannot
  say the rest. `limits.cpu` is a string matching the pattern or a number from 0.01 to 175921860, the range of
  `config.MinCPUCores` and `config.MaxCPUCores` (`cpu: 4`, as examples/agents/custom-agent.yaml writes it; the schema
  had said string alone, which refused a file Load accepts). Load reads the YAML scalar's text and takes decimal digits
  only (`ParseCPUCores`), so a spelling it refuses (`1e3`, `0x10`, `0o17`, `1_000`, `+4`, `.5`) still passes the number
  branch, and the string `"0.001"` passes the pattern and fails the range; the schema is a superset of Load there, and
  Load stays the check, and the `env.set` value pattern writes the NUL as `\x00` where it wrote `\u0000`
  (ECMA-262 takes both; RE2, and so a validator written in Go, takes only `\x00`, and refused to compile the whole schema).
- 2026-10-27, R6 (ADR 0043 C11): the name entries apply: tiers `cgroup` and `bpflsm` refuse a file
  created after compile at a covered name beneath its scopes (the plane's name check; the fanotify fallback's listener
  and supervisor best effort), tier `landlock` keeps the expansion, and `compile` prints where they apply instead of
  "not enforced by this build". The build switch `agent.NameEntriesEnforced` and its test hook are gone; compile's
  name-entry warnings (an entry left out, a missing write entry a name covers, an ask entry of a covered file, a scope
  on an aliasing filesystem) are given in every build.
- 2026-10-19, R15: a unix connect or send row whose name the run's own unix
  walk lands at a `net.ask` `unix:` scope's place is answered as the run answers it, whatever its spelling: a connect no
  declared entry names `refused` under the scope's rule (the run asks a person there), a datagram or a connect a
  declared entry admits `refused`, rule `unix-ask-scope` (`agent.UnixAskScopeRule`, the supervisor's own name). The two
  packages, merged, admitted such a landing through the write entry around the scope (`TestEvaluateUnixLandedAtAnAskScope`).
- 2026-10-19, R22: `net.ask` takes `udp://host:port` and bare `host:port` entries (TCP and UDP) under `ask.hold: connect` (supervisor R13d); a port is required. Before, both were refused as unsupported UDP approvals, and so was the example `queue.internal:5672`.
- 2026-10-19, R15: `agent.ResolveUnixPlace` walks the path from the root one name at a time, one readlink per name, at most 1024 names and 40 links (a path past that is placed at its spelling, `ok` false), where it resolved every prefix of each link's target from the deepest down, which cost tens of seconds on an agent-planted chain of dangling links (`TestResolveUnixPlaceIsBounded`). `NetRule.UnixPath` is the declared path made absolute and cleaned lexically, as every contract path is (`compiler.abs`): a `..` written in it removes the name before it, and only a `..` the walk meets in a link's target applies after that link.
- 2026-10-19, R15: `NetRule.UnixResolved` (`agent.ResolveUnixPlace`) applies a `..` in the path or in a dangling link's target after the symlink before it is followed, as the kernel's lookup and `realpath -m` do, where it cleaned the joined target lexically, so `compile --test` and the run placed a scope at `s -> sub/../x.sock` (`sub` a symlink) beside `s` rather than where the lookup lands (`TestResolveUnixPlaceFollowsALinkBeforeItsDotDot`, on a real filesystem, checked against `realpath -m`).
- 2026-10-19, R15: a `net.ask` `unix:` scope's `NetRule.UnixResolved` follows a symlink whose target does not exist at compile to that target (`agent.ResolveUnixPlace`, shared with the supervisor), where it kept the link's spelling, which the run's lookup no longer lands at once the run makes the target (`TestResolveUnixPlace`, `TestAskUnixScopeIsMatchedByItsResolvedSpelling`).
- 2026-10-19, R15: a `net.ask` `unix:` scope is matched by the spelling it resolved to at compile as well as its declared one (`NetRule.UnixResolved`); a connect to the resolved spelling of a scope under a symlinked directory inside a write entry was `allow` through that entry, which the run asks a person about (`TestEvaluateUnixAskScopeUnderWrite`, `TestAskUnixScopeIsMatchedByItsResolvedSpelling`).
- 2026-10-19, R15: a `net.ask` `unix:` scope inside a write entry is refused by `Evaluate` under the scope's own rule, as every ask scope is; `compile --test` answered `allow` through the write entry around it, a connect the run holds for a person (supervisor R11c) (`TestEvaluateUnixAskScopeUnderWrite`).
- 2026-10-19, R22: `net.ask` takes `unix:` entries under `ask.hold: connect` (supervisor R11c); compile refused them, and still refuses one under `first_write` or `request`.
- 2026-10-17, R15 (ADR 0021 (5), ADR 0028 S3): R15 said a delete, rename or mkdir at
  `TierCgroup` "stays Landlock's"; since 2026-10-04 `Evaluate`'s cgroup column refuses a mutation the root walk
  refuses before the union is asked, as the fallback's supervisor does. Wording only, no behaviour changed.
- 2026-10-05, R6 (ADR 0043): name entries (`RuleTable.NameDeny`, `NameExempt`) and the compaction facts; a top-level write entry at a scanned `.env` drops it from the built-in list instead of a contradiction.
- 2026-10-05, R22: an established first-write relay leaves the `max_pending` count; relays in all are bounded at 256.
- 2026-10-05, R22: every first-write delivery records its refusal or approved outcome; its ask re-checks the process, not the connecting thread.
- 2026-09-22, R6: with no `fs:`, writes are refused (was "unrestricted", which no component did).
- 2026-09-22, R10 (fail-closed): the chain anchor in `~/.tego` is a target of its own.
- 2026-09-22, R14: `AtTier` re-clamps a table to the selected tier.
- 2026-09-22, R15: tier 2 takes tier 1's exec semantics; no-`exec:` execs are also reads, loader included; no-`net:` is `allow`.
- 2026-09-23, R12 (second): `tego run` warns `env-runtime-reserved` when the forwarder runs; no repeat warning.
- 2026-09-23, R18: multicast, private-rebinding and this-host classes; tier 2 rows filtered by the host snapshot.
- 2026-09-23, R19: X socket lookup by name; `net.unix_abstract_scope` capability row.
- 2026-09-23, R20: bounded reads, kernel walk, time limits, two-pass search, unreadable configs reported; enforced best effort in tiers 1-2 by the supervisor.
- 2026-09-30, R18: GCE's IPv6 metadata server `fd20:ce::254` joins the metadata class.
- 2026-09-30, R15: the constant is spelled `TierBPFLSM`, as in the code, not `TierBpfLSM`.
- 2026-09-30, R13: a `<<` beside `deny_read: []` or `pass: []` is written quoted, not `!!merge <<`, so the copy loads back.
- 2026-09-29, R13: the profiles' contents are not a recompile condition; drift reloads the canonical `contract.yaml` with its `extends` sealed.
- R5, R13 (fail-closed, undated): an extending `deny_read: []` is not honoured over declared entries; `[]` is serialized, changing those hashes.
- 2026-09-24, R1: null elements, tags, extra documents, alias bombs and valueless keys refused.
- 2026-09-24, R1: quoted numbers, non-decimal or underflowing `cost_usd`, `version: 00` and `~user` paths refused.
- 2026-09-24, R6a: tier 2's recorder infers by `FSDecider`.
- 2026-09-24, R6a, R10: the price table and profiles directory are denied and protected wherever
  the machine config puts them.
- 2026-10-16, R6a: `~/.tego` under the compile's home is denied too when the chain anchor is
  elsewhere (an adoption's table, ADR 0055), as `RuleTable.OwnState` already named it.
- 2026-10-16, R10, R6a: a write entry at or inside that `~/.tego` (when it exists
  and the anchor is elsewhere) is a contradiction; it had dropped the deny with only `ledger-readable`.
- 2026-09-29, R6: the built-in list also names the snap and flatpak browser profiles and the Chrome and Edge beta, unstable and dev directories.
- 2026-09-29, R11: a machine `memory_high` ceiling above the contract's `memory` is warned at `limits.memory`, naming the ceiling's own line.
- 2026-09-29, R11: cpu is compared as the cpu.max quota the run writes, not hundredths of a core.
- 2026-09-29, R12: the forwarder's peers are `identity.ForwarderVarNames`; the Google names and `CODEX_HOME` went unwarned.
- 2026-09-24, R8: a command-line command is an implicit run-only grant, recorded as `run_command_grant`.
- 2026-09-24, R8: drift falls back to `command[0]` only below `record_minor` 1, as the code does.
- 2026-09-24, R10: targets compared resolved; tego's dir, run dirs, kernel implicits and `/run/tego` added.
- 2026-09-24, R11: `limit-above-machine` names the layer's file and line.
- 2026-09-24, R14 (ADR 0019): `WithTiers`, `Reach`, per-tier diagnostics.
- 2026-10-26, R14: `WithTiers` is the tiers this process can be given here (`doctor.AutoTiers`), so a normal user's tegobpf build no longer compiles `auto` at bpflsm.
- 2026-09-24, R15: nested grants, both spellings, `FSDecider`, link rewrite, resolved exec paths, exec-entry read grant.
- 2026-09-24, R15: both spellings are `FSRule.Spellings`, containment `Covers`, shared with the runtime and tier 2.
- 2026-09-24, R20: `core.hooksPath` values read as git reads them: byte order mark, continuation lines, escaped trailing whitespace.
- 2026-09-24, R20: a second section header on one line is read as git reads it; a `~user/` hooks path is warned as unread, not taken literally.
- 2026-09-24, R21-R24: written as rules with their conditions.
- 2026-09-28, R15 (ADR 0028 S1): `Evaluate` and its walks move to the decision core, `internal/policy/decide`; the
  `RuleTable` methods delegate to it.
- 2026-09-29, R15 (ADR 0019 amendment): `compile --test` resolves each existing row path through the filesystem as the
  kernel would, and answers resolver connects `net.resolver` (ADR 0017 conformance cells).
- 2026-09-29, R15 (TIER3-PLAN T10): the `bpflsm` column of `compile --test` is answered from the plane's rows, with `decision_plane lsm` in
  the header and in `--json`.
- 2026-09-29, R12: `compile --json` prints an empty `env_deny` as `[]` and `env_set` as `{}`,
  not `null`; `env_pass`'s `null` (inherit all) is documented.
- 2026-09-29, R15: a net row's host is canonicalised before any entry is matched (trailing dot).
- 2026-09-29, R20: another case of a target's name on a case-insensitive file system is named as a
  residual of (b).
- 2026-09-30, R20: `truncate(2)` is refused from ABI 3 (supervisor R15c), not a hole of (b).
- 2026-09-30, R18: `Evaluate` refuses the name of an entry R18 left with no address, as `unresolved`.
- 2026-09-30, R20: `.cursor`, `.codex`, `.gemini` and `.vscode` join the harness settings; `.idea` and `.gitmodules` are named residuals.
- 2026-10-05, R20 (ADR 0041 D8, spec-2): the deny_write finding is an error at a pinned or machine-held tier landlock, where every run refused the contract with exit 125 after `compile` passed it.
- 2026-10-05, R2, R5, R20 (ADR 0041 D1 (a)): `fs.assurance` added (stricter value wins across `extends`). By default a run no decision plane decides goes ahead with the supervisor's best-effort refusal of the targets, as before 2026-10-03, disclosed per target at compile and in run_start `best_effort`; the launch refusal, and the compile error at a pinned or held tier landlock, hold only under `fs.assurance: kernel`. The finding is one warning per target, no longer one per write entry.
- 2026-09-30, R8: a relative `PATH` element resolves against the run's cwd, not the compiler process's.
- 2026-09-30, R12: a null `env.set` value is `schema`, not an empty variable.
- 2026-10-05, R15: `compile --test` answers resolver connects `net.resolver` only where the run grants
  the exception: under `net.dns.mode` `off` or `broker` the run hands no resolver to the tier or the supervisor, and
  `compile --test` now passes none either (`agent.DNSPolicy.SystemResolvers`, read by both), so such a row falls
  through to `net.allow` as in the run.
- 2026-10-16, R22: an alternate the contract's gate refuses is refused at answer time and at
  delivery, as the agent's own open of it and a held target are; the delivered open's line carries the gate's decision on
  the file delivered (ADR 0057 D1, D2).
- 2026-10-05, I1: `TestSchemaJSONMatchesGo` compares `spec/agent/v0` with the Go schema tree at every
  depth, required keys included (`net.http` entries now require `host` in the walk, as the JSON says), and
  `TestSchemaJSONValuesMatchGo` ties the JSON's size, duration, `net.ask` and `fs.ask` patterns to the Go checks.
- 2026-10-17, R15: a `compile --test` row whose final name does not exist is
  evaluated in its resolved directory, not as written, so a rename or a link through a symlink into an `exec.allow`
  directory, undeclared or the entry's own declared one, is refused (`EXDEV`) as the run refuses it. (The decision
  core's ends also followed an `exec.allow` directory entry's declared link; withdrawn, next entry.)
- 2026-10-17, R15: the decision core follows a declared
  link by its spelling only for a question asked by name, and only an fs entry's (`Canonical`, `canonicalEnd`). A
  rename's, a link's and an unlink's ends the run asks about are landed, every component but the last already
  followed by the kernel's walk, and are taken as they are (`landedEnd`), with the exec grants by the inodes the
  Landlock builder held, or by the table at each entry's target only; a `compile --test` row is landed by
  `resolveRowPath` before it is asked. A landed end spells a declared link only once the agent replaced the link with
  a real directory, which holds none of the link target's rules, so the rewrite had the run record `refused` for a
  move or a link there that the kernel allowed (ADR 0019's 2026-10-17 design note).
- 2026-10-17, R15: a `compile --test` row whose directory does not exist yet either
  is evaluated beneath its deepest existing ancestor as that resolves, not as written, so a move or a link into a
  subdirectory the agent makes later in an `exec.allow` directory reached through a symlink, declared or not, is
  refused (`EXDEV`) as the run refuses it; the previous entry's "landed by `resolveRowPath`" did not hold for such a
  row, which every column answered `allow`. Still open, and named in ADR 0019's design note: once the agent replaces a
  write entry's declared link with a real directory, the run's line for an open, a mkdir or an unlink inside it names
  that entry (`ruleSteps`, `GrantName`), though its Landlock rule is on the link target's inode and another entry
  granted the operation; every write entry grants the same rights, so no verdict differs, only the rule's name.
- 2026-10-17, R15: `compile --test` lands a row's path
  with the run's own walk, never cleaned first: a rename or a link through a dangling symlink into the directory it
  names, made later, is refused (`EXDEV`) as the run refuses it, a write through a dangling final link is decided on
  the name the open creates, and a new name with `..` after a symlink on where the kernel takes it, where compile
  answered the link's own spelling or the lexically cleaned path. `resolveRowPath` and `walkExisting` are gone, and
  with them the `filepath.EvalSymlinks` walk where `/proc` is not mounted: such a row is evaluated as written, and
  compile says so (ADR 0019's 2026-10-17 note). The previous entry's open naming residue is closed for
  the supervisor's lines (tier 1, and every line the supervisor writes at tiers 2 and 3): an open, a mkdir or an
  unlink inside a directory that replaced a write entry's declared link is named by the entry that grants it. The
  kernel recorder's lines at tiers 2 and 3 still match both spellings (ADR 0019's Condition).

**R27 — `harness:`: the harness the launcher provisions for (added 2026-10-24, ADR 0062).** The contract's
`harness:` is `auto` (the default), `claude-code`, `codex`, `generic` or `none`; merge class `contract-wins` (R5).
- **Resolution.** `auto` is the harness the resolved command's basename names: `claude` is `claude-code`, `codex` is
  `codex`, any other name is `generic` (`pkg/spec/harness.Detect`; a wrapper named `claude` is Claude Code, and a
  contract that means otherwise names its harness). It is the harness of the command the run executes: compile
  resolves it into `RuleTable.Harness` from the command `tego run` was given after the contract, else from the
  contract's own `command:`, and prints a `harness` line (`auto` when there is no command); the launcher resolves the
  contract's declared value again from the command it runs, so `tego run c.yaml -- claude` is a `claude-code` run
  whatever `c.yaml`'s own command is. When the harness has a provisioner, compile
  also prints what it would provision.
- **none.** `harness: none` provisions nothing and records nothing: the run's argv, environment, rule table and filter
  are those of a contract without the key's provisioning.
- **The provisioning point.** Once, after the runtime directory is made and before the tier's `Prepare`, the launcher
  asks the harness's provisioner (Layer 3, `internal/adapters`; in this build `claude-code`'s only, ADR 0063 (8))
  what the harness needs, and makes
  it itself: `hook-state/` (R10a (4)), then each file by its directory's descriptor with `O_CREAT|O_EXCL|O_NOFOLLOW`,
  `0444` in the runtime directory or `0600` in the run's own `CODEX_HOME`; the provision's argv replaces the command
  (its argv[0] the resolved command) and its `TEGO_` variables are added to the agent's environment.
- **Refused, exit 125, before `run_start`** (`ErrHarnessProvision`): a provisioner's error; a file name with `/`, a NUL,
  `.` or `..`; a name given twice or one that exists already; a runtime-directory name the engine reserves, there yet
  or not (`last-refusal.json` and its writer's `.last-refusal.json.*`, `.lock`, `hook-state`, `codex`); a `CODEX_HOME`
  file for a run with none; a variable whose name lacks the `TEGO_` prefix, that the launcher reserves (the identity
  set, `TEGO_DNS_BROKER_DIR`/`_PID`, `TEGO_HELPER_UNPLACED`, `TEGO_CONFIG`, `TEGO_TEST*`), or that the contract's
  `env.set` gives; an argv whose argv[0] is not the resolved command. A variable the agent's environment inherited
  (a parent run's provision, in a nested run) is replaced by the provision's, one entry, as the identity set is.
  `tego compile` decides every one of these but a name that exists already with the run's own check
  (`CheckProvision`) and prints `harness <name> provisions nothing: <why> (a run is refused)`; it asks the provisioner
  as for a run with a `CODEX_HOME`, and a `CODEX_HOME` file's line says a run makes it only when it routes codex
  through the forwarder. *Amended 2026-10-25 (ADR 0063):* the provisioner's
  agent environment is the contract's `env.set` (without `env.deny`'s names), and a contract that inherits any
  variable gets the line `from env.set alone: a variable the run inherits can change what a run provisions`.
  Compile reads none of the user's files: for a user file a provisioner asks for, it makes the run's checks of the
  path alone (`CheckUserFile`: absolute, not under `deny_read`), refusing as the run would, and otherwise prints
  `harness <name> provisions from <path>, which a run reads ...` rather than a refusal a run would not make.
  *Amended 2026-10-25 (ADR 0063):* for a path the checks admit, compile gives
  the provisioner an empty settings object in the file's place and checks the provision as a run does
  (`CheckProvision`, the hook's exec verdict), so the warning or refusal a run makes is shown; the line
  `harness <name> merges <path> into the file at run time ...` sits beside the provision's lines.
- **Dropped whole, the run carries on.** The provision is made only when the run admits its hook's exact argv by the
  decision `compile --test`'s exec row uses, the gate included (an exec the gate scores to `ask` is refused at run
  time, `exec-gate`): by the contract's own exec rules, or, under an allow-list contract whose rules do not admit it,
  through the launcher's grant of that argv (R10a (5), ADR 0064; *amended 2026-10-25*: an allow-list contract always
  dropped it before). Otherwise nothing of it is made, `run_start.harness` says `provisioned: false` with why, and the
  run and compile warn `harness-hook-refused` naming the rule (a refused hook would be a refused exec on every tool
  call): `hook-refused` (the rules or the gate refuse it, or the binary or its loader lies under a `deny_read` entry),
  `harness-hook-writable` (the binary or its loader lies at or below a write entry or an `fs.ask` scope by a name the
  launcher sees, or a write entry or `fs.ask` scope meets a layer, backing file or image beneath its filesystem, or
  it has a name the launcher cannot see: a second link, an unreadable mount table or one that shows no mount holding
  it, a FUSE mount, a block device sysfs does not show; so the agent could rewrite what a grant admits), or
  `hook-not-granted` (the hook names another program than the tego binary, or
  the grant cannot be exact: no ELF binary, a set-id one, or a name a bare `exec.allow` entry or an implicit grant
  keeps at any arguments). Compile prints, under a hook the run
  would grant, `harness hook: exact argv; best effort against a racing thread at tier landlock (ADR 0048 R5)` (at a
  plane tier: kernel-pinned where its plane pins execs). A harness with no provisioner is `why: no-provisioner`.
- **No usable runtime directory** (no absolute `XDG_RUNTIME_DIR`, or a root launcher): nothing is provisioned (`why:
  reason-unavailable`), and a `gap what=record why=reason-unavailable` follows `run_start`.
- **The user's files.** A provisioner reads a file of the user's only through the launcher (`Run.ReadUserFile`):
  refused at euid 0, for a relative path, under any `deny_read` entry of the run, for anything but a regular file (no
  final link followed, no FIFO waited on) and above 2 MiB.
- **Record.** `run_start.harness {name, provisioned, why, files, reason_file, state_dir}` at record minor 14
  (spec/record/v1), and `harness.hook {argv, granted}` at record minor 20 (ADR 0064).

**R28 — `revision:`: the author's name for this version of the contract (added 2026-10-25, ADR 0073).** The
contract's optional `revision:` is a string matching `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$` (a version, a date, a
commit: `1.4.0`, `2026.10.25+1`, `v2-rc_1`); an empty one, a longer one or another character is a `[schema]` error
at its line, in Go and in `spec/agent/v0/agent.schema.json` alike (`TestRevisionIsTheContractsOwn`). It is a YAML
string there as in the JSON Schema's `{"type": "string"}`: an unquoted value YAML reads as a number or a boolean
(`revision: 1`, `1.50`, `true`, `0x1F`) is a `[schema]` error with the fix `quote it: revision: "1.50"`, and a null
one (`revision:` with nothing after it, `~`, `null`) is a `[schema]` error ("no revision is recorded"), never read as
none, in the top-level contract and in a profile alike (`TestRevisionIsAYAMLString`). So are `name` and an `mcp`
server's `name` (`name: 123` is refused with the fix to quote it; `TestNamesAreYAMLStrings`). It names the
top-level file a run compiled, so its merge class is `refused-in-profile` (R5): a profile reached by `extends` that
sets it is a `[schema]` error at the profile's line, fix "set revision in the top-level contract"
(`TestRevisionIsRefusedInAProfile`), and no built-in profile carries one. It is part of the canonical bytes (R13), so
two contracts that differ only in `revision` have different `contract_hash`es, while a contract with none writes no
key and keeps its hash (`TestRevisionIsInTheCanonicalBytes`); the run directory's `contract.yaml` keeps it. `tego
compile` prints it as a `revision` line under `hash` and as `revision` in `--json` (absent for none), and a run
records it as `run_start.contract_revision` at record minor 17 (`TestRevisionIsShownAndKept`). tego never compares
two revisions: it is the author's label, and `contract_hash` remains what says two contracts are the same.

**R29 — `reason.reads:`: a read the Landlock ruleset refuses is recorded (added 2026-10-25, ADR 0077).** The
optional `reason:` section holds the reason channel's keys; its one key, `reads`, is `auto`, `on` or `off` (another
value, or a null section, is a `[schema]` error, in Go and in `spec/agent/v0/agent.schema.json` alike). Its merge class
is `contract-wins` (R5). Compile settles `RuleTable.ReasonReads` (`auto` when unset) and
`RuleTable.ReadsNotifiedWhy(tier)`: `on` has tier 1's filter notify every read open at tier landlock (enforce-landlock
R16) where nothing else in the table does (`record: full`, an `fs.read` gate, an `fs.ask_read` entry, held reads,
R16's other arms), so a read refused under `deny_read` there is one refused `read-denied` line with
`mechanism: landlock`. It never applies at a root tier (their kernel record carries the refusal) nor in an
`--observe` run, and it is never part of `HoldsFSNotifications`. `auto` is ADR 0077's measured default, off: the
rule set before measuring (at most 25 µs an open and 5 % on the offline Claude Code workload) was missed on the
workload. `tego compile` prints, for a table that can land at tier landlock, a `reads recorded at tier landlock`
line under `on` or a `reason-reads-off` line under `auto` and `off`, each with the measured cost
(`agent.ReasonReadCost`, `agent.ReasonReadWorkload`); a run records `run_start.reads_notified` at record minor 23
(`TestReasonReadsWhenAndWhy`, `TestReasonReadsPrint`, `TestReasonReadsSchema`, `TestReasonReadsNotifyEveryOpen`).

**R30 — `credentials:` (added 2026-10-27, ADR 0126 D1).** `credentials:` is a list of `{name, env, allow, base_url_env?}`
entries in the contract format. It merges across `extends` by concatenation (R5). It is part of the canonical bytes, and
a contract without the key hashes as before. `Load` refuses a malformed section, each refusal naming the entry and the
fix (`TestCredentialsAccepted`, `TestCredentialsRefused`, `TestCredentialEnvPassWarned`). Compile refuses the
section, naming each entry and the variable to pass instead. The agent's own key is passed with `env.pass`, as in any other contract.

**R32 — `models[].routes`: backends a person may reroute an endpoint to while a run lives (added 2026-10-27, ADR
0127).** Each `models[]` entry may list `routes`, each `{name, host, port, tls?}`: `name` matches
`^[a-z0-9-]{1,40}$`, is unique in the entry and is not `direct`, the name of the entry's own
endpoint, on which every run starts; `host` and `port` are the backend; `tls` defaults to true (TLS, SNI and
certificate verification for `host`), and `false` is allowed only on a loopback host (`127.0.0.0/8`, the name
`localhost` itself; not a name under `.localhost`, which some resolvers send to DNS), and the forwarder refuses a
plaintext route's connection to any address off loopback whatever its name resolved to.
It merges with its entry (models concatenate across `extends`, R5). `Load` refuses, each naming the entry and the fix:
routes without an explicit `capture: forwarder` (`contradiction`); a route that is the entry's own endpoint
(`contradiction`: that is `direct`); one backend twice in an entry (`contradiction`); `tls: false` off loopback
(`contradiction`); two `models[]` entries of one authority when either declares routes (`contradiction`: a route
switches an endpoint); a bad or repeated name (`schema`). `Compile` refuses routes in a `tego run --observe` run and
where the machine lowered capture below the forwarder. Only declared routes can be put in force (`tego route set`, the
dashboard's Model routes page), never from inside a run; the run's overlay `<run dir>/model-routes.json` names a
route, and a name the contract does not declare resolves to `direct`. Every request of a routed endpoint records its
route (record minor 27). An enforcing forwarder run guards each route's backend as it guards the `models[]` endpoint
(`GuardedModels`; a loopback backend stands for all of 127.0.0.0/8 and ::1 on its port): the agent reaches a declared
backend through the forwarder, captured, budgeted and recorded with its route, or not at all, whatever `net:` allows.
Under a `net:` section a guarded port refuses every destination `net.allow` does not admit (`evaluate_models.go`), so
declaring a route such as `llm-proxy.corp.example:8443` or `localhost:11434` also refuses the agent every unlisted
destination on that port, not only loopback servers.
Part of the canonical bytes; a contract without routes hashes as before (`TestModelRoutesAccepted`,
`TestModelRoutesRefused`, `TestModelRoutesLocalhostPlaintext`, `TestModelRoutesRefusedUnderObserve`,
`TestModelRoutesRefusedUnderALoweredCapture`, `TestGuardedModelsHoldRouteBackends`,
`TestContractHashUnchangedWithoutRoutes`).

**R31 — `live:`: Locked or Adjustable (added 2026-10-27, ADR 0125).** `live.mode` is `locked` (the default, also
with no `live:` key) or `adjustable`; anything else is `[live-mode]`. `live.fence` lists `read`, `net` and `exec`
entries, at most 64 (`[live-too-many]`), and only under `adjustable` (`[live-locked-fence]`). The key is the top-level
contract's alone: a profile that sets it is `[live-in-profile]` at its line (R5, class `refused-in-profile`). It is
part of the canonical bytes and so of `contract_hash`. With no `live:` key, or Locked, `Compile` changes nothing
(`RuleTable.Live` is nil; `TestLiveOffGolden` pins every repository contract's table and diagnostics). Under
`adjustable`, `Compile` refuses `tier: landlock` held by the contract, the machine or `--tier`, and `--observe`
(`[live-tier]`, `LiveTierCheck`), then merges the fence into the contract the fs, net and exec tables are built from,
before they are built, so every kernel layer holds the run to the contract plus the fence: a `read` entry names one
`fs.deny_read` entry exactly (compared where that entry's walk lands, E8) and takes it out (a list it empties becomes
nil, the built-in list), and forces `fs.reads: held` (`[live-reads-direct]` under `direct`); a `net` entry
(`host:port` or `IP:port`) is appended to `net.allow` for TCP alone (`tcp://<value>`: only a TCP connect is relayed,
so the kernel rows keep refusing UDP to it); an `exec` entry (an absolute program path) takes out the `exec.deny`
entry naming its basename, which then refused every program of that name, and carries that name
(`LiveEntry.Name`), and under an `exec.allow` list it is appended to it. Only the top-level contract's own refusals
can be taken out: a `deny_read` or `exec.deny` entry a profile declares, alone or beside the contract's own, is
`[live-fence-entry]` (R5's floor). It refuses an entry the contract already allows
(`[live-fence-allowed]`), a read entry at, under or above a write or ask entry, or an exec entry at or under one
(`[live-fence-write]`), and
(`[live-fence-entry]`) a read or exec entry that is or passes through a symlink (name the path it leads to), a read
entry meeting Tego's own state, a built-in `deny_read` row, another `deny_read` or `ask_read` entry or an
`exec.allow` path beneath it (every one of these relations asked of both the declared and the resolved spelling, E8),
an exec entry, or one of its helper images, at or beneath one of the fence's own read entries (*added 2026-10-27*,
the launcher's fence: lifting the program alone would run it, and read it, inside the refused folder), a unix socket, abstract name, range or port-less net entry, a net
entry with no `net:` section, an exec entry that is not an absolute path to a file, and an entry listed twice; it warns
`[live-fence-local]` at a loopback or link-local destination or localhost. A rule a fence entry added is marked
`Fence` and named `live.fence[<kind>:<value>]`; so is every helper image compile grants for an exec entry's tool
(git's exec-path git and dashed helpers, ADR 0048 (2)), named after the entry (`ExecRule.FenceEntry`) and listed on
`LiveEntry.Images`. The decision core (`decide.Evaluate`, `Evaluator`) names every
allowed action a fence entry reaches (`LiveTable.For`: a read beneath a read entry, an exec of its path, of one of its
`Images` or of its `Name`, a TCP connect to its destination as given; `LiveTable.ForNet` finds a connect by the net
rule it matched) after that entry, whatever contract rule matched it. `RuleTable.Live` holds
the entries, each `{Kind, Value, Source (deny|new), Name, Raw, Pos}` with `Value` as `internal/liveblock.Normalize`
names it, and `SHA256`, the hex sha256 of the JSON array of `{Kind, Value, Source}` in entry order, with `Name` after
`Source` on an entry that has one (`run_start.live_fence.sha256`; `Images` are this host's files and not part of it).
The launcher seeds a refusal of every fence entry before the agent's first instruction (ADR 0125 decision 5);
`runtime.Run` refuses to start an Adjustable run it cannot hold that way (`ErrLiveStart`: no run directory, an
`--observe` run, no supervisor, tier landlock, a plane that decides notifications, or read entries without held
reads). `tego adopt` and `runtime.Adopt` refuse an Adjustable table (`[live-unavailable]`, `ErrLiveUnavailable`): an
adopted process started before any refusal could be in place.
`RuleTable.HoldsFSNotifications` is true for an Adjustable table, so the plane modes keep every fs notification.

## 6. Edge cases

E1. Zero-byte contract → `Diagnostic{Code:"schema", Line:1}`, no panic (yaml.v3's EOF translated, never propagated raw). E2. UTF-8 BOM → stripped before parse (yaml.v3 doesn't strip it and would misreport col 1). E3. CRLF endings → line numbers unaffected (`\n`-counted); no special handling, documented so no one "fixes" it. E4. Unicode path stored NFD (virtiofs/macOS) vs NFC in YAML → raw-byte comparison, no normalization; a "same" path can spuriously `path-missing` — documented limitation, not fixed here. E5. `extends` cycle (`A→B→A`) → visited-name set on the recursion stack; `extends-cycle` names the chain, never a stack overflow. *Amended 2026-10-24 (ADR 0066):* the stack is each path of the walk, so a cycle through any entry of an `extends` list, at any depth, is this error naming that path; a profile two entries reach without a cycle (a diamond: `extends: [a, b]`, both extending `base`) is none, and merges once, at its first position. E6. `extends` name not found → `extends-not-found`, `Fix` names the file to create — `create <profiles>/<name>.yaml, or remove extends:` when the profile source can say where it reads the name from (`agent.ProfileLocator`, which `internal/cli`'s directory source implements), otherwise `add a profile named <name> where profiles: in the machine config points, or remove extends:`. E7. `extends: ../../etc/passwd` or absolute → the filesystem `ProfileSource` rejects any resolved path escaping its root; `extends-not-found`, never an arbitrary read. The containment is resolution-level, not lexical: a name that leaves the root as written is not found without a read, and the file is read through `os.Root` (`internal/profilesrc` `Dir`, internal/cli's `dirProfiles`), which opens every component beneath the root and refuses a symlink leading out of it — `profiles/evil.yaml -> ../outside/x.yaml`, or a linked directory on the name's path — so `Load` reports `extends-not-found` with that refusal as the fix. A relative link that stays inside the root still resolves; `os.Root` refuses every link whose target is absolute, even one naming a file inside the root (`ln -s "$PWD/base/py.yaml" py.yaml`, a stow farm of per-file links), so a link in a profiles directory must be relative — fail-closed, and reported as `extends-not-found` like an escape. A lexical prefix test followed by a plain read is not enough: it would follow such a link and make the outside file contract input with no diagnostic. A profile with a second name (a hard link, anywhere) is untrusted as well (*added 2026-10-20*, ADR 0059): `extends-not-found` naming its count and the fix, since R10 keeps every write entry off the profiles directory and none is compared with the other name. *Amended 2026-10-24 (ADR 0066):* a name under `tego/` is never resolved through the profiles directory: every load site takes its source from `internal/cli` `profileSources`, an `agent.ProfileChain` whose built-in sources alone serve that namespace, and the directory is only asked, by an `lstat` through `os.Root` that reads nothing (`dirProfiles.Holds`), whether it holds the file, which is then `shadowed-builtin`. E8. `fs.write` path is a symlink → existence follows it (`os.Stat`); `FSRule.Path` stays the entry **as declared**, because that string is the ledger's `rule` field and what `tego drift` compares against, while `FSRule.Resolved` carries the symlink-resolved path. Every containment question is asked of `Resolved` — R10's run-dir/contract-file overlap, the `deny_read` `unenforced` marker, and its `exec.allow`-directory extension — and so are the mount/filesystem/device metadata of the print. The run opens each entry `O_PATH` **without** `O_NOFOLLOW`, which *follows* the link and pins the target, so a rule on a symlinked entry governs the target's subtree; comparing declared names answers a different question from the one the kernel asks, and let a `ledger_root` symlinked inside a write entry, or a write entry symlinked onto a secret's parent, pass both checks silently. A path that does not exist yet (the write directory `run` creates) resolves through its parent. Diagnostics name the declared path and its target when the two differ. E9. Multi-segment missing parent chain (`/work/out/deep/nested`) → `path-missing` names the *first* missing segment (only the leaf write dir is created by `run`). A missing `fs.write` entry with a glob character (`./out/*`) is `path-missing` too, its fix naming the directory above the pattern: a write entry is a path, never a glob, and marked missing it would make `run` create a directory literally named `*`. E10. Two `fs.write` entries, one an ancestor of the other → not an error, `redundant-rule` warning on the subsumed one. E11. `Command[0] == ""` → `schema` at `Load`, not deferred to PATH resolution. E12. `exec.allow` basename shadowed by a same-named directory earlier on `PATH` → skipped (R8), search continues; `exec-not-on-path` only if every candidate is shadowed. E13. Basename resolves to a different inode by the time `run` actually execs it (a `pyenv` shim rewrite between `compile` and `run`) → accepted, documented race — the `O_PATH` fd at run start pins whatever exists *then*; `compile`'s read is advisory. E14. Truncated/corrupt ELF (too short for `e_phoff`/`e_phnum`) → `malformed-elf` warning, `Interp` left empty, documented as producing a later Landlock `EACCES` at `run` — the warning exists so that isn't a surprise. E15. `extends` chain deeper than 8 (non-cyclic) → `extends-too-deep`, bounding runaway configs the cycle detector alone wouldn't catch before the bound. *Amended 2026-10-24 (ADR 0066):* the depth is the longest chain through every entry of every list; a profile reached a second time is not merged again, but the chain beneath it still counts toward the path that reached it, so a diamond cannot hide a chain deeper than 8. A list holds 1 to 8 names (`MaxExtendsList`), each a profile name; `extends: []`, a ninth name or a null entry is a `schema` error, and a name the list repeats warns `redundant-rule` and merges once. E16. Statically-linked binary (Go, musl-static) → no `PT_INTERP` header found → `Interp == ""`, **not** `malformed-elf` (E14) — "no header present" (expected) is distinguished from "header too short to tell" (malformed). E17. `net.allow` host is a bare IP literal → `NetRule.Static = true`, no DNS, `TTL` unused. E18. DNS `NXDOMAIN`/timeout → `host-unresolvable`, error without `--offline`, warning with it (`IPs` left empty, the launcher resolves at run start). E19. DNS TTL of 0 (common for CDN-fronted hosts) → floored at 5s before handing to the launcher's re-resolution loop, bounding resolver QPS. E20. Malformed `cidr:port` (`/33`, bad dotted-quad) → `schema` at `Load` time, not deferred to `Compile`'s network phase. So is an IPv4-mapped IPv6 prefix (`::ffff:10.0.0.0/104`), which no connect matches because every address is compared in its IPv4 form — the fix names the IPv4 prefix to write, as the machine config's `denied_resolved_addresses` already refused it — and a host whose last label is all digits (`1.2.3.4.5`, `10.0.0.256`, inet_aton's `127.1`), which is no host name (RFC 3696 §2) and is never sent to DNS as one. So is an IPv6 address with a zone (`[fe80::1%eth0]:443`), in a contract and in a `compile --test` row: a zone names an interface no tier matches on, and the fix names the address without it. E21. Contract file deleted/replaced between `Load` and `Compile` (two CLI invocations) → no effect on an already-returned `*Contract`; `Compile`'s own existence checks surface as ordinary `path-missing` — no liveness promise about the filesystem past any return. E22. Concurrent `Load` racing a non-atomic in-place editor write → each call sees whatever bytes were on disk at its own `ReadFile`; no torn-read protection is promised (contract edits and `compile --upgrade` both write via temp-file-plus-rename in practice). E23. Wall-clock step (NTP, `date -s`) during a long-lived `RuleTable`'s TTL comparisons → `time.Time` from `time.Now()` carries a monotonic reading that survives arithmetic; `NetRule.ResolvedAt` is never marshaled anywhere, kept purely in-memory, precisely so TTL math stays monotonic-safe across a step. E24. Thousands of `fs.write`/`net.allow` entries (machine-generated) → O(n)/O(n log n) validation (map-based dedup, not pairwise), DNS resolved concurrently through a bounded pool (§9), not serially. E25. Contract file over 1 MiB, or YAML anchors/aliases expanding it far larger (a "YAML bomb") → rejected before parse (`Message:"contract exceeds 1MiB"`); yaml.v3's own alias-expansion ceiling backs up the rest. A contract, a profile and a test table are opened `O_NONBLOCK` (`agent.OpenFlags`) and read only from a regular file, a pipe or a socket (standard input handed over as a socketpair; `ErrNotAFile` otherwise), at most 1 MiB and a byte, so a FIFO with no writer cannot hold `compile` or `run` in `open(2)`, and no profile is read whole before the size check. A pipe with a writer (`tego compile <(generate)`) still reads; a FIFO with none reads as empty, which is E1. A contract file given by its path that is a regular file with a second name is refused before it is read, `agent.Load` returning an error that is `config.ErrUntrusted` and the CLI `config-untrusted` (*added 2026-10-20*, R10, ADR 0059), unless no run of the invoking user could write it by any name. E26. Duplicate `mcp[].name` → `schema`, error (names are referenced elsewhere and must be unique). E27. A `models[]` `host:port` also present in `net.allow` produces `model-direct-bypass`: when capture is forwarder, the guard still refuses direct access and the redundant allowance cannot override it. Remove that allowance and use the forwarder. Pinned `capture: uprobe` at cgroup or bpflsm needs direct access and gets no warning; a tier left to the machine gets a conditional warning, and a machine ceiling lowering it to forwarder gets the definite one. Under a `net:` section, unknown destinations on a non-localhost named model's port are refused (`models.port[host:port]`) until explicitly allowed, so unrelated HTTPS services sharing port 443 need `net.allow`; known model addresses remain refused even with such allowances (*amended 2026-10-05:* the reservation applied with no `net:` section too, refusing every other HTTPS host of a contract that declares no network policy, and `compile` only warned `model-port-restricted`; with no `net:` section the port is again not reserved (SEMANTICS §1) and the warning is removed). Observe mode records without enforcing. E28. Relative `fs`/`exec` paths → resolved against `os.Getwd()` captured once at `tego run` start; **not stated by any normative doc**, specified here as the default (§11). E29. `net.allow` and `net.ask` naming the same TCP `host:port` → ordinary allow takes precedence; the approval rule carries no ordinary kernel grant and cannot remove the existing allowance (R22). E30. Binary upgrade mid-run (rename while a run is live) → the live process keeps its in-memory `*Contract`/`*RuleTable`; `Load`/`Compile` are never called again during a run (I9) — only the *next* `tego run` sees a different binary/schema. E31. PID reuse → not applicable: `Action`/`RuleTable` carry no pid, `Evaluate` is stateless with respect to any live process (exec-id stability across reuse is `pkg/spec/identity`'s concern, not this package's). E32. `limits.tokens` overflowing `int64` (`99999999999999999999`) → `UnmarshalYAML` rejects it as `schema`, never silently wraps. E33. `limits.memory: 8GB` (decimal, not IEC) → rejected as `schema`, `Fix` suggests `8GiB` — accepting `GB` silently would make identical-looking contracts mean different byte counts.

E34. Big-endian or 32-bit-on-64 ELF target (mips, s390x BE, x32) → the "ELF64/32 LE" scope in §2/§3 is this package's chosen P0 platform floor, not a documented restriction — `ARCHITECTURE.md` §14's support matrix lists distributions, not architectures, and rules out none of them. `PT_INTERP` extraction checks `e_ident[EI_DATA]`/`EI_CLASS` first; anything other than 32/64-bit little-endian fails closed as `malformed-elf` (E14) rather than being silently misread, per I7. Broadening past LE is unresolved by any doc (§11). E35. `chmod` is denied at tier 3 only. Landlock has no `CHMOD`/`path_chmod` access right in any published ABI: `/usr/include/linux/landlock.h` with the Linux 6.17 headers defines the filesystem rights as bits 0-15, ending at `LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)`, with no chmod, chown, utime or setxattr right, and `man 7 landlock` CAVEATS lists `chmod(2)` among the actions it cannot restrict. Neither enforcing tier below 3 backs it up: tier 1's seccomp notify tables (`internal/runtime/enforce/landlock/filter.go`) carry the `chmod` family (`chmod`, `fchmod`, `fchmodat`, `fchmodat2`) under `record: full`, and under an `fs.write` gate at every record level, so the supervisor records one and at tier 1 continues it unless that gate refuses it (R22a; `docs/p0/gate.md` R4), `deny_write` included (where a decision plane decides the run it refuses one beneath a `deny_write` target first, as the plane's `path_chmod` would; `internal/runtime/supervisor/fs.go`, `docs/p0/supervisor.md` R17, `docs/p0/enforce-landlock.md` R11, R16), and carry the `chown` and xattr families (`fchownat`, `setxattr` and their forms) under an `fs.write` gate only, which the supervisor scores as writes and otherwise continues (amended 2026-10-16: a POSIX ACL set through `setxattr` changes a mode as `chmod` does), and `utimensat` under no option, so without such a gate the supervisor never sees those; tier 2's fanotify listener has no permission event for an attribute change and inherits tier 1's ruleset, which has no right to refuse it with. Only tier 3's BPF LSM `path_chmod` hook (`ARCHITECTURE.md` §11) can. The capability matrix says so: the row "deny delete, rename, mkdir, mknod" is present at every tier (Landlock's `REMOVE_*`/`MAKE_*`/`REFER` rights), and chmod is its own last row, `fs.deny_chmod`, absent at tiers 1 and 2; at tier 3 too as built (TIER3-PLAN T13), whose `path_chmod` refuses a mode change beneath a `deny_write` target only, not under the write rules, which the tier-3 cell says (`pkg/spec/backend/matrix.go`, `spec/backend/CAPABILITIES.md`, `TestChmodDeniedOnlyAtTier3`), so every run's capability line names it absent. The older row keeps its wire name `fs.deny_delete_rename_mkdir_chmod_mknod`, which ledgers carry. `pkg/spec/agent` never claims a chmod refusal: `AccessSet` has no such bit (`access.go`), `AccessWriteSet` cannot grant one, and a `fs.chmod` action is rejected as an unknown kind by both `Evaluate` and `LoadTestTable` rather than answered with a refusal (also R15). The agent-visible consequence belongs with E38: an agent that can create a file inside an `exec.allow` directory can also set its execute bit, because no tier below 3 can stop it. E36. The exit-code table of `spec/identity/RUN-IDENTITY.md` and `pkg/spec/identity/exit.go` no longer use the LSB/systemd range 200–254 for a failed run: the R10 contradiction is a compile error and `tego run` exits 125 with the diagnostic code `[contradiction]`; the machine-config code (formerly 213) is folded into 125 as `[config-untrusted]` (`ExitConfig = ExitLauncher`); the one code in that range is 211, `doctor --require <tier>` below the required tier (`ExitRequire`), never `tego run`'s. This spec's former exit 210 for R10 is gone (SEMANTICS §2 and P0-DESIGN §2.1 are the sources that named it). E37. An `mcp[].command[0]` bare basename is not resolvable on the run's effective `PATH` (distinct from `Command[0]`/`exec.allow`, R8) → `exec-not-on-path`, same code and `Fix` shape as any other PATH exhaustion, with the message additionally naming the offending `mcp[].name` so a contract with several MCP servers doesn't need per-entry guessing. E38. An entry that grants `EXECUTE` resolves at or under an `fs.write` entry, or is a directory that holds one (`exec.allow: [tools]` with `fs.write: [tools/cache]`) → not an error, but an `exec-writable` warning on the exec entry, in **every** tier. A **directory** entry is the whole-list bypass: `LANDLOCK_RULE_PATH_BENEATH` names a file *hierarchy* (`man 2 landlock_add_rule`), so the grant covers files created after `landlock_restrict_self`, and the root tiers match a directory entry by path prefix (`internal/policy/decide/exec.go` `matchExec`) — the agent writes a binary under the directory and runs it, and `exec.allow` has stopped bounding what runs. A **file** entry is the narrower case: `AccessWriteSet` carries `WRITE_FILE` and `TRUNCATE` across the write subtree, so the agent rewrites the allowed binary in place (the landlock tier's pinned inode keeps its `EXECUTE`) or replaces the path (root tiers); Landlock cannot deny `chmod` at any ABI (E35), so setting the execute bit is free. `Fix` names the individual binaries for the directory case and the write entry for the file case. Containment is asked of the **resolved** paths on both sides (E8). Not an error, because a contract may legitimately want it (a build directory whose own output is run under test) — but it must never be silent, the way E27 is not silent for the strictly weaker network analogue. Published shape of the same move: CVE-2025-54135/CVE-2025-54136, where content an agent could write later decided what it was allowed to run; Tego's boundary is the compiled table, not a harness file the agent can edit, and the built-in `deny_write` targets guard those harness files, best effort below a decision plane and race-free only at the tiers with one (R15, R20), unless a write entry opts out. This warning is the other half: what the agent writes and the table lets run. The same `exec-writable` warning names an `exec.allow` directory every user can write (mode o+w, `/tmp`'s 1777) or one that holds `/tmp`, `/var/tmp` or `/dev/shm` (`/`, `/var`, `/dev`) whether or not a write entry reaches it, since anything any process drops there runs; and `fs.write` on procfs (`/proc` or beneath) or on `/dev` itself warns `kernel-fs-write`, since those files write to the kernel, to the uid's other processes and to devices, not to storage (a single device file such as `/dev/null`, and `/dev/shm`, are not warned about; `/sys` is the implicit entries' contradiction).

E39. A write entry holds native code the agent will map executable (an ELF shared object, `*.so` or `*.so.N`, or a Node addon, `*.node`) or a native-module tree that fills with it (a `.venv`, a Rust `target/`), and no `exec.allow` entry covers it → not an error, an `exec-map` warning on the write entry, one per tree, in a contract with an `exec:` section whose run may land at tier `cgroup` or `bpflsm` (added 2026-09-30, ADR 0027). There the decision plane refuses a `PROT_EXEC` map of a file under a write entry unless an `exec.allow` entry covers it (enforce-plane R26), so the import or `dlopen` of such a module fails at run time (a C extension with a pure-Python fallback, markupsafe's, silently slows down). The tree is named by its outermost `.venv`, `venv`, `site-packages`, `node_modules`, `target` or `build` directory under the write entry, else the file's own directory, and `Fix` names the entry to add (`exec.allow: add "./out/.venv/"`); that entry then warns `exec-writable` (E38), the trade the contract makes knowingly. Tier `landlock` decides no mapping, so a run that can land nowhere else is not warned. The scan reads where the agent writes, so it reads as R20's search does (I6): each directory listed with what is left of 20,000 entries per write entry, 10 levels deep, breadth first, no symlink followed, `.git` skipped, and each candidate's magic read through the same `O_PATH`/`fstat`/`fstatfs`/`O_NONBLOCK` open as a candidate binary's (§3), so a FIFO or a leased file named `*.so` is refused, not waited on; the whole scan has a 2 s limit. A tree deeper or later than that is not named, and a scan cut at its entries or its time limit says so in an `exec-map` warning on the write entry (`TestNativeCodeUnderWriteEntryWarns`, `TestNativeCodeScanBoundedWarns`, `TestIsELFRefusesAFIFO`).

**Changes.**
- 2026-10-25, R6 and R12 (ADR 0067): the built-in `deny_read` list gains the agents' own
  token stores and the vendor-documented stores of the tools an agent runs beside (18 rows, the harness's own store
  included), each joining `RuleTable.DenyReadPatterns`; new warning `secret-env` when a contract with no `env.pass`
  hands the agent an environment holding secret-looking variable names (`agent.WithEnviron`). A contract that runs
  Claude Code without `CLAUDE_CONFIG_DIR` now has its reads of `~/.claude.json` and `~/.claude/.credentials.json`
  refused.
- 2026-10-25, R6 (ADR 0067 D3): each
  `RuleTable.AbsentDenyRead` row (`AbsentRow`) carries `At`, the name the Landlock ruleset leaves out for it, which the
  tier models refuse a read beneath; a row that is a symlink leading nowhere is recorded by where the link leads, and
  one an exec.allow directory covers is left out.
- 2026-10-26, R12: a contract tego generated (`tego watch` with no `--boundary`) is compiled
  with no environment too, so secret-env never asks for an `env.pass` its user cannot add.
- 2026-10-25, R12: `tego adopt` and the guard compile a boundary
  with no environment, so secret-env never names the adopting process's variables for a process that has its own.
- 2026-10-25, R12: `secret-env`'s fix is "add env.pass naming the
  variables the agent needs"; it named `tego/no-secrets`, which no binary resolved then.
- 2026-10-25, R6 (ADR 0067 D3): `RuleTable.DenyReadPatterns` refuses
  alternates only; a built-in row absent at compile is recorded in `RuleTable.AbsentDenyRead`, which the Landlock
  ruleset enumerates, so a file created at it during the run is refused for a direct read. The list gains
  `~/.claude/backups`: Claude Code keeps its five newest copies of `~/.claude.json` there.
- 2026-10-25, R29 (new) and R5 (ADR 0077): the optional `reason.reads: auto | on | off`,
  `contract-wins`, in a `reason:` section R5's `section` row merges; `auto` is the measured off; compile prints the
  cost; `run_start.reads_notified` at record minor 23.
- 2026-10-25, R27 (ADR 0063): for a user file a provisioner asks for, compile
  answers an empty settings object once the path passes the run's checks and checks the provision as a run does, so
  a `--settings` path under an allow-list warns `hook-not-granted` and one with `env.set TEGO_CLAUDE_SETTINGS` is
  refused, as a run is; the `provisions from <path>` line became `merges <path> into the file at run time`.
- 2026-10-25, R27 (ADR 0063): compile gives the provisioner the contract's
  `env.set` as the agent's environment and says an inherited variable can change the provision; a user file a
  provisioner asks for is checked as the run checks it (`CheckUserFile`) and printed as read at run time, no longer
  as `(a run is refused)` when a run would read it.
- 2026-10-25, R5 (ADR 0068): a preset and its pin to the revision it is are one profile, merged once
  under the first name, with one `redundant-rule` at the second name's line when one list names both.
- 2026-10-25, R28 (new, ADR 0073): the optional contract key `revision:`, `refused-in-profile` (R5's first row of
  that class), part of the canonical bytes, printed by compile and recorded as `run_start.contract_revision`.
- 2026-10-25, R28 and R3: `revision`, `name` and `mcp[].name` are YAML strings, as
  agent.schema.json types them: an unquoted number or boolean is a `[schema]` error with the fix to quote it, where Go
  took its text and a JSON Schema validator refused it; a null `revision` is a `[schema]` error, not none.
- 2026-10-25, R3: `tego init` writes the name double-quoted, since an agent id such as
  `2024`, `true` or `null` is not a YAML string when plain (`TestInitWritesAContractThatLoadsForAnyName`), and a
  registry entry's refusal gives the fix `write name: "<name>"` (`TestAnEntryRefusalsFixQuotesTheName`).
- 2026-10-25, R20: `RuleTable.DenyWriteLinked` holds one name per
  file, and none for a file whose every name lies beneath a deny_write place or whose inode another row the plane keys
  refuses modifying, since the plane keys one fs row per inode and two hooks linked to each other made an R20-only
  table one no plane held; a linked file another row grants writing is a `contradiction`; under `fs.assurance: kernel`
  a linked-file search a bound cuts is a compile error.
- 2026-10-25, R20: `RuleTable.DenyWriteLinked`, the regular files beneath an
  `fs.deny_write` directory entry or a built-in directory target with another hard link at compile, which the plane
  keys at their inodes.
- 2026-10-25, R20: a candidate is placed at the link's own place too, so a symlink
  beneath a write entry leading out of every one is held at its name rather than left out; an `fs.deny_write` entry is
  placed the same way, and is covered by another only where each of its places that matters is.
- 2026-10-25, R20: an `fs.deny_write` entry at a built-in target's place no longer
  removes the target; both rules hold, so a write entry inside the place still grants nothing beneath the target and
  the target's link spelling stays held.
- 2026-10-25, R5, R20 (ADR 0071): `fs.deny_write`, a contract's own list beside the built-in set:
  literal paths, merge class `union`, compiled into `RuleTable.DenyWrite` with `BuiltIn` false and reopened by a write
  entry strictly beneath it (nearest wins); R20's sentence that a write entry inside a built-in target reopened it by
  nearest wins is corrected, since no tier did and none does.
- 2026-10-25, R10a (5), R27: what lies beneath the filesystem holding the tego binary
  or its loader is held to the write and ask entries (an overlay's layers, a loop device's backing file, an image the
  filesystem is mounted from), and a stacking filesystem whose layers cannot be named (FUSE) or a block device sysfs
  does not show is not granted (`harness-hook-writable`): a binary on an overlay whose upper layer lay under a write
  entry was granted, and the agent could rewrite it through the layer (`TestHarnessHookStackedNamesAreNotGranted`).
- 2026-10-25, R10a (5), R27: a mount table that shows no mount holding the tego
  binary or its loader is one whose bind-mount names of it the launcher cannot see, and no grant is made
  (`harness-hook-writable`): a chroot whose root is no mount point skips the mount above it yet lists the binds beneath,
  so a bind of the binary's directory into a write entry was granted (`TestHarnessHookOtherNamesAreNotGranted`).
- 2026-10-25, R10a (5), R27: the hook grant holds every name of the tego binary and
  its loader to the entries, the places a bind mount shows them included, and is not made for a file with a second
  link or behind an unreadable mount table (`harness-hook-writable`): a hard link made before the run under a write
  entry let the agent rewrite what the grant runs (`TestHarnessHookOtherNamesAreNotGranted`).
- 2026-10-25, R10a, R27 (ADR 0064): R10a (5) (new): under an allow-list contract the launcher
  grants the harness hook's exact argv (`exec.harness-hook[<tego binary>]` in `runtime_grants`), never for a binary or
  loader under a write entry, an `fs.ask` scope or a `deny_read` entry, nor when the binary's name stays at any
  arguments. R27: an allow-list contract's provision is no longer always dropped; the drop reasons are `hook-refused`,
  `harness-hook-writable` and `hook-not-granted` (now only a grant that cannot be exact); compile prints the hook line;
  `harness.hook {argv, granted}` at record minor 20.
- 2026-10-25, R27: compile refuses a provision by the run's own check, so a
  provision variable the contract's `env.set` gives is printed `provisions nothing ... (a run is refused)`, not as made;
  compile shows a `CODEX_HOME` file as a run routed through the forwarder makes it.
- 2026-10-24, R27 (new, ADR 0062): `harness:` names the harness the launcher provisions for, `auto` resolved from the
  command's basename; the launcher makes the provision's files by directory descriptor, read-only to the agent, and
  refuses or drops a provision as R27 says; `run_start.harness` at record minor 14. R5's `contract-wins` row lists
  `harness`. R10a (4) (new): the run's `hook-state` directory is granted as `fs.harness-state[<path>]` when a harness is
  provisioned, refused under an exec directory entry, and a deny-list run refuses an exec from it `harness-state-exec`.
- 2026-10-19, R10a: a launcher killed before its shutdown no longer leaves its runtime directory,
  `CODEX_HOME` and typed key included, until logout: the next unprivileged launch under the same parent removes each
  run's directory whose `.lock` no launcher holds (`TestAKilledLaunchersRuntimeDirIsRemovedByTheNextLaunch`).
- 2026-10-17, R10a: the open read condition names what is read (a typed key, the
  sessions) and the interim measure the operator guide gives; a `<run id>` directory that is not private after its
  own `mkdir` is refused for every run, as the code does, not only for a routed one. On a deny-list the
  `exec-rule-coverage` warning names an ask-only section's tool and tells a contract with `exec.anonymous` to drop it.
- 2026-10-16, E35 (ADR 0041): an `fs.write` gate also has the filter notify the `chown` and xattr families, which the supervisor scores as writes; `utimensat` stays unnotified.
- 2026-10-16, R8a: an ELF entry whose `PT_INTERP` loader is or leads through a `/proc` path is an
  `exec-proc` error too.
- 2026-10-16, R8a (new): an exec entry that is or leads through a `/proc` path is an `exec-proc` error; `/proc/self/exe`
  compiled to tego's own executable. Amended the same day: the walk applies `..` after the links before it, as the
  kernel does, not lexically.
- 2026-10-16, R10a (new): a write or ask entry over or inside tego's runtime directory is a contradiction; the run
  grants its own `CODEX_HOME` (`fs.codex_home`), and an openai listener with no `XDG_RUNTIME_DIR` is exit 125.
  Amended the same day: `/run/user/<uid>/tego` is protected whatever the environment
  says, at every euid; the grant needs the directory the run made; an exec directory over the `CODEX_HOME` refuses
  the run; a root run with an openai listener writes `gap why=codex-unrouted`. Amended again: in
  a deny-list run an exec whose image or loaded program lies in the `CODEX_HOME` is refused `codex-home-exec`; the
  grant carries the directory's identity to Landlock's `Prepare`, and a runtime directory another user could swap is
  refused.
- 2026-10-16, R10a: the text no longer says the grant was a deny-list run's only writable
  place for a copy; a memfd copy, a deleted file's and a mapped program's code run in every deny-list run, and
  `exec-rule-coverage` now warns on every deny-list, not only one beside `fs.write`. `codex-home-exec` stays.
- 2026-10-17, R10a: `codex-home-exec` judges a linked image on the kernel's spelling of it even
  when the supervisor cannot walk that spelling back to the file; a copy in a directory the agent made unsearchable,
  run through its descriptor, ran. And the write closure holds for enforcing runs only: an
  `--observe` run's agent and the user's processes outside tego can write the directory.
- 2026-10-05, E35: an `fs.write` gate keeps the chmod family notified under `summary`/`off`; the gate's verdict on a chmod no longer depends on the record level.
- 2026-10-05, E35: tier 1's filter notifies the chmod family under `record: full`, record-only at tier 1 (enforce-landlock R11, R16); below tier 3 only a decision plane's `deny_write` predicate refuses one.
- 2026-09-30, E38: a directory exec entry that holds a write entry warns too.
- 2026-09-30, E39: the scan's reads bounded as R20's (listing, `openData`, 2 s); a cut scan warns.
- 2026-09-29, E35 (TIER3-PLAN T13): tier 3's `path_chmod` protects `deny_write` targets only, so `fs.deny_chmod` is absent at every tier and the tier-3 cell says why.
- 2026-09-29, E38: `matchExec` is cited at `internal/policy/decide/exec.go` (the decision core moved there, ADR 0028).
- 2026-09-29, E9: a missing `fs.write` entry with a glob character is `path-missing`, not a leaf `run` creates.
- 2026-09-29, E36: `TestRunRefusedForContractOverlapExits125` (`internal/cli`) asserts the exit 125 end to end.
- 2026-09-28, E36: restated to the code: 211 is `doctor --require`, 213 folded into 125, R10's 210 gone (R10, §7 and ErrContractOverlap's note followed).
- 2026-09-23, E7: profiles read through `os.Root`, refusing links out of the root.
- 2026-09-23, E27: pinned uprobe capture and machine ceilings decide `model-direct-bypass`.
- 2026-09-24, E27: one `model-direct-bypass` warning per entry for a pinned uprobe with the tier
  left to the machine, from `Compile`.
- 2026-09-24, E6: the fix no longer names a nonexistent `init --profile`.
- 2026-09-24, E20, E25, E38: mapped prefixes and numeric hosts refused; FIFO-safe bounded reads; world-writable exec dirs and kernel-fs writes warned.
- 2026-09-24, E20: a zoned IPv6 address is refused, in a contract and a test row.
- 2026-09-24, E25: a socket (a socketpair on standard input) is read as a pipe is.
- 2026-09-28, E35: closed; chmod left the delete/rename row for its own `fs.deny_chmod` row, present at tier 3 only.

## 7. Failure modes and handling

| Failure | Detection | Response | Ledger | Exit | User sees |
|---|---|---|---|---|---|
| Top-level file missing/unreadable | `os.ReadFile` error | wrapped I/O error, no `Diagnostic` | none | 125 | `tego: open agent.yaml: no such file or directory` |
| Unknown field | `KnownFields` | `schema`, error | none | 125 | `agent.yaml:14: unknown field "wrte" [schema]` + `Fix` |
| Not-yet-supported field, non-empty | R2 | `not-yet-supported`, error | none | 125 | names the field and release status |
| `extends` cycle/not-found/too-deep | R5/E5/E6/E15 | matching code, error | none | 125 | names the chain |
| A profile sets a key of class `refused-in-profile` | R5's merge classes, at `Load` | `schema`, error | none | 125 | `profiles/p.yaml:2: <key> is the top-level contract's own: a profile cannot set it [schema]`, fix `set <key> in the top-level contract` |
| A profile writes a value a `stricter` key marks loosening | R5's merge classes, at `Load` | `profile-cannot-loosen`, warning; the value is ignored | none | 0 | names the key, the value and the profile's line |
| `fs`/`exec` path missing | `os.Stat` | `path-missing`/`exec-not-on-path` | none | 125 | path, and for exec every `PATH` dir searched |
| An exec entry that is, or leads through, a `/proc` path (added 2026-10-16) | R8a | `exec-proc`, error | none | 125 | the entry and the `/proc` spelling it reached; the fix names the program's own path |
| A write or ask entry at, over or inside `/run/user/<uid>/tego` or `$XDG_RUNTIME_DIR/tego` (added 2026-10-16; the logind directory whatever the environment says, amended the same day) | R10a | `contradiction`, error | none | 125 | the entry and tego's runtime directory; the fix says the run grants its own `CODEX_HOME` |
| An `exec.allow` or `exec.ask` directory that holds or lies in tego's runtime directory (added 2026-10-16) | R10a | `exec-writable`, warning | `tego run` refuses a run whose `CODEX_HOME` grant it covers (`ErrCodexHomeExecutable`) | 0 at compile, 125 at run | the exec entry and the runtime directory; the fix says to list binaries |
| `mcp[].command[0]` unresolved on PATH | R8/E37 | `exec-not-on-path`, error | none | 125 | mcp server name, every `PATH` dir searched |
| `mcp` entry with both or neither of `command` and `url`; a `url` that is not http(s) with a host, or carries credentials, a query or a fragment | R16a | `schema`, error | none | 125 | mcp server name and what is wrong |
| Two `mcp[].url` on one host and port, or one on a `models[]` endpoint | R16a | `contradiction`, error | none | 125 | both names |
| `mcp[].url` on a `models[]` host at another port | R16a | `unenforced`, warning | no tool call of that server derived | 0 | server, host, provider |
| `mcp[].url` endpoint also in `net.allow`, or decided by a `net.ask` entry (same port; same host, or a CIDR or kept address holding one its name resolved to, kept or dropped under R18) | R16a | `redundant-rule`, warning | none derived; the author's entry decides | 0 | the entry, the server, and every address of the server that no ask entry holds by its CIDR or kept addresses (refused unless another `net.allow` entry admits it; one R18 dropped with its class) |
| Host unresolvable, online | DNS error/timeout | `host-unresolvable`, error | none | 125 | host name, suggests `--offline` |
| Host unresolvable, offline | same | `host-unresolvable`, warning | n/a | 0 | printed; launcher resolves at run start |
| Limit above ceiling | R11 | `limit-above-machine`, warning, clamped | n/a | 0 | `ceiling memory=32GiB kept from config.yaml:19` |
| A `limits.tokens`, `cost_usd` or `repeats` budget the contract sets while the capture it compiles to is off (its own `capture: off` or a machine ceiling), or while it declares no `models:` and may capture with the forwarder alone | R11 | `budget-unmetered`, warning, at the budget's line (*amended 2026-10-16*: it was `unenforced`) | `tego run` refuses the run before `run_start`, no record (limits-check-doctor-cli.md R32); a budget a machine ceiling alone imposes is not warned, and its run records `gap what=record why=budget-unmetered binary=<budget>` after `run_start` | 0 at compile; 125 `[budget-unmetered]` at `run` | `limits.tokens budget never trips: the contract sets capture: off, so no model traffic is metered, and every run of this contract is refused` |
| `fs.write` overlaps run-dir/contract/chain anchor | R10 | `contradiction`, error | none | 125 (§5 R10, §6 E36) | names the overlapping path |
| Malformed ELF for `exec.allow`/`mcp` binary | E14 | `malformed-elf`, warning at compile | none at compile; a later Landlock `EACCES` at `run` | 0 then 126 | warning, then a plain refusal later |
| A candidate binary R8 reads cannot be read: a FIFO, a device, a kernel interface file, a file system not on the list of those read as data (R20), a lease or lock held on it, permission (*added 2026-09-23*) | I6, R8 (`openData`) | `malformed-elf`, warning at compile, naming the file and why; the fix names a file system not on the list as the mount table does | none at compile; the landlock and cgroup `run` fails at `Prepare`, which reads it the same way | 0 then 125 | the reason, and for a file system not on the list its name and that it may be reported to be added |
| Exec grant inside a writable directory | E38 | `exec-writable`, warning | n/a | 0 | names the exec entry, the write entry, and what the agent can plant or overwrite |
| `exec.allow` directory every user can write, or holding `/tmp`, `/var/tmp` or `/dev/shm` (added 2026-09-24) | E38 | `exec-writable`, warning | n/a | 0 | names the entry and the shared writable directory |
| `fs.write` on procfs or on `/dev` (added 2026-09-24) | E38 | `kernel-fs-write`, warning | n/a | 0 | names the entry and what it writes to instead of storage |
| `fs.write` over a PATH directory searched before `tego` or `tego-control` (added 2026-11-01) | R10 | `path-shadow`, warning | n/a | 0 | names the entry, the directory and the binary it would stand in for |
| Native code or a native-module tree under a write entry that no `exec.allow` entry covers, at a tier a decision plane may decide (added 2026-09-30) | E39 | `exec-map`, warning | n/a | 0 | names the tree and the `exec.allow` entry to add |
| An exec command pattern the grammar refuses: shell syntax, a path in a deny or ask command word, a glob command word, a misplaced `*`, an allow entry requiring an option its row does not list, the bounds; an unquoted path with spaces naming a file; a directory with words (added 2026-10-06, ADR 0048) | R25, R8 | `exec-rule`, error | none | 125 | names the entry and the word, and the fix (the basename, the separate entries, the quoted path) |
| `$` or a backtick in a pattern word; a deny-list section with no entry (added 2026-10-06) | R25 | `exec-rule`, warning | n/a | 0 | the word is matched literally; the section restricts nothing |
| An `fs.deny_read` or `fs.watch` glob's expansion reaches its bound: 50,000 directory entries, 4,096 files or 2 s, every glob of the compile together (added 2026-09-30) | §3 | `deny_read`: `unenforced`, error; `watch`: `glob-no-match`, warning | none | 125 for `deny_read`, else 0 | names the entry and the bound; `Fix` names the directory entry instead |
| `exec: {anonymous: true}` | SEMANTICS §4 | `unenforced`, warning, at the key | at `run`, no memfd arm: an anonymous exec is `allow`, recorded `fileless`; `run_start.capabilities` has `exec.deny` `false` at tier 1 | 0 | says `exec.allow` no longer bounds what runs, since anything the agent can read or write can run from a memfd; the fix drops the key unless the agent needs an executable memfd (below Linux 6.3, any memfd) |
| `net.allow` host name resolves to a loopback, link-local, metadata, multicast or machine-denied address | R18 | `resolved-denied`, warning; the address is dropped from the entry | at `run`, a connect or send to it is `refused`, `rule: net.denied_resolved[<entry>]`, `reason: net-not-allowed` | 0 | names the entry, each dropped address with its class, and the literal entry that would admit it on purpose |
| A host name whose compile-time answer was public only is rebound, on a refresh, to a private address | R18 | none: compile saw no private address | at `run`, a connect or send to it is `refused`, `rule: net.denied_resolved[<entry>]`, `reason: net-not-allowed` | 0 | the ledger line names the entry; a literal or CIDR entry admits the address on purpose |
| A host name (not a localhost name) resolves, at compile or on a refresh, to one of this host's own interface addresses | R18 | none: compile does not know the host's addresses (I6) | at `run`, a connect or send to it is `refused`, `rule: net.denied_resolved[<entry>]`, `reason: net-not-allowed`; every host entry's destination is refused while the supervisor has no snapshot of the host's addresses | 0 | the ledger line names the entry; a literal or CIDR entry admits the address on purpose |
| `host_sockets: true` with no `net:` section while a well-known host daemon socket exists | R19 | `host-sockets`, warning, once, at the key | run_start `host_sockets: true`; each connect allowed as written | 0 | names each socket and what it gives (docker.sock as root-equivalent), and the abstract-socket condition below Landlock ABI 6; the fix names a `net:` section with a `unix:` entry for the one socket the agent needs (the SSH agent, gpg-agent) |
| No `net:` section and no `host_sockets: true` where the run may land at tier cgroup or bpflsm | R19, ADR 0070 (5) | `unenforced`, warning | run_start `best_effort` lists `host_sockets/root-tier`; a refusal is `rule: host-sockets` | 0 | best effort at the root tiers until the root tiers carry a kernel program for it; the fix names a `net:` section or `tier: landlock` (`TestHostSocketsRootTierBestEffort`) |
| A write entry reaches a built-in `deny_write` target | R20 | `unenforced`, warning, once per target (*amended 2026-10-05, ADR 0041 D1 (a)*); under `fs.assurance: kernel`, an error at a pinned or machine-held tier landlock | below a decision plane, refused by the supervisor best effort and listed in run_start `best_effort`; under `fs.assurance: kernel`, refused before child launch, exit 125 | 0 (1 for the error) | names each target and why it runs code outside the run, says launch requires cgroup with lsm/fmod_ret or bpflsm, and that git's own config writes are refused; the fix narrows the entry or names the target in `fs.write` |
| R20's search is cut (depth, budget, time), finds a file it reads that cannot be read, or has no `/proc` (*added 2026-09-23*) | R20 | `unenforced`, warning of its own for the entry (*amended 2026-10-05:* it rode on the entry's warning when one named a target; targets now warn one by one) | none | 0 | names the entry, each limit, each file not read with why (four, and a count), and a missing `/proc`: a git hook or config beneath the entry may be writable without being named |
| The built-in `.env` scan is cut: entries left unread, its time limit reached, or a directory listed only in part or (the operator's own) not opened (*added 2026-09-23*) | R6, I6 | `unenforced`, warning, once for each | none | 0 | names the run's cwd and the limit, and how many found `.env` files were not resolved; those are not in the built-in `deny_read` list |
| Declared ELF's `PT_INTERP` loader at or below an `fs.write`/`fs.ask`/`fs.deny_read` entry | R15, enforce-landlock E29 | `loader-refused`, warning | none at compile; the landlock and cgroup `run` fails at `Prepare` | 0 then 125 | names the binary, the loader and the entry; the run exits before the agent starts |
| Command, MCP server or `exec.allow` names `bwrap`, `podman`, `buildah`, `unshare`, `runc` or `crun` | SEMANTICS §10 | `landlock-topology`, warning | at `run`, `refused` + `gap why=landlock-topology` when it mounts | 0 | names the entry; the sandbox cannot mount in the landlock or cgroup tier |
| `env.set`/`env.deny` conflict | R12 | `contradiction`, error | none | 125 | names the variable |
| Contract file > 1 MiB | E25 | `schema`, error, before parse | none | 125 | `agent.yaml:1: contract exceeds 1MiB [schema]` |
| `limits.stall_after` set by the contract while the run's record mode (`tego run --record` when given) is not `full` and the run can land at tier `landlock` or is an `--observe` run, where a read is neither a line nor activity (added 2026-10-16), only where a read is unseen there: not under a read gate, which gives each read a line under `summary` and has the supervisor answer it under `off`, nor under `off` with an `fs.ask_read` entry (amended 2026-10-16); or under `summary` below 10 s where the run can land at a root tier, whose recorder counts reads in aggregates flushed every 5 s (amended 2026-10-16). Never at a root tier under `off`, where each allowed open, path change and connect of a stall-bounded run stamps its activity in the kernel (amended 2026-10-19: it was warned there while an allowed open made no sample) | SEMANTICS §8 | `stall-reads-unseen`, warning, at the key, at tier `landlock` and `observe` alone, or at `cgroup` and `bpflsm` alone | at `run`, printed again once the run lands at one of those tiers; an agent that only reads for `stall_after` is ended `limit-stall` | 0 | names the duration and the record mode (`--record` when the run gave it); `Fix` names `record: full` (`--record full` when the run gave `--record`); a root tier only outside an `--observe` run and without `tego run --tier landlock`, which refuses another pin, only one this tego builds and the machine's `tier` admits, under `summary` with a `stall_after` of at least 10 s and under `off` as it is, its kernel stamping each allowed open; the root-tier `summary` warning a `stall_after` of at least 10 s; never `record: off` (`TestStallAfterWarnsWhereReadsAreUnseen`, `TestStallWarningFollowsTheRunsRecordAndObserve`, `TestStallWarningFollowsWhatTheFilterNotifies`, `TestRunStallWarningFollowsRecordAndObserve`, `TestRunStallWarningUnderTierLandlockOffersNoConflictingPin`) |
| A contract's own `record: off`, or a profile's it extends, is the run's record mode: no `tego run --record` replaces it (added 2026-11-02) | `Compile`, once the record mode is resolved (`record` is contract-wins across `extends`, R5) | `record-off`, warning, informational (a note, as `wall-hard-cap` is) | the run's ledger keeps its refusals and no exec or allowed action; its end summary, and a watch's footer, say `record off: refusals only` | 0 | at the `record:` key that set it, a profile's line when the contract extends one; `Fix` names `record: summary` and `tego run --record summary`; `tego run` and `tego watch` print it only under `-v` (limits-check-doctor-cli.md R29, *A quiet start*); none when `--record` is given, `--record off` having its own warning (`TestRecordOffIsNotedWhereTheContractSetsIt`, `TestTheContractsRecordOffIsACompileNote`) |
| `ProfileSource` I/O error (e.g. permission) | wrapped error from `Resolve` | `extends-not-found`, underlying error in `Fix` | none | 125 | one line, OS error appended |
| Profile, its directory or the profiles directory fails the trust rule (spec/config/v0 R20) | `config.ErrUntrusted` from `Resolve` | `extends-not-found`, message `profile "<name>" untrusted: <path> uid=<n> mode=<mode> (<reason>)`, the trust rule's fix in `Fix` | none | 125 | never "not found" |

**Changes.**
- 2026-09-24, `budget-unmetered` row: also warned for a contract with no `models:`.
- 2026-10-16, `budget-unmetered` row: the run is refused, 125 `[budget-unmetered]`, and
  compile's finding carries that code and says so; the run went ahead with a limit that never tripped.
- 2026-09-28, untrusted-profile row added: it was reported as a profile not found.
- 2026-09-29, `.env` scan row: a directory listed only in part or not opened warns; both were silent.
- 2026-09-29, R15: the exec-inside-`deny_read` read is a stated tier-1 exception in SEMANTICS §2, no longer a finding.
- 2026-10-16, `stall-reads-unseen` row added: a `stall_after` that counts no read at tier `landlock` under `summary` or `off` ended an agent that only read, and nothing said so.
- 2026-10-16, `stall-reads-unseen` row amended: it follows `tego run --record`, holds in an `--observe` run, and warns a root tier's `stall_after` under 10 s under `summary`.
- 2026-10-16, `stall-reads-unseen` fix text amended: no root tier for an `--observe` run, none of the 10 s floor under `off`, and `--record` wording in every clause when the run gave it.
- 2026-10-16, `stall-reads-unseen` amended: a root tier under `off` counts no read (no sample is written for an allowed open), so it is warned there and is offered from the landlock warning only with `record: summary` and the 10 s floor; no fix offers `record: off`; a root tier is offered only when this tego builds it and the machine's `tier` admits it.
- 2026-10-16, `stall-reads-unseen` amended: the root-tier `off` warning names every allowed open, read or write, path change and IP connect as neither recorded nor activity (a pure writer was ended `limit-stall` under a reads-only text), and its fix speaks of a stretch without an exec or a refusal; the landlock warning of a `tego run --tier landlock` offers a root tier only without that flag (`WithTierFlag`).
- 2026-10-16, `stall-reads-unseen` amended: under `off` every notification the supervisor answers is activity at every tier, so the root-tier warning no longer calls an allowed connect unseen (a pure connector ran to its end in the KVM guest) and names a write-open or path change only as one the decision plane decides; the warning is derived from what the run notifies (`RuleTable.NotifiesReads`, `RuleTable.HoldsFSNotifications`): none under a read gate, or under `off` with an `fs.ask_read` entry, and reads alone at a root tier under `off` with an fs gate or ask entry.
- 2026-10-19, R16a added: `mcp[].url` declares an HTTP MCP server; under a `net:` section its host and port
  compile to the net rule `mcp[<name>]`; the four diagnostic rows above. An entry with neither `command` nor `url`
  now says so ("has no command and no url").
- 2026-10-19, R16a amended: the derived rule is `tcp://host:port`, so a
  UDP datagram to the server's port is refused (it compiled to both transports); and a `net.ask` entry that would
  decide one of its connects (a CIDR or an address holding the URL's, an entry on its name) derives nothing, where
  only an entry naming the same host and port did, so a wider ask became a silent allow.
- 2026-10-19, R16a amended: every `models[]` entry is compared with a URL; the check stopped at
  the first on its host, so a URL on an exact endpoint listed after one at another port loaded with the warning.
- 2026-10-19, R16a amended: an address R18 dropped from the URL's own name now
  counts towards an ask holding it (the run refuses it by the derived rule's name before any ask), and one dropped
  from the ask entry's name no longer does (that entry never asks for it), so a literal-address server under such
  an ask is admitted by its rule again rather than refused unasked; the warning for an ask holding only some of the
  URL's addresses names the others, which are refused, where it said every connect asked. R18's `resolved-denied`
  warning names the list the entry came from (`net.ask`, `mcp.<i>.url`), where it called every entry `net.allow`.
- 2026-10-19, R16a and R18 amended: R18's `resolved-denied` warning is
  given for an `mcp.<i>.url` only when its rule is derived (it said the URL's other addresses still admitted where an
  ask kept the rule from being derived and they were refused); the ask warning counts an address as asked only by
  an entry's CIDR or kept addresses, also for an entry naming the URL's host (it said connecting asked first where
  that entry kept none of them), and names a dropped address with its class. The rules derived are unchanged.
- 2026-10-19, R2, R5 (ADR 0048 (3) P2, K5): `exec.assurance` (`best-effort` | `kernel`, default `best-effort`) added
  to the exec section, a scalar whose stricter value wins across `extends`, a file's `best-effort` a profile's
  `kernel` outvotes warned `redundant-rule` at that file's line; `kernel` refuses a run whose handle does not claim exec
  pins before its child starts (exit 125), and a contract with no command rules and no exec gate that can escalate
  gets `redundant-rule` for it. `RuleTable.ExecAssurance` holds the compiled value (`ExecutionAssurance`).
- 2026-10-19, `stall-reads-unseen` amended: no warning at a root tier under `off`, where a stall-bounded run's allowed opens, path changes and connects now stamp its activity in the kernel (SEMANTICS §8, limits R4); the landlock warning under `off` offers a root tier without `record: summary` or the 10 s floor.
- 2026-11-02, `record-off` row added: a contract's own `record: off`, or a profile's, cut its runs' ledgers to their
  refusals and no finding named it (`tego run`'s warning is for `--record off`). It is a note: what the author wrote
  weakens no rule, so a run's start leaves it out unless `-v`, and the run's end says `record off: refusals only`.

## 8. Invariants

I1. `Load` never returns a `*Contract` holding an unrecognized field's value. *Enforced by*: `KnownFields` plus the R2 sweep; unit-tested against every field name in `spec/agent/v0`. I2. `Compile` never returns `Limits` exceeding the machine's ceilings. *Enforced by*: R11 always taking `min(contract, ceiling)`; tested with a ceiling below every contract default. I3. `contract_hash` depends only on the merged contract's own content, never the compiling machine. *Enforced by*: `Canonical()` runs before ceiling-clamping; tested by compiling one contract against two machine fixtures and asserting equal hashes. I4. A `*RuleTable` is never mutated after `Compile` returns it — TTL refresh constructs a **new** `*RuleTable` (RCU-style swap, `P0-DESIGN.md` §6), never edits fields in place. *Enforced by*: no exported mutator method besides `Evaluate` (read-only); code review, since Go has no compiler-enforced immutability. I5. Every error-severity `Diagnostic` traces to a concrete `File:Line` in the merged source. *Enforced by*: every validator receiving the `yaml.Node`, not just the decoded value; golden-diagnostic fixtures (§10). I6. This package makes no syscall beyond read-only file and DNS I/O — no write-flagged `open`, no `chmod`/`mkdir`, no `ptrace`/`bpf(2)`/`mount`. *Enforced by*: it is explicitly absent from the TCB list in `ARCHITECTURE.md` §16; `CGO_ENABLED=0` removes any non-Go syscall surface; `TestCompileMakesNoMutatingSyscall` (`test/sysaudit`) runs `LoadBytes` and `Compile` over a contract using fs, deny_read, watch, exec and net entries in a ptrace-traced child, unprivileged, and fails on any write-flagged open, unlink, rename, mkdir, chmod, chown, link, truncate, write to a descriptor that is a file, `ptrace`, `bpf`, `mount`, `unshare` or `setns` (`TestSysTraceSeesAMutation` is the tracer's control; condition: amd64 only). I7. `Load`/`Compile`/`Evaluate` never panic, including on adversarial YAML and adversarial ELF headers of any declared width/endianness (E34). *Enforced by*: the fuzz targets named in `P0-DESIGN.md` §7 plus a dedicated `PT_INTERP` fuzzer (§9); every slice access there is bounds-checked before use. I8. `Load`/`Compile` read no environment variable except `$PATH`, and that is the **run's** effective PATH, never `os.Getenv("PATH")` read ambiently. *Enforced by*: `PATH` threaded explicitly as a parameter, never read below the top of `Compile`. I9. `Load`/`Compile` are called at most once per run's lifetime (P0-DESIGN §4.1 step 1) — never re-invoked mid-run, even across a binary upgrade (E30). *Enforced by*: `internal/runtime.Run`'s call graph; this is what makes I4's immutability meaningful for the run's initial table — TTL refresh is the one sanctioned post-`Compile` mutation, and it only ever touches `NetRule.IPs`/`ResolvedAt`.

**Changes.**
- 2026-09-24, I6: enforced by a ptrace-audited test besides the TCB-list argument; none tested it.

## 9. Conventions and best practices

- **Naming**: `Contract`, `Rule`, `RuleTable`, `Diagnostic`, `Verdict` are the shared domain nouns (`docs/REPO-LAYOUT.md`), used with this exact meaning everywhere, never locally aliased.
- **Errors**: one sentinel per failure family (`ErrInvalidContract`, `ErrProfileNotFound`, `ErrContractOverlap` for R10, so the CLI can `errors.Is` it for the exit-125 `[contradiction]` mapping without string-matching a code), wrapped with `%w`. `Diagnostic.Code` is the machine-readable channel; the error chain is the Go-idiomatic one; callers use whichever fits.
- **No logging**: this package never writes stdout/stderr/a logger — it returns diagnostics and errors, full stop; `internal/cli` is the only place a diagnostic becomes a printed line.
- **Context**: `Compile` takes no `context.Context` (normative signature); DNS lookups use `context.WithTimeout(3*time.Second)` per host internally.
- **Goroutines and the DNS pool — stdlib only**: `pkg/spec`'s import fence (§1) rules out `golang.org/x/sync/errgroup` here — it is neither stdlib nor `yaml.v3`, and REPO-LAYOUT places `errgroup` in `internal/runtime`'s background-worker row, not `pkg/spec`. `Compile`'s bounded DNS resolution is built from stdlib primitives instead: a buffered channel of size 8 as a semaphore, one `sync.WaitGroup` counting outstanding lookups, and a per-host `context.WithTimeout(3*time.Second)`; `Compile` blocks on the `WaitGroup` before returning, so — same guarantee an `errgroup` would have given — zero goroutines outlive the call and 50 distinct hosts neither serialize 150s nor open 50 sockets at once. If a future refactor wants `errgroup` here, REPO-LAYOUT's import-direction rule needs an explicit carve-out first; until then this is the only shape `depguard`/CI accepts (`docs/REPO-LAYOUT.md`: "CI fails when depguard disagrees").
- **Resource lifetimes**: every `os.File` (ELF reads, R8) is `defer`-closed on every return path, including early errors; checked by a `bodyclose`-style lint on file handles.
- **Fuzzing**: `FuzzLoad` round-trips arbitrary bytes with a no-op `ProfileSource`, asserting no panic and that a successful parse's `Canonical()`/`Hash` are stable. `FuzzPTInterp` feeds arbitrary bytes to the ELF reader — including non-LE/non-64-bit headers (E34) — asserting no panic, no out-of-bounds read.
- **Benchmarks**: `BenchmarkCompile` over a 5,000-entry fixture with a zero-latency fake `Resolver`, tracked in CI to catch an accidental O(n²) regression.
- **Doc comments**: every exported symbol documented; `doc.go` states purpose, allowed imports, and must-not-imports (`internal/*`, `x/sync/errgroup`) — CI's `depguard` fails the build on drift.
- **SPDX header**: `Apache-2.0` on every file (not under `bpf/`).

## 10. Tests

| Rule/Edge case | Kind | Fixture |
|---|---|---|
| R1 unknown field | unit, golden diagnostic | `testdata/bad/unknown-field.yaml` → `.golden` exact text |
| R2 not-yet-supported × {absent, empty, non-empty} | unit, table-driven | one case per schema-only field, `env.mask` included (R17) |
| R5 extends merge (concat/override/deny_read-union) | unit | profile+contract pairs; `spec/agent/v0/example.retriever.yaml` |
| R5 merge classes (ADR 0065): one row per key, each class | unit | `TestEveryContractKeyHasAMergeClass`, `TestMergeTableRowsNameRealKeys`, `TestR5ListsEveryMergeClassRow`, the `TestMergeClass*` tests over a fixture table, `TestLoadHoldsProfilesToTheirRules` |
| R5 list `extends` and built-in profiles (ADR 0066) | unit | `TestExtendsListMergesInOrder`, `TestExtendsConflictBetweenParents`, `TestExtendsDuplicatesAcrossFilesMergeSilently`, `TestExtendsDiamondMergesOnce`, `TestExtendsCycleAndDepthAnywhere`, `TestExtendsListSchema`, `TestSingleNameExtendsHashUnchanged`, `TestCanonicalOfMergedList`, `TestBuiltinNamesNeverReadTheProfilesDirectory`, `TestProfileChainOrder` |
| E5 extends cycle | unit | `cycle-a.yaml` ↔ `cycle-b.yaml` via a fake `ProfileSource` |
| R6 fs defaults (nil / `{}` / populated) | unit, table-driven | `Contract` values built directly, asserting `RuleTable.FS` shape |
| R7/R10 path resolution, run-dir overlap, no-uid-check regression | unit | machine+contract pairs, one crafted to hit exit 125 [contradiction], one with a write dir owned by a different simulated uid asserting no false `path-missing` |
| R8 PATH/basename, `PT_INTERP`, `mcp[].command[0]` implicit exec rights | unit, fake `$PATH` | dynamic ELF, static ELF, shell script, non-executable, truncated-ELF (E14), an `mcp:` entry not duplicated in `exec.allow` (R16), an unresolvable `mcp[].command[0]` (E37) |
| E38 exec grant inside a write entry | unit | directory entry under `fs.write` in all three enforcing tiers (with an `Evaluate` row proving a not-yet-existing binary there is `allow`), file entry under `fs.write`, a symlinked write entry that shares no lexical prefix, and the silent controls: grant outside every write entry, and no `fs:` at all |
| R18 resolved addresses | unit | `TestDeniedResolvedClass` (every class, multicast among them, the mapped and NAT64 spellings, a machine range), `TestCompileDropsDeniedResolved` (dropped with a warning, all dropped, a localhost name, a literal, a machine range, `PublicAnswer` per entry; `Evaluate` rows), `TestResolvedDeniedPrivateForAPublicAnswer`, and the supervisor's `TestConnectRefusesDeniedResolvedAddress` (an address a refresh rebound, one compile dropped, a literal behind a refused host entry), `TestConnectAdmitsAnotherEntryBehindARefusedName` (a declared localhost entry behind a name rebound to loopback, with the set's live addresses) `TestConnectRefusesAPrivateRebindOfAPublicName` (a public name rebound to `10.0.0.5`; a split-horizon name; a declared CIDR), `TestConnectRefusesThisHostsAddress` (a name on this host's IPv4 and global IPv6 address refused; its remote address, a localhost name, a literal and a CIDR admitted), `TestThisHostSnapshot` (retaken after a second, kept on a failed retake, every host entry refused with no snapshot) and `TestThisHostSnapshotReal` (the netlink snapshot, unprivileged) |
| R19 host sockets | unit | `TestHostSocketsWarning`: sockets made under a re-rooted probe warn once; `net: {}` and `net.allow` do not; a machine with none does not. `TestHostSocketsX11Planted`: a FIFO at `/tmp/.X11-unix` compiles promptly, and a link there is not followed. `TestHostSocketsX11ManyNames`: `X0` and `X99` are named after a hundred names planted after them on tmpfs, and a planted `X5` that is no socket is not |
| R20 built-in `deny_write` set | unit | `TestBuiltInDenyWriteSet` (repository root, harness settings, shell startup, a home dotfile linked into the worktree; kept out of `FS`; `refused` under the target's rule in tiers 1 and 2; one best-effort warning per target), `TestCompileDenyWriteBestEffortByDefault` (a warning per target at every reach, a pinned or machine-held landlock included; nothing for a pin to bpflsm), `TestCompileDenyWriteErrorsAtPinnedLandlock` (under `fs.assurance: kernel` an error per target there and a warning elsewhere), `TestFSAssuranceKey`, `TestFSAssuranceMergeKeepsKernel`, `TestBestEffortCellsDenyWrite`, `TestCompileAndRunAgreeOnDenyWrite` (internal/cli: `tego compile` and `tego run` agree for both values), `TestEvaluateDenyWrite` (every modification kind, a target's resolved path, a rename above a target, git's own writes beside the targets and a read still allowed, an observe run allowing all), `TestDenyWriteOptOut`, `TestDenyWriteGitLayouts` (bare repository, a `.git` file's gitdir, a gitdir outside every write entry), `TestDenyWriteHooksPath` (Husky 9 and 8, `.githooks`, the global config, `config.worktree`, the last of many assignments, an absolute global hooks path), `TestHooksPathsParse`, `TestHooksPathsMatchGit` and `FuzzHooksPaths` (git's own reading of the same bytes where git is installed), `TestDenyWriteNestedRepositories` (repositories below a non-repository entry, a submodule's git directory, the depth limit, `node_modules` not searched), `TestDenyWriteEnclosingRepository` (Husky's monorepo `core.hooksPath` and a relative global one, from the repository above the entry), `TestDenyWritePlantedPointers` and `TestReadSmall` (a FIFO `commondir`, one linked to `/dev/zero`, a sparse multi-gigabyte `.git` file, a pointer over the bound: each compiles promptly; procfs and sysfs files refused by their file system, and a message queue's file, whose file system neither list named, by the list of those to read; a file under a write lease refused at once, not after the lease-break time), `TestReadBoundedRefusesEAGAIN` (a descriptor answering `EAGAIN` refused at once, not waited on), `TestDenyWriteKernelFileLinks` (a git config, a `commondir` and `~/.gitconfig` linked to `/proc/kmsg` compile within 10 s; the case that hung needs root, and ran as root in the KVM guest: `test/vm/kvm-run.sh`), `TestDenyWriteSharedGitDirPlant` (2500 `.git` files naming one git directory, half through links, with a `modules/` as wide, compile within 10 s and say the budget, which the search for repositories and the walk of `modules/` share, cut the search; 300 over a `modules/` of 50 stay within it), `TestDenyWriteSearchBudgets` (17 directories of 4000 names, 70 configs of 256 KiB, 2000 repositories under 8 global hooks paths: each spends the entry's budget, and the warning says so), `TestDenyWriteProbeCost` (16 `core.hooksPath` values of about 4 KiB through a link loop from 1000 worktrees, 16 naming real directories 1500 levels deep from 400, and two of 250 KiB from 1000: each compiles within 10 s; `TestHooksPathsParse` drops a value of `PATH_MAX` bytes), `TestDenyWriteCutSearchStillWarns` (4200 directories planted beside a repository, and a repository past the depth limit: the entry is named with the limit though its set is empty; a tree that ends at the limit warns nothing), `TestDenyWriteWholeCompileBudget` (four entries of 4100 directories spend what all entries share, and the fifth says so), and, for the bounded reads and walks R20 shares with R8 and the `.env` scan, `TestEnvScanBounded` (150000 names in the project: the scan reads a third of them and warns), `TestEnvScanPlantedLinks` (a thousand `.env.<n>` links into a directory 1500 levels deep compile within 10 s, each resolved), `TestReadInterpAndShebangRefuse` (a FIFO, `/dev/zero`, `/proc/kmsg`, a directory, a leased file and a message queue: each an error at once, never `ErrNotELF` or `ErrMalformedELF`), `TestReadInterpReturnsReadErrors`, `TestExecPlantedFiles` (the command, an mcp command, an `exec.allow` entry and a `#!` interpreter planted as a FIFO or a link to `/dev/zero`: each compiles within 10 s and warns naming it), `TestExecKernelFileLinks` (the same linked to `/proc/kmsg`, as root in the KVM guest with the unread kernel log drained: refused `exec-proc` before any read, R8a, amended 2026-10-16), `TestExecNonDataFileLinks` (the same linked to a sysfs file: the fix names the file system, `sysfs`, and says it is not on the list), `TestDenyWriteSearchTime` (16 `core.hooksPath` values through a chain of 39 links 1980 directories deep, absolute ones and relative ones through each worktree's own link, from 1000 worktrees: compile within 10 s, the entry's warning saying its time ran out), `TestDenyWriteSearchTimeWhole` (two entries over the plant spend the 4 s all entries share; a third, a real repository, still has its own `.git/hooks` and `config` named, probed before any entry's walk, and says the shared time cut the rest), `TestDenyWriteFixedTargetsFirst` (100 git directories planted under `src/.git/modules/`, each setting 16 values through the chain, still leave `src/.husky` named; 800 `.git` files beneath `frontend/` naming gitdirs through the chain still leave the enclosing repository's `frontend/.husky` named; each warning says the walk's time ran out), `TestDenyWriteFixedPassCut` (150 entries whose root names link into the chain spend the shared time in the first pass; the last entry, a real repository, says its root's and repository's targets were cut, and the first says only its walk was), `TestDenyWriteWalkCutByAnotherEntry` (a `.git` file beneath one entry naming another entry's git directory, before a plant that spends the first entry's time: the second entry's submodule is still walked, in its own time, and named), `TestDenyWriteReadCutReadAgain` (configs a budget left unread are read by the next entry to reach the git directory), `TestReadRetriesEINTR` (`EINTR` up to 16 times in one read loop is retried by `readSmall`, `ReadShebang` and `ReadInterp`; past that, and `EAGAIN` at once, refused), `TestEnvScanTime` (10000 `.env.<n>` links into the chain: compile within 10 s, the warning saying the scan's time ran out and how many were not resolved, the project's own `.env` files still in the list), `TestDenyWriteUnreadableFiles` (a repository `config` setting `core.hooksPath = .husky`, and a linked worktree's `.git` file, each made unreadable by `chmod 000` (not as root) and by a write lease held (as root too): the warning names the file and why, in an entry's own warning when nothing else of it is in the set; a directory above a repository made mode 000 is named the same way (not as root); and without `/proc` the entry says the search resolved nothing), `TestDataFSList` (Lustre, GPFS, BeeGFS, aufs, shiftfs, UBIFS, JFFS2, HFS, UFS, VxFS, romfs, hostfs and others read as data; the kernel's interface file systems not) |
| §2 `AccessSet` full bitmask, per ABI gate | unit, table-driven | one row per right (including `Truncate`, `MakeFifo`, `MakeChar`, `MakeBlock`, `ResolveUnix`) crossed with the ABI it requires |
| R11 ceiling precedence | unit, table-driven | ceilings crossed with limits above/below/equal |
| R13 `contract_hash` determinism | unit | same contract, two machine fixtures → equal hash; whitespace/comment-only diff → equal hash (canonicalizes the decoded structure, not source text) |
| R15 `Evaluate` per tier | unit, table-driven — this **is** the `compile --test` fixture format | `{action, tier, want_verdict, want_rule}` rows; a `deny_read`-under-writable-parent row in both `landlock` and `cgroup` |
| E24/E25 scale, size cap | unit + benchmark | 5,000-entry fixture; >1MiB fixture rejected pre-parse |
| Fuzzing | `go test -fuzz`, CI nightly | `FuzzLoad`, `FuzzPTInterp` (seeded with BE/32-bit headers, E34), corpus seeded from `testdata/` |
| Golden diagnostics end-to-end | integration-light, no root | one fixture per `Diagnostic.Code`, `compile`'s stderr byte-compared to `.golden` |

## 11. Open questions

- **Relative `fs`/`exec` path base directory** (E28): unstated by any normative doc; this spec defaults to `os.Getwd()` at `tego run` start.
- **`net.allow`/`net.ask` precedence** is resolved by R22: ordinary allow wins; separate approval rules never widen static grants.
- **`Compile`'s offline-mode plumbing**: `compile --offline` is named in two normative docs but the normative `Compile(c, m)` signature has no parameter for it. This spec assumes a small, additive `CompileOption`/`*Machine` field; which shape is not decided by any doc read for this component.
- **Exact `Canonical()` byte format**: R13 fixes determinism and shape but no doc pins the literal emitter settings. Any consistent choice satisfies I3 — but `internal/ledger` must use the *same* function, not just agree on the hash, since it writes `Canonical()`'s output verbatim as `contract.yaml`.
- **ELF platform scope** (E34): whether P0 must parse big-endian or x32 `PT_INTERP` headers, or may keep failing them closed as `malformed-elf` indefinitely, is not settled by any doc read for this component.
- **No `net:`: two kernel checks stricter than `allow`** (R15): with no `net:` section `Evaluate` answers `allow` for every destination, and the supervisor records the same with `best_effort`, but the agent's own Landlock domain still refuses, at ABI ≥ 6, an abstract name bound outside the run (the scope, enforce-landlock R7) and, at ABI ≥ 9, a pathname socket outside a write entry (`RESOLVE_UNIX` stays handled). Both are kept on purpose: they are the domain's, not a `net:` rule's, and the first is a documented built-in protection. `Evaluate` knows neither the ABI nor who bound a name, so the run is stricter than the row, never looser. Closing it means giving `Evaluate` the ABI and a notion of the run's own names, or an `abstract:` form in `net.allow` the relay serves.
- **No `exec:` at tier 2** (R15): **Closed.** The fanotify policy sets `execOpen` from `Contract != nil && Contract.Exec == nil`, omits exec-denial matcher rows and marks in that state, and delegates `decideExec` to `decide.ListenerExec`, which admits an unrestricted exec. Explicit `exec: {}` and synthetic tables without a contract remain restricted. This removes the earlier exec-list over-refusal; it does not bypass ordinary read-denial checks (`TestPolicyNoExecSectionRefusesNoExec`, `TestListenerExec`).
- **Landlock-tier reads under a grant nested inside a `deny_read` target** (R15): `evalFSLandlock`'s read arm refuses every read at or below an enforceable `deny_read` target, but Landlock unions a nested entry's own rights with the target's `Access: 0` — a `write` entry inside the target carries `READ_FILE`, and `EXECUTE` while exec is unrestricted, into its own subtree, and a declared exec file inside it carries `READ_FILE|EXECUTE` on itself (I11, enforce-landlock R5). So `Evaluate` reports `refused`/`read-denied` in tier 1 for a read of such a path, and for an exec of an undeclared binary under such a `write` entry, while the kernel allows both. It is an over-refusal only, never an over-allow, and the root tiers are not affected: their walk lets the nested `write` entry decide (nearest wins). **Closed.** For a nested `write` entry the read arm answers a read at or below such an entry `allow`, named by it (`fs.write[out/sub/]` for `write: [out/sub/]`, `deny_read: [out/]` reading `out/sub/x`), as the kernel and the root tiers' walk do, and so passes an undeclared binary's exec open there; `compile` warns nothing for the shape, which every tier enforces alike (enforce-landlock I11 (1)). A read of a declared exec entry inside a target, which its own grant lets through, is answered `allow` too (R15, `execReadGrant`).

Conflicts between normative documents found while writing this spec — including `spec/identity/RUN-IDENTITY.md`'s former exit-210/200–254-range inconsistency (E36, resolved) — are reported separately, not repeated here.

**Changes.**
- 2026-09-24, nested-grant over-refusal: closed for nested `write` entries and exec entries.

## Resolved conflicts
Exit codes: the 200–254 collision is resolved in the normative docs (2026-09-22): the contradiction is a compile error and `tego run` exits 125 with code `[contradiction]`; nothing in `run` uses 210, 211 or 213 any more (`doctor --require` alone exits 211). The original ask phase deferral is superseded by R22 and SEMANTICS §6's bounded local approval implementation. `compile --test` is P0 (FEATURES C20 updated). `limit-above-machine` is a warning and the ceiling stands (P0-DESIGN §2.1 updated). The tier-1/tier-2 chmod row (E35) is closed: chmod has its own row, `fs.deny_chmod`, present at tier 3 only.

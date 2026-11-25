# Machine config (spec v0)

Layers, read in order: built-in defaults; optional `/etc/tego/config.yaml`; optional `~/.tego/config.yaml` of the
invoking user; additive `$TEGO_CONFIG` (a selected missing file is an error); then the contract. Two ordinary kinds of key:
- **ceilings** (`tier`, `capture`, `limits.*`): every layer, the contract included, may lower the value it inherited,
  never raise it. Built-in ceilings are unbounded. Raising is not an error: the inherited value stands and `rules check`
  prints `ceiling <key>=<value> kept from <file>:<line>`.
- **settings**: the last layer wins, except `denied_resolved_addresses`, a deny list every layer
  adds to and none removes from, and `landlock.audit`, a floor: once a layer sets `new-exec` a later `off` is not
  applied, and `rules check` prints `floor landlock.audit=new-exec kept from <file>:<line>`.
`tego rules check` prints every effective value with the file and line it came from: the `machine` section under its
rule table, and `machine` in `--json` (*amended 2026-09-24:* the function existed and nothing called it, so no value
was printed; an unset `tier` or `capture` reads `auto`).

```yaml
version: 0
tier: auto              # ceiling; ordered landlock < cgroup < bpflsm; auto = highest the machine allows (doctor).
                        # A concrete name is also a pin: every run gets that tier or none (identity-config R17;
                        # amended 2026-09-24, the comment called it a ceiling only). auto and the three names are
                        # the only values, as auto, off, forwarder and uprobe are capture's; any other is an
                        # error at its line (R24, amended 2026-09-24)
capture: auto           # ceiling; ordered off < forwarder < uprobe; `uprobe` means uprobes plus the forwarder (both run; they never see the same request) when it is this ceiling or `auto` resolved to it, and uprobes alone when the contract pins `capture: uprobe` (the agent's own TLS is read, nothing is proxied; amended 2026-09-23), `forwarder` means forwarder only; auto = the highest the tier allows
ledger_root: ~/.tego/runs        # servers: /var/lib/tego/runs
retention: 30d                    # tego gc default, and what a run start's pass removes (gc_interval); the same
                                  # pass prunes the rule-change journal to it, keeping what a run still in the ledger
                                  # root reads (the lines since it started, those that name it) and each rules
                                  # file's newest 20 changes still standing while the file is there (amended
                                  # 2026-11-02)
gc_interval: 0s                   # how often a tego run start applies retention to the ledger root, as `tego gc`
                                  # with no flags does (which counts as a pass): at most once per interval, with a
                                  # cooperative 2 s budget checked between runs and journal pruning operations.
                                  # Before journal.lock the budget is checked; once held, the journal read,
                                  # filter and rewrite finish as one operation, even after expiry. Other
                                  # filesystem operations already in progress also finish;
                                  # a blocked filesystem call can delay return indefinitely. Completed pruning
                                  # stays committed and the journal stays consistent; leftover work waits for
                                  # the next pass. Budget exhaustion is logged and never fails the starting run.
                                  # Only ended or empty runs older than retention go, never a live one; 0 never.
                                  # chain.log keeps a removed run's line, so the runs left verify as before
stop_grace: 10s                   # SIGTERM, then cgroup.kill
limits:                           # ceilings; same keys and units as the contract's limits, one unit each: wall: 1h30m and memory: 1PiB are errors (amended 2026-09-29)
  cpu_weight: 10000                # 1 to 10000, cgroup cpu.weight ceiling (added 2026-09-29)
  cpu: "8"                        # 0.01 to 175921860 cores, what cpu.max takes (amended 2026-09-24); 0 is refused
  memory: 32GiB
  memory_high: 24GiB              # cgroup memory.high ceiling (added 2026-09-29; the key was parsed, not written here)
  pids: 4096                      # 0, like memory: 0, is the tightest budget (E16) and loads with a warning:
                                  # it lets no process start (memory: 0, none survive the OOM killer)
  tokens: 10000000
  cost_usd: 200
  wall: 24h
  stall_after: 1h
  repeats: 0                      # ceiling on the contract's repeats budget (added 2026-09-29)
ask:
  timeout: 5m                     # stored machine setting; the current broker uses the contract's ask.timeout
  notify: [cli, desktop]          # how a person learns an ask waits (ADR 0122): cli, the run's answer line (run id
                                  # and commands) before the agent starts; desktop, a notice per held request
                                  # through a root-owned notify-send, tier landlock and a non-root tego only;
                                  # [] for neither. webhook:<url> is accepted with a config-ignored warning (not built)
record:
  # max_run_bytes: 1GiB           # ceiling (every layer may lower it, none raise it), unbounded when unset, at
                                  # least 64KiB: a run whose events.jsonl and blobs reach it is ended as a limit, exit 124,
                                  # limit which=ledger_bytes, run_end reason limit, checked at each recorded line
                                  # and once a second (record minor 22; run_start.limits.ledger_bytes records it), so
                                  # a run passes it by the lines in flight. Under
                                  # a unit with Restart=on-failure a 24/7 agent restarts on a new ledger; 1GiB is a
                                  # start for always-on agents (added 2026-10-26)
  ringbuf: 2MiB                   # honoured from /etc/tego/config.yaml only: each tier-2 run's own record ring,
                                  # and its capture ring when it captures with uprobes (a record: off run's
                                  # record ring is a fixed 256KiB); power of two, page multiple. Set anywhere else
                                  # it is ignored with a warning (ADR 0026; amended 2026-09-24, was 8MiB, one ring
                                  # per build, any layer)
bpf:
  linger: 5m                      # honoured from /etc/tego/config.yaml only: how long a tier-2 build's programs,
                                  # maps and host-wide links stay attached after its last run ended, so the next
                                  # run adopts them; 0 removes them when the last launcher leaves (ADR 0022;
                                  # added 2026-09-24)
  ring_budget: 256MiB             # honoured from /etc/tego/config.yaml only: the memlock every live run ring of
                                  # every tier-2 build on the host may charge together; a run whose record ring
                                  # would pass it is refused (exit 125), one whose capture ring would is run
                                  # without capture (refused when it has a tokens, cost_usd or repeats budget).
                                  # `tego machine check` shows its use (ADR 0026; added 2026-09-24)
  plane: auto                     # auto | lsm | fmod_ret: which kernel decision plane tier 2 and tier 3 run.
                                  # Honoured from /etc/tego/config.yaml only (set in any other layer it is
                                  # ignored with a warning); any other value is an error at its line. auto prefers
                                  # lsm, then fmod_ret, then the fanotify fallback, by the doctor's probe; a
                                  # concrete name pins the mode (enforce-plane R18; ADR 0024; added 2026-09-29)
tomoyo:
  facts_dir: ""                   # honoured from /etc/tego/config.yaml only (set in any other layer it is ignored
                                  # with a warning): "" reads TOMOYO's files at /sys/kernel/security/tomoyo; a clean
                                  # absolute path reads self_domain, stat and profile there instead, for a
                                  # container whose AppArmor profile hides the kernel's path. The directory must be a
                                  # read-only bind of the host's /sys/kernel/security/tomoyo: each file is accepted
                                  # only on securityfs, with mount root /tomoyo, read-only; anything else refuses
                                  # held opens as before. No setting assumes TOMOYO enforces nothing (ADR 0041;
                                  # added 2026-11-22)
lsm:
  list_file: ""                   # honoured from /etc/tego/config.yaml only (set in any other layer it is ignored
                                  # with a warning): "" uses no file; a clean absolute path names a file a held open
                                  # reads the active security-module list from when lsm_list_modules(2) and
                                  # /sys/kernel/security/lsm both cannot be read, as in a container under Docker's
                                  # default profile. The file is believed only when it is the host's
                                  # /sys/kernel/security/lsm bound read-only (securityfs, mount root /lsm), or the
                                  # three-line file the container's entrypoint wrote as root at this boot (root's,
                                  # not writable by group or others, in directories only root can write, not on a
                                  # FUSE or network filesystem, this boot's id), and only for a task that holds no
                                  # capability that could rewrite it (and, for the written file, is not root);
                                  # anything else refuses held opens as before. It decides held opens only, never a
                                  # tier. No key supplies a list inline (ADR 0041; added 2026-11-25)
resolver: auto                    # unprivileged-tier UDP rule: auto = nameservers of /etc/resolv.conf at run start;
                                  # or a list of ip[:port] that replaces the file (port 53 when omitted); the
                                  # exception covers port 53 only, so a server on another port needs net.allow
denied_resolved_addresses: []     # cidrs or addresses no net.allow host name admits, added to the built-in
                                  # loopback, link-local, cloud-metadata and multicast classes and this host's
                                  # own addresses (agent-contract R18); e.g.
                                  # [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "fc00::/7"]. The one setting no
                                  # later layer narrows: each layer adds, so ~/.tego cannot lift what /etc set
forwarder:
  listen: 127.0.0.1:0             # loopback only (R19): localhost or a loopback IP, a numeric port 0..65535;
                                  # anything else is an error at its line (amended 2026-09-29). A pinned
                                  # port goes to the first models[] entry; later entries bind port 0
                                  # on the same host (capture-derive R19; 2026-09-30)
prices: ~/.tego/prices.yaml      # price table: version, models.<model>.{input,output,cache_read,cache_write,
                                  # cache_write_1h}_per_mtok, server_tool_per_request.<name> (USD per request).
                                  # *Amended 2026-09-24:* cache_write_1h_per_mtok and
                                  # server_tool_per_request added; a response reporting a counter with no price is
                                  # unpriced, as is a model with no input or
                                  # no output price; an unknown key makes the table unreadable (R32)
                                  # *Amended 2026-10-16:* a run whose contract declares limits.cost_usd and finds
                                  # no table here is refused, exit 125 [budget-unmetered], as is one whose declared
                                  # tokens, cost_usd or repeats budget no capture counts (a capture: ceiling of off
                                  # included); a budget the limits: ceilings alone impose is not refused, it records
                                  # gap why=budget-unmetered
                                  # *Amended 2026-10-17:* so is a run whose contract declares limits.cost_usd
                                  # under a table here that lists no model, or that prices none (every entry
                                  # lacks input_per_mtok or output_per_mtok): no response could be priced (R32)
profiles: ~/.tego/profiles
registry: ~/.config/tego         # the user registry (*added 2026-10-20*, agent-contract.md R26): agents/<name>.yaml
                                  # is the contract `tego run <name>` and `tego rules check <name>` resolve to when
                                  # the working directory's project registry does not hold the name; "" turns it
                                  # off. An entry, agents/ and this directory must be owned by the invoking user or
                                  # root and not group- or other-writable (R20's rule), or the name is refused; so
                                  # is an entry inside tego's own directory, the ledger root or profiles (R6a
                                  # read-denies them, and a contract's directory would lift that) unless the
                                  # working directory is inside it too.
                                  # skills/<name>/ beside agents/ is reserved for skills (FEATURES I6c)
log:
  level: info                     # debug | info | warn
landlock:
  audit: off                      # off | new-exec: the kernel's audit log records the Landlock refusals the agent
                                  # meets after exec (LOG_NEW_EXEC_ON, Landlock ABI 7, Linux 6.15); below ABI 7 the
                                  # run is confined as ever and records gap why=landlock-audit-unavailable;
                                  # the records need the kernel's audit on (auditd, or audit=1 with room in
                                  # audit_backlog_limit), and a run that finds it off records gap
                                  # why=kernel-audit-off, and one that cannot read it (unprivileged: reading it
                                  # needs CAP_AUDIT_CONTROL) gap why=kernel-audit-unknown, see enforce-landlock §4.
                                  # A floor: a later layer's off does not undo an earlier new-exec
privileged_binary: ""             # honoured from /etc/tego/config.yaml only; not used in this release and warns
                                  # "privileged_binary is not used in this release; ADR 0042 (3)(c)": a
                                  # file-capability copy is refused at start (ADR 0042 (3)(a))
users: {}                         # honoured from /etc/tego/config.yaml only (ADR 0042 (4)), read by tegod only:
                                  # uid (canonical decimal, 0..4294967294) -> {contracts: [...], max_runs: n};
                                  # tego run ignores it with a warning, and another layer's is "ignored here"
```

## Trust
- Invoking uid: `SUDO_UID` when the real uid is 0 of the initial user namespace and `SUDO_UID` is set; otherwise
  the real uid. Under `unshare -r` or in a rootless container `SUDO_UID` is ignored (ADR 0042 (5)(d)). The per-user
  file is `<pw_dir>/.tego/config.yaml` from `getpwuid`, never `$HOME`.
- Each layer file is opened then `fstat`ed: regular file, owned by root or the invoking uid, no group/other write
  bit; its directory likewise. And it has one name (no second hard link) unless no run of the invoking user could
  write it by any name (another owner, no group or other write bit, the invoking user not root), since R10 keeps
  every write entry off each layer's names and a second name is compared with nothing (ADR 0059, *added
  2026-10-20*); the price table, the profiles and the registry's entries follow the same rule. Otherwise `tego run` exits 125 with `machine config untrusted: <path> <owner> <mode> [config-untrusted]`;
  decision loads abort. `TrustWarn` is reserved for degraded observation and stop loads: a failed
  layer is unknown, and `Machine.BaselineKnown()` is false (ADR 0144).
- When the process runs with `AT_SECURE` set (the file-capability copy), `$TEGO_CONFIG` and `$HOME` are ignored; a
  static Go binary gets no loader secure-execution stripping, so the binary does it. Since ADR 0042 (3)(a) such a
  process is refused before the config loads (`[privileged-path-unsupported]`); the handling stays as defence in
  depth.
- Before exec of `privileged_binary`: root-owned, not group/other-writable, and its `security.capability` xattr carries
  the three caps (the kernel removes the xattr on write or chown); otherwise doctor's sentence and the unprivileged
  tier. Install it `0750 root:<group>`, because `+ep` grants the caps to whoever can execute it. *Conditioned
  2026-10-05 (ADR 0042 (3)(c)):* not delivered in this release; the setting only warns, and a copy is refused.

### Built-in surface port (ADR 0113)

`serve: {port: 7433}` selects the local TCP port refused by
`builtin.tego_surface` in every enforcing run. `serve.port` is a last-wins
setting, integer 1..65535. `port:` may not be zero. The current dashboard's
legacy default 8484 is protected as well. Set this before using `serve --addr`
with another port; a per-command address is not machine policy.

## Baseline schema (ADR 0144)

`baseline:` is accepted in the system, passwd-home user and additive `$TEGO_CONFIG` file layers.
The built-in value is empty. The compiler applies its immutable union once, preserving the source
contract/hash and exposing a separate effective contract/hash. Unknown snapshots refuse decisions.
Nonempty applied-baseline launches remain refused until the record and guest-proof slices close.
Older binaries reject this key; upgrade launchers first.

```yaml
baseline:
  fs:
    deny_read: [~/secrets]
    deny_write: [/srv/releases]
  exec:
    deny: [git push]
  env:
    deny: [PROD_TOKEN]
```

Only these four lists are allowed. Unknown keys, grants, asks, network entries, limits, nulls and
wrong types (including contradictory YAML type tags) fail at their file and line. Entries are nonempty UTF-8 strings. File entries are literal
absolute or `~/` paths, without globs; environment entries are variable names. The command compiler
validates exec patterns after materialization. A layer may contain at most 100,000 baseline entries
across all four lists, including duplicates; exceeding the limit fails at its file and line. Absent keys and `[]`
add nothing. A union keeps the first position of each exact decoded string per key and every contributing layer/file/entry line. It never deduplicates
or edits a contract. No override, include, YAML merge, null or duplicate key can remove another layer's
entry. Includes/override keys and YAML aliases in baseline lists are rejected. `$TEGO_CONFIG` selects
an additional layer, not a replacement for the fixed system and passwd-home user layers. There is no
command-line config replacement flag. `AT_SECURE` leaves the explicit layer unselected as before.

The immutable snapshot retains raw spellings. Its resolver accepts an explicit agent-owner uid/home
(the compile's `WithHome` context, the agent owner's passwd home at adoption), never `$HOME` or the
caller's home. It retains `~/` expansion without cleaning a symlink followed by `..`. Resolution reads
metadata and creates nothing. Only resolving a `~/` entry needs an owner home. A missing home for that entry fails with
its layer, file, line, uid and advice to give the entry an absolute path or run as a user with a
passwd entry. Loading the raw union needs no home; no passwd home selects no user layer silently. A known home whose directory is
absent can produce an absolute absent row. A missing system-only target retains its existing directory
ancestor and remaining names, pending the later tier/grant checks; **this does not assert coverage**.
An entry also contributed by another layer cannot use that exception. Missing user/explicit targets,
dangling links (including a dangling ancestor), unplaceable paths, procfs paths, unreadable walks and
other lookup errors fail with sources, owner and repair text. Later preparation must recheck identities; no launch calls this resolver yet.

ADR 0144 defines two load classes, even when no baseline entries are configured. Class (a)
`TrustAbort` decides rules: launches, compilation, checks, adoption and current in-force rule views
refuse any unsafe, unreadable or malformed layer. No partial Machine is returned. Class (b)
`TrustWarn` supports observation and stop: failed layers contribute no settings, but are recorded as
`unknown` with their cause, and `Machine.BaselineKnown()` is false. UNKNOWN cannot be treated as
an empty union, used to compile rules, or used to start or widen a run. Every output that would
state the baseline says it could not be read and why. GC keeps working to report the problem but
sweeps and deletes nothing while a layer is unknown, returning 125. Doctor JSON carries
`baseline.known` and, when unknown, `baseline.reasons` with each failed layer, file and cause. The full caller classification is in
[ADR 0144](../../../docs/adr/0144-machine-baseline.md#config-load-classes-amendment-2026-11-12).

The system file and every directory/link placement it walks must be root-owned, with no group/other
write authority; the regular file must be readable by governed users (normally 0644), and placement
directories searchable by them. Sticky group-writable ancestors, such as a 1775 store, are refused.
A user namespace that maps a placement owner to 65534 does not establish root ownership, even
when the optional file is absent. Metadata checks keep I10's open boundary: the loader opens only
layer files and their directories, not the placement ancestors. Complete I10 compliance is not
established: the inherited procfs check makes link-following `statfs` calls on existing ancestor
directories and on absolute path settings, which I10 does not record and the audit's tracer cannot
decode; the inherited metadata/tracing debt remains open. User/explicit layers retain the generic R20
checks. A present dangling layer link fails. Source observations distinguish exact-byte SHA-256 of
an empty present file from absent/unselected inputs; absence and unknown have no digest.

| Layer | Present and good | Present and bad (read, parse, ownership, mode, type/link) | Absent or unselected |
|---|---|---|---|
| Built-in | Empty known union | Not a file | Not applicable |
| System | Parse and union, root placement checks | (a) Stop load; (b) unknown, degraded | Optional, recorded absent after checking existing placement |
| Passwd-home user | Parse and union, generic R20 checks | (a) Stop load; (b) unknown, degraded | Optional file absent; no passwd home selects no user layer and prints no discovery warning |
| Explicit `$TEGO_CONFIG` | Parse and union, generic R20 checks | (a) Stop load; (b) unknown, degraded | Selected missing path is (a) an error or (b) unknown; unset/secure is unselected |

`TestBaselineLayerStateTable`, `TestBaselineSystemTrustWalk` and
`TestBaselineProductionSystemTrustAndDanglingLayers` cover this table with filesystem fixtures and
modeled root metadata. Real privileged ownership and governed layer edits remain **owed in a guest**.

### Local approval authority (ADR 0154)

`local_roles: owner_only` is honoured only from the trusted system layer
`/etc/tego/config.yaml`. `off` or absence keeps personal approval behavior.
`off` and `owner_only` are the exact, case-sensitive string enumeration. `auto`,
empty strings, numbers, lists and every other spelling are invalid. An invalid
or unreadable system layer refuses every launch until corrected; observation
loads retain unknown authority and cannot provide a personal-mode fallback.
User and explicit `$TEGO_CONFIG` layers cannot set or unset this floor.
The floor binds only runs launched after it is set: it is fixed per run at launch, a run already live keeps
same-user approvals until it ends, and every live run is to be stopped before relying on the floor (`tego machine check` lists
the live runs of the selected ledger root that started without it).
The existing system placement trust rules apply. An enabled run pins the source
identity and exact-byte SHA-256; missing, unreadable, edited or replaced input
refuses answers for that run. It never falls back to personal authority.
The authority-drift refusal says the approval policy file changed since this run
started, including when it became unreadable. Clients that reach the broker
receive this cause before the root-only remedy. Approve's strict configuration
load first refuses an unreadable system file without contacting the broker.
Repair its mode on the original inode with the original bytes for a mode-only
mistake. Deny's warning load and dashboard can reach the distinct broker refusal. Saving old
text on a replacement inode does not repair the old run. Stop it as root with `sudo tego session stop <run>`,
then relaunch using the same ledger configuration. The [user guide](../../../docs/site/approvals.md)
gives commands for an explicit `TEGO_CONFIG` and the edit outcome table.
Only a root launcher in the initial user namespace with a verified non-root
child, enforcement and recording may activate the floor. The packet credentials
and process handle bind send-time identity. Only real UID 0 in the initial user
namespace outside every governed run at the decision may answer once; namespace
and scope facts are revalidated through that binding. Always and alternate answers are refused.
Run the approval as root from a terminal outside any governed run.
This is local approval authority, without shared dashboards or other role grants.

[local-authority.schema.json](local-authority.schema.json) describes the closed
local authority selector extracted from a machine layer. Its presence in a user
layer supplies no authority. The full config uses the closed key vocabulary above.

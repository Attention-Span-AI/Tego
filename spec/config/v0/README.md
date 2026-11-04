# Machine config (spec v0)

Layers, read in order, each optional: built-in defaults; `/etc/tego/config.yaml`; `~/.tego/config.yaml` of the
invoking user; `$TEGO_CONFIG`; then the contract. Two kinds of key:
- **ceilings** (`tier`, `capture`, `limits.*`): every layer, the contract included, may lower the value it inherited,
  never raise it. Built-in ceilings are unbounded. Raising is not an error: the inherited value stands and `compile`
  prints `ceiling <key>=<value> kept from <file>:<line>`.
- **settings** (everything else): the last layer wins, except `denied_resolved_addresses`, a deny list every layer
  adds to and none removes from, and `landlock.audit`, a floor: once a layer sets `new-exec` a later `off` is not
  applied, and `compile` prints `floor landlock.audit=new-exec kept from <file>:<line>`.
`tego compile` prints every effective value with the file and line it came from: the `machine` section under its
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
                                  # with no flags does (which counts as a pass): at most once per interval, for at
                                  # most 2 s, stopping between runs (the next pass goes on); only ended or empty
                                  # runs older than retention go, never a live one; 0 never (added 2026-10-26).
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
                                  # `tego doctor` shows its use (ADR 0026; added 2026-09-24)
  plane: auto                     # auto | lsm | fmod_ret: which kernel decision plane tier 2 and tier 3 run.
                                  # Honoured from /etc/tego/config.yaml only (set in any other layer it is
                                  # ignored with a warning); any other value is an error at its line. auto prefers
                                  # lsm, then fmod_ret, then the fanotify fallback, by the doctor's probe; a
                                  # concrete name pins the mode (enforce-plane R18; ADR 0024; added 2026-09-29)
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
                                  # unpriced (docs/p0/limits-check-doctor-cli.md R2), as is a model with no input or
                                  # no output price; an unknown key makes the table unreadable (R32)
                                  # *Amended 2026-10-16:* a run whose contract declares limits.cost_usd and finds
                                  # no table here is refused, exit 125 [budget-unmetered], as is one whose declared
                                  # tokens, cost_usd or repeats budget no capture counts (a capture: ceiling of off
                                  # included); a budget the limits: ceilings alone impose is not refused, it records
                                  # gap why=budget-unmetered (docs/p0/limits-check-doctor-cli.md R32)
                                  # *Amended 2026-10-17:* so is a run whose contract declares limits.cost_usd
                                  # under a table here that lists no model, or that prices none (every entry
                                  # lacks input_per_mtok or output_per_mtok): no response could be priced (R32)
profiles: ~/.tego/profiles
registry: ~/.config/tego         # the user registry (*added 2026-10-20*, agent-contract.md R26): agents/<name>.yaml
                                  # is the contract `tego run <name>` and `tego compile <name>` resolve to when
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
  `compile` and `doctor` warn and continue. (Precedent: `ssh` on `~/.ssh/config`.)
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

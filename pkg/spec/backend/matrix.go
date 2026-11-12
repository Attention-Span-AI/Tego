// SPDX-License-Identifier: Apache-2.0

package backend

// capabilityTitles are the row headings of CAPABILITIES.md.
var capabilityTitles = map[Capability]string{
	CapFileWriteDeny:            "deny file write outside contract",
	CapFileDeleteRename:         "deny delete, rename, mkdir, mknod",
	CapReadDeny:                 "deny read of secret paths",
	CapExecDeny:                 "deny exec",
	CapNetHostDeny:              "deny network by host:port",
	CapUDPByDestination:         "UDP by destination",
	CapUDPPortInKernel:          "UDP by port in-kernel",
	CapUnixSockets:              "unix sockets",
	CapAsk:                      "ask (pause for a human)",
	CapRecordExecOpenNet:        "record exec, write-open, connect",
	CapRecordReads:              "record reads, mmap, chmod",
	CapCaptureModel:             "capture model traffic",
	CapLogAllowed:               "log allowed actions with the rule matched",
	CapAdoptedContainers:        "adopted containers (daemon-created cgroups)",
	CapNetHTTPRules:             "forwarder HTTP method/path rules (`net.http`)",
	CapNamespaceSandbox:         "in-tree namespace sandboxes (podman, bwrap)",
	CapUnixAbstractScope:        "abstract unix names bound outside the run refused",
	CapChmodDeny:                "deny chmod",
	CapTCPDestinationKernel:     "TCP destination admission in-kernel",
	CapUnixDestinationKernel:    "Unix destination admission in-kernel",
	CapExecCommandArgv:          "exec command rules: argv",
	CapGateFSOpenCompletion:     "gate fs open completion",
	CapGateFSMutationCompletion: "gate fs mutation",
	CapGateExecCompletion:       "gate exec",
	CapGateNetCompletion:        "gate net completion",
	CapProtectedWriteTargets:    "protected write targets",
	CapSocketFamilies:           "sockets outside the net rules' families refused",
	CapHostSocketsRefused:       "host daemon sockets refused with no net: section",
	CapReadDenyNested:           "deny read nested in a write entry",
	CapReadDenyCreatedLater:     "deny read of a secret made during the run",
	CapReadDenyMoved:            "deny read of a nested secret moved or hard-linked",
}

// cell is one matrix cell: whether the tier provides the row, and the CAPABILITIES.md prose.
type cell struct {
	present bool
	detail  string
}

// matrix is hand-kept identical to spec/backend/CAPABILITIES.md cell-for-cell (R22, I9): 31 rows x
// 3 tiers. A cell is present unless its prose starts with "no", "refused", "best-effort" (the
// address is read and the call continues, which is not a deny), "conditional", or names a Landlock ABI newer than
// the tested floor (the static matrix is unconditional; ABI-gated rows are recorded per run by the
// tier's own Capabilities()). The golden test parses the markdown and checks both fields.
var matrix = map[Tier]map[Capability]cell{
	TierLandlock: {
		CapTCPDestinationKernel:     {false, "no: supervisor-completed connects"},
		CapUnixDestinationKernel:    {false, "no: supervisor plus ABI-gated pathname backstop"},
		CapFileWriteDeny:            {true, "yes (EACCES)"},
		CapFileDeleteRename:         {true, "yes (EACCES), per process tree"},
		CapReadDeny:                 {true, "by sibling enumeration; under a writable parent, held reads (the default) refuse it; `fs.reads: direct` leaves it unenforced"},
		CapExecDeny:                 {true, "by inode (`EXECUTE` on binaries, their loader, listed scripts)"},
		CapNetHostDeny:              {true, "yes, supervisor-completed connects (Landlock grants declared TCP ports only)"},
		CapUDPByDestination:         {false, "best-effort (address read: refused when refused, an admitted one continued and read again)"},
		CapUDPPortInKernel:          {false, "Landlock ABI ≥ 10 only"},
		CapUnixSockets:              {true, "seccomp connect; `RESOLVE_UNIX` on ABI ≥ 9"},
		CapAsk:                      {true, "yes (seccomp; file reads too, `fs.ask_read`)"},
		CapRecordExecOpenNet:        {true, "yes (seccomp supervisor, advisory against a hostile process)"},
		CapRecordReads:              {true, "only with `record: full` (slow)"},
		CapCaptureModel:             {true, "forwarder"},
		CapLogAllowed:               {true, "seccomp-visible kinds only"},
		CapAdoptedContainers:        {false, "no: boundary events, API record, gaps"},
		CapNetHTTPRules:             {true, "declared forwarder only"},
		CapNamespaceSandbox:         {false, "refused (Landlock topology)"},
		CapUnixAbstractScope:        {false, "Landlock ABI ≥ 6 only"},
		CapChmodDeny:                {false, "no: no Landlock ABI has a chmod right"},
		CapExecCommandArgv:          {false, "best-effort (copied argv; a refusal is exact)"},
		CapGateFSOpenCompletion:     {false, "conditional (completed on the object the gate scored by the run's open deputy under `gate.completion: held`, ADR 0041 Stage B; otherwise best-effort: copied pathname, continued; an ask-range score is held, ADR 0008)"},
		CapGateFSMutationCompletion: {false, "best-effort (unlink, rename, link, symlink, mkdir, mknod, truncate, chmod, chown and xattr changes, ACLs included, scored on copied names and continued; timestamps are not scored; no kernel layer evaluates a gate predicate)"},
		CapGateExecCompletion:       {false, "best-effort (copied image path and argv, continued; an ask-range score is refused)"},
		CapGateNetCompletion:        {true, "yes on IP-domain sockets (performed on the duplicate with the scored address); addressed unix datagrams remain best-effort; enforcing Unix stream connects use the held-inode relay (ADR 0113)"},
		CapProtectedWriteTargets:    {false, "best-effort (the supervisor refuses write-opens and mutations on copied pathnames, not chmod, chown or xattr changes; `fs.assurance: kernel` refuses the run)"},
		CapSocketFamilies:           {true, "yes, under a `net:` section (seccomp allowlist on socket(2) and socketpair(2), `TCP_ULP` refused on setsockopt(2); io_uring refused)"},
		CapHostSocketsRefused:       {true, "yes, by the supervisor (every connect relayed; a datagram it cannot relay is best effort below Landlock ABI 9, `host_sockets/datagram`)"},
		CapReadDenyNested:           {true, "enforced (held), including launch-pinned targets under another name"},
		CapReadDenyCreatedLater:     {true, "enforced (held)"},
		CapReadDenyMoved:            {true, "enforced (held): launch-pinned identities, and files put at protected names later; a change that cannot be followed refuses held reads until restart"},
	},
	TierCgroup: {
		CapTCPDestinationKernel:     {true, "yes (cgroup/connect4 and connect6)"},
		CapUnixDestinationKernel:    {false, "conditional (cgroup/connect_unix and sendmsg_unix, or both plane Unix hooks)"},
		CapFileWriteDeny:            {true, "yes (Landlock and fanotify; fanotify refuses with EPERM)"},
		CapFileDeleteRename:         {true, "via Landlock inside the run (per process tree)"},
		CapReadDeny:                 {true, "yes (fanotify, exact paths)"},
		CapExecDeny:                 {true, "by path (`FAN_OPEN_EXEC_PERM`)"},
		CapNetHostDeny:              {true, "yes, in-kernel per cgroup, IPv4/IPv6"},
		CapUDPByDestination:         {true, "yes (`cgroup/sendmsg`)"},
		CapUDPPortInKernel:          {true, "yes"},
		CapUnixSockets:              {true, "`cgroup/connect_unix` on 6.7+, seccomp below"},
		CapAsk:                      {true, "yes (no held read: `fs.ask_read` is refused)"},
		CapRecordExecOpenNet:        {true, "yes (eBPF)"},
		CapRecordReads:              {true, "yes; tracing callbacks can be skipped on preemptible kernels"},
		CapCaptureModel:             {true, "uprobes and forwarder"},
		CapLogAllowed:               {true, "all"},
		CapAdoptedContainers:        {true, "network and record yes; files by fanotify; `ask` refused inside"},
		CapNetHTTPRules:             {true, "declared forwarder only"},
		CapNamespaceSandbox:         {true, "with `containers: rootless`"},
		CapUnixAbstractScope:        {false, "Landlock ABI ≥ 6 only (the inherited ruleset)"},
		CapChmodDeny:                {false, "no: fanotify has no permission event for it, nor the inherited ruleset a right"},
		CapExecCommandArgv:          {false, "conditional (held by the decision plane's exec pins where doctor's exec pin cell passes; best-effort on the fanotify fallback)"},
		CapGateFSOpenCompletion:     {false, "conditional (completed on the object the gate scored by the run's open deputy under `gate.completion: held`, ADR 0041 Stage B; otherwise best-effort: copied pathname, continued; an ask-range score is held, ADR 0008)"},
		CapGateFSMutationCompletion: {false, "best-effort (unlink, rename, link, symlink, mkdir, mknod, truncate, chmod, chown and xattr changes, ACLs included, scored on copied names and continued; timestamps are not scored; no kernel layer evaluates a gate predicate)"},
		CapGateExecCompletion:       {false, "conditional (held to the scored image and argv by the plane's exec pins where doctor's exec pin cell passes; otherwise best-effort: copied image path and argv, continued; an ask-range score is refused)"},
		CapGateNetCompletion:        {true, "yes on IP-domain sockets (performed on the duplicate with the scored address); addressed unix datagrams remain best-effort; enforcing Unix stream connects use the held-inode relay (ADR 0113)"},
		CapProtectedWriteTargets:    {false, "conditional (a decision plane, `lsm` or `fmod_ret`, by inode, chmod included; best-effort on the fanotify listener, as at tier 1)"},
		CapSocketFamilies:           {true, "yes, under a `net:` section (seccomp allowlist and `TCP_ULP` arm; `cgroup/sock_create` for inet sockets and `cgroup/setsockopt` for `TCP_ULP` on any path; the plane's `socket_create` for every family with a mode)"},
		CapHostSocketsRefused:       {false, "best-effort for the general host-socket policy (`host_sockets/root-tier`); ADR 0113's fixed refusals additionally use Unix kernel programs and the native peer plane where available"},
		CapReadDenyNested:           {true, "yes (the fanotify listener by path, or a decision plane by inode; the nearest entry wins)"},
		CapReadDenyCreatedLater:     {false, "conditional: the plane modes' name check (ADR 0043), for a file created directly at a covered name; the fanotify fallback refuses opens and, best effort, mutations; held reads under `fs.reads: held` (ADR 0069)"},
		CapReadDenyMoved:            {false, "conditional (a decision plane refuses a rename or link out of a `deny_read` tree; on the fanotify listener the supervisor refuses one on copied names, best effort)"},
	},
	TierBPFLSM: {
		CapTCPDestinationKernel:     {true, "yes (cgroup/connect4 and connect6)"},
		CapUnixDestinationKernel:    {false, "conditional (cgroup/connect_unix and sendmsg_unix, or both plane Unix hooks)"},
		CapFileWriteDeny:            {true, "yes, per cgroup, EACCES + reason (decision plane `lsm`; the plane returns 0 or -EACCES only)"},
		CapFileDeleteRename:         {true, "yes, per cgroup; a rename or link out of a `deny_read` tree is refused (REFER)"},
		CapReadDeny:                 {true, "yes, by inode, the nearest entry wins, so a `deny_read` nested in a write entry holds"},
		CapExecDeny:                 {true, "by inode and name per binfmt stage (the file, its directory and its final name)"},
		CapNetHostDeny:              {true, "yes"},
		CapUDPByDestination:         {true, "yes (`cgroup/sendmsg`)"},
		CapUDPPortInKernel:          {true, "yes"},
		CapUnixSockets:              {true, "in-kernel, resolved path"},
		CapAsk:                      {true, "yes (no held read: `fs.ask_read` is refused)"},
		CapRecordExecOpenNet:        {true, "yes"},
		CapRecordReads:              {true, "yes; tracing callbacks can be skipped on preemptible kernels"},
		CapCaptureModel:             {true, "uprobes and forwarder"},
		CapLogAllowed:               {true, "all"},
		CapAdoptedContainers:        {true, "yes, plus delete/rename per cgroup; `ask` refused inside"},
		CapNetHTTPRules:             {true, "declared forwarder only"},
		CapNamespaceSandbox:         {true, "with `containers: rootless`"},
		CapUnixAbstractScope:        {false, "Landlock ABI ≥ 6 only"},
		CapChmodDeny:                {false, "no: `path_chmod` (step B) refuses beneath `deny_write` targets only (enforce-plane R12)"},
		CapExecCommandArgv:          {false, "conditional (held by the plane's exec pins where doctor's exec pin cell passes)"},
		CapGateFSOpenCompletion:     {false, "conditional (completed on the object the gate scored by the run's open deputy under `gate.completion: held`, ADR 0041 Stage B; otherwise best-effort: copied pathname, continued; an ask-range score is held, ADR 0008)"},
		CapGateFSMutationCompletion: {false, "best-effort (unlink, rename, link, symlink, mkdir, mknod, truncate, chmod, chown and xattr changes, ACLs included, scored on copied names and continued; timestamps are not scored; no kernel layer evaluates a gate predicate)"},
		CapGateExecCompletion:       {false, "conditional (held to the scored image and argv by the plane's exec pins where doctor's exec pin cell passes; otherwise best-effort: copied image path and argv, continued; an ask-range score is refused)"},
		CapGateNetCompletion:        {true, "yes on IP-domain sockets (performed on the duplicate with the scored address); addressed unix datagrams remain best-effort; enforcing Unix stream connects use the held-inode relay (ADR 0113)"},
		CapProtectedWriteTargets:    {true, "yes, by inode (decision plane `lsm`), chmod included (`path_chmod`)"},
		CapSocketFamilies:           {true, "yes, under a `net:` section (seccomp allowlist and `TCP_ULP` arm; the plane's `socket_create` for every family, io_uring included; `cgroup/sock_create`; `cgroup/setsockopt` for `TCP_ULP` on any path)"},
		CapHostSocketsRefused:       {false, "best-effort for the general host-socket policy (`host_sockets/root-tier`); ADR 0113's fixed refusals additionally use Unix kernel programs and the native peer plane where available"},
		CapReadDenyNested:           {true, "yes, by inode (decision plane `lsm`), the nearest entry wins"},
		CapReadDenyCreatedLater:     {true, "yes: the plane's name check (ADR 0043), for a file created directly at a covered name beneath each scope; not one reached through a temporary name, a held descriptor or an agent-made symlink; held reads under `fs.reads: held` (ADR 0069)"},
		CapReadDenyMoved:            {true, "yes: a rename or link out of a `deny_read` tree is refused (REFER)"},
	},
}

// Matrix returns the static capability Set of tier as a fresh value (R22: ground truth for what a
// tier can do, never computed from a probe). TierObserve and unknown tiers provide nothing (an
// empty, non-nil Set).
func Matrix(tier Tier) Set {
	out := make(Set, len(allCapabilities))
	for c, k := range matrix[tier] {
		if k.present {
			out[c] = true
		}
	}
	return out
}

// MatrixDetail returns the CAPABILITIES.md prose for one cell, or "" for a tier or row outside the
// table.
func MatrixDetail(tier Tier, c Capability) string { return matrix[tier][c].detail }

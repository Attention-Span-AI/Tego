// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net/netip"
	"strconv"
	"time"
)

// Layer is the provenance source of a value, in merge order.
type Layer int

// Layer values in merge order.
const (
	LayerBuiltin  Layer = iota // compiled-in defaults
	LayerEtc                   // /etc/tego/config.yaml
	LayerUser                  // <pw_dir>/.tego/config.yaml of the invoking user
	LayerEnvFile               // $TEGO_CONFIG
	LayerContract              // the agent contract, merged later by agent.Compile
)

// String names the layer.
func (l Layer) String() string {
	switch l {
	case LayerBuiltin:
		return "built-in"
	case LayerEtc:
		return "etc"
	case LayerUser:
		return "user"
	case LayerEnvFile:
		return "env"
	case LayerContract:
		return "contract"
	}
	return "layer(" + strconv.Itoa(int(l)) + ")"
}

// Provenance says where a value came from: the file and line for a file layer, or the built-in
// layer with an empty File.
type Provenance struct {
	File  string
	Line  int
	Layer Layer
}

// String renders "file:line", or "built-in" for the compiled-in layer.
func (p Provenance) String() string {
	if p.Layer == LayerBuiltin || p.File == "" {
		return LayerBuiltin.String()
	}
	if p.Line <= 0 {
		return p.File
	}
	return p.File + ":" + strconv.Itoa(p.Line)
}

// Ceiling is a value every layer may lower and never raise (R15). Bounded is false while no
// layer has set it: built-in ceilings are unbounded, and an unbounded ceiling has no Value.
type Ceiling[T comparable] struct {
	Value   T
	Source  Provenance
	Bounded bool
}

// Ptr returns the ceiling as agent.Compile consumes it: nil when unbounded, else the value.
func (c Ceiling[T]) Ptr() *T {
	if !c.Bounded {
		return nil
	}
	v := c.Value
	return &v
}

// Setting is a value where the last layer that sets it wins outright (R16).
type Setting[T any] struct {
	Value  T
	Source Provenance
}

// TierSetting is the shape of the tier ceiling: "auto" (unbounded) or a tier name, which the parser
// has checked against its own rank of landlock, cgroup and bpflsm (R24 as amended 2026-09-24).
type TierSetting struct {
	Auto bool
	Tier string
}

// String renders "auto" or the tier name.
func (t TierSetting) String() string {
	if t.Auto {
		return Auto
	}
	return t.Tier
}

// CaptureSetting is the shape of the capture ceiling: "auto" or a capture mode name (R24).
type CaptureSetting struct {
	Auto    bool
	Capture string
}

// String renders "auto" or the mode name.
func (c CaptureSetting) String() string {
	if c.Auto {
		return Auto
	}
	return c.Capture
}

// ResolverMode is the unprivileged tier's UDP rule: auto (the nameservers of /etc/resolv.conf,
// read by the caller at run start, E28) or an explicit server list.
type ResolverMode struct {
	Auto    bool
	Servers []netip.AddrPort
}

// String renders "auto" or the comma-separated servers.
func (r ResolverMode) String() string {
	if r.Auto {
		return Auto
	}
	s := ""
	for i, srv := range r.Servers {
		if i > 0 {
			s += ","
		}
		s += srv.String()
	}
	return s
}

// Limits are the machine's ceilings on a contract's limits, same keys and units as the contract.
// Units: CPU in cores, CPUWeight is cgroup cpu.weight, Memory and MemoryHigh in bytes, Wall and
// StallAfter wall-clock durations, CostUSD in US dollars.
type Limits struct {
	CPU        Ceiling[float64]
	CPUWeight  Ceiling[int]
	Memory     Ceiling[ByteSize]
	MemoryHigh Ceiling[ByteSize]
	Pids       Ceiling[int]
	Tokens     Ceiling[int64]
	CostUSD    Ceiling[float64]
	Wall       Ceiling[time.Duration]
	StallAfter Ceiling[time.Duration]
	Repeats    Ceiling[int]
}

// AskConfig is schema-only in P0 (R26): parsed, stored and reported, enforced from P1 on.
type AskConfig struct {
	Timeout Setting[time.Duration]
	Notify  Setting[[]string] // cli | desktop | webhook:<url> (not built); ADR 0122
}

// RecordConfig holds the recorder settings.
type RecordConfig struct {
	// Ringbuf is the size of each run's record ring, and of its capture ring when it captures with uprobes; a
	// power of two and a page multiple. Honoured only from /etc/tego/config.yaml (ADR 0026 (2)).
	Ringbuf Setting[ByteSize]
	// MaxRunBytes is a ceiling on one run's ledger, its events.jsonl and its blobs together (blobs count from
	// 2026-11-01, under the same record.MinorLedgerCap): a run whose ledger holds this many bytes is ended as a limit,
	// which=ledger_bytes, so an agent under a restarting unit starts a new ledger instead of growing one without
	// bound. Unbounded by default; every layer may lower it, none raise it (R15).
	MaxRunBytes Ceiling[ByteSize]
}

// BPFConfig holds the settings of the tier-2 build's pinned objects.
type BPFConfig struct {
	// Linger is how long a build stays attached after its last run ended (ADR 0022); 0 removes it when the
	// last launcher leaves. Honoured only from /etc/tego/config.yaml (LayerEtc): it decides what stays in the
	// kernel host-wide, which is the administrator's to say, not one invoking user's.
	Linger Setting[time.Duration]
	// RingBudget caps the memlock of every live run ring on the host, all builds together; a Prepare that would
	// pass it fails (ADR 0026 (2)). Honoured only from /etc/tego/config.yaml, like Linger.
	RingBudget Setting[ByteSize]
	// Plane pins the decision plane's attach mode (ADR 0024 (2); docs/p0/enforce-plane.md R18): auto (the
	// default) takes LSM mode where the mode probe passes it, else fmod_ret mode, else the fanotify fallback; lsm
	// or fmod_ret offers that mode only. Honoured only from /etc/tego/config.yaml, like Linger: which programs
	// decide every host process's opens is the administrator's to say.
	Plane Setting[string]
}

// The bpf.plane values.
const (
	PlaneAuto    = "auto"
	PlaneLSM     = "lsm"
	PlaneFmodRet = "fmod_ret"
)

// ForwarderConfig holds the forwarder settings.
type ForwarderConfig struct {
	Listen Setting[string] // host:port; port 0 = ephemeral
}

// LogConfig holds the log settings.
type LogConfig struct {
	Level Setting[string] // debug | info | warn
}

// LandlockConfig holds the Landlock settings a run applies with its ruleset.
type LandlockConfig struct {
	// Audit is off (the default) or new-exec: LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON, so the kernel's audit log
	// records the Landlock refusals the agent meets after the child stage's execve, which by default it does
	// not (Landlock ABI 7, Linux 6.15; enforce-landlock §4 RestrictSelf). It only adds kernel log records, so it
	// is an opt-in and never a ceiling, but a floor: once a layer sets new-exec, a later layer's off is kept
	// from and warned (R16), so the invoking user's own layer cannot switch off what /etc/tego/config.yaml
	// turned on.
	Audit Setting[string]
}

// The landlock.audit values.
const (
	LandlockAuditOff     = "off"
	LandlockAuditNewExec = "new-exec"
)

// UserPolicy is one tegod users entry. users: is honoured from /etc/tego/config.yaml only (ADR 0042 (4)), read
// by nothing in this release, and tego run ignores it with a warning; ADR 0042 (7)(f) reserves its meaning.
type UserPolicy struct {
	Contracts []string
	MaxRuns   int
}

// Machine is the effective machine config after all layers, with the provenance of every value.
// A *Machine is immutable for its process's lifetime (I3): a disk edit never affects an in-flight run.
type Machine struct {
	Version int
	// Layers are the layer files the Load of this Machine consulted, in order and as written: absolute paths whose walk
	// does not reach procfs, never cleaned, so a ".." after a link still names the file the open read, as the kernel
	// walks it. A relative layer or one through procfs names another file in every working directory, so the Load
	// refuses it unread and does not list it (layerPathProblem, RS9-1, RS10-1). A listed layer is there whether a file
	// was there or not and whether it was applied or skipped (TrustWarn): each is a place a later Load reads.
	// R10 keeps every write entry off each one, by every name its walk reads (agent-contract.md R10, ADR 0059): a run
	// that wrote one would choose the registry, the profiles, the prices and the ledger root of the runs after it.
	Layers []string
	// Home is the invoking user's home directory from the passwd database, "" when unknown (E9);
	// a leading "~/" in a path setting was expanded against it at Load.
	ServePort        Setting[int] // serve.port: local TCP port protected by builtin.tego_surface
	Home             string
	Tier             Ceiling[TierSetting]
	Capture          Ceiling[CaptureSetting]
	LedgerRoot       Setting[string]
	Prices           Setting[string]
	Profiles         Setting[string]
	Registry         Setting[string] // the user registry's directory, "" for none (agent-contract.md R26)
	Retention        Setting[time.Duration]
	GCInterval       Setting[time.Duration] // how often a run start applies retention, for at most retentionBudget (internal/cli); 0 never
	StopGrace        Setting[time.Duration]
	Limits           Limits
	Ask              AskConfig
	Record           RecordConfig
	BPF              BPFConfig
	Resolver         Setting[ResolverMode]
	DeniedResolved   Setting[[]netip.Prefix] // ranges no net.allow host name admits, on top of the built-in classes (union across layers, merge.go)
	Forwarder        ForwarderConfig
	Log              LogConfig
	Landlock         LandlockConfig
	PrivilegedBinary Setting[string] // honoured only from /etc/tego/config.yaml (LayerEtc); not used in this release, and warns (ADR 0042 (3)(c), (d)); config.Load never opens its target (E31)
	Users            Setting[map[string]UserPolicy]
}

// Auto is the sentinel for an unbounded tier/capture ceiling or an automatic resolver.
const Auto = "auto"

// Diagnostic is one finding of Load, in the shared file:line[:col]: message [code] format.
type Diagnostic struct {
	File     string
	Line     int
	Col      int
	Message  string
	Code     string
	Fix      string
	Severity string // "error" | "warning"
}

// Diagnostic codes and severities.
const (
	// CodeUntrusted is a layer file that failed the trust check (exit 125 in tego run).
	CodeUntrusted = "config-untrusted"
	// CodeInvalid is a layer that did not parse or holds an invalid value.
	CodeInvalid = "config-invalid"
	// CodeCeilingKept is a layer that tried to raise a ceiling (R15) or to lower landlock.audit's floor
	// (R16); the inherited value stands.
	CodeCeilingKept = "ceiling-kept"
	// CodeIgnored is a key or layer that was skipped: privileged_binary outside /etc, or a
	// per-user layer with no passwd entry (E9).
	CodeIgnored = "config-ignored"
	// CodeAdvisory is a valid but notable value, such as stop_grace: 0s (E17).
	CodeAdvisory = "config-advisory"

	// SeverityError is a diagnostic that fails Load in TrustAbort mode.
	SeverityError = "error"
	// SeverityWarning is a diagnostic that never changes the exit code.
	SeverityWarning = "warning"
)

// String renders the diagnostic as file:line[:col]: message [code], then the fix when set.
func (d Diagnostic) String() string {
	s := ""
	if d.File != "" {
		s = d.File
		if d.Line > 0 {
			s += ":" + strconv.Itoa(d.Line)
			if d.Col > 0 {
				s += ":" + strconv.Itoa(d.Col)
			}
		}
		s += ": "
	}
	s += d.Message
	if d.Code != "" {
		s += " [" + d.Code + "]"
	}
	if d.Fix != "" {
		s += " " + d.Fix
	}
	return s
}

// HasErrors reports whether any diagnostic is an error.
func HasErrors(diags []Diagnostic) bool {
	for _, d := range diags {
		if d.Severity == SeverityError {
			return true
		}
	}
	return false
}

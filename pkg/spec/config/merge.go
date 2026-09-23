// SPDX-License-Identifier: Apache-2.0

package config

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
)

// tierRank and captureRank order the ceiling names locally so config never imports backend. They are
// also the legal names: the parser refuses any other at its own line (parser.ranked, R24 as amended), so
// no unknown name reaches the merge.
var (
	tierRank    = map[string]int{"landlock": 1, "cgroup": 2, "bpflsm": 3}
	captureRank = map[string]int{"off": 1, "forwarder": 2, "uprobe": 3}
)

// merger applies one parsed layer onto a Machine.
type merger struct {
	file  string
	layer Layer
	diags *[]Diagnostic
}

func (g merger) prov(line int) Provenance {
	return Provenance{File: g.file, Line: line, Layer: g.layer}
}

// kept records a raise attempt: the inherited value stands (R15).
func (g merger) kept(line int, key, value string, from Provenance) {
	*g.diags = append(*g.diags, Diagnostic{File: g.file, Line: line, Code: CodeCeilingKept, Severity: SeverityWarning,
		Message: fmt.Sprintf("ceiling %s=%s kept from %s", key, value, from)})
}

// apply merges d into m: ceilings only lowered (R15), settings last-wins but for the deny list's union and
// landlock.audit's floor (R16).
func (g merger) apply(m *Machine, d *layerData) {
	if d.version.set {
		m.Version = d.version.value
	}
	g.tier(&m.Tier, d.tier)
	g.capture(&m.Capture, d.capture)
	g.limits(&m.Limits, &d.limits)

	setting(&m.LedgerRoot, d.ledgerRoot, g)
	setting(&m.Prices, d.prices, g)
	setting(&m.Profiles, d.profiles, g)
	setting(&m.Registry, d.registry, g)
	setting(&m.Retention, d.retention, g)
	setting(&m.GCInterval, d.gcInterval, g)
	lower(&m.Record.MaxRunBytes, d.maxRunBytes, "record.max_run_bytes", ByteSize.String, g)
	setting(&m.StopGrace, d.stopGrace, g)
	setting(&m.Ask.Timeout, d.askTimeout, g)
	setting(&m.Ask.Notify, d.askNotify, g)
	etcOnly(g, &m.Record.Ringbuf, d.ringbuf, "record.ringbuf")
	setting(&m.Resolver, d.resolver, g)
	union(&m.DeniedResolved, d.deniedResolved, g)
	setting(&m.Forwarder.Listen, d.forwarderListen, g)
	setting(&m.Log.Level, d.logLevel, g)
	g.landlockAudit(&m.Landlock.Audit, d.landlockAudit)
	etcOnly(g, &m.Users, d.users, "users")
	etcOnly(g, &m.PrivilegedBinary, d.privilegedBinary, "privileged_binary")
	if d.privilegedBinary.set && g.layer == LayerEtc {
		// ADR 0042 (3)(c), (d): the file-capability copy is not delivered in this release and a copy is refused at
		// start, so the setting stays parsed (a machine config that sets it still loads) and says so once.
		*g.diags = append(*g.diags, Diagnostic{File: g.file, Line: d.privilegedBinary.line, Code: CodeIgnored,
			Severity: SeverityWarning, Message: "privileged_binary is not used in this release; ADR 0042 (3)(c)"})
	}
	etcOnly(g, &m.BPF.Linger, d.bpfLinger, "bpf.linger")
	etcOnly(g, &m.BPF.RingBudget, d.ringBudget, "bpf.ring_budget")
	etcOnly(g, &m.BPF.Plane, d.bpfPlane, "bpf.plane")
}

// etcOnly applies a setting of what root does in the kernel from /etc/tego/config.yaml only: record.ringbuf sizes
// each run's ring and bpf.ring_budget caps them all, both kernel allocations the launcher makes as root, so an
// invoking user's layer would size or lift what root allocates with nothing to bound it (ADR 0026 (2)); bpf.plane
// picks which programs decide every host process's opens (ADR 0024 (2)); bpf.linger is how long a build stays
// attached host-wide after its last run (ADR 0022); privileged_binary names what runs as root; users: is tegod's
// authorization, which an invoking user's own layer would otherwise grant itself (ADR 0042 (4)). Elsewhere the
// value is ignored with a warning.
func etcOnly[T any](g merger, dst *Setting[T], f field[T], key string) {
	if !f.set {
		return
	}
	if g.layer != LayerEtc {
		*g.diags = append(*g.diags, Diagnostic{File: g.file, Line: f.line, Code: CodeIgnored, Severity: SeverityWarning,
			Message: key + " is honoured from /etc/tego/config.yaml only; ignored here"})
		return
	}
	setting(dst, f, g)
}

// landlockAudit applies R16's floor: new-exec, once a layer sets it, holds against a later layer's off, which is
// reported the way R15 reports a raise. At tier landlock the kernel's own refusals are not in the ledger, so the
// audit is the administrator's only view of them; an off in the invoking user's own layer that silently undid
// /etc/tego/config.yaml's new-exec would take that view away and leave no trace (the reason union exists).
func (g merger) landlockAudit(s *Setting[string], f field[string]) {
	if !f.set {
		return
	}
	if s.Value == LandlockAuditNewExec && f.value != LandlockAuditNewExec {
		*g.diags = append(*g.diags, Diagnostic{File: g.file, Line: f.line, Code: CodeCeilingKept, Severity: SeverityWarning,
			Message: fmt.Sprintf("floor landlock.audit=%s kept from %s", s.Value, s.Source)})
		return
	}
	setting(s, f, g)
}

// union is the one setting no later layer can narrow: a layer's entries join the ones already there, and
// the source is the last layer that brought a new entry. A deny list that the invoking user's own layer
// could empty would let that user lift what /etc/tego/config.yaml denied (the same reason deny_read's
// entries are never removed by an extending contract, SEMANTICS §1).
func union[T comparable](s *Setting[[]T], f field[[]T], g merger) {
	if !f.set {
		return
	}
	for _, v := range f.value {
		if !slices.Contains(s.Value, v) {
			s.Value = append(slices.Clone(s.Value), v)
			s.Source = g.prov(f.line)
		}
	}
}

// setting applies R16: the last layer present wins, provenance included.
func setting[T any](s *Setting[T], f field[T], g merger) {
	if !f.set {
		return
	}
	s.Value, s.Source = f.value, g.prov(f.line)
}

// lower applies R15 to an ordered ceiling: min(inherited, layer), equal values move the
// provenance to the later layer (E11), a raise is reported and ignored.
func lower[T cmp.Ordered](c *Ceiling[T], f field[T], key string, format func(T) string, g merger) {
	if !f.set {
		return
	}
	switch {
	case !c.Bounded || f.value < c.Value:
		*c = Ceiling[T]{Value: f.value, Source: g.prov(f.line), Bounded: true}
	case f.value == c.Value:
		c.Source = g.prov(f.line)
	default:
		g.kept(f.line, key, format(c.Value), c.Source)
	}
}

// lowerRanked applies R15 to a named ceiling: "auto" is unbounded, names compare by rank.
func lowerRanked(bounded *bool, current *string, src *Provenance, f field[string], key string, rank map[string]int, g merger) {
	if !f.set {
		return
	}
	prov := g.prov(f.line)
	switch {
	case f.value == Auto && !*bounded:
		*src = prov
	case f.value == Auto:
		g.kept(f.line, key, *current, *src)
	case !*bounded || rank[f.value] < rank[*current]:
		*bounded, *current, *src = true, f.value, prov
	case f.value == *current:
		*src = prov
	default:
		g.kept(f.line, key, *current, *src)
	}
}

func (g merger) tier(c *Ceiling[TierSetting], f field[string]) {
	bounded, name := !c.Value.Auto, c.Value.Tier
	lowerRanked(&bounded, &name, &c.Source, f, "tier", tierRank, g)
	c.Bounded, c.Value = bounded, TierSetting{Auto: !bounded, Tier: name}
}

func (g merger) capture(c *Ceiling[CaptureSetting], f field[string]) {
	bounded, name := !c.Value.Auto, c.Value.Capture
	lowerRanked(&bounded, &name, &c.Source, f, "capture", captureRank, g)
	c.Bounded, c.Value = bounded, CaptureSetting{Auto: !bounded, Capture: name}
}

func (g merger) limits(l *Limits, d *limitsData) {
	lower(&l.CPU, d.cpu, "limits.cpu", formatFloat, g)
	lower(&l.CPUWeight, d.cpuWeight, "limits.cpu_weight", strconv.Itoa, g)
	lower(&l.Memory, d.memory, "limits.memory", ByteSize.String, g)
	lower(&l.MemoryHigh, d.memoryHigh, "limits.memory_high", ByteSize.String, g)
	lower(&l.Pids, d.pids, "limits.pids", strconv.Itoa, g)
	lower(&l.Tokens, d.tokens, "limits.tokens", formatInt64, g)
	lower(&l.CostUSD, d.costUSD, "limits.cost_usd", formatFloat, g)
	lower(&l.Wall, d.wall, "limits.wall", FormatDuration, g)
	lower(&l.StallAfter, d.stallAfter, "limits.stall_after", FormatDuration, g)
	lower(&l.Repeats, d.repeats, "limits.repeats", strconv.Itoa, g)
}

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }
func formatInt64(n int64) string   { return strconv.FormatInt(n, 10) }

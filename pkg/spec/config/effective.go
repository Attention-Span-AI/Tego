// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Value is one effective value with its source, as tego compile prints it.
type Value struct {
	Key       string
	Value     string // rendered in the YAML surface's units ("32GiB", "30d", "auto", "unbounded")
	Source    Provenance
	Ceiling   bool // a ceiling (tier, capture, limits.*) rather than a setting
	Unbounded bool // a ceiling no layer has set
}

// unboundedText renders a ceiling no layer set.
const unboundedText = "unbounded"

// Effective lists every value of m with its provenance, in a fixed order. Pure.
func (m *Machine) Effective() []Value {
	var out []Value
	ceiling := func(key, value string, src Provenance, bounded bool) {
		if !bounded {
			value = unboundedText
		}
		out = append(out, Value{Key: key, Value: value, Source: src, Ceiling: true, Unbounded: !bounded})
	}
	settingRow := func(key, value string, src Provenance) {
		out = append(out, Value{Key: key, Value: value, Source: src})
	}
	// An unbounded tier or capture is auto, the word the config file uses for it; "unbounded" is the limits'.
	named := func(key, value string, src Provenance, bounded bool) {
		if !bounded {
			value = Auto
		}
		out = append(out, Value{Key: key, Value: value, Source: src, Ceiling: true, Unbounded: !bounded})
	}
	named("tier", m.Tier.Value.String(), m.Tier.Source, m.Tier.Bounded)
	named("capture", m.Capture.Value.String(), m.Capture.Source, m.Capture.Bounded)
	settingRow("serve.port", strconv.Itoa(m.ServePort.Value), m.ServePort.Source)
	settingRow("ledger_root", m.LedgerRoot.Value, m.LedgerRoot.Source)
	settingRow("retention", FormatDuration(m.Retention.Value), m.Retention.Source)
	settingRow("gc_interval", FormatDuration(m.GCInterval.Value), m.GCInterval.Source)
	settingRow("stop_grace", FormatDuration(m.StopGrace.Value), m.StopGrace.Source)
	l := &m.Limits
	ceiling("limits.cpu", formatFloat(l.CPU.Value), l.CPU.Source, l.CPU.Bounded)
	ceiling("limits.cpu_weight", strconv.Itoa(l.CPUWeight.Value), l.CPUWeight.Source, l.CPUWeight.Bounded)
	ceiling("limits.memory", l.Memory.Value.String(), l.Memory.Source, l.Memory.Bounded)
	ceiling("limits.memory_high", l.MemoryHigh.Value.String(), l.MemoryHigh.Source, l.MemoryHigh.Bounded)
	ceiling("limits.pids", strconv.Itoa(l.Pids.Value), l.Pids.Source, l.Pids.Bounded)
	ceiling("limits.tokens", formatInt64(l.Tokens.Value), l.Tokens.Source, l.Tokens.Bounded)
	ceiling("limits.cost_usd", formatFloat(l.CostUSD.Value), l.CostUSD.Source, l.CostUSD.Bounded)
	ceiling("limits.wall", FormatDuration(l.Wall.Value), l.Wall.Source, l.Wall.Bounded)
	ceiling("limits.stall_after", FormatDuration(l.StallAfter.Value), l.StallAfter.Source, l.StallAfter.Bounded)
	ceiling("limits.repeats", strconv.Itoa(l.Repeats.Value), l.Repeats.Source, l.Repeats.Bounded)
	settingRow("ask.timeout", FormatDuration(m.Ask.Timeout.Value), m.Ask.Timeout.Source)
	settingRow("ask.notify", strings.Join(m.Ask.Notify.Value, ","), m.Ask.Notify.Source)
	settingRow("record.ringbuf", m.Record.Ringbuf.Value.String(), m.Record.Ringbuf.Source)
	ceiling("record.max_run_bytes", m.Record.MaxRunBytes.Value.String(), m.Record.MaxRunBytes.Source, m.Record.MaxRunBytes.Bounded)
	settingRow("bpf.linger", FormatDuration(m.BPF.Linger.Value), m.BPF.Linger.Source)
	settingRow("bpf.ring_budget", m.BPF.RingBudget.Value.String(), m.BPF.RingBudget.Source)
	settingRow("bpf.plane", m.BPF.Plane.Value, m.BPF.Plane.Source)
	settingRow("resolver", m.Resolver.Value.String(), m.Resolver.Source)
	settingRow("denied_resolved_addresses", formatPrefixes(m.DeniedResolved.Value), m.DeniedResolved.Source)
	settingRow("forwarder.listen", m.Forwarder.Listen.Value, m.Forwarder.Listen.Source)
	settingRow("prices", m.Prices.Value, m.Prices.Source)
	settingRow("profiles", m.Profiles.Value, m.Profiles.Source)
	settingRow("registry", m.Registry.Value, m.Registry.Source)
	settingRow("log.level", m.Log.Level.Value, m.Log.Level.Source)
	settingRow("landlock.audit", m.Landlock.Audit.Value, m.Landlock.Audit.Source)
	settingRow("privileged_binary", m.PrivilegedBinary.Value, m.PrivilegedBinary.Source)
	settingRow("users", formatUsers(m.Users.Value), m.Users.Source)
	return out
}

// LimitCeilings lists the limits.* ceilings some layer set, each with its file and line: the limits every run gets
// whatever its contract says (agent-contract.md R11). Pure; nil for a nil m.
func (m *Machine) LimitCeilings() []Value {
	if m == nil {
		return nil
	}
	var out []Value
	for _, v := range m.Effective() {
		if v.Ceiling && !v.Unbounded && strings.HasPrefix(v.Key, "limits.") {
			out = append(out, v)
		}
	}
	return out
}

// WriteEffective prints one line per value: "<kind> <key>=<value>  (<source>)".
func (m *Machine) WriteEffective(w io.Writer) error {
	for _, v := range m.Effective() {
		kind := "setting"
		if v.Ceiling {
			kind = "ceiling"
		}
		if _, err := fmt.Fprintf(w, "%s %s=%s  (%s)\n", kind, v.Key, v.Value, v.Source); err != nil {
			return fmt.Errorf("config: write effective values: %w", err)
		}
	}
	return nil
}

// formatPrefixes renders the denied ranges comma-separated, or "[]" when the machine adds none to the
// built-in classes.
func formatPrefixes(ps []netip.Prefix) string {
	if len(ps) == 0 {
		return "[]"
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, ",")
}

// formatUsers renders the users map as "uid:max_runs" entries sorted by uid, or "{}".
func formatUsers(users map[string]UserPolicy) string {
	if len(users) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(users))
	for k := range users {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+":"+strconv.Itoa(users[k].MaxRuns))
	}
	return strings.Join(parts, ",")
}

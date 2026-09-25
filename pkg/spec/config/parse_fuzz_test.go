// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

// fuzzBaseLayer bounds every ceiling a layer can set, each at a value a real layer could lower, so that
// FuzzParseLayer can check a fuzzed layer against R15 on every one of them.
const fuzzBaseLayer = `tier: bpflsm
capture: uprobe
limits:
  cpu: "64"
  cpu_weight: 10000
  memory: 1TiB
  memory_high: 1TiB
  pids: 100000
  tokens: 1000000000
  cost_usd: 100000
  wall: 30d
  stall_after: 30d
  repeats: 1000000
`

// fuzzBase is Builtin with fuzzBaseLayer applied as /etc/tego/config.yaml, a fresh Machine on every call.
func fuzzBase(t *testing.T) *Machine {
	t.Helper()
	d, diags := parseLayer("/etc/tego/config.yaml", []byte(fuzzBaseLayer))
	if HasErrors(diags) {
		t.Fatalf("the base layer does not parse: %+v", diags)
	}
	m := Builtin()
	var ds []Diagnostic
	merger{file: "/etc/tego/config.yaml", layer: LayerEtc, diags: &ds}.apply(m, d)
	return m
}

// ceilings is every ceiling of m as a comparable (bounded, value) pair, keyed by its config key; the named
// ones by rank, as lowerRanked compares them.
func ceilings(m *Machine) map[string][2]float64 {
	b := func(ok bool) float64 {
		if ok {
			return 1
		}
		return 0
	}
	l := m.Limits
	return map[string][2]float64{
		"tier":               {b(m.Tier.Bounded), float64(tierRank[m.Tier.Value.Tier])},
		"capture":            {b(m.Capture.Bounded), float64(captureRank[m.Capture.Value.Capture])},
		"limits.cpu":         {b(l.CPU.Bounded), l.CPU.Value},
		"limits.cpu_weight":  {b(l.CPUWeight.Bounded), float64(l.CPUWeight.Value)},
		"limits.memory":      {b(l.Memory.Bounded), float64(l.Memory.Value)},
		"limits.memory_high": {b(l.MemoryHigh.Bounded), float64(l.MemoryHigh.Value)},
		"limits.pids":        {b(l.Pids.Bounded), float64(l.Pids.Value)},
		"limits.tokens":      {b(l.Tokens.Bounded), float64(l.Tokens.Value)},
		"limits.cost_usd":    {b(l.CostUSD.Bounded), l.CostUSD.Value},
		"limits.wall":        {b(l.Wall.Bounded), float64(l.Wall.Value)},
		"limits.stall_after": {b(l.StallAfter.Bounded), float64(l.StallAfter.Value)},
		"limits.repeats":     {b(l.Repeats.Bounded), float64(l.Repeats.Value)},
	}
}

// yamlLines is how many lines the YAML parser can count in data: one more than its line breaks, which are
// CR and NEL, LS and PS as well as LF, in the text as the parser decodes it, which is UTF-16 after a UTF-16
// byte-order mark. The fuzzer found both: a diagnostic on line 3 of a file with two CRs and no LF, and one on
// line 3 of "\xfe\xff (( 00", where " (" is U+2028 in UTF-16BE.
func yamlLines(data []byte) int {
	text := string(data)
	if len(data) >= 2 && (data[0] == 0xfe && data[1] == 0xff || data[0] == 0xff && data[1] == 0xfe) {
		units := make([]uint16, 0, len(data)/2)
		for i := 2; i+1 < len(data); i += 2 {
			if data[0] == 0xfe {
				units = append(units, uint16(data[i])<<8|uint16(data[i+1]))
			} else {
				units = append(units, uint16(data[i+1])<<8|uint16(data[i]))
			}
		}
		text = string(utf16.Decode(units))
	}
	n := 1
	for _, brk := range []string{"\n", "\r", "\u0085", " ", " "} {
		n += strings.Count(text, brk)
	}
	return n
}

// FuzzParseLayer is one config layer file over any bytes, held to more than not panicking. parseLayer
// answers the same both times it is asked; every diagnostic names the file, a code, a
// severity and a message, at a line the file has. A layer it accepts, merged over a machine whose every
// ceiling is bounded, lowers a ceiling or leaves it, never raises or unbounds one (R15), and merged a second
// time changes no value: last-wins settings, the deny list's union and R15's min are all idempotent.
func FuzzParseLayer(f *testing.F) {
	for _, s := range []string{etcLayer, userLayer, envLayer, fuzzBaseLayer, "", "~\n", "tier: auto\n",
		"tier: landlock\ncapture: off\nlimits: {cpu: \"0.5\", memory: 1GiB, pids: 0}\n",
		"denied_resolved: [10.0.0.0/8, \"::1/128\"]\nlandlock:\n  audit: new-exec\n", "tier: [x]\n", "a: b\na: c\n",
		"limits:\n  wall: -1s\n", "users:\n  alice: {tier: landlock}\n", "\t- :\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		const file = "/home/u/.tego/config.yaml"
		d, diags := parseLayer(file, data)
		d2, diags2 := parseLayer(file, data)
		if !reflect.DeepEqual(d, d2) || !reflect.DeepEqual(diags, diags2) {
			t.Fatalf("parseLayer answered twice differently for %q", data)
		}
		lines := yamlLines(data)
		for _, dg := range diags {
			if dg.File != file || dg.Code == "" || dg.Message == "" ||
				(dg.Severity != SeverityError && dg.Severity != SeverityWarning) || dg.Line < 0 || dg.Line > lines+1 {
				t.Fatalf("diagnostic %+v for a %d-line file", dg, lines)
			}
		}
		if HasErrors(diags) {
			return
		}
		base := ceilings(fuzzBase(t))
		m := fuzzBase(t)
		var ds []Diagnostic
		merger{file: file, layer: LayerUser, diags: &ds}.apply(m, d)
		once := ceilings(m)
		for key, was := range base {
			if now := once[key]; now[0] < was[0] || now[1] > was[1] {
				t.Fatalf("%s went from %v to %v (bounded, value): a layer raised a ceiling\n%s", key, was, now, data)
			}
		}
		again := *m
		merger{file: file, layer: LayerUser, diags: &ds}.apply(&again, d)
		if !reflect.DeepEqual(ceilings(&again), once) || !reflect.DeepEqual(again.DeniedResolved.Value, m.DeniedResolved.Value) ||
			again.LedgerRoot.Value != m.LedgerRoot.Value || again.Landlock.Audit.Value != m.Landlock.Audit.Value {
			t.Fatalf("the layer merged twice differs from once\n%s", data)
		}
	})
}

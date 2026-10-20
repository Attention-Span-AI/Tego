// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// perfRecords are the PERF records of kind in a suite's output, decoded.
func perfRecords(t *testing.T, out, kind string) []map[string]any {
	t.Helper()
	var recs []map[string]any
	for _, line := range strings.Split(out, "\n") {
		body, ok := strings.CutPrefix(line, "PERF ")
		if !ok {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("PERF line %q: %v", line, err)
		}
		if m["kind"] == kind {
			recs = append(recs, m)
		}
	}
	return recs
}

// attributedSample is a cold sample as an attributed launch prints it: per-program and per-hook phases, counts and
// a slow load's stack beside the coarse phases.
func attributedSample(up time.Duration) *run {
	r := goodSample()
	r.up = up
	r.phases = map[string]float64{
		"load.obj.trace_proc.new":              900,
		"load.obj.trace_proc.maps":             20,
		"load.prog.trace_proc.a.wall":          300,
		"load.prog.trace_proc.a.verify":        250,
		"load.prog.trace_proc.b.wall":          500,
		"load.prog.trace_proc.b.verify":        450,
		"plane.prog.lsm.p.verify":              40,
		"probe.programs":                       700,
		"probe.d7":                             500,
		"probe.plane":                          200,
		"probe.hook.fexit/security_x.load":     30,
		"probe.hook.fexit/security_x.detach":   60,
		"probe.hook.fexit/security_y.detach":   40,
		"probe.plane.lsm.detach":               70,
		"probe.plane.fmod_ret.detach":          80,
		"probe.plane.prog.lsm.p.verify":        35,
		"probe.plane.prog.fmod_ret.p.verify":   25,
		"probe.plane.lsm.total":                150,
		"probe.plane.fmod_ret.total":           160,
		"load.plane":                           100,
		"prepare":                              1000,
		"probe.hook.fexit/security_y.attach":   1,
		"probe.hook.fexit/security_x.attach":   2,
		"probe.hook.fexit/security_y.load":     3,
		"probe.hook.fexit/security_x.verify":   4,
		"probe.hook.fexit/security_y.verify":   5,
		"probe.plane.prog.lsm.p.wall":          36,
		"probe.plane.prog.fmod_ret.p.wall":     26,
		"load.prog.trace_proc.unrelated_phase": 7, // a two-part name under the prefix: no leaf to sum
	}
	r.stats = map[string]int64{"load.prog.trace_proc.a.insns": 1000, "load.prog.trace_proc.b.insns": 3000,
		"load.prog.trace_proc.a.states": 10}
	r.stacks = []string{"load.prog.trace_proc.b 8 __mutex_lock<bpf_trampoline_get"}
	r.maxrssKB = 51200
	return r
}

// TestReaderTakesCountsAndStacks: the lines an attributed launch prints beside its phases are read into the sample.
func TestReaderTakesCountsAndStacks(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r := &run{res: map[string]float64{}, phases: map[string]float64{}, upCh: make(chan struct{}), readerDone: make(chan struct{})}
	go r.read(pr)
	_, _ = pw.WriteString("tego-phase load.prog.trace_proc.a.wall 300000\ntego-stat load.prog.trace_proc.a.insns 3751\n" +
		"tego-phase-stack load.prog.trace_proc.a 8 __mutex_lock<bpf_trampoline_get\ntego-stat x -1\n")
	_ = pw.Close()
	<-r.readerDone
	if r.phases["load.prog.trace_proc.a.wall"] != 300 {
		t.Errorf("phases %v", r.phases)
	}
	if !reflect.DeepEqual(r.stats, map[string]int64{"load.prog.trace_proc.a.insns": 3751, "x": -1}) {
		t.Errorf("stats %v", r.stats)
	}
	if !reflect.DeepEqual(r.stacks, []string{"load.prog.trace_proc.a 8 __mutex_lock<bpf_trampoline_get"}) {
		t.Errorf("stacks %q", r.stacks)
	}
}

// TestAttributionTotalsSumEachLeafOverItsItems: the attribution record's totals sum a leaf (verify, wall, detach, ...)
// over a collection's programs, over D7's hooks and over the plane probe's modes, which is what the decision gates
// of enforce-plane §10.1 read (G-H1: trace_proc's verify sum; G-detach: D7's and the plane probe's detach sums).
func TestAttributionTotalsSumEachLeafOverItsItems(t *testing.T) {
	t.Parallel()
	r := attributedSample(time.Second)
	got := attributionTotals(r.phases)
	want := map[string]float64{
		"load.prog.trace_proc.wall":        800,
		"load.prog.trace_proc.verify":      700,
		"plane.prog.lsm.verify":            40,
		"probe.hook.load":                  33,
		"probe.hook.attach":                3,
		"probe.hook.verify":                9,
		"probe.hook.detach":                100,
		"probe.plane.detach":               150,
		"probe.plane.total":                310,
		"probe.plane.prog.lsm.verify":      35,
		"probe.plane.prog.lsm.wall":        36,
		"probe.plane.prog.fmod_ret.wall":   26,
		"probe.plane.prog.fmod_ret.verify": 25,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("totals\n got %v\nwant %v", got, want)
	}
	counts := countTotals(r.stats)
	if !reflect.DeepEqual(counts, map[string]int64{"load.prog.trace_proc.insns": 4000, "load.prog.trace_proc.states": 10}) {
		t.Errorf("count totals %v", counts)
	}
}

// TestColdBudgetIsTakenFromUnattributedSamples: with the attribution on (the default), the samples that set
// cold.<mode>.ms and cold.bootfirst.ms launch as they did before the attribution existed, with no
// TEGO_TEST_LOAD_STATS (A-PERF-5: the measurement method is unchanged), and each is followed, after its own gc, by an
// attributed sample of the same mode. Every sample prints a cold-attribution record saying whether it took the
// verifier's statistics; the attributed ones are summed up in a cold-attributed record with what the attribution cost
// (best against best) and never enter a budget, even when they are the faster ones. The cold record keeps its coarse
// phases and leaves the per-program and per-hook ones to the attribution records.
func TestColdBudgetIsTakenFromUnattributedSamples(t *testing.T) {
	s, out := samplingSuite(t)
	s.bootFirst, s.attribution = true, true
	var envs [][]string
	gcs := 0
	s.clearBuilds = func() error { gcs++; return nil }
	s.oneRun = func(sp spec) (*run, error) {
		envs = append(envs, sp.env)
		if slices.Contains(sp.env, "TEGO_TEST_LOAD_STATS=1") {
			return attributedSample(time.Duration(len(envs)) * time.Millisecond), nil // faster than any budget sample
		}
		return attributedSample(time.Duration(100+len(envs)) * time.Millisecond), nil
	}
	s.cold()
	modes := len(s.modes) - 1
	if len(envs) != 2*3*modes {
		t.Fatalf("%d launches, want %d: one unattributed and one attributed a sample", len(envs), 2*3*modes)
	}
	for i, e := range envs {
		if attributed := slices.Contains(e, "TEGO_TEST_LOAD_STATS=1"); attributed != (i%2 == 1) {
			t.Fatalf("launch %d attributed=%v, want the budget's sample unattributed and the next one attributed: %q",
				i, attributed, e)
		}
	}
	if gcs != len(envs)-1 {
		t.Errorf("%d gc --builds for %d launches: every sample but the boot's first starts cold", gcs, len(envs))
	}
	m := s.modes[1].Name
	if s.got["cold.bootfirst.ms"] != 101 {
		t.Errorf("cold.bootfirst.ms = %v, want the boot's first, unattributed, sample's 101", s.got["cold.bootfirst.ms"])
	}
	if s.got["cold."+m+".ms"] != 101 {
		t.Errorf("cold.%s.ms = %v, want the unattributed minimum 101", m, s.got["cold."+m+".ms"])
	}
	recs := perfRecords(t, out.String(), "cold-attribution")
	if len(recs) != len(envs) {
		t.Fatalf("%d cold-attribution records, want one a sample (%d):\n%s", len(recs), len(envs), out)
	}
	if recs[0]["boot_first"] != true || recs[0]["load_stats"] != false || recs[1]["boot_first"] != false ||
		recs[1]["load_stats"] != true || recs[0]["settled"] != false {
		t.Errorf("boot_first/load_stats/settled marks: %v %v", recs[0], recs[1])
	}
	tot, _ := recs[1]["totals_ms"].(map[string]any)
	if tot["load.prog.trace_proc.verify"] != 700.0 || tot["probe.hook.detach"] != 100.0 {
		t.Errorf("totals_ms %v", tot)
	}
	if recs[1]["maxrss_kb"] != 51200.0 || recs[1]["stacks"] == nil || recs[1]["counts"] == nil {
		t.Errorf("record %v", recs[1])
	}
	sum := perfRecords(t, out.String(), "cold-attributed")
	if len(sum) != modes || sum[0]["mode"] != m || sum[0]["min_ms"] != 2.0 || sum[0]["cost_ms"] != -99.0 {
		t.Fatalf("cold-attributed records %v\n%s", sum, out)
	}
	for _, c := range perfRecords(t, out.String(), "cold") {
		ph, _ := c["phases_ms"].(map[string]any)
		for name := range ph {
			if fineGrained(name) {
				t.Errorf("cold record carries the attribution phase %s", name)
			}
		}
		if ph["probe.d7"] == nil || ph["load.obj.trace_proc.new"] == nil {
			t.Errorf("cold record lost a coarse phase: %v", ph)
		}
	}
}

// TestColdWithoutAttributionLaunchesAsBefore: -cold-attribution=false launches cold samples with no
// TEGO_TEST_LOAD_STATS and prints no attribution record (the overhead comparison of enforce-plane §10.1).
func TestColdWithoutAttributionLaunchesAsBefore(t *testing.T) {
	s, out := samplingSuite(t)
	s.oneRun = func(sp spec) (*run, error) {
		if len(sp.env) != 0 {
			t.Errorf("env %q without the attribution", sp.env)
		}
		return goodSample(), nil
	}
	s.cold()
	if recs := perfRecords(t, out.String(), "cold-attribution"); len(recs) != 0 {
		t.Fatalf("attribution records with the attribution off: %v", recs)
	}
}

// TestColdSettleAddsSettledSamplesNotBudgets: -cold-settle takes, after the immediate samples, as many samples again
// that each wait after gc until no function that had a trampoline before it is still traced. They are reported as
// cold-settled, with how long the kernel took and how many trampolines it tore down, and never replace or enter a
// budget: cold.<mode>.ms is still the immediate minimum.
func TestColdSettleAddsSettledSamplesNotBudgets(t *testing.T) {
	s, out := samplingSuite(t)
	s.settle, s.bootFirst = true, true
	s.modes = s.modes[:2] // landlock and one BPF mode
	booted, afterGC, settled, polls := false, false, false, 0
	s.clearBuilds = func() error { afterGC, polls = true, 0; return nil }
	s.tracedFuncs = func() (map[string]bool, error) {
		if !booted {
			return map[string]bool{"__hid_bpf_tail_call": true}, nil // the kernel's own, before any build
		}
		if !afterGC {
			return map[string]bool{"security_file_open": true, "bpf_lsm_file_open": true, "__hid_bpf_tail_call": true}, nil
		}
		polls++
		if polls < 3 {
			return map[string]bool{"security_file_open": true, "bpf_lsm_file_open": true, "other": true,
				"__hid_bpf_tail_call": true}, nil
		}
		settled = true
		return map[string]bool{"other": true, "__hid_bpf_tail_call": true}, nil // not the removed builds'
	}
	s.oneRun = func(sp spec) (*run, error) {
		booted, afterGC = true, false // the run makes a build, and its trampolines, again
		r := goodSample()
		if settled {
			r.up = 5 * time.Millisecond
		}
		return r, nil
	}
	s.cold()
	m := s.modes[1].Name
	if s.got["cold."+m+".ms"] != 10 {
		t.Errorf("cold.%s.ms = %v, want the immediate minimum 10", m, s.got["cold."+m+".ms"])
	}
	for k := range s.got {
		if strings.Contains(k, "settled") {
			t.Errorf("a settled figure entered the budgets: %s", k)
		}
	}
	recs := perfRecords(t, out.String(), "cold-settled")
	if len(recs) != 1 || recs[0]["mode"] != m || recs[0]["min_ms"] != 5.0 {
		t.Fatalf("cold-settled records %v\n%s", recs, out)
	}
	if ws, _ := recs[0]["settle_ms"].([]any); len(ws) != 3 {
		t.Errorf("settle_ms %v, want one wait a sample", recs[0]["settle_ms"])
	}
	if tr, _ := recs[0]["trampolines"].([]any); len(tr) != 3 || tr[0] != 2.0 {
		t.Errorf("trampolines %v, want the 2 traced before each gc", recs[0]["trampolines"])
	}
}

// TestColdSettleTimeoutIsNotASettledSample: a trampoline that outlives the settle bound makes no settled sample; the
// record says the wait timed out and names the functions still traced, the mode's settled samples end there (each
// later wait would wait on the same functions), and the budgets are untouched. A kernel that listed no trampoline before gc has
// nothing to settle on, which is said, never taken for a settled kernel.
func TestColdSettleTimeoutIsNotASettledSample(t *testing.T) {
	s, out := samplingSuite(t)
	s.settle, s.bootFirst = true, true
	s.modes = s.modes[:2]
	s.settleBound = 30 * time.Millisecond
	booted := false
	s.oneRun = func(spec) (*run, error) { booted = true; return goodSample(), nil }
	s.tracedFuncs = func() (map[string]bool, error) {
		if !booted {
			return map[string]bool{}, nil
		}
		return map[string]bool{"security_file_open": true}, nil
	}
	s.cold()
	if recs := perfRecords(t, out.String(), "cold-settled"); len(recs) != 0 {
		t.Fatalf("a sample whose trampolines never went counted as settled: %v", recs)
	}
	recs := perfRecords(t, out.String(), "cold-settle-timeout")
	if len(recs) != 1 {
		t.Fatalf("%d cold-settle-timeout records, want 1 (the mode's settling ends at the first):\n%s", len(recs), out)
	}
	if left, _ := recs[0]["still_traced"].([]any); len(left) != 1 || left[0] != "security_file_open" {
		t.Errorf("still_traced %v", recs[0]["still_traced"])
	}
	if s.failed {
		t.Fatal("a diagnostic's timeout failed the suite's budgets")
	}

	s, out = samplingSuite(t)
	s.settle, s.bootFirst = true, true
	s.modes = s.modes[:2]
	s.tracedFuncs = func() (map[string]bool, error) { return map[string]bool{"__hid_bpf_tail_call": true}, nil }
	s.cold()
	if recs := perfRecords(t, out.String(), "cold-settled"); len(recs) != 0 {
		t.Fatalf("a kernel with no trampoline to wait for made settled samples: %v", recs)
	}
	if recs := perfRecords(t, out.String(), "cold-settle-fail"); len(recs) != 3 {
		t.Fatalf("no cold-settle-fail record:\n%s", out)
	}
}

// TestEnabledFunctionsNamesEachLinesFunction: ftrace's enabled_functions, as 6.17 prints a BPF trampoline's entry on
// one line and 6.8 the direct call's trampoline on a line of its own.
func TestEnabledFunctionsNamesEachLinesFunction(t *testing.T) {
	t.Parallel()
	got := parseEnabledFunctions("security_file_open (1) R   D   M \tdirect-->bpf_trampoline_6442451234+0x0/0x1000\n" +
		"bpf_lsm_file_open (1) R   D   M \tdirect-->bpf_trampoline_6442455678+0x0/0x1000\n\n" +
		"__hid_bpf_tail_call (1) R   D   M\n\tdirect-->bpf_trampoline_6442510829+0x0/0xf1\n")
	want := map[string]bool{"security_file_open": true, "bpf_lsm_file_open": true, "__hid_bpf_tail_call": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("functions %v", got)
	}
}

// TestSettleNeedsColdFirst: -cold-settle's baseline is read before the boot's first run, so it is refused when another
// check runs first.
func TestSettleNeedsColdFirst(t *testing.T) {
	t.Parallel()
	if validateSettle("start,cold", true) == nil {
		t.Fatal("-cold-settle accepted with start before cold")
	}
	if validateSettle("cold,start", true) != nil || validateSettle("start,cold", false) != nil {
		t.Fatal("a valid combination refused")
	}
}

// TestPressureDeltaReadsTheSomeLine: the CPU pressure a sample ran under is the growth of /proc/pressure/cpu's "some"
// total over it.
func TestPressureDeltaReadsTheSomeLine(t *testing.T) {
	t.Parallel()
	us, avg, ok := parsePSI("some avg10=1.50 avg60=0.20 avg300=0.00 total=123456\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	if !ok || us != 123456 || avg != 1.5 {
		t.Fatalf("parsePSI = %v %v %v", us, avg, ok)
	}
	if _, _, ok := parsePSI(""); ok {
		t.Fatal("an empty pressure file parsed")
	}
}

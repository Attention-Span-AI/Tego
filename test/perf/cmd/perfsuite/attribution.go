// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/test/perf"
)

// The cold start's attribution (docs/p0/enforce-plane.md §10.1 "Cold attribution", perf-cold C1): under
// -cold-attribution (the default) every cold sample prints a "cold-attribution" record of its own, and each budgeted
// sample is followed, after its own gc, by one launched with TEGO_TEST_LOAD_STATS beside TEGO_TEST_PHASE_TIMING, so
// the test build prints, beside its phases, each loaded program's span and verifier statistics and the kernel stacks
// of a slow load. Every timed launch prints D7's hooks' load, attach and detach and the plane probe's modes' steps.
// The budgeted samples launch as they did before the attribution existed (A-PERF-5: the measurement method is
// unchanged), so cold.<mode>.ms and cold.bootfirst.ms never carry the attribution's cost; the attributed samples are
// summed up per mode in a "cold-attributed" record with that cost, best against best. -cold-attribution=false takes
// the budgeted samples alone. -cold-settle adds, per mode, as many samples again (attributed under
// -cold-attribution) that each wait after gc until every function the removed builds' trampolines had is untraced
// ("cold-settled"): the difference to the attributed immediate samples is the kernel teardown a cold run inherits
// (gate G-H2). Neither is a budget.

var (
	statRE  = regexp.MustCompile(`^tego-stat (\S+) (-?\d+)`)
	stackRE = regexp.MustCompile(`^tego-phase-stack (\S+ \d+ \S+)`)
)

// envLoadStats is what an attributed cold sample adds to the launch's environment (startphase.EnvTestLoadStats).
const envLoadStats = "TEGO_TEST_LOAD_STATS=1"

// defaultSettleBound is how long a settled sample waits for the removed builds' links to go.
const defaultSettleBound = 60 * time.Second

// fineGrained says whether a phase is the attribution's (one program, one hook, one plane-probe program) rather than a
// coarse phase the cold record's medians keep.
func fineGrained(name string) bool {
	for _, p := range []string{"load.prog.", "plane.prog.", "probe.hook.", "probe.plane.prog."} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// totalKey names the sum a fine-grained name belongs to: its item (a program, a hook, a plane-probe mode) dropped,
// its group and leaf kept. load.prog.<obj>.<prog>.<leaf> sums to load.prog.<obj>.<leaf>, plane.prog.<mode>.<prog>.<leaf>
// to plane.prog.<mode>.<leaf>, probe.plane.prog.<mode>.<prog>.<leaf> to probe.plane.prog.<mode>.<leaf>,
// probe.hook.<hook>.<leaf> to probe.hook.<leaf>, and probe.plane.<mode>.<step> to probe.plane.<step>. A name of any
// other shape has no sum.
func totalKey(name string) (string, bool) {
	parts := strings.Split(name, ".")
	switch {
	case len(parts) == 5 && (parts[0] == "load" || parts[0] == "plane") && parts[1] == "prog":
		return strings.Join([]string{parts[0], parts[1], parts[2], parts[4]}, "."), true
	case len(parts) == 6 && parts[0] == "probe" && parts[1] == "plane" && parts[2] == "prog":
		return strings.Join([]string{"probe.plane.prog", parts[3], parts[5]}, "."), true
	case len(parts) == 4 && parts[0] == "probe" && parts[1] == "hook":
		return "probe.hook." + parts[3], true
	case len(parts) == 4 && parts[0] == "probe" && parts[1] == "plane" && parts[2] != "prog":
		return "probe.plane." + parts[3], true
	}
	return "", false
}

// attributionTotals sums a sample's fine-grained phases by totalKey (milliseconds, to a tenth).
func attributionTotals(ph map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for n, v := range ph {
		if k, ok := totalKey(n); ok {
			out[k] += v
		}
	}
	for k, v := range out {
		out[k] = round1(v)
	}
	return out
}

// countTotals sums a sample's counts (instructions processed, states) by totalKey.
func countTotals(st map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for n, v := range st {
		if k, ok := totalKey(n); ok {
			out[k] += v
		}
	}
	return out
}

// parsePSI reads /proc/pressure/cpu: the "some" line's total (microseconds some task waited for a CPU since boot)
// and its avg10.
func parsePSI(s string) (totalUS int64, avg10 float64, ok bool) {
	for _, line := range strings.Split(s, "\n") {
		rest, found := strings.CutPrefix(line, "some ")
		if !found {
			continue
		}
		var gotTotal, gotAvg bool
		for _, f := range strings.Fields(rest) {
			k, v, _ := strings.Cut(f, "=")
			switch k {
			case "total":
				n, err := strconv.ParseInt(v, 10, 64)
				totalUS, gotTotal = n, err == nil
			case "avg10":
				a, err := strconv.ParseFloat(v, 64)
				avg10, gotAvg = a, err == nil
			}
		}
		return totalUS, avg10, gotTotal && gotAvg
	}
	return 0, 0, false
}

// cpuPressure reads the guest's CPU pressure, or reports none (a kernel without PSI, or psi=0).
func (s *suite) cpuPressure() (int64, float64, bool) {
	if s.pressure != nil {
		return s.pressure()
	}
	b, err := os.ReadFile("/proc/pressure/cpu")
	if err != nil {
		return 0, 0, false
	}
	return parsePSI(string(b))
}

// coldSpec is a cold sample's launch; loadStats adds TEGO_TEST_LOAD_STATS to it.
func coldSpec(m perf.Mode, loadStats bool) spec {
	sp := spec{mode: m, tag: "cold-" + m.Name, args: []string{"-n", "1", "-reps", "1", "-up", "notes.txt"}}
	if loadStats {
		sp.env = []string{envLoadStats}
	}
	return sp
}

// coldSample launches one cold sample, with the verifier's statistics when loadStats, and, under -cold-attribution,
// prints its cold-attribution record: its phases (D7's hooks' and the plane probe's modes' steps among them, which
// every timed launch prints) and, when loadStats, its counts and stacks.
func (s *suite) coldSample(m perf.Mode, k int, bootFirst, settled, loadStats bool, extra map[string]any) (*run, error) {
	p0, _, okBefore := s.cpuPressure()
	r, err := s.one(coldSpec(m, loadStats))
	p1, avg10, okAfter := s.cpuPressure()
	if err != nil || r == nil || !s.attribution {
		return r, err
	}
	rec := map[string]any{"mode": m.Name, "sample": k, "boot_first": bootFirst, "settled": settled,
		"load_stats": loadStats, "up_ms": round1(ms(r.up)), "rc": r.rc, "phases_ms": roundMap(r.phases), "totals_ms": attributionTotals(r.phases),
		"counts": r.stats, "count_totals": countTotals(r.stats), "stacks": r.stacks, "maxrss_kb": r.maxrssKB}
	if okBefore && okAfter {
		rec["cpu_some_us"] = p1 - p0
		rec["cpu_some_avg10"] = avg10
	}
	maps.Copy(rec, extra)
	s.emit("cold-attribution", rec)
	return r, nil
}

// attributedSample takes the attributed sample that follows budgeted sample k of mode m: after its own gc --builds,
// launched with the verifier's statistics. Its start time is reported, never budgeted; a launch that fails fails the
// suite as a budgeted one does.
func (s *suite) attributedSample(m perf.Mode, k int) (float64, bool) {
	if err := s.gcBuilds(); err != nil {
		s.fail("cold-fail", map[string]any{"mode": m.Name, "err": err.Error(), "operation": "gc --builds",
			"load_stats": true})
		return 0, false
	}
	r, err := s.coldSample(m, k, false, false, true, nil)
	if err = sampleError(r, err, "open_0"); err != nil {
		s.fail("cold-fail", map[string]any{"mode": m.Name, "err": fmt.Sprint(err), "tail": tailOf(r), "load_stats": true})
		return 0, false
	}
	return ms(r.up), true
}

// attributedSummary prints mode m's attributed samples (cold-attributed) beside its budgeted ones: what the
// attribution cost is their best less the budgeted best, taken in the same guest, interleaved.
func (s *suite) attributedSummary(m perf.Mode, attrUps, ups []float64) {
	if len(attrUps) == 0 {
		return
	}
	rec := map[string]any{"mode": m.Name, "up_ms": roundAll(attrUps), "min_ms": round1(perf.Min(attrUps)),
		"median_ms": round1(perf.Median(attrUps))}
	if len(ups) > 0 {
		rec["cost_ms"] = round1(perf.Min(attrUps) - perf.Min(ups))
	}
	s.emit("cold-attributed", rec)
}

func roundMap(m map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(m))
	for k, v := range m {
		out[k] = round1(v)
	}
	return out
}

// enabledFunctionsPath is ftrace's list of the kernel functions something is attached to. Every fexit, fmod_ret and
// LSM program reaches its function through a BPF trampoline, an ftrace direct call. The kernel may hold some of its
// own from boot (6.8's HID-BPF attaches __hid_bpf_tail_call), so the builds' trampolines are the list less what it
// held before the boot's first run (baseTraced).
const enabledFunctionsPath = "/sys/kernel/tracing/enabled_functions"

// tracedFunctions reads enabledFunctionsPath: the functions it names.
func tracedFunctions() (map[string]bool, error) {
	b, err := os.ReadFile(enabledFunctionsPath)
	if err != nil {
		return nil, err
	}
	return parseEnabledFunctions(string(b)), nil
}

// parseEnabledFunctions names the function each line of enabled_functions starts with. A line that starts with
// white space continues the entry above it (6.8 prints a direct call's trampoline on a line of its own).
func parseEnabledFunctions(s string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if f := strings.Fields(line); len(f) > 0 {
			out[f[0]] = true
		}
	}
	return out
}

// validateSettle refuses -cold-settle unless cold is the first check: its baseline, what the kernel traces on its
// own, is read before the boot's first run, when no build exists.
func validateSettle(checks string, settle bool) error {
	if settle && !strings.HasPrefix(checks, "cold") {
		return errors.New("-cold-settle needs cold as the first check: its baseline is what the kernel traced before any build")
	}
	return nil
}

// baseTraced reads what the kernel traces before the boot's first run: functions a settled sample never waits for.
func (s *suite) baseTraced() {
	traced := s.tracedFuncs
	if traced == nil {
		traced = tracedFunctions
	}
	s.traceBase, s.traceBaseErr = traced()
}

// settleAfterGC runs gc --builds and then waits until no function that had a trampoline before it is still traced,
// reporting how many there were and how long the last one took to go from gc's return, and false, with the functions
// still traced, when one outlived the bound. A trampoline leaves the list when its last program's link is released (bpf_trampoline_unlink_prog,
// under the trampoline's mutex, which the next load of a program on that function waits for), so this is the
// teardown a cold run's load can inherit. A link's ID is no such signal: the kernel frees it before it releases the
// link (bpf_link_free), so the IDs are gone as soon as gc returns (measured 2026-10-19, enforce-plane §10.1). The
// suite's usual pause after gc follows, as for an immediate sample.
func (s *suite) settleAfterGC() (held int, left []string, waited time.Duration, ok bool, err error) {
	traced := s.tracedFuncs
	if traced == nil {
		traced = tracedFunctions
	}
	bound := s.settleBound
	if bound <= 0 {
		bound = defaultSettleBound
	}
	if s.traceBase == nil && s.traceBaseErr == nil {
		return 0, nil, 0, false, errors.New("no baseline of traced functions: the boot's first run came before it")
	}
	if s.traceBaseErr != nil {
		return 0, nil, 0, false, fmt.Errorf("baseline of traced functions: %w", s.traceBaseErr)
	}
	before, err := traced()
	if err != nil {
		return 0, nil, 0, false, err
	}
	for fn := range s.traceBase {
		delete(before, fn)
	}
	if len(before) == 0 {
		return 0, nil, 0, false, errors.New("no trampoline before gc: nothing to settle on")
	}
	if err := s.gcOnly(); err != nil {
		return len(before), nil, 0, false, err
	}
	t0 := time.Now()
	for {
		now, err := traced()
		if err != nil {
			return len(before), nil, 0, false, err
		}
		left = left[:0]
		for fn := range before {
			if now[fn] {
				left = append(left, fn)
			}
		}
		if len(left) == 0 {
			waited := time.Since(t0)
			s.pauseAfterGC()
			return len(before), nil, waited, true, nil
		}
		if time.Since(t0) > bound {
			sort.Strings(left)
			return len(before), left, time.Since(t0), false, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// settled takes -cold-runs samples of mode m that each start on a settled kernel, and reports them as cold-settled.
func (s *suite) settled(m perf.Mode) {
	var ups, waits []float64
	var trampolines []int
	for k := 0; k < *coldN; k++ {
		held, left, waited, ok, err := s.settleAfterGC()
		if err != nil {
			s.emit("cold-settle-fail", map[string]any{"mode": m.Name, "err": err.Error()})
			continue
		}
		if !ok {
			// The kernel keeps these functions traced past gc and the bound: every later wait would wait on them
			// too, so this mode's settled samples end here, the functions named.
			s.emit("cold-settle-timeout", map[string]any{"mode": m.Name, "trampolines": held, "waited_ms": round1(ms(waited)),
				"still_traced": left})
			break
		}
		r, err := s.coldSample(m, k, false, true, s.attribution, map[string]any{"settle_ms": round1(ms(waited)),
			"trampolines": held})
		if err = sampleError(r, err, "open_0"); err != nil {
			s.emit("cold-settle-fail", map[string]any{"mode": m.Name, "err": err.Error(), "tail": tailOf(r)})
			continue
		}
		ups = append(ups, ms(r.up))
		waits = append(waits, ms(waited))
		trampolines = append(trampolines, held)
	}
	if len(ups) == 0 {
		return
	}
	s.emit("cold-settled", map[string]any{"mode": m.Name, "up_ms": roundAll(ups), "min_ms": round1(perf.Min(ups)),
		"settle_ms": roundAll(waits), "trampolines": trampolines})
}

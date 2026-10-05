// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/test/perf"
)

// TestEveryBudgetBelongsToACheck: a budget no check records would be MISSING on every run, and a check name the
// switch does not know would never be judged.
func TestEveryBudgetBelongsToACheck(t *testing.T) {
	t.Parallel()
	known := map[string]bool{"cold": true, "start": true, "fill": true, "open": true, "name": true, "socket": true, "exec": true, "conc": true}
	for _, b := range perf.Defaults() {
		if c := checkOf(b.Name); !known[c] {
			t.Errorf("budget %s maps to check %q", b.Name, c)
		}
	}
}

func TestContractNamesTheRowsAndTheRecordLevel(t *testing.T) {
	t.Parallel()
	s := &suite{}
	got := s.contract(spec{tag: "x", rows: 2, record: "off", args: []string{"-n", "1", "notes.txt"}})
	for _, want := range []string{`command: ["./openbench", "-n", "1", "notes.txt"]`, `"./data2/g00000"`, `"./data2/g00001"`, "record: off"} {
		if !strings.Contains(got, want) {
			t.Errorf("contract lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "g00002") {
		t.Errorf("contract holds a third row:\n%s", got)
	}
}

func TestReaderTakesPhasesAndResults(t *testing.T) {
	t.Parallel()
	if m := phaseRE.FindStringSubmatch("tego-phase prepare.fill 1500"); m == nil || m[1] != "prepare.fill" || m[2] != "1500" {
		t.Fatalf("phase line: %v", m)
	}
	if m := resRE.FindStringSubmatch("RESULT open_0 2793"); m == nil || m[1] != "open_0" {
		t.Fatalf("result line: %v", m)
	}
}

func samplingSuite(t *testing.T) (*suite, *bytes.Buffer) {
	t.Helper()
	out := new(bytes.Buffer)
	s := &suite{uid: os.Getuid(), gid: os.Getgid(), got: map[string]float64{}, modes: perf.Modes, output: out, proj: t.TempDir()}
	// Production setup creates out/ before the gated concurrent runs.
	if err := os.MkdirAll(filepath.Join(s.proj, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.clearBuilds = func() error { return nil }
	s.oneRun = func(spec) (*run, error) { return goodSample(), nil }
	return s, out
}

func goodSample() *run {
	return &run{up: 10 * time.Millisecond, wall: 20 * time.Millisecond, res: map[string]float64{"up": 1, "open_0": 1000, "open_1": 1100, "open_2": 1200, "socket_0": 900, "setsockopt_0": 400, "exec_p50": 300000, "exec_p99": 900000, "exec_failed": 0, "open_3": 1300, "open_4": 1400, "open_5": 1500, "rename_0": 3000}, phases: map[string]float64{"load.plane": 1, "prepare.fill": 1, "prepare": 2}, rc: 0}
}

func budgetsFor(check string, modes []perf.Mode) []perf.Budget {
	var out []perf.Budget
	for _, b := range perf.ForModes(perf.Defaults(), modes) {
		if checkOf(b.Name) == check {
			out = append(out, b)
		}
	}
	return out
}

func TestRequiredSamplingFailureCannotPassCompleteBudgets(t *testing.T) {
	cases := []struct {
		name string
		bad  func(*run) (*run, error)
	}{
		{"exit125", func(r *run) (*run, error) { r.rc = 125; return r, nil }},
		{"launch_error", func(*run) (*run, error) { return nil, errors.New("owned fixture launch failed") }},
		{"missing_ready", func(r *run) (*run, error) { r.up = 0; return r, nil }},
		{"missing_benchmark", func(r *run) (*run, error) { delete(r.res, "open_0"); return r, nil }},
		{"invalid_benchmark", func(r *run) (*run, error) { r.res["open_0"] = math.NaN(); return r, nil }},
		{"invalid_ready", func(r *run) (*run, error) { r.res["up"] = math.Inf(1); return r, nil }},
	}
	for _, kind := range []string{"cold", "start"} {
		for _, tc := range cases {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				s, out := samplingSuite(t)
				s.bootFirst = true
				measured := 0
				calls := 0
				s.oneRun = func(sp spec) (*run, error) {
					calls++
					r := goodSample()
					if strings.HasPrefix(sp.tag, kind+"-") {
						measured++
						if measured == 2 {
							return tc.bad(r)
						}
					}
					return r, nil
				}
				if kind == "cold" {
					s.cold()
				} else {
					s.start()
				}
				wantCalls := len(perf.Modes[1:]) * *coldN
				if kind == "start" {
					wantCalls = len(perf.Modes) * (*startN + 1)
				}
				if calls != wantCalls {
					t.Fatalf("actual loop calls=%d want=%d", calls, wantCalls)
				}
				bs := budgetsFor(kind, s.modes)
				text, budgetFail := perf.Report(perf.Evaluate(bs, s.got))
				if budgetFail {
					t.Fatalf("regression must retain every original passing metric:\n%s", text)
				}
				if !s.report(bs) || !strings.Contains(out.String(), "PERF-RESULT FAIL") {
					t.Fatalf("failed required sample falsely passed despite complete budgets:\n%s", out.String())
				}
			})
		}
	}
}

func TestFailedCacheClearCannotCertifyColdSample(t *testing.T) {
	s, out := samplingSuite(t)
	s.bootFirst = true
	n := 0
	s.clearBuilds = func() error {
		n++
		if n == 1 {
			return errors.New("owned fixture cache clear failed")
		}
		return nil
	}
	s.cold()
	bs := budgetsFor("cold", s.modes)
	if _, failed := perf.Report(perf.Evaluate(bs, s.got)); failed {
		t.Fatal("remaining samples must retain complete metrics")
	}
	if !s.report(bs) {
		t.Fatalf("cache-clear failure was ignored:\n%s", out.String())
	}
}

func TestCompleteSamplingKeepsOriginalMinima(t *testing.T) {
	for _, kind := range []string{"cold", "start"} {
		t.Run(kind, func(t *testing.T) {
			s, out := samplingSuite(t)
			s.bootFirst = true
			seen := map[string]int{}
			samples := map[string][]float64{}
			s.oneRun = func(sp spec) (*run, error) {
				r := goodSample()
				if strings.HasPrefix(sp.tag, kind+"-") {
					n := 3
					if kind == "start" {
						n = 8
					}
					seen[sp.mode.Name]++
					r.up = time.Duration((n-seen[sp.mode.Name]+1)*10) * time.Millisecond
					samples[sp.mode.Name] = append(samples[sp.mode.Name], ms(r.up))
				}
				return r, nil
			}
			if kind == "cold" {
				s.cold()
			} else {
				s.start()
			}
			for mode, xs := range samples {
				want := 3
				key := "cold." + mode + ".ms"
				if kind == "start" {
					want = 8
					key = "start.warm." + mode + ".min_ms"
				}
				if len(xs) != want || s.got[key] != 10 {
					t.Fatalf("%s samples/min changed: %v %v", mode, xs, s.got[key])
				}
			}
			if kind == "cold" && s.got["cold.bootfirst.ms"] != 30 {
				t.Fatal("boot-first estimator changed")
			}
			if kind == "start" && s.got["start.warm.bpflsm.excess_ms"] != 0 {
				t.Fatal("warm excess estimator changed")
			}
			if s.report(budgetsFor(kind, s.modes)) || !strings.Contains(out.String(), "PERF-RESULT PASS") {
				t.Fatalf("complete source sampling failed:\n%s", out.String())
			}
		})
	}
}

func TestOpenFailureAndMissingResultsCannotPass(t *testing.T) {
	for _, failure := range []string{"complete", "exit", "missing", "prime"} {
		t.Run(failure, func(t *testing.T) {
			s, out := samplingSuite(t)
			calls := 0
			s.oneRun = func(sp spec) (*run, error) {
				r := goodSample()
				if strings.HasPrefix(sp.tag, "open-") && sp.tag != "open-prime" {
					calls++
					if calls == 2 {
						switch failure {
						case "exit":
							r.rc = 125
						case "missing":
							delete(r.res, "open_2")
						}
					}
				}
				if failure == "prime" && sp.tag == "open-prime" && sp.mode.Name == "landlock" {
					r.rc = 125
				}
				return r, nil
			}
			s.open()
			if calls != 2**rounds*len(s.modes) {
				t.Fatalf("required actual open calls=%d", calls)
			}
			bs := budgetsFor("open", s.modes)
			if _, bad := perf.Report(perf.Evaluate(bs, s.got)); bad {
				t.Fatal("healthy rounds must keep complete passing budgets")
			}
			wantFail := failure != "complete"
			if gotFail := s.report(bs); gotFail != wantFail {
				t.Fatalf("required open sample verdict=%v want=%v: %s", gotFail, wantFail, out)
			}
		})
	}
}

func TestRequiredFillHealthAndExpectedCapacitySearch(t *testing.T) {
	for _, failure := range []string{"complete", "one_row", "prime", "missing_phase", "unexpected_cap_failure", "partial_cap_failure", "capacity_timeout", "capacity_signal", "expected_fallback"} {
		t.Run(failure, func(t *testing.T) {
			s, out := samplingSuite(t)
			samples := map[int]int{}
			s.oneRun = func(sp spec) (*run, error) {
				r := goodSample()
				samples[sp.rows]++
				if failure == "prime" && sp.tag == "fill-prime" {
					r.rc = 125
				}
				if failure == "one_row" && sp.rows == 1 && samples[1] == 1 {
					r.rc = 125
				}
				if failure == "missing_phase" && sp.rows == 1000 {
					delete(r.phases, "prepare.fill")
				}
				if sp.rows > 4089 {
					if failure == "unexpected_cap_failure" && sp.rows == 4095 {
						return nil, errors.New("owned fixture transport failure")
					}
					if failure == "partial_cap_failure" && sp.rows == 4095 && samples[4095] == 1 {
						return r, nil
					}
					if failure == "expected_fallback" {
						delete(r.phases, "load.plane")
						return r, nil
					}
					r.rc = 125
					if sp.rows == 4095 {
						switch failure {
						case "capacity_timeout":
							r.rc = -999
						case "capacity_signal":
							r.rc = -1
						}
					}
					r.up = 0
					r.lines = []string{"runtime: the decision plane keys 4102 inodes (at most 4096 a run)"}
				}
				return r, nil
			}
			s.fill()
			failed := s.report(budgetsFor("fill", s.modes))
			want := failure != "complete" && failure != "expected_fallback"
			if failed != want {
				t.Fatalf("final fill failure=%v want%v:\n%s", failed, want, out)
			}
			if !want {
				if s.got["fill.rows1000.ms"] != 1 || s.got["fill.rowscap.ms"] != 1 || strings.Count(out.String(), `"kind":"fill-refused"`) != 6 {
					t.Fatalf("expected cap-search metrics/diagnostics changed:\n%s", out)
				}
			}
		})
	}
}

func TestEveryConcurrentModeRequiresCompleteReadyBenchmarkSamples(t *testing.T) {
	for _, failure := range []string{"complete", "exit", "missing_ready", "missing_result", "launch_error", "prime"} {
		t.Run(failure, func(t *testing.T) {
			s, out := samplingSuite(t)
			s.counts = []int{2}
			launches := 0
			s.launchRun = func(sp spec) (*run, error) {
				launches++
				r := goodSample()
				r.upCh = make(chan struct{})
				close(r.upCh)
				r.done = make(chan struct{})
				close(r.done)
				if sp.mode.Name == "cgroup-lsm" && launches == 3 {
					switch failure {
					case "exit":
						r.rc = 125
					case "missing_ready":
						r.up = 0
					case "missing_result":
						delete(r.res, "open_0")
					case "launch_error":
						return nil, errors.New("owned fixture launch failed")
					}
				}
				return r, nil
			}
			if failure == "prime" {
				s.oneRun = func(sp spec) (*run, error) {
					r := goodSample()
					if sp.mode.Name == "cgroup-lsm" {
						r.rc = 125
					}
					return r, nil
				}
			}
			s.conc()
			bs := budgetsFor("conc", s.modes)
			var selected []perf.Budget
			for _, b := range bs {
				if strings.Contains(b.Name, ".n2.") {
					selected = append(selected, b)
				}
			}
			if _, bad := perf.Report(perf.Evaluate(selected, s.got)); bad {
				t.Fatal("bpflsm metrics must remain complete despite failed non-bpflsm mode")
			}
			if got := s.report(selected); got != (failure != "complete") {
				t.Fatalf("required concurrency failure=%v for %s:\n%s", got, failure, out)
			}
		})
	}
}

func TestSampleRequestsValidatedBeforeWork(t *testing.T) {
	for _, tc := range []struct {
		cold, warm, rounds, opens int
		conc                      string
	}{{0, 8, 9, 200000, "2,8,32"}, {3, 0, 9, 200000, "2,8,32"}, {3, 8, 0, 200000, "2,8,32"}, {3, 8, 9, 0, "2,8,32"}, {3, 8, 9, 200000, "0"}, {3, 8, 9, 200000, "2,bad"}, {3, 8, 9, 200000, "2,2"}, {3, 8, 9, 200000, ""}} {
		if _, err := validateSampleCounts(tc.cold, tc.warm, tc.rounds, tc.opens, tc.conc); err == nil {
			t.Fatalf("invalid requested counts accepted: %+v", tc)
		}
	}
	counts, err := validateSampleCounts(3, 8, 9, 200000, "2,8,32")
	if err != nil || len(counts) != 3 || counts[0] != 2 || counts[1] != 8 || counts[2] != 32 {
		t.Fatalf("original defaults changed: %v %v", counts, err)
	}
}

func TestCompleteAllRequestedChecksKeepOriginalVerdict(t *testing.T) {
	s, out := samplingSuite(t)
	s.bootFirst = true
	s.counts = []int{2, 8, 32}
	s.oneRun = func(sp spec) (*run, error) {
		r := goodSample()
		if sp.rows > 4089 {
			r.rc = 125
			r.up = 0
			r.lines = []string{"runtime: the decision plane keys 4102 inodes (at most 4096 a run)"}
		}
		return r, nil
	}
	s.launchRun = func(spec) (*run, error) {
		r := goodSample()
		r.upCh = make(chan struct{})
		close(r.upCh)
		r.done = make(chan struct{})
		close(r.done)
		return r, nil
	}
	s.cold()
	s.start()
	s.fill()
	s.open()
	s.nameCheck()
	s.socket()
	var calls uint64
	s.pinStats = func() (uint64, uint64, error) { calls++; return calls * 9000, calls * 100, nil }
	s.doctorRun = func() ([]byte, error) {
		return []byte("tego-phase probe.plane.lsm.exec_pin 21000\ntego-phase probe.plane.fmod_ret.exec_pin 18500\n"), nil
	}
	s.execCheck()
	s.conc()
	if s.report(perf.Defaults()) {
		t.Fatalf("complete requested suite failed: %s", out)
	}
	kinds := map[string]int{}
	for _, line := range strings.Split(out.String(), "\n") {
		if !strings.HasPrefix(line, "PERF ") {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line[5:]), &row); err != nil {
			t.Fatal(err)
		}
		kind := row["kind"].(string)
		kinds[kind]++
		switch kind {
		case "cold":
			if len(row["up_ms"].([]any)) != 3 {
				t.Fatal("cold count changed")
			}
		case "start":
			if len(row["up_ms"].([]any)) != 8 {
				t.Fatal("warm count changed")
			}
		case "fill":
			if row["samples"] != float64(3) {
				t.Fatalf("actual fill samples: %v", row)
			}
		case "open":
			if row["rounds"] != float64(9) {
				t.Fatal("open rounds changed")
			}
			samples, ok := row["samples"].(map[string]any)
			if !ok || len(samples) != 3*len(s.modes) {
				t.Fatalf("actual open sample inventory: %v", row)
			}
			for _, m := range s.modes {
				for _, path := range []string{"norow", "write", "deep"} {
					if samples[m.Name+"/"+path] != float64(9) {
						t.Fatalf("actual open sample count: %v", row)
					}
				}
			}
		case "conc":
			if row["ready_samples"] != row["n"] || row["benchmark_samples"] != row["n"] {
				t.Fatalf("actual concurrent sample counts: %v", row)
			}
		}
	}
	for kind, want := range map[string]int{"cold": 3, "start": 4, "fill": 3, "fill-refused": 6, "open": 2, "socket": 1, "exec": 1, "doctor-exec-pin": 1, "conc": 14, "name": 3, "name-fill": 1} {
		if kinds[kind] != want {
			t.Fatalf("%s rows=%d want%d", kind, kinds[kind], want)
		}
	}
	// 22 figures before the exec check, which adds four a plane mode and doctor's cell in each of two; the name check
	// adds six a plane mode and fill.name.
	if len(s.got) != 22+4*3+2+6*3+1 || s.got["open.name.refused.deep.bpflsm_ns"] != 100 || s.got["exec.norules.bpflsm.pin_check_ns"] != 90 || s.got["socket.excess.cgroup_ns"] != 0 || s.got["setsockopt.excess.cgroup_ns"] != 0 || s.got["cold.bootfirst.ms"] != 10 || s.got["start.warm.landlock.min_ms"] != 10 || s.got["fill.rows1000.ms"] != 1 || s.got["open.excess.bpflsm_ns"] != 0 {
		t.Fatalf("original complete metrics changed: %v", s.got)
	}
}

// TestSocketCheckIsTheFallbacksExcess: the socket check alternates landlock and tier cgroup on the fanotify fallback
// over -rounds rounds, both with a net: section, and records the best fallback loop less the best landlock loop as
// socket.excess.cgroup_ns: cgroup/sock_create's cost on an admitted socket (ADR 0018 PR 2), since the fallback attaches
// nothing else that runs when a socket is made; and the same of a setsockopt(TCP_NODELAY) loop as
// setsockopt.excess.cgroup_ns, cgroup/setsockopt's cost on an option it passes (ADR 0018 (7)). A missing sample of
// either fails the check, and no figure is recorded for the budget to pass on.
func TestSocketCheckIsTheFallbacksExcess(t *testing.T) {
	s, out := samplingSuite(t)
	var specs []spec
	s.oneRun = func(sp spec) (*run, error) {
		specs = append(specs, sp)
		r := goodSample()
		if sp.mode.Plane == "fanotify" {
			r.res["socket_0"] = 1150
			r.res["setsockopt_0"] = 470
		}
		return r, nil
	}
	s.socket()
	if c := checkOf("setsockopt.excess.cgroup_ns"); c != "socket" {
		t.Errorf("setsockopt.excess.cgroup_ns is judged by the %q check, want socket", c)
	}
	if s.failed || s.got["socket.excess.cgroup_ns"] != 250 || s.got["setsockopt.excess.cgroup_ns"] != 70 {
		t.Fatalf("socket check: failed %v, got %v\n%s", s.failed, s.got, out)
	}
	tiers := map[string]int{}
	for _, sp := range specs {
		if !slices.Contains(sp.args, "-socket") || !slices.Contains(sp.args, "-setsockopt") {
			t.Errorf("a socket run without -socket and -setsockopt: %v", sp.args)
		}
		tiers[sp.mode.Tier+"/"+sp.mode.Plane]++
	}
	if tiers["landlock/auto"] != *rounds+1 || tiers["cgroup/fanotify"] != *rounds+1 {
		t.Errorf("runs per mode: %v, want %d each (a prime and the rounds)", tiers, *rounds+1)
	}

	s, out = samplingSuite(t)
	s.oneRun = func(sp spec) (*run, error) {
		r := goodSample()
		if sp.mode.Plane == "fanotify" {
			delete(r.res, "socket_0")
		}
		return r, nil
	}
	s.socket()
	if !s.failed {
		t.Fatalf("a missing fallback sample did not fail the check:\n%s", out)
	}
	if _, ok := s.got["socket.excess.cgroup_ns"]; ok {
		t.Fatalf("a check missing its samples recorded %v", s.got)
	}

	s, out = samplingSuite(t)
	s.oneRun = func(sp spec) (*run, error) {
		r := goodSample()
		if sp.mode.Plane == "fanotify" {
			delete(r.res, "setsockopt_0")
		}
		return r, nil
	}
	s.socket()
	if !s.failed {
		t.Fatalf("a missing fallback setsockopt sample did not fail the check:\n%s", out)
	}
	if _, ok := s.got["setsockopt.excess.cgroup_ns"]; ok {
		t.Fatalf("a check missing its setsockopt samples recorded %v", s.got)
	}
}

func TestMissingFirstColdSampleStaysMissing(t *testing.T) {
	s, out := samplingSuite(t)
	s.bootFirst = true
	calls := 0
	s.oneRun = func(spec) (*run, error) {
		calls++
		r := goodSample()
		if calls == 1 {
			r.rc = 125
		}
		return r, nil
	}
	s.cold()
	if _, ok := s.got["cold.bootfirst.ms"]; ok {
		t.Fatal("later cold sample fabricated a boot-first measurement")
	}
	if !s.report(budgetsFor("cold", s.modes)) || !strings.Contains(out.String(), "BUDGET MISSING") {
		t.Fatalf("failed first sample accepted: %s", out)
	}
}

// fakeTego points -tego and -base at a shell script standing in for tego run and a scratch directory, for
// the tests that drive launch and wait on a real process. Not parallel: the flags are the package's.
func fakeTego(t *testing.T, script string) *suite {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "tego")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldBin, oldBase := *tegoBin, *base
	*tegoBin, *base = bin, filepath.Join(dir, "base")
	t.Cleanup(func() { *tegoBin, *base = oldBin, oldBase })
	return &suite{uid: os.Getuid(), gid: os.Getgid(), proj: t.TempDir()}
}

// TestWaitReturnsOnlyOnceTheOutputIsRead: a line still in the pipe when the process exits (a descendant holding
// its stdout writes it later) is in the run's results when wait returns. wait once returned 20 ms after the exit
// whatever the reader still had to read, and sampleError and fill then read r.res and r.phases unlocked while
// the reader wrote them: a sample judged on part of its output, or a concurrent map read and write.
func TestWaitReturnsOnlyOnceTheOutputIsRead(t *testing.T) {
	s := fakeTego(t, "echo 'RESULT up 1'\n(sleep 0.3; echo 'tego-phase prepare 2000'; echo 'RESULT open_0 7') &\nexit 0\n")
	r, err := s.launch(spec{tag: "late"})
	if err != nil {
		t.Fatal(err)
	}
	r.wait(30 * time.Second)
	if err := sampleError(r, nil, "open_0"); err != nil {
		t.Fatalf("wait returned before the output was read: %v (results %v)", err, r.res)
	}
	if r.phases["prepare"] != 2 {
		t.Fatalf("the late phase line is missing: %v", r.phases)
	}
}

// TestWaitDoesNotWaitForeverOnAHeldPipe: a descendant that keeps the output open and silent does not hold wait
// past readerGrace, and the reader has returned when wait does.
func TestWaitDoesNotWaitForeverOnAHeldPipe(t *testing.T) {
	old := readerGrace
	readerGrace = 200 * time.Millisecond
	t.Cleanup(func() { readerGrace = old })
	s := fakeTego(t, "echo 'RESULT up 1'\nsleep 5 &\nexit 0\n")
	r, err := s.launch(spec{tag: "held"})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	r.wait(30 * time.Second)
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("wait took %v on a pipe a descendant holds", d)
	}
	select {
	case <-r.readerDone:
	default:
		t.Fatal("wait returned before the reader did")
	}
	if r.res["up"] != 1 {
		t.Fatalf("the output read before the grace ran out is lost: %v", r.res)
	}
}

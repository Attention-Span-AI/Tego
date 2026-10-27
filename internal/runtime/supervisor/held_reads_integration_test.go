// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// BenchmarkHeldReadOpen is ADR 0069's cost on a real kernel, filter, loop and deputy at tier landlock: a read-open of
// an existing regular file in a run that holds its reads (fs.reads: held, no gate), against the same open notified
// and continued with no deputy (the copied path a record: full run takes), alternated round by round so box load
// cancels out. It reports the held p50 and p99 against supervisor R22's 200 µs soft ceiling, and 30,000 held opens
// across four workers; a p99 at or over the ceiling on an idle box prints TARGET-MISS with its number (on a loaded box
// it prints it and does not fail, as BenchmarkHeldOpen's idle-box terms do).
func BenchmarkHeldReadOpen(b *testing.B) {
	as, _ := heldAgent(b)
	at := heldBenchAt{as: as, reads: true}
	n := 2000
	if b.N > n {
		n = b.N
	}
	var held, direct benchRun
	var hp50s, hp99s, dp50s []time.Duration
	steal0, total0 := cpuTicks()
	for round := 0; round < heldBenchRounds; round++ {
		d := runHeldBench(b, at, false, n, false)
		h := runHeldBench(b, at, true, n, round == heldBenchRounds-1)
		hp50s, hp99s, dp50s = append(hp50s, h.p50), append(hp99s, h.p99), append(dp50s, d.p50)
		held, direct = h, d
	}
	slices.Sort(hp50s)
	slices.Sort(hp99s)
	slices.Sort(dp50s)
	held.p50, held.p99, direct.p50 = hp50s[len(hp50s)/2], hp99s[len(hp99s)/2], dp50s[len(dp50s)/2]
	idle, steal := idleBox(steal0, total0)
	b.ReportMetric(float64(held.p50.Nanoseconds()), "held-p50-ns")
	b.ReportMetric(float64(held.p99.Nanoseconds()), "held-p99-ns")
	b.ReportMetric(float64(direct.p50.Nanoseconds()), "continued-p50-ns")
	b.ReportMetric(held.mallocsPerOp, "held-allocs/op")
	b.ReportMetric(float64(held.parallel.Milliseconds()), "held-30k-ms")
	b.Logf("held read p50 %v p99 %v; notified and continued p50 %v; +%v per open; %.1f allocs/op; 30k in %v; load/cpu %.2f; steal %.1f%%",
		held.p50, held.p99, direct.p50, held.p50-direct.p50, held.mallocsPerOp, held.parallel, loadPerCPU(), 100*steal)
	if held.p99 >= 200*time.Microsecond {
		msg := fmt.Sprintf("TARGET-MISS: BenchmarkHeldReadOpen: held read p99 %v (R22's soft ceiling 200 µs; load/cpu %.2f, steal %.1f%%)",
			held.p99, loadPerCPU(), 100*steal)
		fmt.Println(msg)
		if idle {
			b.Error(msg)
		}
	}
}

// TestHeldReadsSixtyFourThreads: 64 threads of a run that holds its reads open regular files at once, and none is
// refused held-limit: the outstanding held opens are bounded by the loop's workers and standby, never by the
// agent's thread count (ADR 0069 D2, supervisor R21).
func TestHeldReadsSixtyFourThreads(t *testing.T) {
	as, _ := heldAgent(t)
	h := startHarnessWith(t, harnessOpts{as: as, loops: 10, mode: modeBenchHeld, filterGate: "r", deputy: true,
		env:     []string{helperHeldOps + "=parallel", helperHeldThreads + "=64"},
		prepare: func(dir string) { _ = os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644) },
		rules: func(rt *agent.RuleTable, _ string) {
			rt.Tier = backend.TierLandlock
			rt.Reads = agent.HeldReads{Mode: agent.ReadsHeld}
		}})
	h.stop(t)
	for _, c := range h.report.Checks {
		if (c.Name == "fails" || c.Name == "parallel_fails") && c.N != 0 {
			t.Fatalf("%s = %d: a held read was refused with 64 threads opening at once (%+v)", c.Name, c.N, h.report.Checks)
		}
	}
	if !slices.ContainsFunc(h.report.Checks, func(c checkResult) bool { return c.Name == "parallel" }) {
		t.Fatalf("no parallel part ran: %+v", h.report.Checks)
	}
	if n := h.loop.metrics.relayLimited.Load(); n != 0 {
		t.Fatalf("%d held opens refused held-limit", n)
	}
}

// modeHeldReadRace is ADR 0069's race: a target whose run holds its reads opens a benign file by a name a sibling
// thread races to the nested secret's (heldReadRaceChecks).
const modeHeldReadRace = "heldreadrace"

// heldReadRaceAttempts is how many opens each of heldReadRaceChecks' races makes.
const heldReadRaceAttempts = 10000

// heldReadRaceFixture is the race's directory: the nested secret .env, the benign a.txt, and lk, a symlink to a.txt.
func heldReadRaceFixture(t *testing.T) func(string) {
	return func(dir string) {
		for _, err := range []error{
			os.WriteFile(filepath.Join(dir, ".env"), []byte("TOKEN=s3cr3t"), 0o644),
			os.WriteFile(filepath.Join(dir, "a.txt"), []byte("benign"), 0o644),
			os.Symlink("a.txt", filepath.Join(dir, "lk")),
		} {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

// heldReadRaceRules makes the harness's table a run at tier landlock that holds its reads (fs.reads: held) with its
// .env a deny_read inside the write entry over the directory, which the Landlock ruleset leaves unenforced.
func heldReadRaceRules(rt *agent.RuleTable, dir string) {
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	rt.Tier = backend.TierLandlock
	for i := range rt.FS {
		if rt.FS[i].Resolved == "" {
			rt.FS[i].Resolved = rt.FS[i].Path
		}
	}
	env := filepath.Join(dir, ".env")
	rule := agent.FSRule{Path: env, Resolved: env, Raw: "./.env", Kind: agent.FSDenyRead, Unenforced: true}
	rt.FS = append(rt.FS, rule)
	rt.Reads = agent.HeldReads{Mode: agent.ReadsHeld, Nested: []agent.NestedRead{{Rule: rule.RuleName(), Path: env}}}
}

// heldReadRaceChecks races the name of each read-open between the benign a.txt and the nested .env twice: a sibling
// thread flips the path buffer the syscall reads, then a sibling swaps the symlink lk between the two. N is how many
// opens returned a descriptor of the secret's inode: a read of a deny_read target.
func heldReadRaceChecks() []checkResult {
	dir := os.Getenv(helperDir)
	if err := unix.Chdir(dir); err != nil {
		return []checkResult{{Name: "chdir", Err: err.Error()}}
	}
	var secret unix.Stat_t
	if err := unix.Stat(".env", &secret); err != nil {
		return []checkResult{{Name: "stat", Err: err.Error()}}
	}
	// race tallies heldReadRaceAttempts opens while flip runs on a sibling thread.
	race := func(name string, flip func(i int), open func() (int, error)) checkResult {
		var stop atomic.Bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; !stop.Load(); i++ {
				flip(i)
			}
		}()
		counts := map[string]int{}
		bypass := 0
		for range heldReadRaceAttempts {
			fd, err := open()
			if err != nil {
				counts[errName(err)]++
				continue
			}
			counts["ok"]++
			var st unix.Stat_t
			if unix.Fstat(fd, &st) == nil && st.Dev == secret.Dev && st.Ino == secret.Ino {
				bypass++
			}
			_ = unix.Close(fd)
		}
		stop.Store(true)
		<-done
		return checkResult{Name: name, N: bypass, Out: countsText(counts)}
	}
	buf := make([]uint64, 2)
	addr := uintptr(unsafe.Pointer(&buf[0]))
	states := []uint64{nameWord("a.txt"), nameWord(".env")}
	path := race("race_path", func(i int) { atomic.StoreUint64(&buf[0], states[i%2]) }, func() (int, error) {
		r, _, e := unix.Syscall6(unix.SYS_OPENAT, cwdArg, addr, uintptr(unix.O_RDONLY|unix.O_CLOEXEC), 0, 0, 0)
		if e != 0 {
			return -1, e
		}
		return int(r), nil
	})
	runtime.KeepAlive(buf)
	targets := []string{"a.txt", ".env"}
	link := race("race_link", func(i int) {
		if unix.Symlink(targets[i%2], "lk.tmp") == nil && unix.Rename("lk.tmp", "lk") != nil {
			_ = unix.Unlink("lk.tmp")
		}
	}, func() (int, error) { return unix.Open("lk", unix.O_RDONLY|unix.O_CLOEXEC, 0) })
	return []checkResult{path, link}
}

// TestHeldReadsRaceFree is ADR 0069's race test at tier landlock: 10,000 read-opens race a sibling that flips the
// path buffer between ./a.txt and the nested ./.env, and 10,000 more race a sibling that swaps a symlink between the
// two. Without a deputy (a run whose deputy fails never starts, so this is the pre-fix count) the opens the copied
// path lets through reach the secret; with it none does, since the floor's object is the descriptor delivered, and
// the benign file still opens.
func TestHeldReadsRaceFree(t *testing.T) {
	as, own := heldAgent(t)
	opts := func(deputy bool) harnessOpts {
		return harnessOpts{as: as, mode: modeHeldReadRace, prepare: ownedTree(t, own, heldReadRaceFixture(t)), filterGate: "r",
			deputy: deputy, rules: heldReadRaceRules, timeout: 3 * helperTimeout}
	}
	before := startHarnessWith(t, opts(false))
	before.stop(t)
	pre := 0
	for _, c := range before.report.Checks {
		pre += c.N
		t.Logf("without the deputy, %s: %d of %d reached the secret (%s)", c.Name, c.N, heldReadRaceAttempts, c.Out)
	}
	after := startHarnessWith(t, opts(true))
	after.stop(t)
	if len(after.report.Checks) != 2 {
		t.Fatalf("checks %+v, want the path and the link race", after.report.Checks)
	}
	for _, c := range after.report.Checks {
		t.Logf("held, %s: %d of %d reached the secret (%s)", c.Name, c.N, heldReadRaceAttempts, c.Out)
		if c.Err != "" {
			t.Fatalf("%s: %s", c.Name, c.Err)
		}
		if c.N != 0 {
			t.Errorf("%s: %d held reads delivered the nested secret; want none", c.Name, c.N)
		}
		if !strings.Contains(c.Out, "EACCES=") || !strings.Contains(c.Out, "ok=") {
			t.Errorf("%s: want both the floor's refusal and a benign open (%s): the race did not run", c.Name, c.Out)
		}
	}
	t.Logf("pre-fix count (no deputy): %d reads of the secret over %d opens", pre, 2*heldReadRaceAttempts)
}

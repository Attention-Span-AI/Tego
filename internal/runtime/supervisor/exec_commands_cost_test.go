// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// selfKernel is the fake kernel with this process as the target's memory: every argv and pathname read is a real
// process_vm_readv of this process, so a measurement pays what a real notification pays for its reads. A walk asked
// for an image's head reads it for real too (readHead: the reopen through /proc/self/fd, its identity check and the
// pread) after the permission check (execRefused), from heads' file for the walked spelling, else from this test
// binary.
type selfKernel struct {
	*fakeKernel
	sys   sysKernel
	heads map[string]headFile
	elf   headFile
	// read counts the bytes the reads of the target's memory returned, when set.
	read *atomic.Int64
}

// headFile is an O_PATH descriptor a walk would hold, with its identity and permission bits.
type headFile struct {
	fd       int
	id       fileID
	mode     uint32
	uid, gid uint32
}

// openHeadFile opens p O_PATH for readHead, closed at the end of the test.
func openHeadFile(t *testing.T, p string) headFile {
	t.Helper()
	fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	return headFile{fd: fd, id: fileID{dev: st.Dev, ino: st.Ino}, mode: st.Mode & 0o7777, uid: st.Uid, gid: st.Gid}
}

func (k selfKernel) ExecImage(q pathQuery) (execImage, error) {
	img, err := k.fakeKernel.ExecImage(q)
	if err != nil || !q.head {
		return img, err
	}
	h, ok := k.heads[q.joined]
	if !ok {
		h = k.elf
	}
	// The permission check sysKernel makes before the head is read (execRefused), paid as a real exec pays it.
	probe := img
	probe.mode, probe.uid, probe.gid = h.mode, h.uid, h.gid
	if execRefused(h.fd, probe, q.tid) {
		return execImage{}, unix.EACCES
	}
	img.head = readHead(h.fd, h.id)
	return img, nil
}

func (k selfKernel) ReadMem(_ int, addr uint64, buf []byte) (int, error) {
	return k.counted(k.sys.ReadMem(os.Getpid(), addr, buf))
}

func (k selfKernel) ReadMemV(_ int, segs []memSeg, buf []byte) (int, error) {
	return k.counted(k.sys.ReadMemV(os.Getpid(), segs, buf))
}

func (k selfKernel) counted(n int, err error) (int, error) {
	if k.read != nil && n > 0 {
		k.read.Add(int64(n))
	}
	return n, err
}

// liveExec is one exec's pathname and argv laid out in this process's memory.
type liveExec struct {
	path []byte
	strs [][]byte
	ptrs []uint64
}

func newLiveExec(path string, argv []string) *liveExec {
	e := &liveExec{path: append([]byte(path), 0)}
	for _, a := range argv {
		s := append([]byte(a), 0)
		e.strs = append(e.strs, s)
		e.ptrs = append(e.ptrs, uint64(uintptr(unsafe.Pointer(&s[0]))))
	}
	e.ptrs = append(e.ptrs, 0)
	return e
}

func (e *liveExec) notif(nr int32) *notif {
	return notifFor(nr, os.Getpid(), uint64(uintptr(unsafe.Pointer(&e.path[0]))), uint64(uintptr(unsafe.Pointer(&e.ptrs[0]))), 0)
}

// TestExecCommandCostBudget is ADR 0048 C8's supervisor half: what command rules add to one exec's notification,
// measured interleaved A/B (the same exec with and without the rules, the side that goes first alternating) as the
// minimum of many rounds. Reads are real process_vm_readv calls of this process's memory, and the walk's head reads
// real files. In budget mode (testutil.BudgetsEnv, set by scripts/timing-budgets.sh) the figures are wall-clock
// time, held to each case's Target (a miss is printed TARGET-MISS) and Limit (about twice it: over it fails); in the
// unit gate the same rounds are read on the handling thread's own figures (testutil.MinOfThread: handle does its work
// on the calling goroutine): its own time, the wall clock less the waits for a CPU that other processes filled where
// the thread never blocked, is held to testutil.CeilingFactor times the Limit and its wall clock to
// testutil.WallCeilingFactor times it, which only a regression of several times the budget reaches on a busy
// machine, whether it works or waits (docs/BENCHMARKS.md, "Timing budgets in the test suites"). Skipped under -short
// and the race detector.
func TestExecCommandCostBudget(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("a timing budget; -short and -race skip it")
	}
	mode := testutil.TimingMode(t)
	nr := nrFor(t, "execve")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	elf, heads := openHeadFile(t, self), map[string]headFile{script: openHeadFile(t, script)}
	sinks, reads := map[*Loop]*testSink{}, map[*Loop]*atomic.Int64{}
	loop := func(pol *Policy) *Loop {
		pol.Record = agent.RecordOff
		sink, read := &testSink{}, new(atomic.Int64)
		l, err := New(testListener(), pol, sink, Options{kernel: selfKernel{fakeKernel: newFake(), heads: heads, elf: elf, read: read}, Workers: 1})
		if err != nil {
			t.Fatal(err)
		}
		sinks[l], reads[l] = sink, read
		return l
	}
	mk := func(entries ...string) *Loop {
		if len(entries) == 0 {
			return loop(contractPolicy(&agent.Contract{Exec: &agent.ExecSection{Deny: []string{}}}, nil, nil))
		}
		return loop(commandPolicy(t, entries...))
	}
	// floorless is an allow-list run whose image floor grants git and python3, not rm, with its command rules or
	// without them: the A/B of an exec the floor refuses.
	floorless := func(rules bool) *Loop {
		pol := commandPolicy(t, "allow: git status", "deny: rm -r")
		pol.Rules.Exec = slices.DeleteFunc(pol.Rules.Exec, func(r agent.ExecRule) bool { return r.Path == "/usr/bin/rm" })
		if !rules {
			pol.Rules.ExecCommands = nil
		}
		return loop(pol)
	}
	args := func(cmd string, n, width int) []string {
		out := []string{cmd}
		for i := 1; i < n; i++ {
			s := "f" + strconv.Itoa(i)
			for len(s) < width {
				s += "x"
			}
			out = append(out, s)
		}
		return out
	}
	cases := []struct {
		name  string
		rules []string
		path  string
		argv  []string
		// verdict is what the run with the rules answers.
		verdict record.Verdict
		// limit 0: the time is reported against target only, and readLimit is the case's limit.
		target, limit time.Duration
		rounds        int
		// floorRefused: the image floor refuses the exec (floorless), so the rules do not decide it, and the rules
		// may add at most readLimit bytes to what one such exec reads of the target's memory.
		floorRefused bool
		readLimit    int64
	}{
		{"unguarded exec, run with command rules", []string{"deny: git push"}, "/usr/bin/ls", args("ls", 8, 8), record.VerdictAllow, 6 * time.Microsecond, 12 * time.Microsecond, 400, false, 0},
		{"a #!/bin/sh script, run with command rules", []string{"deny: git push"}, script, args("s", 8, 8), record.VerdictAllow, 15 * time.Microsecond, 30 * time.Microsecond, 400, false, 0},
		{"guarded exec, 16 arguments", []string{"deny: git push --force"}, "/usr/bin/git", append([]string{"git", "push"}, args("x", 14, 8)[1:]...), record.VerdictAllow, 15 * time.Microsecond, 30 * time.Microsecond, 400, false, 0},
		{"guarded exec, 128 arguments", []string{"deny: rm -r"}, "/usr/bin/rm", args("rm", 128, 12), record.VerdictAllow, 150 * time.Microsecond, 300 * time.Microsecond, 200, false, 0},
		{"guarded exec, 8192 arguments / 112 KiB", []string{"deny: rm -r"}, "/usr/bin/rm", args("rm", 8192, 13), record.VerdictAllow, time.Millisecond, 2 * time.Millisecond, 30, false, 0},
		{"guarded exec past the bound, refused", []string{"deny: rm -r"}, "/usr/bin/rm", args("rm", 8192, 20), record.VerdictRefused, time.Millisecond, 2 * time.Millisecond, 30, false, 0},
		// An exec the image floor refuses is walked for what it loads (dropped, R16b) and no
		// further, as an unguarded exec is. It paid the guarded tool's whole staged argv read and match, thrown away,
		// and its line then read argv again: +460 to +790 µs at 8192 arguments, and some 180 KiB more read of the
		// target's memory. The walk costs about what an unguarded exec's does whatever argc is (measured +8.5 to
		// +12.4 µs at 8 arguments, where the line reads argv[0] once more, so bounds of 10 and 20 µs). At 8192
		// arguments both sides pay the line's own copy of the vector, 6 to 7 ms, whose minimum varies by tens of µs
		// with the host's load: the time is reported against a 30 µs target, and the limit is on the bytes read.
		{"guarded exec the floor refuses, 8 arguments", nil, "/usr/bin/rm", args("rm", 8, 8), record.VerdictRefused, 10 * time.Microsecond, 20 * time.Microsecond, 400, true, 4096},
		{"guarded exec the floor refuses, 8192 arguments / 112 KiB", nil, "/usr/bin/rm", args("rm", 8192, 13), record.VerdictRefused, 30 * time.Microsecond, 0, 30, true, 4096},
	}
	for _, c := range cases {
		withRules, without := mk(c.rules...), mk()
		if c.floorRefused {
			withRules, without = floorless(true), floorless(false)
		}
		e := newLiveExec(c.path, c.argv)
		// A case measured on an answer it does not expect measures another path: the 8192-argument case was refused
		// args-unreadable until the staged read read the NULL after a vector of exactly the bound. The run without the
		// rules continues the exec, unless the image floor refuses it on both sides.
		withRules.handle(e.notif(nr))
		wantExecAnswer(t, withRules.k.(selfKernel).fakeKernel, c.verdict)
		without.handle(e.notif(nr))
		wantExecAnswer(t, without.k.(selfKernel).fakeKernel, map[bool]record.Verdict{false: record.VerdictAllow, true: record.VerdictRefused}[c.floorRefused])
		m := mode.Measure(c.rounds,
			func() { withRules.handle(e.notif(nr)) },
			func() { without.handle(e.notif(nr)) })
		runtime.KeepAlive(e)
		t.Logf("%s: with rules %v; without %v", c.name, m[0], m[1])
		if c.floorRefused {
			// What is measured is the floor's refusal, its line whole, with the rules and without them.
			var read [2]int64
			for i, l := range [2]*Loop{withRules, without} {
				reads[l].Store(0)
				l.handle(e.notif(nr))
				read[i] = reads[l].Load()
				evs := sinks[l].all()
				if len(evs) == 0 || evs[len(evs)-1].Verdict != record.VerdictRefused || evs[len(evs)-1].Rule != ruleUnmatched {
					t.Fatalf("%s: the last line %+v, want the floor's refusal %s", c.name, evs[len(evs)-1:], ruleUnmatched)
				}
				if p := execPayloadOf(t, evs[len(evs)-1]); len(p.Argv) != len(c.argv) || p.ArgvTruncated {
					t.Fatalf("%s: the line's argv has %d of %d entries (truncated %v)", c.name, len(p.Argv), len(c.argv), p.ArgvTruncated)
				}
			}
			runtime.KeepAlive(e)
			t.Logf("%s: %d bytes read with rules, %d without (limit +%d)", c.name, read[0], read[1], c.readLimit)
			if read[0]-read[1] > c.readLimit {
				t.Errorf("%s: the rules added %d bytes read of the target's memory, over the +%d limit (ADR 0048 C8)", c.name, read[0]-read[1], c.readLimit)
			}
		}
		added := m[0].Sub(m[1])
		if c.limit == 0 {
			// No time limit: the time is reported against the target alone (in budget mode, where the target is
			// written in wall-clock figures), and the case's limit is readLimit's.
			t.Logf("%s: %v (target +%v; the limit is on bytes read)", c.name, added, c.target)
			if mode.Budgets() && added.Wall > c.target {
				t.Logf("TARGET-MISS: %s +%v > +%v (ADR 0048 C8)", c.name, added.Wall, c.target)
			}
			continue
		}
		mode.Judge(t, testutil.Budget{Name: c.name, Target: c.target, Limit: c.limit, Spec: "ADR 0048 C8", Added: true}, added)
	}
}

// TestExecCommandIndexCostBudget is C8's decision-core case: ExecCommand over 512 patterns for an exec whose tool
// none of them names costs one index lookup, at most +1 µs (target +0.5 µs), and Match allocates nothing. In budget
// mode the figure is the median of seven 100 ms testing.Benchmark runs, as C8 measured it; in the unit gate it is
// the fastest of 1000 batches of 256 decisions in the deciding thread's own time (testutil.MinOfThread), held to
// testutil.CeilingFactor times the limit, its wall clock to testutil.WallCeilingFactor times it.
func TestExecCommandIndexCostBudget(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("a timing budget; -short and -race skip it")
	}
	mode := testutil.TimingMode(t)
	var ps []*execmatch.Pattern
	for i := 0; i < 512; i++ {
		p, err := execmatch.Parse("tool"+strconv.Itoa(i)+" sub"+strconv.Itoa(i), execmatch.ListDeny, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	ix := execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{})
	f := execmatch.Facts{Requested: "ls", Image: "ls", Argv0: "ls", Argv: []string{"ls", "-l", "x"}, ArgvComplete: true}
	budget := testutil.Budget{Name: "ExecCommand over 512 patterns, an exec whose tool has none",
		Target: 500 * time.Nanosecond, Limit: time.Microsecond, Spec: "ADR 0048 C8"}
	if !mode.Budgets() {
		// One sample is a batch: one decision is too short to time alone.
		const batch = 256
		m := testutil.MinOfThread(1000, func() {
			for range batch {
				ix.Decide(&f)
			}
		})
		mode.Judge(t, budget, m[0].Div(batch))
		return
	}
	// testing.Benchmark runs each for -test.benchtime, 1 s unless set; 100 ms each measures as steadily.
	if bt := flag.Lookup("test.benchtime"); bt != nil && bt.Value.String() == bt.DefValue {
		if err := flag.Set("test.benchtime", "100ms"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = flag.Set("test.benchtime", bt.DefValue) })
	}
	var times []time.Duration
	for range 7 {
		r := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				ix.Decide(&f)
			}
		})
		times = append(times, time.Duration(r.NsPerOp()))
	}
	slices.Sort(times)
	mode.Judge(t, budget, testutil.Figure{Wall: times[3]})
}

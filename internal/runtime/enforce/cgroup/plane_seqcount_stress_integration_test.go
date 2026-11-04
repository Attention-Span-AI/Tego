// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// stressSecondsEnv sets the seconds the churn runs for at least, for a run of the test binary itself (the harnesses
// pass the guest and sudo no variables of their own): a run that wants to look harder for a race sets it to minutes.
const stressSecondsEnv = "TEGO_STRESS_SECONDS"

const (
	stressSeconds     = 6     // enough on x86, whose loads are not reordered, to confirm the protocol
	stressWeakSeconds = 30    // on an architecture whose loads are, where a walk that slipped its ordering is rare
	stressRestSeconds = 2     // the control run, whose chain does not move
	stressMinOps      = 20000 // calls the agent completes before it stops, whatever the seconds say
	stressMinNamed    = 100   // lines named by a path the cell needs to have seen to call a run a stress at all
)

// stressSettings are the seconds the churn runs for, the agent's thread count and the calls the agent completes at
// least. The threads leave a CPU to the renamer and one to the launcher's reader, which the ledger's pace depends on.
func stressSettings() (seconds, threads, minOps int) {
	seconds = stressSeconds
	if runtime.GOARCH != "amd64" {
		seconds = stressWeakSeconds
	}
	if v, err := strconv.Atoi(os.Getenv(stressSecondsEnv)); err == nil && v > 0 {
		seconds = v
	}
	threads = min(max(runtime.NumCPU()-1, 2), 6)
	return seconds, threads, stressMinOps
}

// stressRename flips the chain until stop closes, in bursts of one to eight flips of the cycle with a pause of up
// to 100 µs between them, so that a walk of a few tens of microseconds meets no flip, one, or several. It runs in
// the test process, outside the run, so no hook decides a flip and each costs a rename and little more. It returns
// the flips it made. It sleeps through the kernel (nanosleep, with the thread's timer slack) and not through the Go
// runtime, whose netpoller rounds a sleep under a millisecond up to one.
func stressRename(c stressChain, stop <-chan struct{}) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rnd := rand.New(rand.NewPCG(1, 1))
	flips := 0
	for {
		select {
		case <-stop:
			return flips, nil
		default:
		}
		pause := unix.NsecToTimespec(int64(rnd.IntN(100)) * 1000)
		_ = unix.Nanosleep(&pause, nil)
		for burst := 1 + rnd.IntN(len(stressCycle)); burst > 0; burst-- {
			pos := stressCycle[flips%len(stressCycle)]
			from, to := c.flip(pos)
			if err := os.Rename(from, to); err != nil {
				return flips, fmt.Errorf("flip %d (position %d), %s to %s: %w", flips, pos, from, to, err)
			}
			c.bits ^= 1 << pos
			flips++
		}
	}
}

// readStressLedger reads the run's one ledger line by line (a stress run writes hundreds of thousands, which
// runEvents would hold whole) into the tally, and returns the decision plane run_start names and the lines read.
func readStressLedger(t *testing.T, ledger string, c stressChain, project string) (tally stressTally, plane string, lines int) {
	t.Helper()
	runs, err := filepath.Glob(filepath.Join(ledger, "*", "events.jsonl"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("ledgers under %s: %v (%v), want exactly one run", ledger, runs, err)
	}
	f, err := os.Open(runs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	valid := c.states()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		lines++
		var l stressLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("ledger line %d %q: %v", lines, sc.Bytes(), err)
		}
		if l.Kind == "run_start" {
			plane = l.DecisionPlane
		}
		tally.add(c.root, project, valid, l)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", runs[0], err)
	}
	return tally, plane, lines
}

// TestPlaneSeqcountStress is enforce-plane §2.15's ordering on a kernel that is run, not read. The recorder names a
// plane run's fs mutations by walking the parent directory in the kernel, and its walk is a seqcount reader of the
// dentries' d_seq: each level's sequence, then its parent and its name, then a second pass that must find every
// sequence unmoved. A reader needs a read barrier between the sequence and the data and another before the
// re-read, which BPF has no instruction for; the walk uses an atomic fetch, which is fully ordered (the arm64 JIT
// emits ldaddal, or an exclusive pair and dmb ish), and internal/bpf TestDirWalkFencesItsSequenceReads checks the
// compiled walk carries it. x86's loads are not reordered, so on amd64 this cell can only confirm the protocol; on
// arm64, where loads are, it is what would show a walk whose reads slipped past it. ci.yml's build-test-arm64 runs
// it there; on that runner's 7.0 kernel, which preempts kernel code, doctor rules fmod_ret mode out (ADR 0024 (16)),
// so it runs report-only under the test builds' TEGO_TEST_PLANE_PREEMPT=waive.
//
// A run's agent churns a leaf directory through a descriptor it holds (mkdir and rmdir, create and unlink, symlink
// and unlink, an open and a read of a file), on several threads, so that every action is decided by the plane and
// recorded with a walk of the leaf's path, while this process, outside the run, renames the directories above the
// leaf in a fixed cycle (stressChain): two positions are renamed where they are, and two are a rename that moves a
// directory between two parents and changes its name in one step, so a walk that read the parent before the rename
// and the name after it names a directory that never existed. The cycle visits eight of the sixteen spellings the
// chain can have, so a path spelled any other way is a torn read, and a line the ledger carries is one of three
// things: named by a path the leaf really had, marked dev:ino/name because the walk found a sequence moved and
// said so (it fails closed), or wrong. A wrong line fails the cell.
//
// The cell asserts no wrong allow in the same run. The agent also attempts, every few turns, what the contract
// denies: a read and a mkdir and an unlink in the denied tree, a rename and a link out of it, a write outside every
// entry. Each must be refused while the renames go on, and none may succeed, in the agent's own count or on the
// ledger. The plane's decision walk reads no sequence, so this is no ordering: the denied tree is not among the
// renamed directories, and its refusals come from rows the walk meets before any ancestor, so what is asserted is
// that the load and the renames beside it never turn one into an allow. The walks of the allowed actions do climb the
// renamed chain, to the write entry's row above it, and a torn climb could only refuse them (TIER3-PLAN §8: an
// ancestor renamed during the unlocked d_parent walk cannot loosen a rule), which the rest run holds to none.
//
// Each plane mode runs it twice. The rest run is the control: the same agent for two seconds with the chain still,
// where no walk may be marked (a walk marked with nothing moving would be failing for another reason, and the churn
// run's marks would then say nothing about a race) and no action under the chain may be refused. The churn run is
// the stress, and must see both kinds of walk: some that proved their path and some that found the chain moved.
//
// It prints one SEQCOUNT-STRESS line per run with the counts, so that a log pasted from a runner is the evidence.
// It skips where no plane mode passes: the walk is the plane's.
func TestPlaneSeqcountStress(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	seconds, threads, minOps := stressSettings()
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			t.Run("rest", func(t *testing.T) {
				r := stressRun(t, bin, uid, gid, mode, stressRestSeconds, threads, minOps/4, false)
				r.check(t, mode, minOps/4)
				if r.tally.marked != 0 {
					t.Errorf("%d walks were marked with the chain at rest: they fail for a reason that is not a race, and the churn "+
						"run's marks would say nothing about one", r.tally.marked)
				}
				if r.tally.refusedInChain != 0 {
					t.Errorf("the plane refused %d actions under a chain that never moved", r.tally.refusedInChain)
				}
			})
			t.Run("churn", func(t *testing.T) {
				r := stressRun(t, bin, uid, gid, mode, seconds, threads, minOps, true)
				r.check(t, mode, minOps)
				// The churn stressed something only if the chain moved while the agent's calls were walked: some walks
				// proved their path, some found a sequence moved.
				if r.flips == 0 {
					t.Error("the renamer made no flip")
				}
				if r.tally.marked == 0 {
					t.Error("no walk found the chain moved under it: the renamer never met a walk, so the sequence check was not exercised")
				}
			})
		})
	}
}

// stressResult is what one run of the stress agent came to.
type stressResult struct {
	churn, denied map[string]float64 // the agent's own count of its calls, and of its attempts at what is denied
	tally         stressTally        // the ledger, read by the oracle
	plane         string             // run_start's decision_plane
	lines, flips  int
	// waived says the mode is admitted here by the test builds' waiver alone (plane_waiver_integration_test.go): the
	// run measures the walk, and its wrong allows are counted, not held.
	waived bool
}

// check holds a run to what both of the cell's runs must show: decided by the mode under test, no path the chain
// never had, no wrong allow, and enough of both to mean something.
func (r stressResult) check(t *testing.T, mode string, minOps int) {
	t.Helper()
	if r.plane != mode {
		t.Errorf("run_start names decision_plane %q, want %q: the run was not decided by the mode under test", r.plane, mode)
	}
	if r.tally.wrong > 0 {
		t.Errorf("%d ledger lines under the chain name a path it never had (the walk's reads of one dentry or of several "+
			"were torn and its sequence check missed it), or no path at all; the first: %q", r.tally.wrong, r.tally.wrongPath)
	}
	// A wrong allow fails the cell on a kernel that admits the mode. Under the waiver alone the kernel can skip a plane
	// program and let a denied call through, which no count over the run can tell from a plane fault (a 2026-11-03
	// review), so there the cell measures the walk and says what it saw; the plane's decisions are held with no
	// tolerance by every other plane test under the waiver, and by this cell wherever the mode is admitted.
	allowed := int(r.denied["allowed"])
	switch {
	case r.waived && (r.tally.wrongAllow > 0 || allowed > 0):
		t.Logf("not held under the test builds' waiver of fmod_ret mode's preemption precondition (ADR 0024 (16)): %d of "+
			"the agent's %.0f attempts at what the contract denies were allowed, and %d ledger lines about them are not "+
			"refusals; the first: %q", allowed, r.denied["attempts"], r.tally.wrongAllow, r.tally.wrongAllowLine)
	case r.tally.wrongAllow > 0 || allowed > 0:
		t.Errorf("a wrong allow: the agent was allowed %d of its %.0f attempts at what the contract denies, and the ledger "+
			"has %d lines about them that are not refusals, the first: %q", allowed, r.denied["attempts"],
			r.tally.wrongAllow, r.tally.wrongAllowLine)
	}
	if r.denied["attempts"] == 0 || r.denied["refused"]+r.denied["other"]+r.denied["allowed"] != r.denied["attempts"] {
		t.Errorf("the agent's attempts at what is denied: %v, want some, each refused, an error, or a wrong allow said above",
			r.denied)
	}
	if r.churn["ops"] < float64(minOps) {
		t.Errorf("the agent completed %.0f calls, want at least %d: the churn did not run", r.churn["ops"], minOps)
	}
	if r.tally.named < stressMinNamed {
		t.Errorf("%d lines are named by a path the chain had, want at least %d: the walk named nothing, or the ledger lost the lines",
			r.tally.named, stressMinNamed)
	}
}

// stressRun runs the stress agent once under mode, for seconds and at least minOps calls, with the chain flipping
// meanwhile when move is set, and reads its ledger.
func stressRun(t *testing.T, bin string, uid, gid int, mode string, seconds, threads, minOps int, move bool) stressResult {
	t.Helper()
	tool, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skipf("the project's binary is a copy of /bin/true: %v", err)
	}
	rel := stressChain{root: filepath.Join("out", "sq")}
	files := map[string]string{
		"agent.py": stressAgent(rel, seconds, threads, minOps), "agent.yaml": dropContract, "bin/tool": string(tool),
		filepath.Join(rel.leaf(), "data"): "data\n",
		"out/secret/key":                  "k\n", "out/secret/key2": "k2\n", "out/secret/key3": "k3\n", "out/secret/key4": "k4\n",
	}
	p := newPlaneProject(t, uid, gid, files, rel.layout(), nil)
	project, err := filepath.EvalSymlinks(p.project)
	if err != nil {
		t.Fatal(err)
	}
	chain := stressChain{root: filepath.Join(project, "out", "sq")}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	waived := mode == "fmod_ret" && planeModeWaived(mode)
	var out bytes.Buffer
	cmd := p.run(ctx, bin, "agent.yaml", mode, &out)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// The agent has opened the leaf and says ready; only then does the chain move, so the descriptor is of the
	// leaf at state 0, and the first walks are of a chain at rest.
	waitFile(t, filepath.Join(p.project, "out", "ready"), time.Minute, cmd, &out)
	stop := make(chan struct{})
	stopRenamer := sync.OnceFunc(func() { close(stop) })
	t.Cleanup(stopRenamer)
	type renamed struct {
		flips int
		err   error
	}
	flipped := make(chan renamed, 1)
	if move {
		go func() {
			n, err := stressRename(chain, stop)
			flipped <- renamed{n, err}
		}()
	} else {
		flipped <- renamed{}
	}
	if err := os.WriteFile(filepath.Join(p.project, "out", "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	runErr := <-done
	stopRenamer()
	f := <-flipped
	t.Logf("tego run (%s): %v\n%s", mode, runErr, out.String())
	if runErr != nil {
		t.Fatalf("the run did not complete: %v", runErr)
	}
	if f.err != nil {
		t.Fatalf("the renamer failed: %v", f.err)
	}

	res := agentResults(t, out.String())
	r := stressResult{churn: stressFields(res["stress"]), denied: stressFields(res["denied"]), flips: f.flips, waived: waived}
	r.tally, r.plane, r.lines = readStressLedger(t, p.ledger, chain, project)
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	phase := "rest"
	if move {
		phase = "churn"
	}
	t.Logf("SEQCOUNT-STRESS mode=%s phase=%s arch=%s kernel=%s seconds=%.1f threads=%d ops=%.0f flips=%d lines=%d named=%d marked=%d "+
		"wrong_path=%d refused_in_chain=%d denied_attempts=%.0f denied_refused=%d wrong_allow=%d waived=%v",
		mode, phase, runtime.GOARCH, unix.ByteSliceToString(uts.Release[:]), r.churn["seconds"], int(r.churn["threads"]), r.churn["ops"],
		r.flips, r.lines, r.tally.named, r.tally.marked, r.tally.wrong, r.tally.refusedInChain, r.denied["attempts"],
		r.tally.deniedRefused, r.tally.wrongAllow+int(r.denied["allowed"]), r.waived)
	return r
}

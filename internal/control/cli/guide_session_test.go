// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/web"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

type helperStarts struct{ Launcher, Worker int }

// helperMarker is one note a helper process of this test binary wrote about itself (pathcheck_dispatch_test.go): its
// role, its pid, the clock tick (since boot) at which it was created, and the request pipe it was given.
type helperMarker struct {
	role     string
	pid      int
	created  int64
	requests string
	rawNote  string
}

// startOf is the start time of process pid in /proc/<pid>/stat (field 22, in clock ticks since boot), the unit of the
// "started" a helper's note holds. Both come from the one clock, in the order the processes were created in.
func startOf(pid int) (int64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(f) < 20 {
		return 0, fmt.Errorf("/proc/%d/stat has %d fields after the name", pid, len(f))
	}
	return strconv.ParseInt(f[19], 10, 64)
}

// fenceTick creates a process that ends at once and returns its start time: every process created before this call has
// a start time up to it, and one created after it and a clock tick later has a greater one.
func fenceTick(t *testing.T) int64 {
	t.Helper()
	// By path: the tests that count set PATH to a directory with nothing in it.
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		cmd = exec.Command("/usr/bin/true")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	tick, err := startOf(cmd.Process.Pid)
	_ = cmd.Wait()
	if err != nil {
		t.Fatal(err)
	}
	return tick
}

// readHelperMarkers reads every note in dir, roles first.
func readHelperMarkers(dir string) ([]helperMarker, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []helperMarker
	for _, entry := range entries { // ReadDir sorts by name, roles first
		role, pidText, _ := strings.Cut(entry.Name(), "-")
		pid, _ := strconv.Atoi(pidText)
		note, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
		m := helperMarker{role: role, pid: pid, rawNote: strings.TrimSpace(string(note))}
		for _, field := range strings.Fields(m.rawNote) {
			key, value, _ := strings.Cut(field, "=")
			switch key {
			case "started":
				m.created, _ = strconv.ParseInt(value, 10, 64)
			case "requests":
				m.requests = value
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// countBegan is the start time of the fence process at which the latest guideHelperCount began, for describeHelpers.
var countBegan int64

// guideHelperCount counts the helper processes that the code under test starts from the moment it returns.
//
// A helper writes its note when its own start-up has run, and a test binary of the race detector takes tens of
// milliseconds to get there, so a helper that an earlier test's session started, and that the test ended without waiting
// for, can write its note after this count began: a launcher whose worker is still to come, or a worker of a launcher
// that is gone. None of them belongs to this test, so a note counts only when its process was created after the count
// began (its creation time is in the note, and is the fork's, not the note's: see fenceTick), and a worker only when it holds the
// request pipe of a launcher that counted (a launcher passes its pipes on, and is gone, so no longer its worker's
// parent, by the time a worker's note is written in a build without the race detector). A request that opened a
// second session still shows as a second launcher with a second worker.
func guideHelperCount(t *testing.T) func() helperStarts {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := executable + ".count"
	if err := os.Mkdir(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(marker); err != nil {
			t.Error(err)
		}
	})
	// Every helper an earlier test started was created before this fence process, and a start time is in clock ticks
	// (hundredths of a second), so this test's own helpers are created after a pause of two.
	began := fenceTick(t)
	countBegan = began
	time.Sleep(20 * time.Millisecond)
	return func() helperStarts {
		markers, err := readHelperMarkers(marker)
		if err != nil {
			t.Fatal(err)
		}
		var starts helperStarts
		sessions := map[string]bool{} // the request pipes of the launchers that count
		for _, m := range markers {
			if m.role == "launcher" && m.created > began {
				sessions[m.requests] = true
				starts.Launcher++
			}
		}
		for _, m := range markers {
			switch m.role {
			case "launcher":
			case "worker":
				if m.requests != "?" && sessions[m.requests] {
					starts.Worker++
				}
			default:
				t.Fatalf("unknown helper process role %q", m.role)
			}
		}
		return starts
	}
}

// describeHelpers says what the markers of guideHelperCount hold, for a count that is not the wanted one: each helper's
// role and pid, who its parent was when it started and who it is now, when it started, and whether it is still alive
// (a worker that its session abandoned stays alive until its mount answers, one that was closed ends), with the load
// average that a starved start-up or request bound is judged against. The reason a session dropped a worker is not
// recorded by the product, so it is not here: the order and the times are what tells a bound that ended from a worker
// that was started late by another test.
func describeHelpers(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		return err.Error()
	}
	markers, err := readHelperMarkers(executable + ".count")
	if err != nil {
		return err.Error()
	}
	var b strings.Builder
	for _, m := range markers {
		now := "gone"
		if st, err := os.ReadFile("/proc/" + strconv.Itoa(m.pid) + "/stat"); err == nil {
			s := string(st)
			f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
			if len(f) > 1 {
				now = "alive, state " + f[0] + ", parent now " + f[1]
			}
		}
		fmt.Fprintf(&b, "\n  %s-%d: %s; %s", m.role, m.pid, m.rawNote, now)
	}
	load, _ := os.ReadFile("/proc/loadavg")
	return fmt.Sprintf("helpers started (test process %d, now %s, the count began at tick %d):%s\n  load average %s", os.Getpid(), time.Now().Format("15:04:05.000000"), countBegan, b.String(), strings.TrimSpace(string(load)))
}

func TestOverviewBootstrapSharesRequestHelper(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	t.Setenv("PATH", filepath.Join(f.Root, "absent-bin"))
	original := selfExecutable
	selfExecutable = func() (string, error) { return filepath.Join(f.Root, "absent-self"), nil }
	defer func() { selfExecutable = original }()
	count := guideHelperCount(t)
	ctx, closeHelpers := contracts.WithHelperSession(context.Background())
	defer closeHelpers()
	s, err := web.New(web.Config{Ledger: f.Ledger, Guide: guideInputs(f.Machine(t), f.Ledger, f.Anchor)})
	if err != nil {
		t.Fatal(err)
	}
	s.Prewarm(ctx)
	t.Logf("overview including binary bootstrap processes: %+v", count())
	if count() != (helperStarts{Launcher: 1, Worker: 1}) {
		t.Errorf("overview bootstrap processes: %+v; want one launcher and one worker\n%s", count(), describeHelpers(t))
	}
}

func TestCancelledOverviewBootstrapStartsNoHelper(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	count := guideHelperCount(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := guideInputs(f.Machine(t), f.Ledger, f.Anchor)(ctx)
	if in.Exe != "" {
		t.Error("cancelled bootstrap returned a checked binary")
	}
	if count() != (helperStarts{}) {
		t.Errorf("cancelled bootstrap processes: %+v", count())
	}
}

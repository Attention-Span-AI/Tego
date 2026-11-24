// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/web"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

type helperStarts struct{ Launcher, Worker int }

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
	return func() helperStarts {
		entries, err := os.ReadDir(marker)
		if err != nil {
			t.Fatal(err)
		}
		var starts helperStarts
		for _, entry := range entries {
			switch {
			case strings.HasPrefix(entry.Name(), "launcher-"):
				starts.Launcher++
			case strings.HasPrefix(entry.Name(), "worker-"):
				starts.Worker++
			default:
				t.Fatalf("unknown helper process role %q", entry.Name())
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
	entries, err := os.ReadDir(executable + ".count")
	if err != nil {
		return err.Error()
	}
	var b strings.Builder
	for _, entry := range entries { // ReadDir sorts by name, roles first
		note, _ := os.ReadFile(filepath.Join(executable+".count", entry.Name()))
		pid := entry.Name()[strings.LastIndexByte(entry.Name(), '-')+1:]
		now := "gone"
		if st, err := os.ReadFile("/proc/" + pid + "/stat"); err == nil {
			s := string(st)
			f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
			if len(f) > 1 {
				now = "alive, state " + f[0] + ", parent now " + f[1]
			}
		}
		fmt.Fprintf(&b, "\n  %s: %s; %s", entry.Name(), strings.TrimSpace(string(note)), now)
	}
	load, _ := os.ReadFile("/proc/loadavg")
	return fmt.Sprintf("helpers started (test process %d, now %s):%s\n  load average %s", os.Getpid(), time.Now().Format("15:04:05.000000"), b.String(), strings.TrimSpace(string(load)))
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

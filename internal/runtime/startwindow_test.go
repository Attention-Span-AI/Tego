// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// holdingBackend is a fakeBackend whose Prepare says it has begun and then waits for the run to be cancelled, as a
// tier's kernel checks and program loads do for seconds on a first use.
type holdingBackend struct {
	fakeBackend
	entered chan struct{}
}

func (b *holdingBackend) Prepare(ctx context.Context, _ *agent.RuleTable, _ enforce.RunRef) (api.Handle, error) {
	close(b.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestARunHoldsItsLockBeforeItNamesItsAgent pins the window between a run's start and its first line that names the agent (`tego stop` right then):
// the launcher takes the run's lock when it opens the ledger, and run_start, the first line that names the agent, is
// written only after the run's enforcement is prepared. While Prepare runs the run exists and is live, with no
// agent id on record; anything that needs the agent id of a live run (stop's backstop kill finds the run's scope by
// it) must treat that as a state of the run, not as damage. The test holds Prepare open, so it does not depend on how
// long a kernel takes to prepare.
func TestARunHoldsItsLockBeforeItNamesItsAgent(t *testing.T) {
	testutil.NoFDLeak(t)
	m, rt, root := startupFixture(t)
	b := &holdingBackend{entered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	released := false
	defer func() {
		if !released { // a failed check below still lets the run go before the descriptor check
			cancel()
			time.Sleep(200 * time.Millisecond)
		}
	}()
	log, _ := newUnwindLog()
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, rt, []string{"/bin/true"},
			Deps{Config: m, Cgroups: &fakeCgroups{root: t.TempDir()}, Enforce: b, Environ: []string{}, Cwd: root, Logger: log})
		done <- err
	}()
	select {
	case <-b.entered:
	case err := <-done:
		t.Fatalf("the run ended before it reached Prepare: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the run never reached Prepare")
	}
	runs := filepath.Join(root, "runs")
	var dir string
	for _, name := range leftBehind(t, runs) {
		if !strings.HasPrefix(name, ledger.LiveDir+"/") { // leftBehind also lists the live index entries
			dir = filepath.Join(runs, name)
		}
	}
	if dir == "" {
		t.Fatal("a run in Prepare has a run directory")
	}
	f, err := os.Open(filepath.Join(dir, ledger.LockFile))
	if err != nil {
		t.Fatalf("a run in Prepare has its lock file: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("flock of a run in Prepare: %v, want it held by the run (EWOULDBLOCK)", err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("a run in Prepare has its ledger open: %v", err)
	}
	defer func() { _ = r.Close() }()
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		if e.Agent != "" {
			t.Fatalf("a run in Prepare already names its agent (%q): run_start is written after Prepare", e.Agent)
		}
	}
	released = true
	cancel()
	if err := <-done; err == nil {
		t.Fatal("a run cancelled in Prepare must fail before run_start")
	}
}

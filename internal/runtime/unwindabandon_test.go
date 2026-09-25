// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestRunUnwindWritesNoRunEnd: unwind closed the Writer of a run that never started with Close, which appended
// run_end as the ledger's line 0. The directory is removed next, but a launcher that died in between, or a removal
// that failed, left a run that read as ended with no run_start rather than one that never started. With the removal
// left out, the ledger unwind leaves must hold nothing.
func TestRunUnwindWritesNoRunEnd(t *testing.T) {
	testutil.NoFDLeak(t)
	m, rt, root := startupFixture(t)
	orig := removeRunDir
	removeRunDir = func(string) error { return nil }
	t.Cleanup(func() { removeRunDir = orig })
	log, logged := newUnwindLog()
	deps := Deps{
		Config: m, Cgroups: &fakeCgroups{root: t.TempDir()}, Enforce: &fakeBackend{}, Logger: log,
		Launcher: &launch.Launcher{Exe: filepath.Join(root, "no-such-binary")},
		Environ:  []string{"PATH=/bin"},
		Cwd:      root,
	}
	if _, err := Run(context.Background(), rt, []string{"/bin/true"}, deps); err == nil {
		t.Fatal("a launcher that cannot start the child must fail the run")
	}
	runs := runDirsIn(t, filepath.Join(root, "runs"))
	if len(runs) != 1 {
		t.Fatalf("run directories %v, want the one unwind left in place; the run logged: %s", runs, logged)
	}
	b, err := os.ReadFile(filepath.Join(runs[0], ledger.EventsFile))
	if err != nil {
		t.Fatalf("read the ledger: %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("a run that never started holds %q; unwind must write no line", b)
	}
	state, err := ledger.NewRunRepository(filepath.Join(root, "runs")).State(context.Background(), filepath.Base(runs[0]))
	if err != nil || state != ledger.StateEmpty {
		t.Fatalf("state %q (%v), want empty", state, err)
	}
}

// runDirsIn lists the run directories under a ledger root.
func runDirsIn(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read ledger root: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && ledger.IsRunID(e.Name()) {
			out = append(out, filepath.Join(root, e.Name()))
		}
	}
	return out
}

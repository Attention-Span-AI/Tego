// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
)

func TestRunScopeKeepsAnUnreadableRunIdentity(t *testing.T) {
	const id = "r-00000000-000000000000a-r5read"
	root, m, _ := orphanFixture(t, id)
	// State can still read an intact tail. Scope identity must not treat a malformed first line as the
	// legacy absence of a recorded cgroup id, which would accept any same-name scope.
	dir := filepath.Join(root, id)
	path := filepath.Join(dir, ledger.EventsFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte("broken first line\n"), b...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := RunScope(m, root, id, "tester"); ok || !errors.Is(err, ledger.ErrCorruptLedger) {
		t.Fatalf("RunScope = found %v, %v; want unknown recorded identity", ok, err)
	}
}

func TestRunScopeKeepsAnUnknownRunDirectory(t *testing.T) {
	m := &scopeCgroups{fakeCgroups: fakeCgroups{root: t.TempDir()}}
	_, ok, err := RunScope(m, t.TempDir(), "r-00000000-000000000000a-r5stat", "tester")
	if ok || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("RunScope = found %v, %v; want unknown directory identity", ok, err)
	}
}

func TestSweepRetainsUnknownAdoptionScope(t *testing.T) {
	const id = "r-00000000-000000000000a-r5adop"
	root, tree := t.TempDir(), t.TempDir()
	lostRunIn(t, root, id, 77)
	scope := adoptScopeUnder(t, tree, id)
	m := &unreadableCgroups{scopeCgroups: &scopeCgroups{
		fakeCgroups: fakeCgroups{root: tree}, ids: map[string]uint64{scope: 77},
	}, idErr: unix.EIO}
	previousBases, previousUID := adoptScopeBases, sweeperUID
	adoptScopeBases = func([]string) []string { return []string{tree} }
	sweeperUID = func() int { return 1000 }
	t.Cleanup(func() { adoptScopeBases, sweeperUID = previousBases, previousUID })
	res, err := Sweep(context.Background(), root, 0, WithSweepManager(m))
	if err != nil || res.Deleted != 0 || res.Orphaned != 0 || len(res.Errs) != 1 || !errors.Is(res.Errs[0], unix.EIO) {
		t.Fatalf("unknown adoption scope: %+v, %v; want retained identity read error", res, err)
	}
	if state := runState(t, root, id); state != ledger.StateLost {
		t.Fatalf("unknown adoption state = %s; want lost", state)
	}
	if len(m.killed) != 0 || m.removed != 0 {
		t.Fatalf("unknown adoption touched: killed=%v removed=%d", m.killed, m.removed)
	}
}

func TestSweepRetainsUnknownRootLaunchRecords(t *testing.T) {
	for _, failure := range []string{"record directory", "record file"} {
		t.Run(failure, func(t *testing.T) {
			rootMarksIn(t)
			const id = "r-00000000-000000000000a-r5mark"
			root, tree := t.TempDir(), t.TempDir()
			endedListedRun(t, root, id, 77, goneLauncher(t))
			dir := filepath.Join(root, id)
			if err := writeRootMark(dir, id); err != nil {
				t.Fatal(err)
			}
			var want error
			if failure == "record directory" {
				old := string(rootMarkDir)
				moved := old + "-moved"
				if err := os.Rename(old, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, old); err != nil {
					t.Fatal(err)
				}
				want = unix.ENOTDIR
			} else {
				path := filepath.Join(string(rootMarkDir), id)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path, path); err != nil {
					t.Fatal(err)
				}
				want = unix.ELOOP // unavailable authority for every uid, including root
			}
			m := &scopeCgroups{fakeCgroups: fakeCgroups{root: tree}, ids: map[string]uint64{}}
			res, err := Sweep(context.Background(), root, 0, WithSweepManager(m))
			if err != nil || res.Deleted != 0 || len(res.Errs) != 1 || !errors.Is(res.Errs[0], want) {
				t.Fatalf("unknown root launch record: %+v, %v; want retained %v", res, err, want)
			}
			if _, err := os.Stat(dir); err != nil {
				t.Fatalf("unknown launch record lost its retry record: %v", err)
			}
		})
	}
}

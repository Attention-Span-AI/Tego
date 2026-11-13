// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type unreadableCgroups struct {
	*scopeCgroups
	idErr error
}

func (m *unreadableCgroups) ID(c cgroup.Cgroup) (uint64, error) {
	if m.idErr != nil {
		return 0, m.idErr
	}
	return m.scopeCgroups.ID(c)
}

// Remove must model the scope disappearing, as the kernel manager does. Retention rechecks an ended run
// after its successful sweep and must then see absence rather than a stale populated fixture directory.
func (m *unreadableCgroups) Remove(ctx context.Context, c cgroup.Cgroup) error {
	if err := m.scopeCgroups.Remove(ctx, c); err != nil {
		return err
	}
	return os.RemoveAll(c.Path)
}

var scopeReadFailures = []struct {
	name string
	err  error
}{
	{"scope-access", os.ErrPermission},
	{"cgroup-id", syscall.EIO},
	{"events-read", syscall.EISDIR},
}

// unreadableScope leaves the real discovery path in place: Lstat searches the stand-in tree, ID is called on the
// candidate it finds, and Populated reads its cgroup.events. Only the failing read is changed, then restored.
func unreadableScope(t *testing.T, id string, ended bool, failure string) (string, *unreadableCgroups, func()) {
	t.Helper()
	root, tree := t.TempDir(), t.TempDir()
	if ended {
		endedListedRun(t, root, id, 77, goneLauncher(t))
	} else {
		lostRunIn(t, root, id, 77)
		if err := ledger.MarkLive(root, id); err != nil {
			t.Fatal(err)
		}
	}
	scope := scopeUnder(t, tree, id)
	m := &unreadableCgroups{scopeCgroups: &scopeCgroups{
		fakeCgroups: fakeCgroups{root: tree}, ids: map[string]uint64{scope: 77},
	}}
	previous := orphanRoots
	orphanRoots = func(cgroup.Manager, markDir, runDir) ([]string, error) { return []string{tree}, nil }
	t.Cleanup(func() { orphanRoots = previous })

	var restore func() error
	switch failure {
	case "scope-access":
		if os.Geteuid() == 0 {
			t.Skip("root can search a mode-000 directory; real EACCES needs an unprivileged reader")
		}
		parent := filepath.Dir(scope)
		if err := os.Chmod(parent, 0); err != nil {
			t.Fatal(err)
		}
		restore = func() error { return os.Chmod(parent, 0o700) }
	case "cgroup-id":
		m.idErr = syscall.EIO
		restore = func() error { m.idErr = nil; return nil }
	case "events-read":
		path := filepath.Join(scope, "cgroup.events")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		restore = func() error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.WriteFile(path, []byte("populated 1\nfrozen 1\n"), 0o600)
		}
	default:
		t.Fatalf("unknown failure %q", failure)
	}
	cleared := false
	clear := func() {
		t.Helper()
		if !cleared {
			if err := restore(); err != nil {
				t.Fatal(err)
			}
			cleared = true
		}
	}
	t.Cleanup(clear)
	return root, m, clear
}

func TestKillOrphanKeepsScopeReadErrors(t *testing.T) {
	const id = "r-00000000-000000000000a-unkill"
	for _, tc := range scopeReadFailures {
		t.Run(tc.name, func(t *testing.T) {
			root, m, _ := unreadableScope(t, id, false, tc.name)
			err := killOrphan(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, id)), record.RunRef{ID: id, Agent: "tester"})
			if !errors.Is(err, errOrphanAlive) || !errors.Is(err, tc.err) {
				t.Errorf("killOrphan = %v, want errOrphanAlive and %v", err, tc.err)
			}
			if len(m.killed) != 0 || m.removed != 0 {
				t.Errorf("an unknown scope was touched: killed %v removed %d", m.killed, m.removed)
			}
		})
	}
}

// An unknown scope cannot be ended or aged out. Both passes retain it, including its live entry, and finish once
// the same read succeeds on a later pass. No scope-discovery helper is replaced by a canned found/absent answer.
func TestSweepRetainsScopeReadErrorsForRetry(t *testing.T) {
	const id = "r-00000000-000000000000a-unlost"
	for _, pass := range []string{"live", "retention"} {
		t.Run(pass, func(t *testing.T) {
			for _, tc := range scopeReadFailures {
				t.Run(tc.name, func(t *testing.T) {
					root, m, clear := unreadableScope(t, id, false, tc.name)
					sweep := func() (SweepResult, error) {
						if pass == "live" {
							return SweepLive(context.Background(), root, WithSweepManager(m))
						}
						return Sweep(context.Background(), root, 0, WithSweepManager(m))
					}
					res, err := sweep()
					if err != nil || len(res.Errs) != 1 || !errors.Is(res.Errs[0], errOrphanAlive) || !errors.Is(res.Errs[0], tc.err) {
						t.Errorf("sweep = %+v, %v; want the unknown scope and its cause", res, err)
					}
					if res.Orphaned != 0 || res.Deleted != 0 || runState(t, root, id) != ledger.StateLost {
						t.Fatalf("unknown scope ended or collected: %+v", res)
					}
					if _, err := os.Lstat(filepath.Join(root, ledger.LiveDir, id)); err != nil {
						t.Fatalf("unknown scope lost its retry entry: %v", err)
					}
					clear()
					res, err = sweep()
					if err != nil || len(res.Errs) != 0 || res.Orphaned != 1 || len(m.killed) != 1 || m.removed != 1 {
						t.Fatalf("retry = %+v, %v; killed %v removed %d", res, err, m.killed, m.removed)
					}
					if pass == "retention" && res.Deleted != 1 {
						t.Errorf("retention after successful cleanup deleted %d runs, want 1", res.Deleted)
					}
				})
			}
		})
	}
}

func TestEndedListedRetainsScopeReadErrorsForRetry(t *testing.T) {
	const id = "r-00000000-000000000000a-unend0"
	for _, tc := range scopeReadFailures {
		t.Run(tc.name, func(t *testing.T) {
			root, m, clear := unreadableScope(t, id, true, tc.name)
			res, err := SweepLive(context.Background(), root, WithSweepManager(m))
			if err != nil || len(res.Errs) != 1 || !errors.Is(res.Errs[0], errOrphanAlive) || !errors.Is(res.Errs[0], tc.err) {
				t.Errorf("SweepLive = %+v, %v; want the unknown scope and its cause", res, err)
			}
			if _, err := os.Lstat(filepath.Join(root, ledger.LiveDir, id)); err != nil {
				t.Fatalf("ended run with an unknown scope lost its retry entry: %v", err)
			}
			if len(m.killed) != 0 || m.removed != 0 {
				t.Fatalf("unknown scope was touched: killed %v removed %d", m.killed, m.removed)
			}
			clear()
			res, err = SweepLive(context.Background(), root, WithSweepManager(m))
			if err != nil || len(res.Errs) != 0 || len(m.killed) != 1 || m.removed != 1 {
				t.Fatalf("retry = %+v, %v; killed %v removed %d", res, err, m.killed, m.removed)
			}
			if _, err := os.Lstat(filepath.Join(root, ledger.LiveDir, id)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("successfully cleaned ended run is still listed: %v", err)
			}
		})
	}
}

func TestSweepRetainsEndedScopeReadErrorsForRetry(t *testing.T) {
	const id = "r-00000000-000000000000a-unend1"
	for _, tc := range scopeReadFailures {
		t.Run(tc.name, func(t *testing.T) {
			root, m, clear := unreadableScope(t, id, true, tc.name)
			res, err := Sweep(context.Background(), root, 0, WithSweepManager(m))
			if err != nil || len(res.Errs) != 1 || !errors.Is(res.Errs[0], errOrphanAlive) || !errors.Is(res.Errs[0], tc.err) {
				t.Errorf("Sweep = %+v, %v; want the unknown scope and its cause", res, err)
			}
			if res.Deleted != 0 || runState(t, root, id) != ledger.StateEnded {
				t.Fatalf("ended record with an unknown scope was collected: %+v", res)
			}
			if len(m.killed) != 0 || m.removed != 0 {
				t.Fatalf("unknown scope was touched: killed %v removed %d", m.killed, m.removed)
			}
			clear()
			res, err = Sweep(context.Background(), root, 0, WithSweepManager(m))
			if err != nil || len(res.Errs) != 0 || res.Deleted != 1 || len(m.killed) != 1 || m.removed != 1 {
				t.Fatalf("retry = %+v, %v; killed %v removed %d", res, err, m.killed, m.removed)
			}
		})
	}
}

func TestSweepKeepsEndedRunsWithoutACgroupManager(t *testing.T) {
	const id = "r-00000000-000000000000a-unend2"
	for _, pass := range []string{"live", "retention"} {
		t.Run(pass, func(t *testing.T) {
			root := t.TempDir()
			endedListedRun(t, root, id, 77, goneLauncher(t))
			previous := detectCgroups
			detectCgroups = func(int) (*cgroup.FS, error) { return nil, os.ErrPermission }
			t.Cleanup(func() { detectCgroups = previous })
			var res SweepResult
			var err error
			if pass == "live" {
				res, err = SweepLive(context.Background(), root)
			} else {
				res, err = Sweep(context.Background(), root, 0)
			}
			if err != nil || len(res.Errs) != 2 || !errors.Is(res.Errs[1], errOrphanAlive) {
				t.Errorf("sweep = %+v, %v; want detection and incomplete cleanup errors", res, err)
			}
			if res.Deleted != 0 || runState(t, root, id) != ledger.StateEnded {
				t.Fatalf("ended record with no cgroup manager was collected: %+v", res)
			}
			if _, err := os.Lstat(filepath.Join(root, ledger.LiveDir, id)); err != nil {
				t.Fatalf("ended record with no cgroup manager lost its retry entry: %v", err)
			}
		})
	}
}

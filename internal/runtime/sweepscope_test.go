// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// scopeCgroups is a cgroup.Manager over a temporary tree: its root is own, a scope's id comes from ids by
// path, and it records what it killed.
type scopeCgroups struct {
	fakeCgroups
	ids     map[string]uint64
	killErr error
	waitErr error
	// removeErr is what Remove returns, with the scope left in place.
	removeErr error
	killed    []string
	onKill    func() // what the kill does to the run's processes, when a test has any
}

func (s *scopeCgroups) ID(c cgroup.Cgroup) (uint64, error) { return s.ids[c.Path], nil }
func (s *scopeCgroups) Kill(c cgroup.Cgroup) error {
	s.killed = append(s.killed, c.Path)
	if s.onKill != nil && s.killErr == nil {
		s.onKill()
	}
	return s.killErr
}
func (s *scopeCgroups) Remove(ctx context.Context, c cgroup.Cgroup) error {
	if s.removeErr != nil {
		return s.removeErr
	}
	return s.fakeCgroups.Remove(ctx, c)
}
func (s *scopeCgroups) WaitEmpty(context.Context, cgroup.Cgroup) error { return s.waitErr }

// lostRunIn leaves a run that recorded cgroup id in its run_start and died without run_end.
func lostRunIn(t *testing.T, root, id string, cgroupID uint64) {
	t.Helper()
	w := openRun(t, root, id)
	if err := w.WriteRunStartIn(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}, cgroupID); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	truncateRunEnd(t, filepath.Join(root, id))
}

// scopeUnder makes the run's scope directory under base, populated, and returns its path.
func scopeUnder(t *testing.T, base, id string) string {
	t.Helper()
	p := filepath.Join(base, identity.TopSlice, identity.AgentSlice(identity.AgentID("tester")), identity.RunScope(identity.RunID(id)))
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "cgroup.events"), []byte("populated 1\nfrozen 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSweepFindsTheOrphansScopeWhereItsLauncherMadeIt: `sudo tego run`'s
// sweep of the user's lost run looked for its scope under the root cgroup while the scope lived under
// user@<uid>.service, killed nothing and wrote run_end over a tree still running. The sweep now looks under
// every root the scope can be under, takes the one whose id run_start recorded, never a same-named scope with
// another id, and keeps the run lost while its tree survives, so the next pass meets it again.
func TestSweepFindsTheOrphansScopeWhereItsLauncherMadeIt(t *testing.T) {
	const id = "r-00000000-000000000000a-orphan"
	for _, tc := range []struct {
		name      string
		killErr   error
		waitErr   error
		decoy     bool // a scope of the same name, another id, under the sweeper's own root
		wantKill  bool
		wantEnded bool
	}{
		{"the scope under the other root is killed", nil, nil, false, true, true},
		{"a same-named scope with another id is left alone", nil, nil, true, true, true},
		{"a refused kill keeps the run lost", errors.New("EACCES"), nil, false, true, false},
		{"a tree that does not empty keeps the run lost", nil, context.DeadlineExceeded, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, own, other := t.TempDir(), t.TempDir(), t.TempDir()
			lostRunIn(t, root, id, 77)
			scope := scopeUnder(t, other, id)
			m := &scopeCgroups{fakeCgroups: fakeCgroups{root: own}, ids: map[string]uint64{scope: 77},
				killErr: tc.killErr, waitErr: tc.waitErr}
			if tc.decoy {
				m.ids[scopeUnder(t, own, id)] = 99
			}
			prev := orphanRoots
			orphanRoots = func(cgroup.Manager, markDir, runDir) []string { return []string{own, other} }
			t.Cleanup(func() { orphanRoots = prev })

			res, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(m))
			if err != nil {
				t.Fatalf("Sweep: %v", err)
			}
			if got := strings.Join(m.killed, ","); tc.wantKill != (got == scope) {
				t.Errorf("killed %q, want exactly %s", got, scope)
			}
			st, err := ledger.NewRunRepository(root).State(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if ended := st == ledger.StateEnded; ended != tc.wantEnded {
				t.Errorf("state %s after the sweep (errs %v), want ended=%v", st, res.Errs, tc.wantEnded)
			}
		})
	}
}

// TestSweepEndsARunWhoseScopeIsGone: no scope of the run's under any root is a tree already gone, and the run
// is ended as before.
func TestSweepEndsARunWhoseScopeIsGone(t *testing.T) {
	const id = "r-00000000-000000000000a-orphan"
	root, own := t.TempDir(), t.TempDir()
	lostRunIn(t, root, id, 77)
	m := &scopeCgroups{fakeCgroups: fakeCgroups{root: own}}
	prev := orphanRoots
	orphanRoots = func(cgroup.Manager, markDir, runDir) []string { return []string{own} }
	t.Cleanup(func() { orphanRoots = prev })
	res, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(m))
	if err != nil || res.Orphaned != 1 || len(m.killed) != 0 {
		t.Fatalf("orphaned %d killed %v err %v errs %v", res.Orphaned, m.killed, err, res.Errs)
	}
}

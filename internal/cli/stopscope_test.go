// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// treeCgroups is a cgroup.Manager over a temporary tree: its root is root, a scope's id comes from ids by path,
// and it records what it was asked to kill.
type treeCgroups struct {
	root   string
	ids    map[string]uint64
	killed []string
}

func (m *treeCgroups) Root() string { return m.root }
func (m *treeCgroups) Create(string, string) (cgroup.Cgroup, error) {
	return cgroup.Cgroup{}, nil
}
func (m *treeCgroups) ID(c cgroup.Cgroup) (uint64, error)             { return m.ids[c.Path], nil }
func (m *treeCgroups) SetLimits(cgroup.Cgroup, cgroup.Limits) error   { return nil }
func (m *treeCgroups) Kill(c cgroup.Cgroup) error                     { m.killed = append(m.killed, c.Path); return nil }
func (m *treeCgroups) WaitEmpty(context.Context, cgroup.Cgroup) error { return nil }
func (m *treeCgroups) OOMKilled(cgroup.Cgroup) (bool, error)          { return false, nil }
func (m *treeCgroups) Remove(context.Context, cgroup.Cgroup) error    { return nil }
func (m *treeCgroups) Events(context.Context, cgroup.Cgroup) (<-chan bool, error) {
	return nil, nil
}

// recordRootLaunch writes, in a temporary directory stop is pointed at (stopRootMarks), the record a root
// launcher leaves for the run in runDir (internal/runtime rootmark.go): a file named after the run id holding
// the directory's device and inode, the file and its directory root's alone. The real /run/tego is never
// written.
func recordRootLaunch(t *testing.T, runDir, id string) string {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(runDir, &st); err != nil {
		t.Fatal(err)
	}
	marks := filepath.Join(t.TempDir(), "launched")
	if err := os.Mkdir(marks, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(marks, id), fmt.Appendf(nil, "%d %d\n", st.Dev, st.Ino), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := stopRootMarks
	stopRootMarks = marks
	t.Cleanup(func() { stopRootMarks = prev })
	return marks
}

// TestStopEscalatesOnlyTheRunsOwnScope: the backstop kill built the scope's path under the stopper's own cgroup root
// and wrote cgroup.kill there with no check that the scope was the run's. A scope of that name whose cgroup id is not
// the one run_start recorded is not the run's, and is left alone; the one with that id is killed. As root, a
// root-owned run's scope is searched only on a root launch record, so the run's own scope with no record is left
// alone too.
func TestStopEscalatesOnlyTheRunsOwnScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		id       uint64
		noRecord bool
		wantKill bool
	}{
		{"a same-named scope with another id", 99, false, false},
		{"the run's own scope", 77, false, true},
		{"the run's own scope with no root launch record", 77, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.noRecord && os.Geteuid() != 0 {
				tc.wantKill = true // a stop by the run's owner searches its own subtree, record or none
			}
			root := gcRoot(t)
			var host [32]byte
			rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, string(rid))
			w, err := ledger.Open(dir, record.RunRef{ID: string(rid), Agent: "tester"}, ledger.WithAnchor(nopAnchor{}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = w.Close(record.RunEndPayload{Reason: record.RunEndExit}) })
			if err := w.WriteRunStartIn(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "landlock"}, 77); err != nil {
				t.Fatal(err)
			}
			// As root (root-suites), a root stop searches a root-owned run's scope only on the record a root launcher writes
			// (runtime orphanRoots), so the run is stood up as one leaves it.
			if os.Geteuid() == 0 {
				marks := recordRootLaunch(t, dir, string(rid))
				if tc.noRecord {
					if err := os.Remove(filepath.Join(marks, string(rid))); err != nil {
						t.Fatal(err)
					}
				}
			}
			tree := t.TempDir()
			scope := filepath.Join(tree, identity.TopSlice, identity.AgentSlice("tester"), identity.RunScope(rid))
			if err := os.MkdirAll(scope, 0o700); err != nil {
				t.Fatal(err)
			}
			m := &treeCgroups{root: tree, ids: map[string]uint64{scope: tc.id}}
			prev := stopCgroups
			stopCgroups = func(int) (cgroup.Manager, error) { return m, nil }
			t.Cleanup(func() { stopCgroups = prev })

			escalate(dir, string(rid), io.Discard)
			if killed := len(m.killed) == 1 && m.killed[0] == scope; killed != tc.wantKill || len(m.killed) > 1 {
				t.Errorf("killed %v, want %s killed: %v", m.killed, scope, tc.wantKill)
			}
		})
	}
}

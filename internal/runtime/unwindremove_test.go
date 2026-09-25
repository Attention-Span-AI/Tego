// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
)

// removeFailingCgroups is fakeCgroups whose Remove fails: the scope outlives the launcher's release.
type removeFailingCgroups struct{ *fakeCgroups }

func (c removeFailingCgroups) Remove(context.Context, cgroup.Cgroup) error {
	c.removed++
	return errors.New("cgroup: rmdir: device or resource busy")
}

// A run that never started, whose scope unwind could not remove, keeps its directory and its live-index entry
// as shutdown does: unwind removed both whatever the removal said, and the scope and its root launch record were
// left with nothing listing the run, which no sweep met again. With the removal done, both go.
func TestUnwindKeepsTheRunListedWhenTheScopeStays(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cgm    cgroup.Manager
		listed bool
	}{
		{"remove fails", removeFailingCgroups{&fakeCgroups{root: t.TempDir()}}, true},
		{"remove succeeds", &fakeCgroups{root: t.TempDir()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, rt, root := startupFixture(t)
			log, logged := newUnwindLog()
			deps := Deps{
				Config: m, Cgroups: tc.cgm, Enforce: &fakeBackend{}, Logger: log,
				Launcher: &launch.Launcher{Exe: filepath.Join(root, "no-such-binary")},
				Environ:  []string{"PATH=/bin"},
				Cwd:      root,
			}
			if _, err := Run(context.Background(), rt, []string{"/bin/true"}, deps); err == nil {
				t.Fatal("a launcher that cannot start the child must fail the run")
			}
			runs := runDirsIn(t, filepath.Join(root, "runs"))
			live, err := ledger.LiveEntries(filepath.Join(root, "runs"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.listed {
				if len(runs) != 1 || !slices.Contains(live, filepath.Base(runs[0])) {
					t.Fatalf("run dirs %v, live %v: the run whose scope stayed must stay listed; logged: %s", runs, live, logged)
				}
				return
			}
			if len(runs) != 0 || len(live) != 0 {
				t.Fatalf("run dirs %v, live %v: a run unwound whole must leave neither", runs, live)
			}
		})
	}
}

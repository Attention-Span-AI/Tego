// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
)

// TestRunIsListedWhileItHoldsItsLock is the launcher's half of the live index's completeness
// (record-ledger.md §3): the run is listed while it holds its lock and before run_start, so any run that can
// be lost is in the index `run` and `stop` sweep; and a run that never started takes its entry away with its
// directory.
//
// Also pins runtime-launch.md R20: the launcher lists its run after taking the lock and before run_start.
func TestRunIsListedWhileItHoldsItsLock(t *testing.T) {
	m, rt, root := startupFixture(t)
	type seen struct {
		id     string
		held   bool
		events int64
		err    error
	}
	var at seen
	prev := markLive
	markLive = func(ledgerRoot, id string) error {
		dir := filepath.Join(ledgerRoot, id)
		at.id = id
		at.held, _, at.err = ProbeLock(dir)
		if st, err := os.Stat(filepath.Join(dir, ledger.EventsFile)); err == nil {
			at.events = st.Size()
		} else {
			at.err = errors.Join(at.err, err)
		}
		if err := prev(ledgerRoot, id); err != nil {
			return err
		}
		if _, err := os.Lstat(filepath.Join(ledgerRoot, ledger.LiveDir, id)); err != nil {
			at.err = errors.Join(at.err, err)
		}
		return nil
	}
	defer func() { markLive = prev }()
	log, logged := newUnwindLog()
	_, err := Run(context.Background(), rt, []string{"/bin/true"}, Deps{
		Config: m, Cgroups: &fakeCgroups{root: t.TempDir()}, Enforce: &fakeBackend{}, Logger: log,
		Launcher: &launch.Launcher{Exe: filepath.Join(root, "no-such-binary")},
		Environ:  []string{"PATH=/bin"}, Cwd: root,
	})
	if err == nil {
		t.Fatal("a launcher that cannot start the child must fail the run")
	}
	if at.id == "" {
		t.Fatal("the run was never listed in the live index")
	}
	if at.err != nil || !at.held || at.events != 0 {
		t.Fatalf("listed with the lock held %v and %d bytes of ledger (%v), want the lock held and no line yet",
			at.held, at.events, at.err)
	}
	if left := leftBehind(t, filepath.Join(root, "runs")); len(left) != 0 {
		t.Fatalf("a run that never started left %v behind; the run logged: %s", left, logged)
	}
}

// TestRunRefusedWhenItCannotBeListed: a run the index cannot name would be lost to every sweep but gc's if
// its launcher died, so it does not start. Nothing of it is left, and no cgroup was made for it.
func TestRunRefusedWhenItCannotBeListed(t *testing.T) {
	m, rt, root := startupFixture(t)
	boom := errors.New("live index unwritable")
	prev := markLive
	markLive = func(string, string) error { return boom }
	defer func() { markLive = prev }()
	cgroups := &fakeCgroups{root: t.TempDir()}
	log, logged := newUnwindLog()
	res, err := Run(context.Background(), rt, []string{"/bin/true"},
		Deps{Config: m, Cgroups: cgroups, Enforce: &fakeBackend{}, Environ: []string{}, Cwd: root, Logger: log})
	if !errors.Is(err, boom) || res.ExitCode != 125 {
		t.Fatalf("Run: %+v %v, want exit 125 with the index's error", res, err)
	}
	if cgroups.created != 0 {
		t.Errorf("%d cgroup(s) made for a run that was never listed", cgroups.created)
	}
	if left := leftBehind(t, filepath.Join(root, "runs")); len(left) != 0 {
		t.Fatalf("left %v behind; the run logged: %s", left, logged)
	}
}

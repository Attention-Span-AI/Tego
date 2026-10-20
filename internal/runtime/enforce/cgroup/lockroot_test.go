// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestHostPinsLockOnlyInTheHostStateDir: a build pinned under the host's bpf filesystem takes its build lock, slot
// table and rings lock in the verified /run/tego and nowhere else. Every tego process on the machine (a launcher's
// Prepare and last-out removal, a reaper's build duties, the linger timer, gc) reads that one; a caller that named
// another directory for the same pins held a lock none of them saw, and on 2026-10-16 a linger timer swept a build
// under a test's Prepare that way (base finding 9). Each entry point refuses the pairing before it locks or removes
// anything; pins under another root keep a state directory of their own (the timer tests, the fake-kernel suites).
func TestHostPinsLockOnlyInTheHostStateDir(t *testing.T) {
	for _, bpffs := range []string{"", DefaultBPFFS, DefaultBPFFS + "/"} {
		state := t.TempDir()
		opts := SweepOptions{BPFFS: bpffs, StateDir: state, CgroupMount: t.TempDir(), Linger: time.Hour}
		calls := map[string]func() error{
			"ListBuilds":   func() error { _, err := ListBuilds(opts, nil); return err },
			"SweepBuilds":  func() error { _, err := SweepBuilds(opts); return err },
			"ReclaimRings": func() error { _, _, err := ReclaimRings(opts); return err },
			"TrimRings":    func() error { _, _, err := TrimRings(opts, "h1"); return err },
			"PurgeRun": func() error {
				_, err := PurgeRun(PurgeOptions{BPFFS: bpffs, StateDir: state, CgroupMount: opts.CgroupMount, Hash: "h1",
					RunID: "r1", CgroupID: 1})
				return err
			},
			"ReapBuild": func() error {
				return ReapBuild(ReapTarget{Hash: "h1", BPFFS: bpffs, StateDir: state, Linger: time.Hour}, opts.CgroupMount, nil)
			},
			"RearmTimers": func() error { _, err := RearmTimers(opts, "/nonexistent/tego"); return err },
			"Prepare": func() error {
				f := newFixture(t, func(o *Options) { o.BPFFS = bpffs; o.StateDir = state })
				h, err := f.backend.Prepare(context.Background(), f.table, f.run)
				if h != nil {
					_ = h.Close()
				}
				return err
			},
		}
		for name, call := range calls {
			if err := call(); !errors.Is(err, hoststate.ErrHostState) {
				t.Errorf("%s with pins under %q and state %s: %v, want ErrHostState: a lock no other tego process reads",
					name, bpffs, state, err)
			}
		}
		// A timer that took the split lock goes on to wait for the linger: its first sleep ends the test.
		waits := timerClock{sleep: func(time.Duration) {
			t.Fatalf("the linger timer with pins under %q and state %s took that lock and waited", bpffs, state)
		}}
		if code := runTimer("h1", time.Hour, bpffs, state, waits); code != identity.ExitError {
			t.Errorf("the linger timer with pins under %q and state %s: exit %d, want %d", bpffs, state, code, identity.ExitError)
		}
	}
}

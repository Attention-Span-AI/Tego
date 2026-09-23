// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestWatchCgroupTurnsTheKernelsCountersIntoAReason exercises R10 and R11 without a kernel: the
// watcher reads memory.events and pids.events from the cgroup's own path, so a directory holding
// those two files is all it needs. A pids.events increase kills the run at once (R11); an oom_kill
// increase does not, because the kernel has already killed what it chose (R10).
//
// It runs in a synctest bubble, whose clock is the watcher's ticker: synctest.Wait returns once the
// watcher has read its baseline and is parked on the ticker, a tick with the counters unchanged is
// shown to decide nothing, and the one tick after the bump is shown to be enough. Sleeping two real
// poll intervals only guessed that the baseline read had happened, and a slow machine could read the
// bumped counter as its baseline and never see an increase.
func TestWatchCgroupTurnsTheKernelsCountersIntoAReason(t *testing.T) {
	// returns: a refused fork ends the run, so the watcher's work is done; an oom kill is only recorded, and
	// the watcher keeps polling, so a pids.max hit after it is still acted on.
	tests := []struct {
		name     string
		bump     func(dir string)
		want     identity.EndReason
		wantKill int
		returns  bool
	}{
		{"a refused fork ends the run", func(dir string) {
			writeFile(t, filepath.Join(dir, "pids.events"), []byte("max 1\n"))
		}, identity.ReasonPids, 1, true},
		{"an oom kill is reported, not repeated", func(dir string) {
			writeFile(t, filepath.Join(dir, "memory.events"), []byte("low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n"))
		}, identity.ReasonOOM, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "pids.events"), []byte("max 0\n"))
			writeFile(t, filepath.Join(dir, "memory.events"), []byte("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"))
			synctest.Test(t, func(t *testing.T) {
				cgroups := &fakeCgroups{root: dir}
				r := &runner{
					log: slog.New(slog.DiscardHandler),
					cgm: cgroups,
					cg:  cgroup.Cgroup{Path: dir},
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- r.watchCgroup(ctx) }()
				synctest.Wait()
				time.Sleep(limitPollInterval)
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatalf("the watcher returned (%v) on a tick where no counter had moved", err)
				default:
				}
				tc.bump(dir)
				time.Sleep(limitPollInterval)
				synctest.Wait()
				select {
				case err := <-done:
					if !tc.returns {
						t.Fatalf("the watcher returned (%v) after an oom kill; it must keep polling for pids", err)
					}
					if err != nil {
						t.Fatalf("watchCgroup: %v", err)
					}
				default:
					if tc.returns {
						t.Fatal("the watcher did not act on the first tick after the counter moved")
					}
				}
				r.termMu.Lock()
				got := r.terminal
				r.termMu.Unlock()
				if got != tc.want {
					t.Fatalf("reason %q after the first tick, want %q", got, tc.want)
				}
				if !tc.returns {
					cancel()
					synctest.Wait()
					if err := <-done; err != nil {
						t.Fatalf("watchCgroup: %v", err)
					}
				}
				if r.terminal != tc.want {
					t.Fatalf("reason %q, want %q", r.terminal, tc.want)
				}
				if cgroups.killed != tc.wantKill {
					t.Fatalf("killed %d times, want %d", cgroups.killed, tc.wantKill)
				}
			})
		})
	}
}

// TestWatchCgroupStopsWithTheRun checks the watcher is an ordinary member of the run's group: it
// returns on cancellation and decides nothing. In a synctest bubble "returns" is exact: after cancel
// and synctest.Wait the watcher has either returned or is blocked for good, and the bubble fails the
// test if it leaves a goroutine behind.
func TestWatchCgroupStopsWithTheRun(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pids.events"), []byte("max 0\n"))
	writeFile(t, filepath.Join(dir, "memory.events"), []byte("oom_kill 0\n"))
	synctest.Test(t, func(t *testing.T) {
		r := &runner{log: slog.New(slog.DiscardHandler), cgm: &fakeCgroups{root: dir},
			cg: cgroup.Cgroup{Path: dir}}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- r.watchCgroup(ctx) }()
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("watchCgroup: %v", err)
			}
		default:
			t.Fatal("the watcher outlived its context")
		}
		if r.terminal != "" {
			t.Fatalf("a cancelled watcher decided %q", r.terminal)
		}
	})
}

// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeHost lays out the procfs and cgroupfs files threadBudget reads: this process's cgroup, the pids limits
// of each level of it, kernel.threads-max, the thread total in /proc/loadavg and this process's own threads.
type fakeHost struct {
	cgroup     string
	pids       map[string][2]int64 // level -> {pids.max (0 = "max"), pids.current}
	threadsMax int64
	threads    int64
	self       int64
}

func (h fakeHost) build(t *testing.T) (procRoot, cgroupRoot string) {
	t.Helper()
	root := t.TempDir()
	procRoot, cgroupRoot = filepath.Join(root, "proc"), filepath.Join(root, "cgroup")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(filepath.Join(procRoot, "self", "cgroup"), "0::"+h.cgroup+"\n")
	write(filepath.Join(procRoot, "self", "status"), "Name:\ttego\nThreads:\t"+strconv.FormatInt(h.self, 10)+"\n")
	if h.threadsMax > 0 {
		write(filepath.Join(procRoot, "sys", "kernel", "threads-max"), strconv.FormatInt(h.threadsMax, 10)+"\n")
		write(filepath.Join(procRoot, "loadavg"), "0.30 0.40 0.50 2/"+strconv.FormatInt(h.threads, 10)+" 5678\n")
	}
	for level, v := range h.pids {
		limit := "max"
		if v[0] > 0 {
			limit = strconv.FormatInt(v[0], 10)
		}
		write(filepath.Join(cgroupRoot, level, "pids.max"), limit+"\n")
		write(filepath.Join(cgroupRoot, level, "pids.current"), strconv.FormatInt(v[1], 10)+"\n")
	}
	return procRoot, cgroupRoot
}

// TestOverdueCeilingFitsTheMeasuredBudget is the half of §6 E34 a fixed ceiling got wrong. The launcher
// aborts when it cannot have another thread, and on a small host that is not the Go runtime's 10,000: clone
// fails with EAGAIN at a pids.max on the launcher's own cgroup chain, and systemd's DefaultTasksMax puts one
// at 15% of min(pid_max, threads-max), about 1,229 tasks per GiB of RAM. A 2 GiB host allows about 2,458.
// The fixed ceiling of 1,024, checked only between 64 KiB reads, let the count reach 1,024 + 2,730 + 32 =
// 3,786 blocked threads, so on that host the abort E34 calls prevented still happened, with no teardown
// (E15, E38). The ceiling is now sized from the nearest measured limit, and ceiling plus overshoot must stay
// inside half of it on every host the listener agrees to start on.
func TestOverdueCeilingFitsTheMeasuredBudget(t *testing.T) {
	t.Parallel()
	const scope = "/user.slice/user-0.slice/session-1.scope"
	cases := []struct {
		name string
		host fakeHost
		// wantSource names the limit that should bind; empty means the Go runtime's.
		wantSource string
		refuse     bool
	}{
		{
			name: "2 GiB host under systemd's DefaultTasksMax",
			host: fakeHost{cgroup: scope, self: 12, threadsMax: 16384, threads: 400,
				pids: map[string][2]int64{scope: {2458, 180}, "/user.slice": {0, 300}}},
			wantSource: "pids.max 2458",
		},
		{
			name: "3 GiB host",
			host: fakeHost{cgroup: scope, self: 12, threadsMax: 24576, threads: 500,
				pids: map[string][2]int64{scope: {3686, 200}}},
			wantSource: "pids.max 3686",
		},
		{
			name: "an ancestor's limit binds before the leaf's",
			host: fakeHost{cgroup: scope, self: 12, threadsMax: 1 << 20, threads: 500,
				pids: map[string][2]int64{scope: {0, 40}, "/user.slice/user-0.slice": {1500, 900}}},
			wantSource: "pids.max 1500",
		},
		{
			name: "kernel.threads-max nearly used up",
			host: fakeHost{cgroup: scope, self: 12, threadsMax: 8192, threads: 7600,
				pids: map[string][2]int64{scope: {0, 40}}},
			wantSource: "kernel.threads-max 8192",
		},
		{
			name: "no pids limit and a large host: the Go runtime's limit binds",
			host: fakeHost{cgroup: scope, self: 12, threadsMax: 1 << 22, threads: 900},
		},
		{
			name: "a host too small for any ceiling refuses to start the listener",
			host: fakeHost{cgroup: scope, self: 12, threadsMax: 1 << 20, threads: 500,
				pids: map[string][2]int64{scope: {400, 200}}},
			wantSource: "pids.max 400",
			refuse:     true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			procRoot, cgroupRoot := tc.host.build(t)
			budget := threadBudget(procRoot, cgroupRoot)
			want := tc.wantSource
			if want == "" {
				want = "the Go runtime's"
			}
			if !strings.Contains(budget.source, want) {
				t.Fatalf("budget %d bound by %q, want the limit %q", budget.headroom, budget.source, want)
			}
			ceiling, err := overdueCeilingFor(budget)
			if tc.refuse {
				if !errors.Is(err, errThreadBudget) {
					t.Fatalf("overdueCeilingFor(%d) = %d, %v; want errThreadBudget: no ceiling fits", budget.headroom,
						ceiling, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("overdueCeilingFor(%d): %v", budget.headroom, err)
			}
			if ceiling < fanotifyWorkers || ceiling > fanotifyOverdueCeiling {
				t.Fatalf("ceiling %d outside [%d, %d]", ceiling, fanotifyWorkers, fanotifyOverdueCeiling)
			}
			if worst := ceiling + fanOverdueOvershoot; 2*worst > budget.headroom {
				t.Fatalf("ceiling %d plus the %d-decision overshoot is %d blocked threads, more than half of the "+
					"%d this host allows (%s): the launcher can still reach the abort E34 exists to prevent",
					ceiling, fanOverdueOvershoot, worst, budget.headroom, budget.source)
			}
		})
	}
}

// TestListenerConstructorSizesItsCeiling pins the E34 sizing where it is applied, not only in the helpers
// above: with the listener constructor's measurement replaced by the fixed 1,024 cap, every other test in
// this package still passed. On a host too small for any ceiling, newFanotifyListener refuses with
// ErrFanotify before any group exists, and so does Prepare, which reaches it through its default listener
// factory; on a host that fits, the listener runs with the ceiling that host's budget allows, below the cap.
//
// It swaps package state (threadRoots, fanotifyInit) and so cannot run in parallel.
func TestListenerConstructorSizesItsCeiling(t *testing.T) {
	const scope = "/user.slice/user-0.slice/session-1.scope"
	small := fakeHost{cgroup: scope, self: 12, threadsMax: 1 << 20, threads: 500,
		pids: map[string][2]int64{scope: {400, 200}}}
	// About 1,000 tasks to spare: enough for a listener, not enough for the 1,024 cap.
	sized := fakeHost{cgroup: scope, self: 12, threadsMax: 16384, threads: 400,
		pids: map[string][2]int64{scope: {1200, 180}}}

	inits := 0
	saved, savedInit := threadRoots, fanotifyInit
	t.Cleanup(func() { threadRoots, fanotifyInit = saved, savedInit })
	fanotifyInit = func(uint, uint) (int, error) {
		inits++
		r, w, err := os.Pipe()
		if err != nil {
			return -1, err
		}
		defer r.Close()
		defer w.Close()
		return unix.Dup(int(r.Fd()))
	}
	use := func(h fakeHost) threadLimit {
		threadRoots.proc, threadRoots.cgroup = h.build(t)
		return threadBudget(threadRoots.proc, threadRoots.cgroup)
	}

	use(small)
	if l, err := newFanotifyListener(&policy{}, Run{}, nil, 0); !errors.Is(err, ErrFanotify) || !errors.Is(err, errThreadBudget) {
		if l != nil {
			_ = l.Close()
		}
		t.Fatalf("newFanotifyListener on a host with 200 tasks to spare = %v; want ErrFanotify for the thread budget", err)
	}
	if inits != 0 {
		t.Fatalf("fanotify_init was called %d times on a host too small for the listener", inits)
	}

	f := newFixture(t, func(o *Options) { o.newListener = nil })
	if _, err := f.backend.Prepare(context.Background(), f.table, f.run); !errors.Is(err, ErrFanotify) || !errors.Is(err, errThreadBudget) {
		t.Fatalf("Prepare with an fs rule on that host = %v; want ErrFanotify for the thread budget", err)
	}
	if n := f.kernel.net.rowsFor(0); n != 0 {
		t.Fatalf("%d rows left after the refused Prepare (§8 I10)", n)
	}

	budget := use(sized)
	want, err := overdueCeilingFor(budget)
	if err != nil {
		t.Fatalf("overdueCeilingFor(%d): %v", budget.headroom, err)
	}
	l, err := newFanotifyListener(&policy{}, Run{}, nil, 0)
	if err != nil {
		t.Fatalf("newFanotifyListener on a host that fits: %v", err)
	}
	defer l.Close()
	if l.overdueCeiling != want || l.overdueCeiling >= fanotifyOverdueCeiling {
		t.Fatalf("listener ceiling = %d; want %d, the budget's (%s), below the %d cap", l.overdueCeiling, want,
			budget.source, fanotifyOverdueCeiling)
	}
}

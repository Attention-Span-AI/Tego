// SPDX-License-Identifier: Apache-2.0

//go:build integration

package doctor

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestIntegrationCancelledDuringProgramsAndFanotifyLeavesNothing is I7 at the two probes that make kernel state,
// as root: doctor's context is cancelled while D7 is loading and attaching its programs and while D8 holds its
// fanotify group, and afterwards the bpf filesystem holds exactly what it held before (no pin of doctor's), no
// scratch cgroup of D3's or D7's is left, and this process holds no more BPF or fanotify descriptors than it did.
// TestProbeCancelled covers a cancel before any probe; the steps check the context only between probes, so a
// cancel during one lets that probe finish its own cleanup, which is what this test holds it to.
func TestIntegrationCancelledDuringProgramsAndFanotifyLeavesNothing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("D7 and D8 make kernel state only as root (CAP_BPF, CAP_SYS_ADMIN): run under `make vm-root-test`")
	}
	if !bpfobj.Available() {
		t.Skip("untagged: D7 loads the compiled objects; the tegobpf suite runs this")
	}
	for _, tc := range []struct {
		name string
		wrap func(cancel context.CancelFunc, c checks) checks
	}{
		{"cancelled as D7 starts", func(cancel context.CancelFunc, c checks) checks {
			real := c.programs
			c.programs = func(root bool, uid int, k Version, tier, capture []hook) (Result, []HookResult) {
				cancel()
				return real(root, uid, k, tier, capture)
			}
			return c
		}},
		{"cancelled half way through D7", func(cancel context.CancelFunc, c checks) checks {
			real := c.programs
			c.programs = func(root bool, uid int, k Version, tier, capture []hook) (Result, []HookResult) {
				// The first half of the hooks are probed, the context ends, and the rest are probed after.
				half := len(tier) / 2
				r1, rows := real(root, uid, k, tier[:half], nil)
				cancel()
				r2, more := real(root, uid, k, tier[half:], capture)
				if !r1.OK {
					r2 = r1
				}
				return r2, append(rows, more...)
			}
			return c
		}},
		{"cancelled while D8 holds its group", func(cancel context.CancelFunc, c checks) checks {
			real := c.fanotify
			c.fanotify = func(root bool, k Version) (Result, FanotifyState) {
				done := make(chan struct{})
				go func() { time.Sleep(time.Millisecond); cancel(); close(done) }()
				r, st := real(root, k)
				<-done
				return r, st
			}
			return c
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinsBefore, fdsBefore, cgBefore := bpffsEntries(t), kernelFDs(t), scratchCgroups(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			uid, _ := config.InvokingUID()
			st := scope{uid: uid, root: true, checks: tc.wrap(cancel, machineChecks)}.run(ctx)
			if ctx.Err() == nil {
				t.Fatal("the context was never cancelled: the probe the case names did not run")
			}
			t.Logf("%d checks ran before the cancel was seen", len(st.results))
			if after := bpffsEntries(t); !slices.Equal(after, pinsBefore) {
				t.Errorf("the bpf filesystem changed: before %v, after %v", pinsBefore, after)
			}
			if after := kernelFDs(t); !slices.Equal(after, fdsBefore) {
				t.Errorf("this process's BPF and fanotify descriptors: before %v, after %v", fdsBefore, after)
			}
			if after := scratchCgroups(t); !slices.Equal(after, cgBefore) {
				t.Errorf("scratch cgroups: before %v, after %v", cgBefore, after)
			}
		})
	}
}

// bpffsEntries lists every path under /sys/fs/bpf, sorted.
func bpffsEntries(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir("/sys/fs/bpf", func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an entry removed under the walk is not this test's subject
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// kernelFDs lists what this process's BPF and fanotify descriptors point at, sorted: anon_inode:bpf-prog,
// bpf-map, bpf_link and [fanotify], one entry each.
func kernelFDs(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(target, "bpf") || strings.Contains(target, "fanotify") {
			out = append(out, target)
		}
	}
	slices.Sort(out)
	return out
}

// scratchCgroups lists the cgroups whose names D3 and D7 give their throwaway cgroups, anywhere two levels down.
func scratchCgroups(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, pattern := range []string{"/sys/fs/cgroup/.tego-doctor*", "/sys/fs/cgroup/*/.tego-doctor*",
		"/sys/fs/cgroup/*/*/.tego-doctor*"} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m...)
	}
	slices.Sort(out)
	return out
}

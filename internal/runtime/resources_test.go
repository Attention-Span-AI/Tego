// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
)

// TestRunResourcesIsWhatTheCgroupSaid pins run_end.resources to the reader's answer: every value it read, a
// memory_events object only when memory.events gave a key, nothing at all for a run with no cgroup or a
// cgroup whose files gave nothing, and what was read kept when another file failed. It swaps the package's
// reader, so it does not run in parallel.
func TestRunResourcesIsWhatTheCgroupSaid(t *testing.T) {
	defer func(f func(cgroup.Cgroup) (cgroup.Resources, error)) { readResources = f }(readResources)
	u := func(n uint64) *uint64 { return &n }
	r := &runner{log: slog.New(slog.NewTextHandler(io.Discard, nil)), cg: cgroup.Cgroup{Path: "/sys/fs/cgroup/x"}}

	readResources = func(cgroup.Cgroup) (cgroup.Resources, error) {
		return cgroup.Resources{MemoryPeak: u(0), PidsPeak: u(3), CPUUsageUsec: u(9), MemoryOOMKill: u(1)},
			errors.New("cpu.stat: permission denied")
	}
	got := r.runResources()
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	// A zero peak is a value, and is written: only an absent file is absent.
	if want := `{"memory_peak":0,"pids_peak":3,"cpu_usage_usec":9,"memory_events":{"oom_kill":1}}`; string(b) != want {
		t.Fatalf("run_end.resources = %s, want %s", b, want)
	}

	readResources = func(cgroup.Cgroup) (cgroup.Resources, error) { return cgroup.Resources{}, nil }
	if got := r.runResources(); got != nil {
		t.Fatalf("nothing read became %+v, want no resources key", got)
	}
	called := false
	readResources = func(cgroup.Cgroup) (cgroup.Resources, error) { called = true; return cgroup.Resources{}, nil }
	if got := (&runner{}).runResources(); got != nil || called {
		t.Fatalf("a run with no cgroup read one (%v) or reported %+v", called, got)
	}
	if strings.Contains(string(b), "cpu_user_usec") {
		t.Fatal("a key the reader did not return was written")
	}
}

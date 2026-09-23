// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationRunEndCarriesResourcePeaks runs a workload that holds 64 MiB and twenty processes at once and
// asserts run_end.resources says so, value for value what the cgroup's own files said when they were read,
// after the tree emptied and before the cgroup was removed (runtime-launch.md §4.1 step 13). Before, run_end
// said nothing of what a run used, and an operator had nothing to size limits.memory or limits.pids from. The
// reader is wrapped to keep what it returned, so the comparison is with the files at that moment; a file this
// kernel lacks must be an absent key.
func TestIntegrationRunEndCarriesResourcePeaks(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("the workload allocates with python3: %v", err)
	}
	defer func(f func(cgroup.Cgroup) (cgroup.Resources, error)) { readResources = f }(readResources)
	var read cgroup.Resources
	var readFrom string
	readResources = func(c cgroup.Cgroup) (cgroup.Resources, error) {
		got, err := cgroup.ReadResources(c)
		read, readFrom = got, c.Path
		return got, err
	}

	script := `for i in $(seq 20); do sleep 1 & done
python3 -c 'b = b"x" * (64 << 20)'
wait
`
	f := newFixture(t, contractFor("ipeaks", []string{"/bin/sh"}, []string{"/bin/sh", python, "sleep", "seq"}))
	path := filepath.Join(f.dir, "peaks.sh")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", path}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("result %+v, want exit 0", res)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	evs := events(t, dirs[0])
	var end record.RunEndPayload
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if readFrom == "" || end.Resources == nil {
		t.Fatalf("run_end.resources = %+v, read from %q: the run's cgroup files were not read", end.Resources, readFrom)
	}
	if _, err := os.Stat(readFrom); !os.IsNotExist(err) {
		t.Errorf("the cgroup %s is still there after the run (%v)", readFrom, err)
	}
	r := end.Resources
	same := func(name string, gotp, wantp *uint64) {
		t.Helper()
		switch {
		case gotp == nil && wantp == nil:
			t.Logf("%s: absent on this kernel", name)
		case gotp == nil || wantp == nil || *gotp != *wantp:
			t.Errorf("run_end.resources.%s = %v, the file said %v", name, valueOr(gotp), valueOr(wantp))
		}
	}
	same("memory_peak", r.MemoryPeak, read.MemoryPeak)
	same("pids_peak", r.PidsPeak, read.PidsPeak)
	same("cpu_usage_usec", r.CPUUsageUsec, read.CPUUsageUsec)
	same("cpu_user_usec", r.CPUUserUsec, read.CPUUserUsec)
	same("cpu_system_usec", r.CPUSystemUsec, read.CPUSystemUsec)
	if r.CPUUsageUsec == nil || *r.CPUUsageUsec == 0 {
		t.Errorf("cpu_usage_usec = %v: cpu.stat's usage is on every cgroup v2 kernel", valueOr(r.CPUUsageUsec))
	}
	if r.MemoryPeak != nil && *r.MemoryPeak < 64<<20 {
		t.Errorf("memory_peak = %d, below the 64 MiB the workload held", *r.MemoryPeak)
	}
	if r.PidsPeak != nil && *r.PidsPeak < 20 {
		t.Errorf("pids_peak = %d, below the twenty sleeps the workload held at once", *r.PidsPeak)
	}
	t.Logf("run_end.resources: memory_peak=%v pids_peak=%v cpu_usage_usec=%v memory_events=%+v",
		valueOr(r.MemoryPeak), valueOr(r.PidsPeak), valueOr(r.CPUUsageUsec), r.MemoryEvents)
}

func valueOr(p *uint64) any {
	if p == nil {
		return "absent"
	}
	return *p
}

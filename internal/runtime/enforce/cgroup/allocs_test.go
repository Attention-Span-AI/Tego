// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The read loop answers every open a mark reports with decideOpen, by any process on the host (§6 E35), and
// the benchmarks below it show the decision making no allocation at all. These tests hold it there: a change
// that makes the decision allocate adds garbage to every open on the machine, which a benchmark only reports
// and CI's bench gate compares against the parent commit, while these fail the unit suite outright. Each
// mirrors its benchmark's policy and path.

// TestPolicyDecideOpenAllocatesNothing is BenchmarkPolicyDecideOpen's decision, allowed and refused.
func TestPolicyDecideOpenAllocatesNothing(t *testing.T) {
	p := newPolicy(policyTable([]agent.FSRule{
		fsRule(agent.FSDenyRead, "/home/u/.ssh", "/home", "~/.ssh"),
		fsRule(agent.FSDenyRead, "/home/u/.aws", "/home", "~/.aws"),
		fsRule(agent.FSDenyRead, "/etc/shadow", "/", "/etc/shadow"),
		fsRule(agent.FSWrite, "/home/u/work", "/home", "~/work"),
		fsRule(agent.FSWrite, "/tmp/run", "/tmp", "/tmp/run"),
	}, nil), "/run.scope")
	for _, tc := range []struct {
		path  string
		allow bool
	}{
		{"/home/u/work/src/main.go", true},
		{"/home/u/.ssh/id_ed25519", false},
	} {
		if v := p.decideOpen(tc.path); v.allow != tc.allow {
			t.Fatalf("decideOpen(%s) allow=%v, want %v", tc.path, v.allow, tc.allow)
		}
		if n := testing.AllocsPerRun(100, func() { p.decideOpen(tc.path) }); n != 0 {
			t.Errorf("decideOpen(%s) makes %v allocations, want 0", tc.path, n)
		}
	}
}

// TestDecideOpenByEntryCountAllocatesNothing is BenchmarkDecideOpenByEntryCount's decision at each of its entry
// counts: the index answers without allocating however many .env entries the scan wrote.
func TestDecideOpenByEntryCountAllocatesNothing(t *testing.T) {
	const allowedPath, refusedPath = "/home/u/work/pkg3/sub7/main.go", "/home/u/work/pkg3/sub3/.env"
	for _, n := range []int{20, 1000, 50_000} {
		p := entryCountPolicy(t, n)
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			for _, path := range []string{allowedPath, refusedPath} {
				if got := testing.AllocsPerRun(100, func() { p.decideOpen(path) }); got != 0 {
					t.Errorf("decideOpen(%s) against %d entries makes %v allocations, want 0", path, n, got)
				}
			}
		})
	}
}

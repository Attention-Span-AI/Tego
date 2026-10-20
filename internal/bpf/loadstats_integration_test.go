// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"sort"
	"testing"

	"github.com/cilium/ebpf"
)

// TestLoadStatsMatchKernel loads trace_proc as a timed test build does (LoadOptions: BPF_LOG_STATS, perf-cold C1) and
// holds ParseVerifierStats to the kernel: every program's log parses, and on 5.16 and later its processed count is
// the program's verified_insns (bpf_prog_info), which the kernel sets from the same counter. It also checks that each
// program has a load_time, which the cold attribution splits a collection load at (attributeLoads). The largest
// program's log is printed whole: it is the fixture testdata/verifierstats/<kernel>.log is taken from.
func TestLoadStatsMatchKernel(t *testing.T) {
	requireBPF(t)
	spec, err := Load(ObjectTraceProc)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	dropOptionalWhereAbsent(t, spec)
	unpin(spec)
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		t.Fatalf("load trace_proc with the verifier's statistics: %v", err)
	}
	defer coll.Close()
	names := make([]string, 0, len(coll.Programs))
	for name := range coll.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	var total int64
	largest, largestLog := "", ""
	var largestInsns int64
	compared := 0
	for _, name := range names {
		p := coll.Programs[name]
		st, ok := ParseVerifierStats(p.VerifierLog)
		if !ok {
			t.Errorf("%s: no statistics in its log %q", name, p.VerifierLog)
			continue
		}
		if st.Insns <= 0 || st.Limit <= 0 {
			t.Errorf("%s: %+v, want a positive count and limit", name, st)
		}
		info, err := p.Info()
		if err != nil {
			t.Fatalf("%s: info: %v", name, err)
		}
		if _, ok := info.LoadTime(); !ok {
			t.Errorf("%s: no load_time", name)
		}
		if n, ok := info.VerifiedInstructions(); ok {
			compared++
			if int64(n) != st.Insns {
				t.Errorf("%s: the log says %d insns processed, verified_insns says %d", name, st.Insns, n)
			}
		}
		t.Logf("%s: %d insns, %d states (peak %d), verified in %v", name, st.Insns, st.TotalStates, st.PeakStates, st.Verify)
		total += st.Insns
		if st.Insns > largestInsns {
			largest, largestLog, largestInsns = name, p.VerifierLog, st.Insns
		}
	}
	if compared == 0 {
		t.Logf("this kernel predates verified_insns (5.16): the log's counts are not compared")
	}
	t.Logf("trace_proc: %d programs, %d insns processed; %s's log:\n%s", len(names), total, largest, largestLog)
}

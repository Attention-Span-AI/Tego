// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestParseVerifierStatsReadsEveryKernelsFormat: the statistics lines at BPF_LOG_STATS, as each matrix kernel prints
// them (testdata/verifierstats/<row>-<kernel>.log, the largest program's log TestLoadStatsMatchKernel printed in each
// row's guest on 2026-10-19: 5.14, 6.1, 6.8, 6.12, 6.17 and 7.0; enforce-plane §10.1's cold attribution). Every one
// prints mark_read after peak_states; a kernel that drops it, or appends a field, still parses (TestParseVerifierStats).
func TestParseVerifierStatsReadsEveryKernelsFormat(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join("testdata", "verifierstats", "*.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no verifier-statistics fixtures in testdata/verifierstats")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		st, ok := ParseVerifierStats(string(b))
		if !ok {
			t.Errorf("%s: not parsed", f)
			continue
		}
		if st.Insns <= 0 || st.Limit != 1000000 || st.TotalStates <= 0 || st.PeakStates <= 0 || st.Verify <= 0 {
			t.Errorf("%s: %+v, want positive insns, states and time and the 1M limit", f, st)
		}
	}
}

func TestParseVerifierStats(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, log string
		want      VerifierStats
		ok        bool
	}{
		{"with mark_read", "verification time 5873 usec\nstack depth 64+0\n" +
			"processed 3751 insns (limit 1000000) max_states_per_insn 4 total_states 260 peak_states 251 mark_read 22\n",
			VerifierStats{Verify: 5873 * time.Microsecond, Insns: 3751, Limit: 1000000, MaxStatesPerInsn: 4, TotalStates: 260, PeakStates: 251}, true},
		{"without mark_read", "verification time 12 usec\nstack depth 0\n" +
			"processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0\n",
			VerifierStats{Verify: 12 * time.Microsecond, Insns: 2, Limit: 1000000}, true},
		{"a field appended", "verification time 7 usec\nstack depth 8\n" +
			"processed 9 insns (limit 1000000) max_states_per_insn 1 total_states 1 peak_states 1 mark_read 0 later 3\n",
			VerifierStats{Verify: 7 * time.Microsecond, Insns: 9, Limit: 1000000, MaxStatesPerInsn: 1, TotalStates: 1, PeakStates: 1}, true},
		{"a log with no processed line", "verification time 7 usec\n", VerifierStats{}, false},
		{"no log", "", VerifierStats{}, false},
	} {
		got, ok := ParseVerifierStats(c.log)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got %+v, %v; want %+v, %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

// TestAttributeLoadsSplitsAtEachProgramsLoadTime: a collection load is the maps (and the loader's preparation of the
// first program) up to the first program's load_time, then each program from its own load_time to the next one's,
// in the order the kernel took them, the last up to the end.
func TestAttributeLoadsSplitsAtEachProgramsLoadTime(t *testing.T) {
	t.Parallel()
	ms := time.Millisecond
	before, spans := attributeLoads(100*ms, 900*ms, []programStart{
		{name: "b", at: 400 * ms}, {name: "a", at: 150 * ms}, {name: "c", at: 700 * ms},
	})
	if before != 50*ms {
		t.Errorf("before the first program: %v, want 50ms", before)
	}
	want := []programSpan{{name: "a", from: 150 * ms, to: 400 * ms}, {name: "b", from: 400 * ms, to: 700 * ms},
		{name: "c", from: 700 * ms, to: 900 * ms}}
	if !reflect.DeepEqual(spans, want) {
		t.Errorf("spans %+v, want %+v", spans, want)
	}
	// No program loaded (a load that failed before its first program): everything is before.
	before, spans = attributeLoads(100*ms, 300*ms, nil)
	if before != 200*ms || len(spans) != 0 {
		t.Errorf("no programs: %v, %v", before, spans)
	}
	// A load_time outside [start, end] (a clock read before the trace began) is clamped, never negative.
	before, spans = attributeLoads(100*ms, 300*ms, []programStart{{name: "x", at: 50 * ms}})
	if before != 0 || len(spans) != 1 || spans[0].from != 100*ms || spans[0].to != 300*ms {
		t.Errorf("clamped: %v, %+v", before, spans)
	}
}

func TestKernelFramesNamesTheTopFunctions(t *testing.T) {
	t.Parallel()
	stack := "[<0>] __mutex_lock.constprop.0+0x4a4/0x9b0\n[<0>] bpf_trampoline_get+0x2c/0x90\n" +
		"[<0>] check_attach_btf_id+0x1f6/0x430\n[<0>] bpf_check+0x9a1/0x2d40\n[<0>] bpf_prog_load+0x6a2/0xb70\n"
	if got := kernelFrames(stack, 3); got != "__mutex_lock.constprop.0<bpf_trampoline_get<check_attach_btf_id" {
		t.Errorf("frames %q", got)
	}
	if got := kernelFrames("", 3); got != "running" {
		t.Errorf("empty stack: %q, want running (a task on a CPU has no saved stack to read)", got)
	}
}

// TestSlowStacksAreThoseOfSlowLoadsOnly: a sample counts for the span it fell in, and only a span over the threshold
// is reported, its commonest stacks first.
func TestSlowStacksAreThoseOfSlowLoadsOnly(t *testing.T) {
	t.Parallel()
	ms := time.Millisecond
	spans := []programSpan{{name: "maps", from: 0, to: 100 * ms}, {name: "slow", from: 100 * ms, to: 800 * ms},
		{name: "fast", from: 800 * ms, to: 900 * ms}}
	var samples []stackSample
	for at := 25 * ms; at < 900*ms; at += 50 * ms {
		frames := "running"
		if at > 300*ms && at < 700*ms {
			frames = "__mutex_lock<bpf_trampoline_get"
		}
		samples = append(samples, stackSample{at: at, frames: frames})
	}
	got := slowStacks(spans, samples, 500*ms)
	want := []stackCount{{owner: "slow", n: 8, frames: "__mutex_lock<bpf_trampoline_get"}, {owner: "slow", n: 6, frames: "running"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got := slowStacks(spans, samples, time.Second); len(got) != 0 {
		t.Errorf("no span over 1s, got %+v", got)
	}
	for _, s := range got {
		if strings.Contains(s.frames, " ") {
			t.Errorf("frames %q hold a space: the line is <name> <n> <frames>", s.frames)
		}
	}
}

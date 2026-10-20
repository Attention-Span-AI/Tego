// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The cold start's attribution (docs/p0/enforce-plane.md §10.1, perf-cold C1): what a cold `tego run` spends in each
// program's load, in each object's maps, at each of D7's hooks and in each plane-probe mode. It is measured in a test
// build only, with TEGO_TEST_PHASE_TIMING set (loadstats_tegotesthooks.go); a product build loads with cilium/ebpf's
// zero options and starts no trace (loadstats_stub.go). This file is the arithmetic both share, pure so that it is
// tested without a kernel.

// VerifierStats is what the verifier prints for a program it accepted at BPF_LOG_STATS (log_level 4): the
// "verification time N usec" line and the "processed N insns (limit L) max_states_per_insn M total_states T
// peak_states P" line. Every kernel the matrix boots (5.14 to 7.x) prints both, and mark_read after peak_states
// (testdata/verifierstats, one log a row, captured by TestLoadStatsMatchKernel).
type VerifierStats struct {
	// Verify is the kernel's own measure of bpf_check, from its start to the end of its fixups: the attach-target
	// lookup (a tracing program's bpf_trampoline_get, and any wait on its mutex) is inside it, and so is the JIT of a
	// program with subprograms (jit_subprogs); a program without any is JITed after it.
	Verify           time.Duration
	Insns            int64 // instructions processed, the verifier's cost in steps
	Limit            int64
	MaxStatesPerInsn int64
	TotalStates      int64
	PeakStates       int64
}

var (
	verifyTimeRE = regexp.MustCompile(`(?m)^verification time (\d+) usec`)
	processedRE  = regexp.MustCompile(`(?m)^processed (\d+) insns \(limit (\d+)\) max_states_per_insn (\d+) ` +
		`total_states (\d+) peak_states (\d+)`)
)

// ParseVerifierStats reads the statistics of a verifier log taken at BPF_LOG_STATS. ok is false when the log holds no
// "processed" line (a log taken at another level, or none); a log without the time line parses with Verify zero.
func ParseVerifierStats(log string) (st VerifierStats, ok bool) {
	m := processedRE.FindStringSubmatch(log)
	if m == nil {
		return VerifierStats{}, false
	}
	n := func(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v }
	st = VerifierStats{Insns: n(m[1]), Limit: n(m[2]), MaxStatesPerInsn: n(m[3]), TotalStates: n(m[4]), PeakStates: n(m[5])}
	if t := verifyTimeRE.FindStringSubmatch(log); t != nil {
		st.Verify = time.Duration(n(t[1])) * time.Microsecond
	}
	return st, true
}

// programStart is one program of a collection load and when the kernel began it: its load_time (bpf_prog_info,
// CLOCK_BOOTTIME), which bpf_prog_load sets after copying the instructions in and before bpf_check.
type programStart struct {
	name string
	at   time.Duration
}

// programSpan is the part of a collection load a program owns.
type programSpan struct {
	name     string
	from, to time.Duration
}

// attributeLoads splits a collection load that ran from start to end (CLOCK_BOOTTIME) at its programs' load_times:
// before is everything up to the first program's (cilium/ebpf creates every map before it loads any program, so this
// is the maps, with the loader's preparation of the first program: its CO-RE relocation and, in a process's first
// load, the kernel BTF it reads); each program then owns its time up to the next one's load_time (its verification
// and JIT, and the loader's preparation of the next), the last up to end. cilium/ebpf loads a collection's programs
// one after another in one goroutine, so the spans do not overlap. A load_time outside [start, end] is clamped.
func attributeLoads(start, end time.Duration, progs []programStart) (before time.Duration, spans []programSpan) {
	sorted := append([]programStart(nil), progs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].at < sorted[j].at })
	clamp := func(t time.Duration) time.Duration { return min(max(t, start), end) }
	if len(sorted) == 0 {
		return end - start, nil
	}
	before = clamp(sorted[0].at) - start
	for i, p := range sorted {
		to := end
		if i+1 < len(sorted) {
			to = clamp(sorted[i+1].at)
		}
		spans = append(spans, programSpan{name: p.name, from: clamp(p.at), to: to})
	}
	return before, spans
}

// stackSample is one read of the loading thread's kernel stack, at a CLOCK_BOOTTIME instant.
type stackSample struct {
	at     time.Duration
	frames string
}

// stackCount is how many samples of span owner found its thread in frames.
type stackCount struct {
	owner  string
	n      int
	frames string
}

// kernelFrames names the top n functions of a /proc/<pid>/task/<tid>/stack read ("[<0>] fn+0x1/0x2" lines), joined
// innermost first with "<" so the name holds no space. A task running on a CPU has no saved stack to show: "running".
func kernelFrames(stack string, n int) string {
	var fns []string
	for _, line := range strings.Split(stack, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		fn, _, _ := strings.Cut(f[1], "+")
		fns = append(fns, fn)
		if len(fns) == n {
			break
		}
	}
	if len(fns) == 0 {
		return "running"
	}
	return strings.Join(fns, "<")
}

// maxStacksPerSpan bounds what one slow span reports: its commonest stacks.
const maxStacksPerSpan = 3

// slowStacks counts the samples of each span longer than slow by the frames they found, the commonest first, at most
// maxStacksPerSpan a span, the spans in their order. A span at or under slow reports nothing: the samples are
// evidence of what held a slow load, not a profile.
func slowStacks(spans []programSpan, samples []stackSample, slow time.Duration) []stackCount {
	var out []stackCount
	for _, sp := range spans {
		if sp.to-sp.from <= slow {
			continue
		}
		counts := map[string]int{}
		for _, s := range samples {
			if s.at >= sp.from && s.at < sp.to {
				counts[s.frames]++
			}
		}
		var cs []stackCount
		for frames, n := range counts {
			cs = append(cs, stackCount{owner: sp.name, n: n, frames: frames})
		}
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].n != cs[j].n {
				return cs[i].n > cs[j].n
			}
			return cs[i].frames < cs[j].frames
		})
		if len(cs) > maxStacksPerSpan {
			cs = cs[:maxStacksPerSpan]
		}
		out = append(out, cs...)
	}
	return out
}

// SPDX-License-Identifier: Apache-2.0

// Package perf holds the tier-3 performance budgets and the arithmetic the guest perf suite (cmd/perfsuite, run
// by test/vm/perf.sh) judges its measurements with. A Budget has a Limit, which fails the suite when a
// measurement is over it, and an optional Target: the figure a spec or an ADR states (kill test 4's start
// allowance, ADR 0022's cold start) that a measurement may still miss. A miss is printed as TARGET-MISS and is an
// open condition for the owner in docs/p0/enforce-plane.md §10, never a silently relaxed budget.
package perf

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Budget is one stated ceiling on one measurement.
type Budget struct {
	// Name is the measurement's name, dotted: "start.warm.bpflsm.p50_ms".
	Name string
	// Limit fails the suite when the measurement is over it.
	Limit float64
	// Target, when nonzero, is the spec's figure: a measurement over it and at or under Limit is a TARGET-MISS.
	Target float64
	// Report marks a figure the spec states as "report" (ADR 0043 C10's deep refusal and warm start): no limit
	// fails it, and a measurement over its Target is a TARGET-MISS. It must still be present and finite.
	Report bool
	Unit   string
	// Doc says what the measurement is and where its figure is stated.
	Doc string
}

// Result is a Budget judged against a measurement.
type Result struct {
	Budget
	Value   float64
	Present bool
}

// Over says the measurement is over its limit, missing, or numerically invalid.
func (r Result) Over() bool { return !r.Present || r.invalid() || (!r.Report && r.Value > r.Limit) }

func (r Result) invalid() bool {
	for _, value := range [...]float64{r.Value, r.Limit, r.Target} {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return true
		}
	}
	return false
}

// TargetMiss says the measurement is within its limit and over the spec's figure.
func (r Result) TargetMiss() bool {
	return r.Present && !r.Over() && r.Target > 0 && r.Value > r.Target
}

// Evaluate judges each budget against got.
func Evaluate(bs []Budget, got map[string]float64) []Result {
	rs := make([]Result, 0, len(bs))
	for _, b := range bs {
		v, ok := got[b.Name]
		rs = append(rs, Result{Budget: b, Value: v, Present: ok})
	}
	return rs
}

// Report renders one line per result and says whether any failed.
func Report(rs []Result) (text string, failed bool) {
	var sb strings.Builder
	for _, r := range rs {
		status := "ok"
		switch {
		case !r.Present:
			status = "MISSING"
			failed = true
		case r.invalid():
			status = "INVALID"
			failed = true
		case r.Over():
			status = "OVER"
			failed = true
		case r.TargetMiss():
			status = "TARGET-MISS"
		}
		val := "-"
		if r.Present {
			val = strconv.FormatFloat(r.Value, 'f', -1, 64)
		}
		target := ""
		if r.Target > 0 {
			target = fmt.Sprintf(" target %v", r.Target)
		}
		limit := fmt.Sprintf("limit %v", r.Limit)
		if r.Report {
			limit = "report"
		}
		fmt.Fprintf(&sb, "BUDGET %-11s %-46s %s %s (%s%s)\n", status, r.Name, val, r.Unit, limit, target)
	}
	return sb.String(), failed
}

// Override lowers or raises limits by name, "name=value", for a dry run of the suite's failure path (a limit set
// under a measurement must fail it) and for a machine slower than the guest the figures were taken on. A name that
// is no budget, a malformed pair, or a nonfinite limit is an error.
func Override(bs []Budget, kv []string) ([]Budget, error) {
	out := append([]Budget(nil), bs...)
	for _, s := range kv {
		name, val, ok := strings.Cut(s, "=")
		if !ok {
			return nil, fmt.Errorf("override %q: want name=value", s)
		}
		v, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return nil, fmt.Errorf("override %q: %w", s, err)
		}
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("override %q: limit must be finite", s)
		}
		found := false
		for i := range out {
			if out[i].Name == name {
				out[i].Limit, out[i].Report, found = v, false, true // an override gives a report row a limit
			}
		}
		if !found {
			return nil, fmt.Errorf("override %q: no budget of that name", s)
		}
	}
	return out, nil
}

// Median is the middle of xs (the mean of the two middle ones for an even count), 0 for none.
func Median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// Min is the smallest of xs, 0 for none. Another tenant on the host only ever adds to a measurement, so the best of a
// few runs is the figure that repeats.
func Min(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	lo := xs[0]
	for _, x := range xs[1:] {
		lo = math.Min(lo, x)
	}
	return lo
}

// Percentile is the nearest-rank p-th percentile of xs (p in 1..100), 0 for none.
func Percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	rank := int(math.Ceil(p / 100 * float64(len(s))))
	if rank < 1 {
		rank = 1
	}
	return s[rank-1]
}

// Modes are the configurations the suite measures, in the order it alternates them: tier landlock is the control
// (the inherited tier-1 state every root tier composes), cgroup's plane in each mode, and tier bpflsm.
var Modes = []Mode{
	{Name: "landlock", Tier: "landlock", Plane: "auto"},
	{Name: "cgroup-lsm", Tier: "cgroup", Plane: "lsm"},
	{Name: "cgroup-fmod_ret", Tier: "cgroup", Plane: "fmod_ret"},
	{Name: "bpflsm", Tier: "bpflsm", Plane: "lsm"},
}

// SocketModes are the socket check's two configurations: landlock, the control, and tier cgroup on the fanotify
// fallback, where the only program a run attaches that runs when a socket is made is cgroup/sock_create (no plane
// socket_create; connect4 and the rest run at connect and send), so the difference is that program's cost.
var SocketModes = []Mode{Modes[0], {Name: "cgroup-fanotify", Tier: "cgroup", Plane: "fanotify"}}

// Mode is one tier and the plane mode TEGO_TEST_PLANE pins for it.
type Mode struct{ Name, Tier, Plane string }

// ModesFor is the modes a boot offers, from its /sys/kernel/security/lsm: without bpf in the list there is no LSM
// mode, so tier bpflsm and the plane's LSM mode are absent and the plane is measured in fmod_ret mode. The last mode
// is the one the fill check measures.
func ModesFor(lsm string) []Mode {
	for _, l := range strings.Split(lsm, ",") {
		if l == "bpf" {
			return Modes
		}
	}
	return []Mode{Modes[0], Modes[2]}
}

// ForModes drops the budgets that name a mode ms does not hold (a "bpflsm" or "cgroup-lsm" budget on a boot with no
// BPF LSM). A fill budget is measured in the last mode ModesFor gave.
func ForModes(bs []Budget, ms []Mode) []Budget {
	have := map[string]bool{}
	for _, m := range ms {
		have[m.Name] = true
	}
	var out []Budget
	for _, b := range bs {
		keep := true
		for _, m := range Modes {
			if !have[m.Name] && (strings.Contains(b.Name, "."+m.Name+".") || strings.Contains(b.Name, "."+m.Name+"_")) {
				keep = false
			}
		}
		if keep {
			out = append(out, b)
		}
	}
	return out
}

// Defaults are the budgets. Each cites its measurement in docs/p0/enforce-plane.md §10.
func Defaults() []Budget {
	var bs []Budget
	add := func(b Budget) { bs = append(bs, b) }
	for _, m := range Modes {
		add(Budget{Name: "start.warm." + m.Name + ".min_ms", Limit: startLimit[m.Name], Unit: "ms",
			Doc: "best of the warm starts: launch to the agent running, the build already pinned, " + m.Name})
	}
	add(Budget{Name: "start.warm.bpflsm.excess_ms", Limit: 600, Target: 130, Unit: "ms",
		Doc: "bpflsm's best warm start minus landlock's: kill test 4's allowance is about one baseline, 130 ms"})
	add(Budget{Name: "cold.bootfirst.ms", Limit: 30000, Target: 2300, Unit: "ms",
		Doc: "the boot's very first plane run, nothing pinned and the binaries and objects uncached, launch to the agent running (only when cold is the first check)"})
	for _, m := range Modes[1:] {
		add(Budget{Name: "cold." + m.Name + ".ms", Limit: 9000, Target: 2300, Unit: "ms",
			Doc: "best of the cold starts: launch to the agent running with no pinned build (after tego gc --builds), " + m.Name + "; ADR 0022's up to 2.3 s"})
	}
	add(Budget{Name: "fill.rows1000.ms", Limit: 1000, Unit: "ms", Doc: "Prepare's fill phase at 1000 deny_read rows, bpflsm"})
	add(Budget{Name: "fill.rowscap.ms", Limit: 2000, Unit: "ms", Doc: "Prepare's fill phase one row under the 4096-row cap, bpflsm"})
	for _, m := range Modes[1:] {
		add(Budget{Name: "open.excess." + m.Name + "_ns", Limit: 2000, Unit: "ns",
			Doc: "worst of three paths: best ns per open+close over landlock's (200k opens, one pinned CPU, modes alternated, record summary); kill test 4's 2 us"})
	}
	add(Budget{Name: "socket.excess.cgroup_ns", Limit: 2000, Target: 300, Unit: "ns",
		Doc: "best ns per socket(AF_INET, SOCK_STREAM, 0)+close on tier cgroup's fanotify fallback over landlock's (200k sockets, one pinned CPU, modes alternated, record summary): cgroup/sock_create's cost on an admitted socket, ADR 0018 PR 2"})
	add(Budget{Name: "setsockopt.excess.cgroup_ns", Limit: 2000, Target: 300, Unit: "ns",
		Doc: "best ns per setsockopt(TCP_NODELAY) on tier cgroup's fanotify fallback over landlock's (200k calls, one pinned CPU, modes alternated, record summary): cgroup/setsockopt's cost on an option it passes, the kernel's copy of the value included, ADR 0018 (7)"})
	for _, m := range Modes[1:] {
		add(Budget{Name: "exec.pinned." + m.Name + ".p50_excess_us", Limit: 30, Target: 15, Unit: "us",
			Doc: "best p50 of a pinned fork+exec+wait of a minimal static image, argv 512 bytes, under a command rule that " +
				"reads the whole vector, over the same mode's best p50 without rules (10,000 execs a sample, one pinned CPU, " +
				"modes and contracts alternated): ADR 0048 K7's +15 us, " + m.Name})
		add(Budget{Name: "exec.pinned." + m.Name + ".p99_excess_us", Limit: 100, Target: 50, Unit: "us",
			Doc: "the same, p99: ADR 0048 K7's +50 us, " + m.Name})
		add(Budget{Name: "exec.argv128k." + m.Name + ".excess_ms", Limit: 3, Target: 1.5, Unit: "ms",
			Doc: "best p50 of a pinned exec of a 128 KiB vector (the whole vector read, decided and pinned) over the same " +
				"mode's best p50 of that exec without rules: ADR 0048 K7's +1.5 ms, " + m.Name})
		add(Budget{Name: "exec.norules." + m.Name + ".pin_check_ns", Limit: 200, Target: 100, Unit: "ns",
			Doc: "ns a sched_process_exec pin check program spends per exec while a run without rules execs (kernel " +
				"bpf_stats, both pin programs summed): what P2 adds to every exec of an unpinned run, ADR 0048 K7's +100 ns, " +
				m.Name})
	}
	for _, m := range []string{"cgroup-lsm", "cgroup-fmod_ret"} {
		add(Budget{Name: "doctor.exec_pin." + m + ".cold_ms", Limit: 60, Target: 30, Unit: "ms",
			Doc: "doctor's exec pin cell (plane.exec_pin) in its plane mode, its phase under TEGO_TEST_PHASE_TIMING in a " +
				"doctor run, which keeps no cell answer (doctor's own scope measures every cell afresh): ADR 0048 K7's +30 ms, " + m})
	}
	// ADR 0043 C10: the name entries' figures, per plane mode (the name check, nameCheck). "set" is a contract with
	// the built-in .env entries (the slot header's name flag set), "clear" the same with deny_read: [] (flag clear).
	for _, m := range Modes[1:] {
		add(Budget{Name: "open.name.miss." + m.Name + "_ns", Limit: 100, Target: 30, Unit: "ns",
			Doc: "median ns per open+close of a name that passes no lead (out/f), set over clear: ADR 0043 C10's +30 ns, " + m.Name})
		add(Budget{Name: "open.name.lead." + m.Name + "_ns", Limit: 300, Unit: "ns",
			Doc: "the same for .envrc, a lead hit with no row: ADR 0043 C10's 300 ns, " + m.Name})
		add(Budget{Name: "open.name.refused." + m.Name + "_ns", Limit: 1000, Unit: "ns",
			Doc: "median ns per refused open of a .env.local made after Arm three levels below the scope (the name check " +
				"and its climb) over a refused open of a .env.prod beside it that has its own row (no name check): ADR 0043 " +
				"C10's 1 us, ADR 0039's go condition, " + m.Name})
		add(Budget{Name: "open.name.refused.deep." + m.Name + "_ns", Target: 1000, Report: true, Unit: "ns",
			Doc: "the same 32 levels below the scope: ADR 0043 C10's target 1 us, report, " + m.Name})
		add(Budget{Name: "rename.dir." + m.Name + "_ns", Limit: 2000, Unit: "ns",
			Doc: "median ns per rename of a directory within the scope (two climbs), set over clear: ADR 0043 C10's 2 us, " + m.Name})
		add(Budget{Name: "start.name." + m.Name + ".excess_ms", Target: 5, Report: true, Unit: "ms",
			Doc: "the name check's best warm start, set over clear (the name map's fill and the header's leads): the " +
				"package's +5 ms, report; the warm start's limit stays start.warm's, " + m.Name})
	}
	add(Budget{Name: "fill.name.ms", Limit: 5, Unit: "ms",
		Doc: "Prepare's fill phase with 64 name rows and 8 scope rows over the same contract with deny_read: [] " +
			"(medians of three), the fill check's mode: ADR 0043 C10's 5 ms"})
	for _, n := range []int{2, 8, 32} {
		add(Budget{Name: fmt.Sprintf("conc.bpflsm.n%d.all_up_s", n), Limit: concUpLimit[n], Unit: "s",
			Doc: fmt.Sprintf("time until %d simultaneous bpflsm runs are all running", n)})
		add(Budget{Name: fmt.Sprintf("conc.bpflsm.n%d.open_ratio", n), Limit: 1.5, Unit: "x",
			Doc: fmt.Sprintf("median ns per open of %d concurrent bpflsm runs over that of %d concurrent landlock runs (the control): "+
				"the plane's share stays under half again the control's at every count; an absolute difference is noise "+
				"once the runs outnumber the guest's CPUs", n, n)})
	}
	return bs
}

// startLimit is the warm start's limit per mode, ms.
var startLimit = map[string]float64{"landlock": 250, "cgroup-lsm": 1000, "cgroup-fmod_ret": 1000, "bpflsm": 1000}

// concUpLimit is the seconds n simultaneous runs may take to be all running: the build lock and the slot table
// serialize the starts, about 50 ms a run at bpflsm.
var concUpLimit = map[int]float64{2: 2, 8: 4, 32: 10}

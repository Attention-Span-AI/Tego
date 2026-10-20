// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package bpf

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/startphase"
)

// A test build's cold-start attribution (enforce-plane §10.1, perf-cold C1), on only while TEGO_TEST_PHASE_TIMING
// times the phases and TEGO_TEST_LOAD_STATS asks for it (startphase.Attributing). It never changes what is loaded or
// in what order: a collection is still one cilium/ebpf load, and the per-program split is read afterwards from each
// program's load_time, so an attributed load is the product's load with only the verifier's statistics added to it
// (what that adds is measured: enforce-plane §10.1, "Cold attribution").

var (
	// readTaskStack reads a thread's kernel stack (root only: /proc/<pid>/task/<tid>/stack needs CAP_SYS_ADMIN); a
	// test replaces it.
	readTaskStack = func(tid int) (string, error) {
		b, err := os.ReadFile(fmt.Sprintf("/proc/self/task/%d/stack", tid))
		return string(b), err
	}
	// sampleEvery is the sampler's period, and slowLoad the span over which a load's samples are reported.
	sampleEvery = 50 * time.Millisecond
	slowLoad    = 500 * time.Millisecond
)

// stackFrames is how many of a sample's innermost kernel functions are kept: enough to name a mutex and its caller
// (__mutex_lock < bpf_trampoline_get < check_attach_btf_id < bpf_check).
const stackFrames = 4

// LoadOptions asks the verifier for its statistics (BPF_LOG_STATS, log_level 4: the verification time, the
// instructions processed and the states, a few lines at the end of the log) while the load is attributed, and is the
// product's zero options otherwise. cilium/ebpf loads a program with a log level once, with no retry at the branch
// level, so a refusal in an attributed test build carries the verifier's error lines and statistics rather than the
// branch log.
func LoadOptions() ebpf.ProgramOptions {
	if !startphase.Attributing() {
		return ebpf.ProgramOptions{}
	}
	return ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}
}

// LoadTrace is one collection load's attribution: begun before the load, ended after it, in the same goroutine.
type LoadTrace struct {
	sink        startphase.Sink
	maps, progs string
	start       time.Duration // CLOCK_BOOTTIME, the clock of a program's load_time
	stop, done  chan struct{}
	samples     []stackSample // the sampler's alone until done is closed
}

// BeginLoad starts the attribution of a collection load, nil when the load is not attributed. maps names the phase
// the maps (and the loader's preparation of the first program) are reported as, and progs prefixes each program's
// own: "<progs>.<program>.{wall,verify}" phases and "<progs>.<program>.{insns,states,peak}" counts. It locks the
// calling goroutine to its thread until End, so the stack sampler reads the thread that makes the bpf(2) calls.
func BeginLoad(sink startphase.Sink, maps, progs string) *LoadTrace {
	if !startphase.Attributing() {
		return nil
	}
	runtime.LockOSThread()
	t := &LoadTrace{sink: sink, maps: maps, progs: progs, start: bootNow(), stop: make(chan struct{}), done: make(chan struct{})}
	go t.sample(unix.Gettid())
	return t
}

// sample reads the loading thread's kernel stack every sampleEvery until End: the evidence of what a slow load
// waited on (a trampoline's mutex, an RCU grace period) or that it was running. A stack the process may not read
// ends the sampling at the first read.
func (t *LoadTrace) sample(tid int) {
	defer close(t.done)
	tick := time.NewTicker(sampleEvery)
	defer tick.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-tick.C:
		}
		at := bootNow()
		s, err := readTaskStack(tid)
		if err != nil {
			return
		}
		t.samples = append(t.samples, stackSample{at: at, frames: kernelFrames(s, stackFrames)})
	}
}

// End ends the load's attribution and reports it: the maps phase, each program's span and verifier statistics, and
// the stacks of any span longer than slowLoad. progs is what the load returned (nil after a failed load, which
// reports the whole load as the maps phase). On a nil trace it does nothing.
func (t *LoadTrace) End(progs map[string]*ebpf.Program) {
	if t == nil {
		return
	}
	end := bootNow()
	close(t.stop)
	<-t.done
	runtime.UnlockOSThread()
	var starts []programStart
	for name, p := range progs {
		if p == nil {
			continue
		}
		info, err := p.Info()
		if err != nil {
			continue
		}
		if at, ok := info.LoadTime(); ok {
			starts = append(starts, programStart{name: name, at: at})
		}
	}
	before, spans := attributeLoads(t.start, end, starts)
	startphase.Report(t.sink, t.maps, before)
	all := []programSpan{{name: t.maps, from: t.start, to: t.start + before}}
	for _, sp := range spans {
		name := t.progs + "." + sp.name
		startphase.Report(t.sink, name+".wall", sp.to-sp.from)
		reportProgram(t.sink, name, progs[sp.name])
		all = append(all, programSpan{name: name, from: sp.from, to: sp.to})
	}
	for _, c := range slowStacks(all, t.samples, slowLoad) {
		startphase.Stack(c.owner, c.n, c.frames)
	}
}

// ReportProgram reports one loaded program's verifier statistics under name, for a load made outside a LoadTrace
// (D7's one program per hook).
func ReportProgram(name string, p *ebpf.Program) { reportProgram(nil, name, p) }

func reportProgram(sink startphase.Sink, name string, p *ebpf.Program) {
	if p == nil || !startphase.Attributing() {
		return
	}
	st, ok := ParseVerifierStats(p.VerifierLog)
	if !ok {
		return
	}
	startphase.Report(sink, name+".verify", st.Verify)
	startphase.Stat(name+".insns", st.Insns)
	startphase.Stat(name+".states", st.TotalStates)
	startphase.Stat(name+".peak", st.PeakStates)
}

// bootNow is CLOCK_BOOTTIME, the clock bpf_prog_info's load_time is read on.
func bootNow() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}

// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// Skipped programs (ADR 0148, GAPS C53). The kernel skips a BPF program it finds already running on the CPU: the
// trampoline's per-program recursion guard (fexit, fmod_ret, and LSM before 6.2 and 6.1.54), the raw tracepoint's
// (tp_btf) and the one bpf_prog_active
// counter of the syscall tracepoints. Where the kernel preempts kernel code, a task preempted inside such a program
// holds its guard, and every other task that reaches the hook on that CPU before it resumes is skipped; the program
// counts each skip in bpf_prog_info.recursion_misses. A skipped deciding program lets the hooked action go on
// undecided; a skipped cgroup_mkdir leaves a child cgroup of a run out of the run set, so its tasks are no run's.
//
// A run watches the programs its rules rely on: the plane's hooks in its mode when the plane decides it, the exec pin
// check when its slot is pinned and the run claims the kernel holds its execs (ExecPinClaim), the listener cleanup when
// its row carries RunListenerResults, and cgroup_mkdir, since every run's row admits descendants. Each is resolved from
// the link this launcher holds, which keeps that instance attached for the run, and the instance is held open, so the
// counter read is the one the hook runs. LSM programs are read too: from 6.2 (6.1.54 in the 6.1 series) the trampoline
// enters them with no recursion check, and before it doctor admits LSM mode only where kernel code is not preempted
// (internal/doctor lsmrecursion.go), so a move there is a kernel that changed, seen rather than trusted, for one bpf(2)
// call per program per reading. A pinned run whose claim doctor withheld (a kernel that preempts kernel code, where the
// check can be skipped) does not watch the check: its run_start already says exec rules on argv are best effort, and
// each exec the check missed is its own line, argv_facts unproven. cgroup_mkdir runs with interrupts off under
// trace_cgroup_path_lock, so no skip of it is reachable; it is watched as a kernel that changed would be. Programs whose
// run path has no skip counter at all (the cgroup programs, the capture uprobes) are not read.

// ProgramSkips is one reading of the kernel's skip counters (bpf_prog_info.recursion_misses) of the shared programs a
// run's rules rely on: Deciding sums the programs that decide or hold decision state for it (the plane's hooks and,
// when the run uses them, its exec pin check and listener cleanup), Tracking the program that adds its child cgroups to
// the run set. The programs are the build's and serve every run of it and every task that reaches their hooks, so a
// count is build-wide: it says a skip may have been this run's, never that it was.
type ProgramSkips struct {
	Deciding, Tracking uint64
	// Programs is how many programs the reading summed.
	Programs int
}

// skipClass is what a watched program's skip can break.
type skipClass uint8

const (
	// skipDeciding: an action the program decides goes on undecided, or decision state it clears is left behind.
	skipDeciding skipClass = iota + 1
	// skipTracking: a child cgroup of the run is left out of the run set.
	skipTracking
)

// programCounter is one watched program's skip counter.
type programCounter interface {
	misses() (uint64, error)
	close() error
}

// watchedProgram is one program a run's rules rely on.
type watchedProgram struct {
	name    string
	class   skipClass
	counter programCounter
}

// skipWatch is the programs one run watches. It is built once, after Prepare attached them, and closed with the
// handle.
type skipWatch struct {
	mu     sync.Mutex
	progs  []watchedProgram
	closed bool
}

// read sums the watched programs' counters by class. Any counter that cannot be read fails the whole reading: a
// partial sum would read as fewer skips.
func (w *skipWatch) read() (ProgramSkips, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ProgramSkips{}, errors.New("cgroup: the run's skip counters are closed")
	}
	s := ProgramSkips{Programs: len(w.progs)}
	for _, p := range w.progs {
		n, err := p.counter.misses()
		if err != nil {
			return ProgramSkips{}, fmt.Errorf("cgroup: skip counter of %s: %w", p.name, err)
		}
		switch p.class {
		case skipDeciding:
			s.Deciding += n
		case skipTracking:
			s.Tracking += n
		}
	}
	return s, nil
}

func (w *skipWatch) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	var err error
	for _, p := range w.progs {
		err = errors.Join(err, p.counter.close())
	}
	w.progs = nil
	return err
}

// linkedCounter is the counter of the program instance a held link runs. The link is the kernel's or the plane's,
// which close it; the program descriptor is this counter's own.
type linkedCounter struct {
	prog *ebpf.Program
}

func (c linkedCounter) misses() (uint64, error) {
	st, err := c.prog.Stats()
	if err != nil {
		return 0, err
	}
	return st.RecursionMisses, nil
}

func (c linkedCounter) close() error { return c.prog.Close() }

// namedLink is a held link, by the program name it was attached for, and how to open the counter of the program it
// runs.
type namedLink struct {
	name string
	open func() (programCounter, error)
}

// skipLinker is a loaded object set that names the links it holds (bpfKernel, bpfPlane). The test fakes have none, so a
// handle over one watches nothing and ProgramSkips refuses.
type skipLinker interface {
	skipLinks() []namedLink
}

func (k *bpfKernel) skipLinks() []namedLink { return namedLinks(k.shared) }

func (p *bpfPlane) skipLinks() []namedLink { return namedLinks(p.links) }

func namedLinks(ls []sharedLink) []namedLink {
	out := make([]namedLink, 0, len(ls))
	for _, l := range ls {
		if l.Link == nil {
			continue
		}
		held := l.Link
		out = append(out, namedLink{name: filepath.Base(l.pin), open: func() (programCounter, error) {
			return openLinkedCounter(held)
		}})
	}
	return out
}

// skipWant is the programs a run's rules rely on, by name and class (the package comment above); pinned is a pinned run
// that claims the kernel holds its execs.
func skipWant(planeMode ebpfbindings.PlaneMode, pinned, listener bool) map[string]skipClass {
	want := map[string]skipClass{ebpfbindings.ProgCgroupMkdir: skipTracking}
	if planeMode != "" {
		for _, h := range ebpfbindings.PlaneHooks {
			want[planeProgram(h, planeMode)] = skipDeciding
		}
		if pinned {
			want[ebpfbindings.PlaneExecPinProgram(planeMode)] = skipDeciding
		}
	}
	if listener {
		for _, name := range []string{ebpfbindings.ProgBindResult, ebpfbindings.ProgListenResult,
			ebpfbindings.ProgURingBindResult, ebpfbindings.ProgURingListenResult} {
			want[name] = skipDeciding
		}
	}
	return want
}

// openLinkedCounter opens the program a held link runs: the instance the hook runs for as long as the link is held.
func openLinkedCounter(l link.Link) (programCounter, error) {
	info, err := l.Info()
	if err != nil {
		return nil, fmt.Errorf("link info: %w", err)
	}
	p, err := ebpf.NewProgramFromID(info.Program)
	if err != nil {
		return nil, fmt.Errorf("program %d: %w", info.Program, err)
	}
	return linkedCounter{prog: p}, nil
}

// kernelCountsSkips reports whether the running kernel's bpf_prog_info carries recursion_misses (5.12 and later). A
// kernel without it reads every counter as 0, which must not pass for "no skips". A variable for the tests.
var kernelCountsSkips = func() error {
	spec, err := ebpfbindings.KernelBTF()
	if err != nil {
		return fmt.Errorf("kernel BTF: %w", err)
	}
	var info *btf.Struct
	if err := spec.TypeByName("bpf_prog_info", &info); err != nil {
		return fmt.Errorf("kernel BTF has no struct bpf_prog_info: %w", err)
	}
	for _, m := range info.Members {
		if m.Name == "recursion_misses" {
			return nil
		}
	}
	return errors.New("this kernel's bpf_prog_info has no recursion_misses: it does not count skipped programs")
}

// buildSkipWatch resolves the programs want names from the links the sets hold. A wanted program with no link is one
// this kernel or this build did not attach (an optional hook, a listener program of a run with none), which nothing can
// skip; a link whose program cannot be opened fails the watch.
func buildSkipWatch(want map[string]skipClass, sets ...skipLinker) (*skipWatch, error) {
	if err := kernelCountsSkips(); err != nil {
		return nil, err
	}
	w := &skipWatch{}
	for _, set := range sets {
		if set == nil {
			continue
		}
		for _, nl := range set.skipLinks() {
			class, ok := want[nl.name]
			if !ok {
				continue
			}
			c, err := nl.open()
			if err != nil {
				_ = w.close()
				return nil, fmt.Errorf("cgroup: skip counter of %s: %w", nl.name, err)
			}
			w.progs = append(w.progs, watchedProgram{name: nl.name, class: class, counter: c})
		}
	}
	return w, nil
}

// ProgramSkips is the runtime's enforce.SkipCounter: the summed skip counters of the programs this run's rules rely on. The first
// call, which the runtime makes before the child is released, resolves them; a handle with no loaded objects, or one
// already detached, refuses rather than read as no skips.
func (h *Handle) ProgramSkips() (ProgramSkips, error) {
	h.skipMu.Lock()
	if h.skips == nil {
		if h.kern == nil || !h.prepared || h.detached || h.closed {
			h.skipMu.Unlock()
			return ProgramSkips{}, errors.New("cgroup: the run's programs are not attached")
		}
		kern, ok := h.kern.(skipLinker)
		if !ok {
			h.skipMu.Unlock()
			return ProgramSkips{}, errors.New("cgroup: this kernel names no links to watch")
		}
		var plane skipLinker
		if h.planeMode != "" {
			if plane, ok = h.plane.(skipLinker); !ok {
				h.skipMu.Unlock()
				return ProgramSkips{}, errors.New("cgroup: the plane names no links to watch")
			}
		}
		_, pinned := h.ExecPins()
		claimed, _ := h.ExecPinClaim()
		listener := h.runRow().Flags&ebpfbindings.RunListenerResults != 0
		w, err := buildSkipWatch(skipWant(h.planeMode, pinned && claimed, listener), kern, plane)
		if err != nil {
			h.skipMu.Unlock()
			return ProgramSkips{}, err
		}
		h.skips = w
	}
	w := h.skips
	h.skipMu.Unlock()
	return w.read()
}

// closeSkips releases the watched programs' descriptors (Close).
func (h *Handle) closeSkips() error {
	h.skipMu.Lock()
	defer h.skipMu.Unlock()
	if h.skips == nil {
		return nil
	}
	err := h.skips.close()
	h.skips = nil
	return err
}

// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// ErrAttachRefused is AttachTrace's refusal, made before the kernel is asked: a name that is no host-wide tracing
// program, no program at all, or a program whose type is not the one its attach kind takes.
var ErrAttachRefused = errors.New("bpf: attach refused before the kernel was asked")

// AttachKind is how a host-wide tracing program (one of TrackPrograms and TracePrograms) reaches its hook: the link
// constructor that takes it, and so the program type it has. A program's kind follows from its name alone
// (AttachKindOf), and AttachTrace is the only code that acts on it, for the backend (attachShared) and for every
// integration fixture that loads trace_proc alike, so the choice has one copy that cannot go stale in another
// (enforce-cgroup-observe.md R14, v73 review root R8). TestTraceProgramsAttachByTheirProgramType holds every
// program's kind to the type its SEC() compiles to.
type AttachKind uint8

const (
	// AttachKindTracing is a BPF_PROG_TYPE_TRACING program (tp_btf, fentry, fexit), attached by link.AttachTracing:
	// the kernel takes the hook from the target the program was loaded with.
	AttachKindTracing AttachKind = iota + 1
	// AttachKindTracepoint is a BPF_PROG_TYPE_TRACEPOINT program on a syscall tracepoint (ListenerTracepoints and
	// ExecResultTracepoints name the event), attached by link.Tracepoint.
	AttachKindTracepoint
)

// syscallsGroup is the tracefs group of every AttachKindTracepoint program's event.
const syscallsGroup = "syscalls"

// String names the kind as the attach errors do.
func (k AttachKind) String() string {
	switch k {
	case AttachKindTracing:
		return "tracing"
	case AttachKindTracepoint:
		return "tracepoint"
	}
	return fmt.Sprintf("AttachKind(%d)", uint8(k))
}

// ProgramType is the type of the programs a kind attaches, which is what the loader gives them from their SEC().
func (k AttachKind) ProgramType() ebpf.ProgramType {
	switch k {
	case AttachKindTracing:
		return ebpf.Tracing
	case AttachKindTracepoint:
		return ebpf.TracePoint
	}
	return ebpf.UnspecifiedProgram
}

// AttachKindOf is the kind of the program called name, and for a tracepoint the event of the syscalls group it
// attaches to ("" for a tracing program); ok is false for a name that is neither in TrackPrograms nor in
// TracePrograms. The programs of ListenerTracepoints and ExecResultTracepoints are the tracepoint ones, and every
// other is tracing, whatever its hook (a raw tracepoint, fentry, fexit).
func AttachKindOf(name string) (kind AttachKind, event string, ok bool) {
	if !slices.Contains(TrackPrograms, name) && !slices.Contains(TracePrograms, name) {
		return 0, "", false
	}
	for _, tracepoints := range []map[string]string{ListenerTracepoints, ExecResultTracepoints} {
		if ev, isTracepoint := tracepoints[name]; isTracepoint {
			return AttachKindTracepoint, ev, true
		}
	}
	return AttachKindTracing, "", true
}

// AttachTrace attaches prog, the loaded program called name, to its hook as its kind says (AttachKindOf), and returns
// the link. What link.Tracepoint or link.AttachTracing answers is returned as it came, never wrapped:
// ExecResultAttachUnavailable reads the library's own error text to tell an optional link the machine refuses from
// a failure. A name with no kind, a nil program and a program of another type than its kind attaches are refused
// first (ErrAttachRefused), naming the program, which the library's own check of the type does not (and
// link.AttachTracing does not check a nil program at all).
func AttachTrace(name string, prog *ebpf.Program) (link.Link, error) {
	kind, event, ok := AttachKindOf(name)
	if !ok {
		return nil, fmt.Errorf("%w: %s is neither a TrackPrograms nor a TracePrograms program", ErrAttachRefused, name)
	}
	if prog == nil {
		return nil, fmt.Errorf("%w: %s was not loaded", ErrAttachRefused, name)
	}
	if got, want := prog.Type(), kind.ProgramType(); got != want {
		return nil, fmt.Errorf("%w: %s attaches as a %s program (%s), but the loaded program is %s: its SEC() in bpf/ "+
			"and its place in names.go disagree", ErrAttachRefused, name, kind, want, got)
	}
	switch kind {
	case AttachKindTracepoint:
		return link.Tracepoint(syscallsGroup, event, prog, nil)
	case AttachKindTracing:
		return link.AttachTracing(link.TracingOptions{Program: prog})
	}
	return nil, fmt.Errorf("%w: %s has kind %s", ErrAttachRefused, name, kind)
}

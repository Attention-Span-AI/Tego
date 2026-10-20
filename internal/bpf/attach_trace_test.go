// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// TestAttachKindOfNamesEveryHostWideTracingProgram is the name half of the v73 review's root R8: every program
// the backend attaches host-wide (TrackPrograms and TracePrograms) has an attach kind, the programs of
// ListenerTracepoints and ExecResultTracepoints are exactly the tracepoint ones and carry the event those maps
// name, and no other name has a kind. The type half, that each kind is the type the object's SEC() compiles to,
// needs the objects (TestTraceProgramsAttachByTheirProgramType).
func TestAttachKindOfNamesEveryHostWideTracingProgram(t *testing.T) {
	t.Parallel()
	events := map[string]string{}
	for _, m := range []map[string]string{ListenerTracepoints, ExecResultTracepoints} {
		for name, event := range m {
			if prev, dup := events[name]; dup {
				t.Fatalf("%s is in both tracepoint maps, as %s and %s", name, prev, event)
			}
			events[name] = event
			if !slices.Contains(TracePrograms, name) {
				t.Errorf("%s names a syscall tracepoint but is not in TracePrograms, so no loader would attach it", name)
			}
		}
	}
	if len(events) == 0 {
		t.Fatal("no program is attached as a tracepoint")
	}
	for _, name := range slices.Concat(TrackPrograms, TracePrograms) {
		kind, event, ok := AttachKindOf(name)
		if !ok {
			t.Errorf("%s has no attach kind", name)
			continue
		}
		want, isTracepoint := events[name]
		switch {
		case isTracepoint && (kind != AttachKindTracepoint || event != want):
			t.Errorf("%s is attached as %s on %q, want a tracepoint on %q (the syscall result programs are not tracing programs)",
				name, kind, event, want)
		case !isTracepoint && (kind != AttachKindTracing || event != ""):
			t.Errorf("%s is attached as %s on %q, want a tracing program with no event", name, kind, event)
		}
	}
	for _, name := range slices.Concat(CgroupPrograms, NetControlPrograms, SSLPrograms, []string{"", "tego_nope"}) {
		if kind, event, ok := AttachKindOf(name); ok {
			t.Errorf("%q has the attach kind %s on %q, but it is no host-wide tracing program", name, kind, event)
		}
	}
}

// TestAttachKindsKnowTheirProgramTypes pins the two kinds to the program types the library's constructors take:
// link.AttachTracing wants Tracing and link.Tracepoint wants TracePoint.
func TestAttachKindsKnowTheirProgramTypes(t *testing.T) {
	t.Parallel()
	for kind, want := range map[AttachKind]ebpf.ProgramType{AttachKindTracing: ebpf.Tracing, AttachKindTracepoint: ebpf.TracePoint} {
		if got := kind.ProgramType(); got != want {
			t.Errorf("%s programs have type %s, want %s", kind, got, want)
		}
	}
	if got := AttachKind(0).ProgramType(); got != ebpf.UnspecifiedProgram {
		t.Errorf("no kind has the program type %s", got)
	}
}

// TestAttachTraceRefusesBeforeAskingTheKernel: a name with no kind, a program that was never loaded and a program
// of the wrong type are refused with ErrAttachRefused and the program named, whatever the privilege of the caller.
// A zero ebpf.Program has the unspecified type, which no kind takes.
func TestAttachTraceRefusesBeforeAskingTheKernel(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		prog *ebpf.Program
		want []string
	}{
		{"tego_nope", &ebpf.Program{}, []string{"tego_nope", "neither"}},
		{ProgConnect4, &ebpf.Program{}, []string{ProgConnect4, "neither"}},
		{ProgBindResult, nil, []string{ProgBindResult, "not loaded"}},
		{ProgSchedExec, nil, []string{ProgSchedExec, "not loaded"}},
		{ProgBindResult, &ebpf.Program{}, []string{ProgBindResult, "tracepoint program", ebpf.TracePoint.String(), ebpf.UnspecifiedProgram.String()}},
		{ProgSchedExec, &ebpf.Program{}, []string{ProgSchedExec, "tracing program", ebpf.Tracing.String(), ebpf.UnspecifiedProgram.String()}},
	} {
		l, err := AttachTrace(tc.name, tc.prog)
		if l != nil || !errors.Is(err, ErrAttachRefused) {
			t.Errorf("AttachTrace(%s, %v) = %v, %v, want ErrAttachRefused", tc.name, tc.prog, l, err)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("AttachTrace(%s) says %q, which does not name %q", tc.name, err, w)
			}
		}
	}
}

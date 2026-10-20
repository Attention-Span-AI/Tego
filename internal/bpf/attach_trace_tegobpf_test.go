// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"slices"
	"testing"

	"github.com/cilium/ebpf"
)

// tracingHooks are the attach types of the Tracing programs AttachTrace hands to link.AttachTracing with no attach
// type of its own: the kernel reads the hook from the program's load-time target.
var tracingHooks = []ebpf.AttachType{ebpf.AttachTraceRawTp, ebpf.AttachTraceFEntry, ebpf.AttachTraceFExit}

// TestTraceProgramsAttachByTheirProgramType is the type half of the v73 review's root R8, which needs the objects:
// every program the backend attaches host-wide, in both builds of trace_proc and in cgroup_track, has the attach
// kind its compiled type calls for. AttachTrace picks link.Tracepoint or link.AttachTracing by the kind, and a
// program of the other type fails the attach ("invalid program type TracePoint, expected Tracing") only where
// the program is loaded: as root, in the guest. A tracepoint program's section also names the event
// ExecResultTracepoints or ListenerTracepoints give it, and a tracing program is a raw tracepoint, fentry or
// fexit program, which is what link.AttachTracing takes with no attach type.
func TestTraceProgramsAttachByTheirProgramType(t *testing.T) {
	for _, tc := range []struct {
		object   Object
		programs []string
	}{
		{ObjectCgroupTrack, TrackPrograms},
		{ObjectTraceProc, TracePrograms},
	} {
		readers := []Reader{ReaderProbe}
		if HasReaders(tc.object) {
			readers = Readers
		}
		for _, r := range readers {
			t.Run(tc.object.String()+"/"+string(r), func(t *testing.T) {
				spec, err := LoadReader(tc.object, r)
				if err != nil {
					t.Fatalf("LoadReader: %v", err)
				}
				for _, name := range tc.programs {
					ps, ok := spec.Programs[name]
					if !ok {
						t.Errorf("%s has no program %s", tc.object, name)
						continue
					}
					kind, event, ok := AttachKindOf(name)
					if !ok {
						t.Errorf("%s has no attach kind", name)
						continue
					}
					if got := kind.ProgramType(); ps.Type != got {
						t.Errorf("%s is SEC(%q), a %s program, and is attached as %s, which takes %s programs", name,
							ps.SectionName, ps.Type, kind, got)
						continue
					}
					switch kind {
					case AttachKindTracepoint:
						if want := syscallsGroup + "/" + event; ps.AttachTo != want || ps.SectionName != "tracepoint/"+want {
							t.Errorf("%s is SEC(%q) on %q, want tracepoint/%s", name, ps.SectionName, ps.AttachTo, want)
						}
					case AttachKindTracing:
						if !slices.Contains(tracingHooks, ps.AttachType) {
							t.Errorf("%s is SEC(%q), attach type %s: not a raw tracepoint, fentry or fexit program", name,
								ps.SectionName, ps.AttachType)
						}
					}
				}
			})
		}
	}
}

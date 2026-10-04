// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type fsNamingRecorder struct {
	plainSource
	fn    func(tid int, op, name, name2 string, at uint64) (string, string, string, record.Verdict, record.Reason, bool)
	execs bool
}

func (s *fsNamingRecorder) SetContinuedFS(fn func(tid int, op, name, name2 string, at uint64) (string, string, string, record.Verdict, record.Reason, bool)) {
	s.fn = fn
}

func (s *fsNamingRecorder) SetSupervisorExecs(on bool) { s.execs = on }

// TestKernelRecorderTakesTheSupervisorsFSNaming: the kernel recorder is handed the supervisor's naming of the fs
// actions the supervisor leaves to the recorder's line, and told the supervisor writes every exec's line
// (supervisor.md R7a); a recorder that cannot take them, or no recorder, is left alone.
func TestKernelRecorderTakesTheSupervisorsFSNaming(t *testing.T) {
	lookup := func(tid int, op, name, name2 string, at uint64) (supervisor.FSNaming, bool) {
		return supervisor.FSNaming{Path: "/p/" + name, Rule: "unmatched", Verdict: record.VerdictRefused}, tid == 7 && at == 9
	}
	rec := &fsNamingRecorder{plainSource: plainSource{name: "observe"}}
	r := newTestRunner(Deps{})
	r.kernelRecord = rec
	r.superviseKernelRecord(lookup)
	if rec.fn == nil || !rec.execs {
		t.Fatalf("the kernel recorder was not handed the naming (%v) or the exec ownership (%v)", rec.fn != nil, rec.execs)
	}
	if p, _, rule, v, _, ok := rec.fn(7, record.FSUnlink, "x", "", 9); !ok || p != "/p/x" || rule != "unmatched" || v != record.VerdictRefused {
		t.Errorf("the recorder's lookup answers %q %q %s %v", p, rule, v, ok)
	}
	for _, src := range []source.Source{nil, &plainSource{name: "observe"}} {
		r := newTestRunner(Deps{})
		r.kernelRecord = src
		r.superviseKernelRecord(lookup) // must not panic
	}
}

// planeHandle is a tier whose kernel decision plane runs in mode and decides execs when execs is set.
type planeHandle struct {
	plainHandle
	mode  string
	execs bool
}

func (h planeHandle) DecisionPlane() (string, bool) { return h.mode, h.execs }

type planeNamingRecorder struct {
	fsNamingRecorder
	mode string
}

func (s *planeNamingRecorder) SetDecisionPlane(mode string) { s.mode = mode }

// TestKernelRecorderOwnsExecsUnderThePlane is supervisor.md R7a at tier 3 (TIER3-PLAN T9): when the run's decision
// plane decides its execs, the kernel writes each continued exec's one line, so the recorder is told the supervisor
// does not, and it names the plane's mode; a plane that decides no exec (no exec: section) leaves the execs to the
// supervisor.
func TestKernelRecorderOwnsExecsUnderThePlane(t *testing.T) {
	lookup := func(int, string, string, string, uint64) (supervisor.FSNaming, bool) {
		return supervisor.FSNaming{}, false
	}
	for _, tc := range []struct {
		handle    planeHandle
		supExecs  bool
		planeExec bool
	}{
		{planeHandle{mode: record.DecisionPlaneLSM, execs: true}, false, true},
		{planeHandle{mode: record.DecisionPlaneFmodRet, execs: false}, true, false},
		{planeHandle{}, true, false},
	} {
		rec := &planeNamingRecorder{fsNamingRecorder: fsNamingRecorder{plainSource: plainSource{name: "observe"}}}
		r := newTestRunner(Deps{})
		r.kernelRecord, r.handle = rec, tc.handle
		r.superviseKernelRecord(lookup)
		if rec.execs != tc.supExecs || rec.mode != tc.handle.mode || r.planeExecs() != tc.planeExec {
			t.Errorf("%+v: supervisor execs %v, mode %q, plane execs %v; want %v, %q, %v", tc.handle, rec.execs,
				rec.mode, r.planeExecs(), tc.supExecs, tc.handle.mode, tc.planeExec)
		}
	}
}

// filterHandle is a tier whose plane leaves dropped out of its filter once told to (enforce.PlaneFilterer).
type filterHandle struct {
	plainHandle
	dropped []string
	used    *bool
}

func (h filterHandle) UsePlaneFilter() []string { *h.used = true; return h.dropped }

// namingSource is a kernel recorder that says whether it names path-hook records on its own (PathHookNamer).
type namingSource struct {
	plainSource
	names bool
}

func (s *namingSource) NamesPathHooks() bool { return s.names }

// TestPlaneFilterIsUsedOnlyWithARecorder is ADR 0024 (14)'s condition (TIER3-PLAN T16): the tier's filter stops
// notifying what its plane decides only when the run's kernel recorder will write those actions' lines and name
// them by path on its own (observe.Recorder does, by the kernel's directory walk); without one, or with one that
// cannot name them, every notification stays. With mutations left out the supervisor keeps no walk cache (planeFS).
func TestPlaneFilterIsUsedOnlyWithARecorder(t *testing.T) {
	obs := plainSource{name: "observe"}
	for _, tc := range []struct {
		name    string
		rec     source.Source
		dropped []string
		used    bool
		planeFS bool
	}{
		{"no recorder", nil, []string{"rename"}, false, false},
		{"a recorder that does not name path hooks", &plainSource{name: "observe"}, []string{"rename"}, false, false},
		{"a recorder that says it cannot", &namingSource{plainSource: obs}, []string{"rename"}, false, false},
		{"a naming recorder, mutations dropped", &namingSource{plainSource: obs, names: true}, []string{"rename"}, true, true},
		{"a naming recorder, nothing to drop", &namingSource{plainSource: obs, names: true}, nil, true, false},
	} {
		used := false
		r := newTestRunner(Deps{})
		r.kernelRecord = tc.rec
		r.usePlaneFilter(filterHandle{dropped: tc.dropped, used: &used})
		if used != tc.used || r.planeFS != tc.planeFS {
			t.Errorf("%s: used %v, planeFS %v; want %v, %v", tc.name, used, r.planeFS, tc.used, tc.planeFS)
		}
	}
}

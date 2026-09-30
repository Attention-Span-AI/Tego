// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRecorderPlaneFailClosedAndMalformedSamples: a plane sample that failed closed (path-unresolved) is named so on
// exec, attr, fs and socket lines with no malformed-record gap, while a reason the hook never refuses with, or a hook
// index that names no hook of its kind, is a malformed-record gap and the documented fallback line (attr: chmod;
// fs: an open).
func TestRecorderPlaneFailClosedAndMalformedSamples(t *testing.T) {
	f := newFixture(t)
	rt, _ := planeTable(f)
	f.rules = rt
	di, ok := statDevIno(f.out)
	if !ok {
		t.Fatal("could not stat the write directory")
	}
	none := uint32(bpf.PlaneRuleNone)
	base := func(reason bpf.ReasonCode) sample {
		return sample{PID: 50, TID: 50, MonoNS: 1, Start: 900, Reason: uint8(reason)}
	}
	own := func(kind Kind, hook uint16, reason bpf.ReasonCode) []byte {
		return planeOwnSample(base(reason), kind, hook, none, di.Dev, di.Ino, "c1", 0, 0, 0)
	}
	sock := func(reason bpf.ReasonCode) []byte {
		return planeOwnSample(base(reason), KindPlaneSocket, hookNumber(t, "socket_create"), none, 0, 0, "", 40, 1, 0)
	}
	badHook := uint16(len(bpf.PlaneHooks) + 1)
	cases := []struct {
		name      string
		sample    []byte
		kind      record.Kind
		reason    record.Reason
		op        string
		malformed int64
	}{
		{"exec path-unresolved", planeExecSample(base(bpf.ReasonPathUnresolved), none, "/usr/bin/x"),
			record.KindExec, record.ReasonPathUnresolved, "", 0},
		{"exec unknown reason", planeExecSample(base(bpf.ReasonReadDenied), none, "/usr/bin/x"),
			record.KindExec, record.ReasonPathUnresolved, "", 1},
		{"exec unrelated process-scope", planeExecSample(base(bpf.ReasonProcessScope), none, "/usr/bin/x"),
			record.KindExec, record.ReasonPathUnresolved, "", 1},
		{"attr path-unresolved", own(KindPlaneAttr, hookNumber(t, "path_chown"), bpf.ReasonPathUnresolved),
			record.KindFS, record.ReasonPathUnresolved, record.FSChown, 0},
		{"attr unknown reason", own(KindPlaneAttr, hookNumber(t, "path_chown"), bpf.ReasonNetHTTP),
			record.KindFS, record.ReasonPathUnresolved, record.FSChown, 1},
		{"attr unrelated process-scope", own(KindPlaneAttr, hookNumber(t, "path_chown"), bpf.ReasonProcessScope),
			record.KindFS, record.ReasonPathUnresolved, record.FSChown, 1},
		{"attr unknown wire code", own(KindPlaneAttr, hookNumber(t, "path_chown"), bpf.ReasonCode(255)),
			record.KindFS, record.ReasonPathUnresolved, record.FSChown, 1},
		{"attr hook 0", own(KindPlaneAttr, 0, bpf.ReasonPathUnresolved),
			record.KindFS, record.ReasonPathUnresolved, record.FSChmod, 1},
		{"attr hook out of range", own(KindPlaneAttr, badHook, bpf.ReasonPathUnresolved),
			record.KindFS, record.ReasonPathUnresolved, record.FSChmod, 1},
		{"attr hook of another kind", own(KindPlaneAttr, hookNumber(t, "file_open"), bpf.ReasonPathUnresolved),
			record.KindFS, record.ReasonPathUnresolved, record.FSChmod, 1},
		{"fs path-unresolved", own(KindPlaneFS, hookNumber(t, "file_open"), bpf.ReasonPathUnresolved),
			record.KindFS, record.ReasonPathUnresolved, fsOp(KindOpen), 0},
		{"fs unknown reason", own(KindPlaneFS, hookNumber(t, "file_open"), bpf.ReasonNetHTTP),
			record.KindFS, record.ReasonPathUnresolved, fsOp(KindOpen), 1},
		{"fs unrelated process-scope", own(KindPlaneFS, hookNumber(t, "file_open"), bpf.ReasonProcessScope),
			record.KindFS, record.ReasonPathUnresolved, fsOp(KindOpen), 1},
		{"fs hook 0", own(KindPlaneFS, 0, bpf.ReasonPathUnresolved),
			record.KindFS, record.ReasonPathUnresolved, fsOp(KindOpen), 1},
		{"fs hook out of range", own(KindPlaneFS, badHook, bpf.ReasonPathUnresolved),
			record.KindFS, record.ReasonPathUnresolved, fsOp(KindOpen), 1},
		{"fs hook of another kind", own(KindPlaneFS, hookNumber(t, "path_chmod"), bpf.ReasonPathUnresolved),
			record.KindFS, record.ReasonPathUnresolved, fsOp(KindOpen), 1},
		{"socket path-unresolved", sock(bpf.ReasonPathUnresolved), record.KindRefused, record.ReasonPathUnresolved, "", 0},
		{"socket unknown reason", sock(bpf.ReasonReadDenied), record.KindRefused, record.ReasonNetNotAllowed, "", 1},
		{"socket unrelated process-scope", sock(bpf.ReasonProcessScope), record.KindRefused, record.ReasonNetNotAllowed, "", 1},
		{"socket unknown wire code", sock(bpf.ReasonCode(255)), record.KindRefused, record.ReasonNetNotAllowed, "", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM}, c.sample)
			lines := sink.byKind(c.kind)
			if len(lines) != 1 {
				t.Fatalf("%d %s lines, want 1", len(lines), c.kind)
			}
			ev := lines[0]
			if ev.Rule != RuleUnmatched || ev.Reason != c.reason {
				t.Errorf("line rule %s reason %s, want %s %s", ev.Rule, ev.Reason, RuleUnmatched, c.reason)
			}
			if c.op != "" {
				if p := payload[record.FSPayload](t, ev); p.Op != c.op {
					t.Errorf("op %s, want %s", p.Op, c.op)
				}
			}
			if n := gapCount(r.Gaps())[GapMalformedRecord]; n != c.malformed {
				t.Errorf("%d malformed-record gaps, want %d", n, c.malformed)
			}
		})
	}
}

func TestRecorderPlaneMapInvalidReasonKeepsFallbackAndReportsGap(t *testing.T) {
	for _, reason := range []bpf.ReasonCode{bpf.ReasonProcessScope, 255} {
		f := newFixture(t)
		bad := planeOwnSample(sample{PID: 50, TID: 50, MonoNS: 1, Start: 900, Reason: uint8(reason)},
			KindPlaneMap, hookNumber(t, "mmap_file"), uint32(bpf.PlaneRuleNone), 0, 0, "", 0, 0, 0)
		r, sink := runRecorder(t, f, Options{DecisionPlane: record.DecisionPlaneLSM}, bad)
		evs := sink.byKind(record.KindRefused)
		if len(evs) != 1 || evs[0].Rule != PlaneMapRule || evs[0].Reason != record.ReasonExecNotAllowed {
			t.Fatalf("fallback changed for reason %d: %+v", reason, evs)
		}
		p := payload[record.RefusedPayload](t, evs[0])
		if p.Op != "mmap" || p.Target != "anonymous" || p.Rule != PlaneMapRule || p.Reason != record.ReasonExecNotAllowed {
			t.Fatalf("fallback payload changed for reason %d: %+v", reason, p)
		}
		if n := gapCount(r.Gaps())[GapMalformedRecord]; n != 1 {
			t.Fatalf("reason %d: malformed gaps %d, want 1", reason, n)
		}
	}
}

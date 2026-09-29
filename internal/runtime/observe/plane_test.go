// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// planeTable is a bpflsm table over the fixture's directory: a write entry holding a deny_read subtree and a
// deny_write target, an exec file entry and an exec.allow directory. Its plane rows are what the kernel was
// filled from, so a rule_idx is a position in them.
func planeTable(f *fixture) (*agent.RuleTable, *decide.PlaneRows) {
	w, s, bin, tools := f.out, filepath.Join(f.out, "s"), filepath.Join(f.dir, "bin", "t"), filepath.Join(f.dir, "tools")
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Record: agent.RecordFull,
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: w, Raw: "./out", Resolved: w, Access: agent.AccessWriteSet},
			{Kind: agent.FSDenyRead, Path: s, Raw: "./out/s", Resolved: s},
		},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: filepath.Join(w, ".git/hooks"),
			Resolved: filepath.Join(w, ".git/hooks"), BuiltIn: true}},
		Exec: []agent.ExecRule{
			{Path: bin, Resolved: bin, Raw: "./bin/t", Basename: "t", Verdict: agent.VerdictAllow},
			{Path: tools, Resolved: tools, Raw: "./tools", IsDir: true, Verdict: agent.VerdictAllow},
		},
	}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		panic(err)
	}
	return rt, rows
}

func planeRow(t *testing.T, rows *decide.PlaneRows, p string) uint16 {
	t.Helper()
	for i, r := range rows.FS {
		if r.Path == p {
			return uint16(i)
		}
	}
	t.Fatalf("no plane row at %s", p)
	return 0
}

// planeExecSample builds the plane's own refusal sample (struct tego_ev_plane).
func planeExecSample(h sample, rule uint32, path string) []byte {
	h.Kind = KindPlaneExec
	h.Verdict = KernelRefused
	h.RuleIdx = uint16(rule)
	e := bpf.PlaneEvent{Hdr: h.header(PlaneSize), StartNS: h.Start, RuleIdx: rule, Hook: 2}
	copy(e.Path[:], fixed(path, PathMax))
	if len(path) > 0 && len(path) < PathMax {
		e.PathOK = 1
	}
	return wire(&e)
}

// execSamplePlane is execSample with the plane's naming of an allowed exec (struct tego_ev_exec.plane).
func execSamplePlane(h sample, path string, named uint8) []byte {
	b := execSample(h, 900, "t", path, []string{"t"}, false)
	e, err := bpf.Decode[bpf.ExecEvent](b)
	if err != nil {
		panic(err)
	}
	e.Plane = named
	return wire(&e)
}

// TestRecorderNamesPlaneRefusals is TIER3-PLAN T9 in the recorder: a refusal the plane made is the fs line's
// verdict with the plane's reason, the rule its rule_idx names through the plane's rows, mechanism plane and the
// plane's mode, and the plane's own cause where the closed reason set has no code for it; an exec the plane
// refused in bprm_check is one exec line from its own sample; an exec it allowed by an exec.allow directory (the
// rule_idx is the fs row's position with bit 16 set) is named by that directory's exec entry. Each action is one
// line.
func TestRecorderNamesPlaneRefusals(t *testing.T) {
	f := newFixture(t)
	rt, rows := planeTable(f)
	f.rules = rt
	secret, git := filepath.Join(f.out, "s"), filepath.Join(f.out, ".git")
	sRow, gitRow, toolsRow := planeRow(t, rows, secret), planeRow(t, rows, git), planeRow(t, rows, filepath.Join(f.dir, "tools"))
	refused := func(k Kind, mono uint64, reason bpf.ReasonCode, rule uint16) sample {
		return sample{Kind: k, PID: 50, TID: 50, MonoNS: mono, Start: 900, Verdict: KernelRefused,
			Reason: uint8(reason), RuleIdx: rule, Ret: -13, RetOK: true}
	}
	dev := uint64(2049)
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneFmodRet},
		fsSample(refused(KindOpen, 1, bpf.ReasonReadDenied, sRow), 0, 1, dev, filepath.Join(secret, "k"), ""),
		fsSample(refused(KindRename, 2, bpf.ReasonRefer, sRow), 0, 1, dev, "k", "k2"),
		fsSample(refused(KindRename, 3, bpf.ReasonDenyWriteAncestor, gitRow), 0, 1, dev, ".git", ".git.old"),
		fsSample(refused(KindUnlink, 4, bpf.ReasonIdentityMismatch, bpf.PlaneRuleNone), 0, 1, dev, "f", ""),
		fsSample(refused(KindOpen, 5, bpf.ReasonWriteOutsideContract, bpf.PlaneRuleNone), 01, 1, dev, "/etc/x", ""),
		planeExecSample(sample{PID: 50, TID: 50, MonoNS: 6, Start: 900, Reason: uint8(bpf.ReasonExecNotAllowed)},
			uint32(bpf.PlaneRuleNone), "/usr/bin/unlisted"),
		planeExecSample(sample{PID: 50, TID: 50, MonoNS: 7, Start: 900, Reason: uint8(bpf.ReasonIdentityMismatch)},
			0, filepath.Join(f.dir, "bin", "t")),
		execSamplePlane(sample{PID: 51, PPID: 50, MonoNS: 8, RuleIdx: toolsRow}, filepath.Join(f.dir, "tools", "x"),
			bpf.PlaneNamedFSRow),
	)
	fs, execs := sink.byKind(record.KindFS), sink.byKind(record.KindExec)
	if len(fs) != 5 || len(execs) != 3 {
		t.Fatalf("%d fs and %d exec lines, want one per action (5, 3): %+v %+v", len(fs), len(execs), fs, execs)
	}
	for i, want := range []struct {
		rule        string
		reason      record.Reason
		planeReason string
	}{
		{"fs.deny_read[./out/s]", record.ReasonReadDenied, ""},
		{"fs.deny_read[./out/s]", record.ReasonRenameOutsideContract, record.PlaneReasonRefer},
		{rt.DenyWrite[0].RuleName(), record.ReasonRenameOutsideContract, record.PlaneReasonDenyWriteAncestor},
		{RuleUnmatched, record.ReasonPathUnresolved, record.PlaneReasonIdentityMismatch},
		{RuleUnmatched, record.ReasonWriteOutsideContract, ""},
	} {
		ev := fs[i]
		p := payload[record.FSPayload](t, ev)
		if ev.Verdict != record.VerdictRefused || ev.Rule != want.rule || ev.Reason != want.reason ||
			p.Mechanism != record.MechanismPlane || p.DecisionPlane != record.DecisionPlaneFmodRet ||
			p.PlaneReason != want.planeReason || p.VerdictFrom != record.FSVerdictChain {
			t.Errorf("fs line %d: %s %s %s %+v, want refused %s %s mechanism plane, decision_plane fmod_ret, "+
				"plane_reason %q", i, ev.Verdict, ev.Rule, ev.Reason, p, want.rule, want.reason, want.planeReason)
		}
	}
	for i, want := range []struct {
		verdict     record.Verdict
		rule        string
		reason      record.Reason
		planeReason string
	}{
		{record.VerdictRefused, RuleUnmatched, record.ReasonExecNotAllowed, ""},
		{record.VerdictRefused, "exec[./bin/t]", record.ReasonPathUnresolved, record.PlaneReasonIdentityMismatch},
		// The bit-16 case: the row's position resolves to the exec.allow directory's entry.
		{record.VerdictAllow, "exec[./tools]", "", ""},
	} {
		ev := execs[i]
		p := payload[record.ExecPayload](t, ev)
		if ev.Verdict != want.verdict || ev.Rule != want.rule || ev.Reason != want.reason ||
			p.Mechanism != record.MechanismPlane || p.DecisionPlane != record.DecisionPlaneFmodRet ||
			p.PlaneReason != want.planeReason {
			t.Errorf("exec line %d: %s %s %s %+v, want %s %s %s plane_reason %q", i, ev.Verdict, ev.Rule, ev.Reason, p,
				want.verdict, want.rule, want.reason, want.planeReason)
		}
	}
	if p := payload[record.ExecPayload](t, execs[0]); p.Path != "/usr/bin/unlisted" || p.Argv == nil {
		t.Errorf("the plane's exec line names %q (argv %v), want the spelling the task passed and an empty argv",
			p.Path, p.Argv)
	}
}

// TestRecorderNamesExecPinRefusals is ADR 0048 (8)'s bprm_check row: an exec the plane refused at a pin step is one
// line, refused, reason exec-not-allowed, rule exec.pin, with the pin step's cause in plane_reason, whatever exec rule
// the sample's rule index would otherwise name.
func TestRecorderNamesExecPinRefusals(t *testing.T) {
	f := newFixture(t)
	rt, _ := planeTable(f)
	f.rules = rt
	codes := []struct {
		code bpf.ReasonCode
		want string
	}{
		{bpf.ReasonPinMissing, record.PlaneReasonPinMissing},
		{bpf.ReasonPinMismatch, record.PlaneReasonPinMismatch},
		{bpf.ReasonPinUnverifiable, record.PlaneReasonPinUnverifiable},
		{bpf.ReasonExecTraced, record.PlaneReasonExecTraced},
	}
	var samples [][]byte
	for i, c := range codes {
		samples = append(samples, planeExecSample(sample{PID: 50, TID: 50, MonoNS: uint64(i + 1), Start: 900,
			Reason: uint8(c.code)}, 0, "/usr/bin/git"))
	}
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM}, samples...)
	execs := sink.byKind(record.KindExec)
	if len(execs) != len(codes) {
		t.Fatalf("%d exec lines, want one per refused exec (%d): %+v", len(execs), len(codes), execs)
	}
	for i, c := range codes {
		ev := execs[i]
		p := payload[record.ExecPayload](t, ev)
		if ev.Verdict != record.VerdictRefused || ev.Rule != RuleExecPin || ev.Reason != record.ReasonExecNotAllowed ||
			p.Mechanism != record.MechanismPlane || p.PlaneReason != c.want {
			t.Errorf("pin refusal %d: %s %s %s %+v, want refused exec.pin exec-not-allowed plane_reason %q",
				i, ev.Verdict, ev.Rule, ev.Reason, p, c.want)
		}
	}
}

// TestRecorderKeepsPlaneRefusalsUnderRecordOff: a plane refusal is a refusal, which record: off keeps (ADR 0016
// (3)), fs and exec alike.
func TestRecorderKeepsPlaneRefusalsUnderRecordOff(t *testing.T) {
	f := newFixture(t)
	rt, rows := planeTable(f)
	rt.Record = agent.RecordOff
	f.rules = rt
	secret := filepath.Join(f.out, "s")
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM},
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 1, Verdict: KernelRefused, Reason: uint8(bpf.ReasonReadDenied),
			RuleIdx: planeRow(t, rows, secret), Ret: -13, RetOK: true}, 0, 1, 2049, filepath.Join(secret, "k"), ""),
		planeExecSample(sample{PID: 50, MonoNS: 2, Reason: uint8(bpf.ReasonExecNotAllowed)}, uint32(bpf.PlaneRuleNone),
			"/usr/bin/unlisted"),
	)
	if fs, execs := sink.byKind(record.KindFS), sink.byKind(record.KindExec); len(fs) != 1 || len(execs) != 1 ||
		fs[0].Verdict != record.VerdictRefused || execs[0].Verdict != record.VerdictRefused {
		t.Fatalf("record: off kept %+v and %+v, want the two refusals", fs, execs)
	}
}

// TestDecodePlaneExec: struct tego_ev_plane decodes whole, its rule with bit 16, and a name with no terminator is
// truncated.
func TestDecodePlaneExec(t *testing.T) {
	var rec Record
	raw := planeExecSample(sample{PID: 7, MonoNS: 3, Start: 11, Reason: uint8(bpf.ReasonExecNotAllowed)},
		bpf.PlaneRuleFSRow|5, "/bin/x")
	if err := DecodeInto(&rec, raw); err != nil {
		t.Fatal(err)
	}
	if rec.Kind != KindPlaneExec || rec.Verdict != KernelRefused || rec.Plane.RuleIdx != bpf.PlaneRuleFSRow|5 ||
		rec.RuleIdx != 5 || rec.Plane.Path != "/bin/x" || rec.Plane.PathTruncated || rec.StartNS != 11 {
		t.Fatalf("decoded %+v", rec)
	}
	long := make([]byte, PathMax)
	for i := range long {
		long[i] = 'a'
	}
	if err := DecodeInto(&rec, planeExecSample(sample{}, 0, string(long))); err != nil || !rec.Plane.PathTruncated {
		t.Fatalf("a name that fills the buffer: %v, %+v", err, rec.Plane)
	}
	if err := DecodeInto(&rec, planeExecSample(sample{}, 0, "/x")[:PlaneSize-1]); err == nil {
		t.Fatal("a short plane sample decoded")
	}
}

// planeOwnSample builds the plane's own step B refusal sample (struct tego_ev_plane): an attribute change named by
// its directory and final component, or a socket named by its family, type and protocol.
func planeOwnSample(h sample, kind Kind, hook uint16, rule uint32, dev, dirIno uint64, name string, family, typ, proto int32) []byte {
	h.Kind = kind
	h.Verdict = KernelRefused
	h.RuleIdx = uint16(rule)
	e := bpf.PlaneEvent{Hdr: h.header(PlaneSize), StartNS: h.Start, RuleIdx: rule, Hook: hook, Dev: kernelDev(dev),
		DirIno: dirIno, Family: family, Type: typ, Protocol: proto}
	copy(e.Path[:], fixed(name, PathMax))
	if len(name) < PathMax { // an empty name is a deliberately nameless file: path_ok 1, as the kernel sends it
		e.PathOK = 1
	}
	return wire(&e)
}

// hookNumber is enum tego_plane_hook's value of a hook: its bpf.PlaneHooks index plus one.
func hookNumber(t *testing.T, name string) uint16 {
	t.Helper()
	for i, h := range bpf.PlaneHooks {
		if h.Name == name {
			return uint16(i + 1)
		}
	}
	t.Fatalf("no plane hook %s", name)
	return 0
}

// TestRecorderNamesPlaneAttrAndSocketRefusals is TIER3-PLAN T13 in the recorder (enforce-plane R12, R14, R23): the
// plane's own sample of a refused attribute change is one fs line, its file named through the directory index as a
// file operation's is, its operation by the hook (chmod and an ACL are chmod, chown is chown, an xattr is xattr),
// its rule the deny_write target its row names, mechanism plane; a refused socket is one refused line naming the
// family, type and protocol, reason net-not-allowed, rule unmatched, mechanism plane; both are kept under record:
// off, since they are refusals.
func TestRecorderNamesPlaneAttrAndSocketRefusals(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordOff} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t)
			rt, rows := planeTable(f)
			rt.Record = mode
			f.rules = rt
			di, ok := statDevIno(f.out)
			if !ok {
				t.Fatal("could not stat the write directory")
			}
			hooks := planeRow(t, rows, filepath.Join(f.out, ".git/hooks"))
			attr := func(mono uint64, hook string, reason bpf.ReasonCode, rule uint32) []byte {
				return planeOwnSample(sample{PID: 50, TID: 50, MonoNS: mono, Start: 900, Reason: uint8(reason)}, KindPlaneAttr,
					hookNumber(t, hook), rule, di.Dev, di.Ino, "c1", 0, 0, 0)
			}
			_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM},
				attr(1, "path_chmod", bpf.ReasonWriteOutsideContract, uint32(hooks)),
				attr(2, "path_chown", bpf.ReasonWriteOutsideContract, uint32(hooks)),
				attr(3, "inode_setxattr", bpf.ReasonWriteOutsideContract, uint32(hooks)),
				attr(4, "inode_set_acl", bpf.ReasonWriteOutsideContract, uint32(hooks)),
				attr(5, "inode_removexattr", bpf.ReasonIdentityMismatch, uint32(bpf.PlaneRuleNone)),
				planeOwnSample(sample{PID: 50, TID: 50, MonoNS: 6, Start: 900, Reason: uint8(bpf.ReasonNetNotAllowed)},
					KindPlaneSocket, hookNumber(t, "socket_create"), uint32(bpf.PlaneRuleNone), 0, 0, "", 40, 1, 0),
			)
			fs, refused := sink.byKind(record.KindFS), sink.byKind(record.KindRefused)
			if len(fs) != 5 || len(refused) != 1 {
				t.Fatalf("%d fs and %d refused lines, want 5 and 1: %+v %+v", len(fs), len(refused), fs, refused)
			}
			target := rt.DenyWrite[0].RuleName()
			for i, want := range []struct {
				op, rule    string
				reason      record.Reason
				planeReason string
			}{
				{record.FSChmod, target, record.ReasonWriteOutsideContract, ""},
				{record.FSChown, target, record.ReasonWriteOutsideContract, ""},
				{record.FSXattr, target, record.ReasonWriteOutsideContract, ""},
				{record.FSChmod, target, record.ReasonWriteOutsideContract, ""},
				{record.FSXattr, RuleUnmatched, record.ReasonPathUnresolved, record.PlaneReasonIdentityMismatch},
			} {
				ev := fs[i]
				p := payload[record.FSPayload](t, ev)
				if ev.Verdict != record.VerdictRefused || ev.Rule != want.rule || ev.Reason != want.reason || p.Op != want.op ||
					p.Path != filepath.Join(f.out, "c1") || p.Mechanism != record.MechanismPlane ||
					p.DecisionPlane != record.DecisionPlaneLSM || p.PlaneReason != want.planeReason {
					t.Errorf("attr line %d: %s %s %s %+v, want refused %s %s op %s at out/c1, plane_reason %q", i, ev.Verdict,
						ev.Rule, ev.Reason, p, want.rule, want.reason, want.op, want.planeReason)
				}
			}
			for _, ev := range append(fs, refused...) {
				if err := ev.Validate(); err != nil {
					t.Errorf("a plane line the ledger would refuse: %v: %+v", err, ev)
				}
			}
			ev := refused[0]
			p := payload[record.RefusedPayload](t, ev)
			if ev.Rule != RuleUnmatched || ev.Reason != record.ReasonNetNotAllowed || p.Op != "socket" ||
				p.Target != "AF_VSOCK SOCK_STREAM protocol 0" || p.Mechanism != record.MechanismPlane ||
				p.DecisionPlane != record.DecisionPlaneLSM {
				t.Errorf("socket line: %s %s %+v", ev.Rule, ev.Reason, p)
			}
		})
	}
}

// TestDecodePlaneAttrAndSocket: the step B samples decode their own tails, an attribute change into the file
// operation's fields and a socket into its triple.
func TestDecodePlaneAttrAndSocket(t *testing.T) {
	var rec Record
	if err := DecodeInto(&rec, planeOwnSample(sample{PID: 7, Start: 11}, KindPlaneAttr, 12, 3, 2049, 77, "cfg", 0, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if rec.Kind != KindPlaneAttr || rec.FS.Dev != 2049 || rec.FS.Ino != 77 || rec.FS.Path != "cfg" || rec.FS.PathTruncated ||
		rec.Plane.Hook != 12 || rec.Plane.Path != "" || rec.StartNS != 11 {
		t.Fatalf("attr decoded %+v", rec)
	}
	if err := DecodeInto(&rec, planeOwnSample(sample{}, KindPlaneSocket, 18, 0, 0, 0, "", 40, 2, 7)); err != nil {
		t.Fatal(err)
	}
	if rec.Kind != KindPlaneSocket || rec.Plane.Family != 40 || rec.Plane.Type != 2 || rec.Plane.Protocol != 7 || rec.FS.Path != "" {
		t.Fatalf("socket decoded %+v", rec)
	}
}

// TestPlaneTruncatedNameCountsOnlyPathTruncated: a plane sample of a name the kernel did not read whole (path_ok 0)
// is one path-truncated gap, never also a dir-unresolved directory-index miss that did not happen (enforce-plane R9).
func TestPlaneTruncatedNameCountsOnlyPathTruncated(t *testing.T) {
	f := newFixture(t)
	rt, rows := planeTable(f)
	f.rules = rt
	di, ok := statDevIno(f.out)
	if !ok {
		t.Fatal("could not stat the write directory")
	}
	long := strings.Repeat("n", PathMax)
	hooks := uint32(planeRow(t, rows, filepath.Join(f.out, ".git/hooks")))
	h := func(mono uint64, k Kind, hook string, reason bpf.ReasonCode) []byte {
		return planeOwnSample(sample{PID: 50, TID: 50, MonoNS: mono, Start: 900, Reason: uint8(reason)}, k,
			hookNumber(t, hook), hooks, di.Dev, di.Ino, long, 0, 0, 0)
	}
	r, _ := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM},
		h(1, KindPlaneAttr, "path_chmod", bpf.ReasonWriteOutsideContract),
		h(2, KindPlaneFS, "path_unlink", bpf.ReasonDeleteOutsideContract),
		h(3, KindPlaneMap, "mmap_file", bpf.ReasonExecNotAllowed),
	)
	g := gapCount(r.Gaps())
	if g[GapDirUnresolved] != 0 || g[GapPathTruncated] != 3 {
		t.Errorf("gaps %+v, want three path-truncated and no dir-unresolved", r.Gaps())
	}
}

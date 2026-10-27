// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// pinKeyForTest is the run's MAC key in these tests.
var pinKeyForTest = execpin.Key{0xa, 0xb, 0xc}

// pinWrite is one ExecPinner.Pin call: its key, the encoded pin, and how many answers the loop had sent by then.
type pinWrite struct {
	tid      uint32
	start    uint64
	pin      []byte
	answered int
}

// fakePinner records the pins a loop writes. full makes that many writes answer ErrExecPinsFull, err every write
// fail; swept holds what each Sweep's live answered for the pins it was given (live).
type fakePinner struct {
	mu     sync.Mutex
	f      *fakeKernel
	writes []pinWrite
	full   int
	err    error
	live   []pinKeyT
	swept  []bool
	seq    uint32
}

type pinKeyT struct {
	tid   uint32
	start uint64
}

func (p *fakePinner) Pin(tid uint32, start uint64, pin []byte) (uint32, error) {
	p.f.mu.Lock()
	answered := len(p.f.responses)
	p.f.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.full > 0 {
		p.full--
		return 0, ErrExecPinsFull
	}
	if p.err != nil {
		return 0, p.err
	}
	p.seq++
	p.writes = append(p.writes, pinWrite{tid: tid, start: start, pin: pin, answered: answered})
	return p.seq, nil
}

func (p *fakePinner) Sweep(live func(uint32, uint64) bool) error {
	p.mu.Lock()
	keys := p.live
	p.mu.Unlock()
	for _, k := range keys {
		p.swept = append(p.swept, live(k.tid, k.start))
	}
	return nil
}

// pinnedLoop is a test loop whose run is pinned through a fakePinner, the exec's thread 42 started at tick 777, and
// whose kernel recorder reads the run, so a continued exec's line is the kernel's (KernelExecHandoff).
func pinnedLoop(t *testing.T, f *fakeKernel, pol *Policy) (*Loop, *testSink, *fakePinner) {
	t.Helper()
	return pinnedLoopRecorded(t, f, pol, true)
}

// pinnedLoopRecorded is pinnedLoop with the kernel recorder reading the run (recorded) or not.
func pinnedLoopRecorded(t *testing.T, f *fakeKernel, pol *Policy, recorded bool) (*Loop, *testSink, *fakePinner) {
	t.Helper()
	if f.stats == nil {
		f.stats = map[int]procStat{}
	}
	f.stats[42] = procStat{ppid: 1, start: 777}
	pinner := &fakePinner{f: f}
	sink := &testSink{}
	l, err := New(testListener(), pol, sink, Options{kernel: f, Workers: 1, ExecPinner: pinner, ExecPinKey: pinKeyForTest,
		KernelExecHandoff: func() bool { return recorded }})
	if err != nil {
		t.Fatal(err)
	}
	return l, sink, pinner
}

// TestExecPinRefusedWithoutAKernelLine (ADR 0048 (8)): a pinned run's continued exec is the kernel's line, the
// recorder's exec record folded with the plane's held or kill sample. With no recorder reading the run a kill would
// have no line and this loop's allow would stand for a killed exec, so the exec is refused exec.pin, pin_unavailable,
// and no pin is written.
func TestExecPinRefusedWithoutAKernelLine(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	l, sink, pinner := pinnedLoopRecorded(t, f, commandPolicy(t, "deny: git push"), false)
	execAt(l, f, nr, 42, 0, "/usr/bin/git", "git", "status")
	wantExecAnswer(t, f, record.VerdictRefused)
	ev := sink.one(t)
	if ev.Verdict != record.VerdictRefused || ev.Rule != ruleExecPin || !execPayloadOf(t, ev).PinUnavailable || len(pinner.writes) != 0 {
		t.Fatalf("line %s %s %+v, %d pins written", ev.Verdict, ev.Rule, execPayloadOf(t, ev).ExecPayload, len(pinner.writes))
	}
	if m := l.Metrics(); m.ExecRules == nil || m.ExecRules.PinRefused != 1 {
		t.Fatalf("run_end exec_rules %+v: want one pin refusal", m.ExecRules)
	}
}

// decodePin reads back the fields of an encoded pin the tests check.
func decodePin(b []byte) execpin.Pin {
	le := binary.LittleEndian
	p := execpin.Pin{Form: b[8], Flags: b[9], NChain: b[10], K: le.Uint32(b[12:]), Argc: le.Uint32(b[16:]),
		LenCov: le.Uint32(b[20:]), LenTail: le.Uint32(b[24:]), LenPath: le.Uint32(b[28:]),
		Image: execpin.Ident{Dev: le.Uint64(b[32:]), Ino: le.Uint64(b[40:])}, MACCov: le.Uint64(b[48:]), MACTail: le.Uint64(b[56:]),
		MACName: le.Uint64(b[64:]), MACPath: le.Uint64(b[72:])}
	for i := range p.Chain {
		p.Chain[i] = execpin.Ident{Dev: le.Uint64(b[80+16*i:]), Ino: le.Uint64(b[88+16*i:])}
	}
	return p
}

func covMAC(v ...string) uint64 {
	return execpin.MAC(pinKeyForTest, execpin.DomainCovered, []byte(strings.Join(v, "\x00")+"\x00"))
}

// TestExecPinWrittenBeforeContinue (ADR 0048 (3) P2 "Write"): in a pinned run with command rules, an exec the loop
// continues carries one pin, written before the answer, keyed by the thread and its start time, holding the image's
// kernel identity, its name, the filename and the elements the decision read; a guarded tool's pin has the guard bit.
// A refused exec writes none.
func TestExecPinWrittenBeforeContinue(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	l, sink, pinner := pinnedLoop(t, f, commandPolicy(t, "deny: git push"))
	execAt(l, f, nr, 42, 0, "/usr/bin/git", "git", "status", "-s")
	wantExecAnswer(t, f, record.VerdictAllow)
	if len(pinner.writes) != 1 {
		t.Fatalf("%d pins written, want 1", len(pinner.writes))
	}
	w := pinner.writes[0]
	if w.tid != 42 || w.start != 777 || w.answered != 0 || len(w.pin) != execpin.Size {
		t.Fatalf("pin write %+v: want thread 42 at tick 777, before any answer", w)
	}
	p := decodePin(w.pin)
	if p.Form != execpin.FormDirect || p.Flags != execpin.FlagGuard || p.Image != (execpin.Ident{Dev: 8<<20 | 1, Ino: fakeID("/usr/bin/git").ino}) {
		t.Fatalf("pin %+v: want a guarded direct pin of git's kernel identity", p)
	}
	if p.K < 2 || p.MACCov != covMAC([]string{"git", "status", "-s"}[:p.K]...) {
		t.Fatalf("pin k %d: want at least git status covered, under the run's key", p.K)
	}
	if p.MACName != execpin.MAC(pinKeyForTest, execpin.DomainName, []byte("git")) || p.MACPath != execpin.MAC(pinKeyForTest, execpin.DomainPath, []byte("/usr/bin/git")) || p.LenPath != 12 {
		t.Fatalf("pin %+v: the name and path MACs", p)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Fatalf("a pinned exec the kernel's line names was written here too: %+v", evs)
	}
	execAt(l, f, nr, 42, 1, "/usr/bin/git", "git", "push")
	wantExecAnswer(t, f, record.VerdictRefused)
	if len(pinner.writes) != 1 {
		t.Fatal("a refused exec wrote a pin")
	}
}

// TestExecPinUnguardedCoversArgv0: an exec no command rule could apply to has k = 1, its argv[0], and no guard.
func TestExecPinUnguardedCoversArgv0(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	l, _, pinner := pinnedLoop(t, f, commandPolicy(t, "deny: git push"))
	execAt(l, f, nr, 42, 0, "/usr/bin/ls", "ls", "-l")
	wantExecAnswer(t, f, record.VerdictAllow)
	if len(pinner.writes) != 1 {
		t.Fatalf("%d pins", len(pinner.writes))
	}
	if p := decodePin(pinner.writes[0].pin); p.K != 1 || p.Flags != 0 || p.MACCov != covMAC("ls") || p.Argc != execpin.ArgcUnknown {
		t.Fatalf("pin %+v: want k 1 over argv[0], no guard, no argc", p)
	}
}

// TestExecPinScriptCoversTheMappedVector: a script's pin holds its #! chain's kernel identities and binfmt_script's
// whole vector, read whole although the decision needed argv[0] alone.
func TestExecPinScriptCoversTheMappedVector(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	f.images = map[string]execImage{
		"/opt/x/tool":      {id: fakeID("/opt/x/tool"), linked: true, link: "/opt/x/tool", here: true, head: []byte("#!/usr/bin/python3 -u\n")},
		"/usr/bin/python3": {id: fakeID("/usr/bin/python3"), linked: true, link: "/usr/bin/python3", here: true, head: []byte("\x7fELF")},
	}
	l, _, pinner := pinnedLoop(t, f, commandPolicy(t, "deny: git push"))
	execAt(l, f, nr, 42, 0, "/opt/x/tool", "tool", "go", "now")
	wantExecAnswer(t, f, record.VerdictAllow)
	if len(pinner.writes) != 1 {
		t.Fatalf("%d pins", len(pinner.writes))
	}
	p := decodePin(pinner.writes[0].pin)
	area := "/usr/bin/python3\x00-u\x00/opt/x/tool\x00go\x00now\x00"
	if p.Form != execpin.FormScript || p.NChain != 1 || p.Chain[0] != (execpin.Ident{Dev: 8<<20 | 1, Ino: fakeID("/usr/bin/python3").ino}) ||
		p.LenCov != uint32(len(area)) || p.MACCov != execpin.MAC(pinKeyForTest, execpin.DomainScript, []byte(area)) {
		t.Fatalf("pin %+v: want the script vector %q and python3's identity", p, area)
	}
}

// TestExecPinGateAloneIsUnknownForm: under an exec gate alone the pin covers the whole vector the gate scored, in the
// unknown form with interp_ok (no command rule is reachable through an interpreter) and the guard bit, and no image
// head is read.
func TestExecPinGateAloneIsUnknownForm(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/rm", Source: agent.ExecSourceAllow}}
	pol.Rules.Gate = testGate(t, gate.ExecMatches, "rm", 40)
	l, _, pinner := pinnedLoop(t, f, pol)
	execAt(l, f, nr, 42, 0, "/usr/bin/rm", "rm", "-f", "x")
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response %+v: the gate's allow was not continued", got)
	}
	if len(pinner.writes) != 1 {
		t.Fatalf("%d pins", len(pinner.writes))
	}
	p := decodePin(pinner.writes[0].pin)
	if p.Form != execpin.FormUnknown || p.Flags != execpin.FlagGuard|execpin.FlagInterpOK || p.K != 3 || p.Argc != 3 ||
		p.MACCov != covMAC("rm", "-f", "x") || p.MACTail != execpin.MAC(pinKeyForTest, execpin.DomainTail, []byte("/usr/bin/rm\x00-f\x00x\x00")) {
		t.Fatalf("pin %+v", p)
	}
	for _, q := range f.execQueries {
		if q.head {
			t.Fatal("a gate-only run read the image's head")
		}
	}
}

// TestExecPinUnavailableRefuses (ADR 0048 (8)): a pin that cannot be written, or cannot be built, refuses the exec
// with EACCES and a refused line, rule exec.pin, pin_unavailable; a full map is swept once of the pins whose thread is
// gone, and the write retried.
func TestExecPinUnavailableRefuses(t *testing.T) {
	nr := nrFor(t, "execve")
	for name, setup := range map[string]func(*fakeKernel, *fakePinner){
		"write fails":          func(_ *fakeKernel, p *fakePinner) { p.err = errors.New("map gone") },
		"full after the sweep": func(_ *fakeKernel, p *fakePinner) { p.full = 2 },
		"identity unreadable":  func(f *fakeKernel, _ *fakePinner) { f.kidless = map[string]bool{"/usr/bin/git": true} },
		"thread gone":          func(f *fakeKernel, _ *fakePinner) { delete(f.stats, 42) },
	} {
		f := newFake()
		l, sink, pinner := pinnedLoop(t, f, commandPolicy(t, "deny: git push"))
		setup(f, pinner)
		execAt(l, f, nr, 42, 0, "/usr/bin/git", "git", "status")
		wantExecAnswer(t, f, record.VerdictRefused)
		ev := sink.one(t)
		if ev.Verdict != record.VerdictRefused || ev.Rule != ruleExecPin || ev.Reason != record.ReasonExecNotAllowed || !execPayloadOf(t, ev).PinUnavailable {
			t.Errorf("%s: line %s %s %s %+v", name, ev.Verdict, ev.Rule, ev.Reason, execPayloadOf(t, ev).ExecPayload)
		}
	}
	f := newFake()
	l, _, pinner := pinnedLoop(t, f, commandPolicy(t, "deny: git push"))
	f.stats[50] = procStat{start: 9}
	pinner.full = 1
	pinner.live = []pinKeyT{{42, 777}, {43, 5}, {50, 9}, {50, 10}}
	execAt(l, f, nr, 42, 0, "/usr/bin/git", "git", "status")
	wantExecAnswer(t, f, record.VerdictAllow)
	if len(pinner.writes) != 1 || len(pinner.swept) != 4 || !pinner.swept[0] || pinner.swept[1] || !pinner.swept[2] || pinner.swept[3] {
		t.Fatalf("writes %d, sweep answers %v: want one write after a sweep that keeps only live threads", len(pinner.writes), pinner.swept)
	}
}

// TestExecPinFilenameOfExecveat: the path MAC covers bprm->filename as alloc_bprm spells an execveat relative to a
// descriptor, and AT_EMPTY_PATH's "/dev/fd/<n>".
func TestExecPinFilenameOfExecveat(t *testing.T) {
	nr := nrFor(t, "execveat")
	const argvAddr = 0x20000
	f := newFake()
	f.links["/proc/42/fd/7"] = "/usr/bin/ls"
	f.put(emptyPathAddr, cstr(""))
	execFixture(f, argvAddr, []string{"ls"})
	l, _, pinner := pinnedLoop(t, f, commandPolicy(t, "deny: git push"))
	l.handle(notifFor(nr, 42, 7, emptyPathAddr, argvAddr, 0, unix.AT_EMPTY_PATH))
	wantExecAnswer(t, f, record.VerdictAllow)
	if len(pinner.writes) != 1 {
		t.Fatalf("%d pins", len(pinner.writes))
	}
	if p := decodePin(pinner.writes[0].pin); p.MACPath != execpin.MAC(pinKeyForTest, execpin.DomainPath, []byte("/dev/fd/7")) || p.LenPath != 9 ||
		p.MACName != execpin.MAC(pinKeyForTest, execpin.DomainName, []byte("ls")) {
		t.Fatalf("pin %+v: want the path MAC over /dev/fd/7 and the name ls", p)
	}
}

// TestExecPinNotInObserve: an observe run enforces nothing (R30), so it writes no pin.
func TestExecPinNotInObserve(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	pol := commandPolicy(t, "deny: git push")
	pol.Observe = true
	l, _, pinner := pinnedLoop(t, f, pol)
	execAt(l, f, nr, 42, 0, "/usr/bin/git", "git", "push")
	execAt(l, f, nr, 42, 1, "/usr/bin/git", "git", "status")
	if len(pinner.writes) != 0 {
		t.Fatalf("an observe run wrote %d pins", len(pinner.writes))
	}
}

// TestPinName: the dentry's name of a linked file, an unlinked one and a memfd whose name holds "/".
func TestPinName(t *testing.T) {
	for _, c := range []struct {
		img  execImage
		want string
	}{
		{execImage{linked: true, link: "/usr/bin/git"}, "git"},
		{execImage{linked: true, here: true, link: "/w/x (deleted)"}, "x (deleted)"},
		{execImage{linked: true, link: "/w/x (deleted)"}, "x"},
		{execImage{linked: false, link: "/w/x (deleted)"}, "x"},
		{execImage{linked: false, link: "/memfd:a/b (deleted)"}, "memfd:a/b"},
		{execImage{linked: false, link: "anon_inode:[eventfd]"}, ""},
	} {
		if got := pinName(c.img); got != c.want {
			t.Errorf("pinName(%q) = %q, want %q", c.img.link, got, c.want)
		}
	}
}

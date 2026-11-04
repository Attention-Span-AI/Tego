// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// askReadKernel is the fake kernel with the real held-open walk and the real alternate open: what a held read pins
// and what an alternate opens are real files in the test's directory; only the notification and the ADDFD delivery
// are fake. Every real descriptor the loop is handed is closed through CloseFD, which closes it.
type askReadKernel struct {
	*fakeKernel
	tid int

	mu        sync.Mutex
	completed []int    // the flags each approved open was completed with
	delivered []string // the contents of each alternate descriptor delivered
	accmode   []int    // the access mode of each alternate descriptor delivered
	closed    int
	// completeErr and deliverErr, when set, are what CompleteAskOpen and DeliverFD return in place of a delivery.
	completeErr, deliverErr error
	// beforePrepare, when set, runs before PrepareAskOpen pins: what a sibling of the task does between this loop's
	// walk of the copied name and the pin.
	beforePrepare func()
	// onSend, when set, runs at each ADDFD+SEND (CompleteAskOpen, DeliverFD): the moment the kernel releases the
	// thread, whose next syscall can then be received.
	onSend func()
	// beforeCheck, when set, runs after CompleteAskOpen reopened the pin and before the loop's check of the reopened
	// descriptor: what another process does during the completion.
	beforeCheck func()
}

func (k *askReadKernel) sent() {
	if k.onSend != nil {
		k.onSend()
	}
}

func (k *askReadKernel) PrepareAskOpen(q pathQuery, flags int) (*heldAskOpen, error) {
	if k.beforePrepare != nil {
		k.beforePrepare()
	}
	q.tid = k.tid
	return sysKernel{}.PrepareAskOpen(q, flags)
}

func (k *askReadKernel) CompleteAskOpen(_ uint64, h *heldAskOpen, flags int, _ uint32, check func(int) error) (int, error) {
	if check != nil {
		// Reopened as sysKernel does (the pin's own inode, read-only here: the fake delivers nothing), then checked.
		fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(h.fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, err
		}
		if k.beforeCheck != nil {
			k.beforeCheck()
		}
		err = check(fd)
		_ = unix.Close(fd)
		if err != nil {
			return -1, &askOpenDeliveryError{err}
		}
	}
	k.sent()
	k.mu.Lock()
	defer k.mu.Unlock()
	k.completed = append(k.completed, flags)
	if k.completeErr != nil {
		return -1, k.completeErr
	}
	return 8, nil
}

func (k *askReadKernel) OpenAlternate(h *heldAskOpen, alt *ask.AlternateFile, flags int, probe bool, refuse func(string) string) (int, string, error) {
	return sysKernel{}.OpenAlternate(h, alt, flags, probe, refuse)
}

// altOf opens p as `tego alternate` does, in this process; the test closes it at its end (a decision that owns it
// may close it first).
func altOf(t *testing.T, p string) *ask.AlternateFile {
	t.Helper()
	a, err := ask.OpenAlternateFile(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// alternateDecision is a person's alternate answer naming p, the decision owning its own descriptor of p.
func alternateDecision(t *testing.T, p string) ask.Decision {
	t.Helper()
	a, err := ask.OpenAlternateFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return ask.Decision{Alternate: a.Named, File: a, By: "uid:1 pid:2"}
}

func (k *askReadKernel) DeliverFD(_ uint64, fd int, _ int) (int, error) {
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return -1, err
	}
	buf := make([]byte, 256)
	n, _ := unix.Pread(fd, buf, 0)
	k.sent()
	k.mu.Lock()
	defer k.mu.Unlock()
	k.delivered = append(k.delivered, string(buf[:max(n, 0)]))
	k.accmode = append(k.accmode, fl&unix.O_ACCMODE)
	if k.deliverErr != nil {
		return -1, k.deliverErr
	}
	return 9, nil
}

func (k *askReadKernel) CloseFD(fd int) error {
	k.mu.Lock()
	k.closed++
	k.mu.Unlock()
	return unix.Close(fd)
}

// askReadFixture is a directory holding a secret under an fs.ask_read entry, a deny_read nested in the entry, a
// file outside it and a stand-in, and a loop over a tier-landlock table with that entry.
type askReadFixture struct {
	dir, vault, secret, nested, outside, standIn string
	k                                            *askReadKernel
	f                                            *fakeKernel
	pol                                          *Policy
	addr                                         uint64                // where the next open's path is put in the fake's memory
	live                                         func() *liveblock.Set // Options.LiveBlocks
}

func newAskReadFixture(t *testing.T) *askReadFixture {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	x := &askReadFixture{dir: dir, vault: filepath.Join(dir, "vault")}
	x.secret = filepath.Join(x.vault, "token")
	x.nested = filepath.Join(x.vault, "never")
	x.outside = filepath.Join(dir, "plain.txt")
	x.standIn = filepath.Join(dir, "stand-in")
	if err := os.MkdirAll(x.nested, 0o700); err != nil {
		t.Fatal(err)
	}
	for p, body := range map[string]string{x.secret: "real secret", filepath.Join(x.nested, "key"): "never", x.outside: "plain", x.standIn: "fake credentials"} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	x.f = newFake()
	x.k = &askReadKernel{fakeKernel: x.f, tid: selfTask(t)}
	x.pol = testPolicy(nil, []agent.FSRule{
		{Path: x.vault, Resolved: x.vault, Kind: agent.FSDenyRead, AskRead: true, Raw: x.vault},
		{Path: x.nested, Resolved: x.nested, Kind: agent.FSDenyRead, Raw: x.nested},
	}, nil)
	x.pol.Rules.Tier = backend.TierLandlock
	x.pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
	x.pol.Rules.OwnState = []string{filepath.Join(dir, "own")}
	x.pol.Rules.ContractPath = filepath.Join(dir, "contract", "agent.yaml")
	return x
}

// writable adds a write entry at p to the fixture's table.
func (x *askReadFixture) writable(p string) {
	x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: p, Resolved: p, Kind: agent.FSWrite, Raw: p})
}

// loop builds the loop with answer as the broker.
func (x *askReadFixture) loop(t *testing.T, answer func(ask.Request) ask.Decision) (*Loop, *testSink, *[]ask.Request) {
	t.Helper()
	var asked []ask.Request
	sink := &testSink{}
	l, err := New(testListener(), x.pol, sink, Options{kernel: x.k, LiveBlocks: x.live, Ask: func(_ context.Context, req ask.Request) (ask.Decision, error) {
		asked = append(asked, req)
		return answer(req), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.closeAskScopes)
	return l, sink, &asked
}

// open drives one openat of path with flags through the loop.
func (x *askReadFixture) open(t *testing.T, l *Loop, path string, flags int) *notif {
	t.Helper()
	// Each open's path at an address of its own: the fake reads the first region holding an address.
	x.addr += 0x2000
	x.f.put(0x10000+x.addr, cstr(path))
	n := notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000+x.addr, uint64(flags))
	l.handle(n)
	return n
}

// A read-open under an fs.ask_read entry is held for a person with op read, its rule named fs.ask_read[...], and an
// approval completes it read-only and records a human line; a denial and a timeout refuse it with their reasons.
func TestAskReadHoldsAReadAndAnswersIt(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision ask.Decision
		reason   record.Reason
	}{
		{"approved", ask.Decision{Approved: true, By: "uid:1 pid:2"}, ""},
		{"denied", ask.Decision{Reason: ask.ReasonDenied, By: "uid:1 pid:2"}, record.ReasonAskDenied},
		{"timed out", ask.Decision{Reason: ask.ReasonTimeout, By: "timeout"}, record.ReasonAskTimeout},
		{"unavailable", ask.Decision{Reason: ask.ReasonUnavailable, By: "shutdown"}, record.ReasonAskUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newAskReadFixture(t)
			l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return tc.decision })
			n := x.open(t, l, x.secret, unix.O_RDONLY|unix.O_CLOEXEC)
			if len(*asked) != 1 {
				t.Fatalf("asked %d times, want once", len(*asked))
			}
			req := (*asked)[0]
			if req.Op != ask.OpRead || req.Hold != ask.HoldOpen || req.Target != x.secret || req.Rule != "fs.ask_read["+x.vault+"]" || req.Alternates == nil {
				t.Fatalf("the request %+v: want a held read of the secret under its entry, taking an alternate", req)
			}
			evs := sink.all()
			if len(evs) != 1 || evs[0].Kind != record.KindFS {
				t.Fatalf("lines %+v", evs)
			}
			if tc.reason == "" {
				if len(x.k.completed) != 1 || x.k.completed[0]&unix.O_ACCMODE != unix.O_RDONLY || !n.answered {
					t.Fatalf("approval completed %v answered=%v: want one read-only completion", x.k.completed, n.answered)
				}
				if evs[0].Authority != record.AuthorityHuman || evs[0].Verdict != record.VerdictAllow || evs[0].Rule != req.Rule {
					t.Fatalf("the approved line %+v", evs[0])
				}
				return
			}
			if len(x.k.completed) != 0 {
				t.Fatal("a refused read was completed")
			}
			res, _ := x.f.lastResp()
			if res.Error != -int32(unix.EACCES) || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != tc.reason || evs[0].Rule != req.Rule {
				t.Fatalf("the refusal %+v line %+v: want EACCES and %s", res, evs[0], tc.reason)
			}
		})
	}
}

// What is not held: a read outside the entry, a read a nested deny_read decides, a write-open, an O_PATH or a
// directory open under the entry, and a held file in tego's own state (refused, never asked). Under record: summary
// a read the filter notified only for the entry, and that nothing refuses, leaves no line.
func TestAskReadHoldsOnlyAReadOfAFileTheEntryDecides(t *testing.T) {
	x := newAskReadFixture(t)
	own := filepath.Join(x.vault, "own")
	if err := os.Mkdir(own, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(own, "chain.log"), []byte("anchor"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.pol.Rules.OwnState = []string{own}
	l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true} })
	x.open(t, l, x.outside, unix.O_RDONLY)
	if len(*asked) != 0 || len(sink.all()) != 0 {
		t.Fatalf("a read outside the entry was asked (%d) or recorded under summary (%d lines)", len(*asked), len(sink.all()))
	}
	if res, _ := x.f.lastResp(); res.Flags != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE {
		t.Fatalf("a read outside the entry was not continued: %+v", res)
	}
	for _, tc := range []struct {
		name  string
		path  string
		flags int
	}{
		{"the nested deny_read", filepath.Join(x.nested, "key"), unix.O_RDONLY},
		{"a write-open", x.secret, unix.O_RDWR},
		{"an O_PATH open", x.secret, unix.O_PATH},
		{"a directory open", x.vault, unix.O_RDONLY | unix.O_DIRECTORY},
		{"an O_DIRECTORY open of the file", x.secret, unix.O_RDONLY | unix.O_DIRECTORY},
	} {
		x.open(t, l, tc.path, tc.flags)
		if len(*asked) != 0 {
			t.Fatalf("%s was asked: %+v", tc.name, *asked)
		}
		if res, _ := x.f.lastResp(); res.Flags != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE {
			t.Fatalf("%s was not left to the kernel: %+v", tc.name, res)
		}
	}
	before := len(sink.all())
	x.open(t, l, filepath.Join(own, "chain.log"), unix.O_RDONLY)
	evs := sink.all()
	if len(*asked) != 0 || len(evs) != before+1 || evs[len(evs)-1].Verdict != record.VerdictRefused || evs[len(evs)-1].Reason != record.ReasonReadDenied {
		t.Fatalf("a file in tego's own state under the entry: asked %d, lines %+v; want refused read-denied unasked", len(*asked), evs[before:])
	}
	if res, _ := x.f.lastResp(); res.Error != -int32(unix.EACCES) {
		t.Fatalf("tego's own state answered %+v", res)
	}
	// Under record: full the read outside is recorded as before.
	x.pol.Rules.Record = agent.RecordFull
	lf, sf, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	x.open(t, lf, x.outside, unix.O_RDONLY)
	if evs := sf.all(); len(evs) != 1 || evs[0].Verdict != record.VerdictAllow {
		t.Fatalf("record: full read outside the entry: %+v", evs)
	}
}

// A read gate can escalate a held read: a refusal refuses it unasked (fs-gate), and a score below refusal goes with
// the request, which is then never remembered.
func TestAskReadReadGateEscalates(t *testing.T) {
	for _, score := range []int{60, 90} {
		x := newAskReadFixture(t)
		x.pol.Rules.Workdir = x.dir
		x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "token", score)
		l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true} })
		x.open(t, l, x.secret, unix.O_RDONLY)
		if score >= 80 {
			evs := sink.all()
			if len(*asked) != 0 || len(evs) != 1 || evs[0].Reason != record.ReasonFSGate {
				t.Fatalf("score %d: asked %d, lines %+v; want refused fs-gate", score, len(*asked), evs)
			}
			continue
		}
		if len(*asked) != 1 || (*asked)[0].Score == nil || *(*asked)[0].Score != score {
			t.Fatalf("score %d: requests %+v; want one carrying the score", score, *asked)
		}
	}
}

// An entry whose pinned scope was replaced since the run started is refused ask-unavailable, unasked.
func TestAskReadReplacedScopeIsRefused(t *testing.T) {
	x := newAskReadFixture(t)
	l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true} })
	if err := os.Rename(x.vault, x.vault+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(x.vault, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(x.secret, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.open(t, l, x.secret, unix.O_RDONLY)
	evs := sink.all()
	if len(*asked) != 0 || len(evs) != 1 || evs[0].Reason != record.ReasonAskUnavailable {
		t.Fatalf("asked %d, lines %+v; want refused ask-unavailable", len(*asked), evs)
	}
}

// An alternate answers a held read with the person's file: delivered read-only, its line naming the file delivered
// with the target it stands for; and the check the request carries refuses what the delivery would.
func TestAskReadAlternateDeliversTheStandInReadOnly(t *testing.T) {
	x := newAskReadFixture(t)
	l, sink, asked := x.loop(t, func(req ask.Request) ask.Decision {
		if resolved, err := req.Alternates.Check(altOf(t, filepath.Join(x.dir, "stand-in"))); err != nil || resolved != x.standIn {
			t.Errorf("the check refused a good stand-in: %q %v", resolved, err)
		}
		return alternateDecision(t, x.standIn)
	})
	n := x.open(t, l, x.secret, unix.O_RDONLY|unix.O_CLOEXEC)
	if len(*asked) != 1 || len(x.k.completed) != 0 {
		t.Fatalf("asked %d, completed the target %v: an alternate never opens the target", len(*asked), x.k.completed)
	}
	if len(x.k.delivered) != 1 || x.k.delivered[0] != "fake credentials" || x.k.accmode[0] != unix.O_RDONLY || !n.answered {
		t.Fatalf("delivered %q mode %v answered %v: want the stand-in, read-only", x.k.delivered, x.k.accmode, n.answered)
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Authority != record.AuthorityHuman || evs[0].Verdict != record.VerdictAllow {
		t.Fatalf("lines %+v", evs)
	}
	var p struct {
		Path         string `json:"path"`
		AlternateFor string `json:"alternate_for"`
		FDDelivered  bool   `json:"fd_delivered"`
	}
	if err := json.Unmarshal(evs[0].Payload, &p); err != nil || p.Path != x.standIn || p.AlternateFor != x.secret || !p.FDDelivered {
		t.Fatalf("the alternate's line %s: want path the stand-in, alternate_for the target", evs[0].Payload)
	}
	if b, err := os.ReadFile(x.secret); err != nil || string(b) != "real secret" {
		t.Fatalf("the target changed: %q %v", b, err)
	}
}

// An alternate that fails its checks at delivery (it changed after the answer, or was never checked) refuses the
// open ask-unavailable, delivers nothing and opens nothing of the target.
func TestAskReadBadAlternateAtDeliveryRefuses(t *testing.T) {
	for name, answer := range map[string]func(x *askReadFixture) ask.Decision{
		"inside a deny_read": func(x *askReadFixture) ask.Decision { return alternateDecision(t, filepath.Join(x.nested, "key")) },
		"a path and no file": func(x *askReadFixture) ask.Decision { return ask.Decision{Alternate: x.standIn, By: "uid:1 pid:2"} },
		"an already closed one": func(x *askReadFixture) ask.Decision {
			d := alternateDecision(t, x.standIn)
			_ = d.File.Close()
			return d
		},
	} {
		x := newAskReadFixture(t)
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return answer(x) })
		x.open(t, l, x.secret, unix.O_RDONLY)
		evs := sink.all()
		if len(x.k.delivered) != 0 || len(x.k.completed) != 0 || len(evs) != 1 || evs[0].Reason != record.ReasonAskUnavailable || evs[0].Verdict != record.VerdictRefused {
			t.Fatalf("%s: delivered %v completed %v lines %+v; want refused ask-unavailable", name, x.k.delivered, x.k.completed, evs)
		}
		if res, _ := x.f.lastResp(); res.Error != -int32(unix.EACCES) {
			t.Fatalf("%s: answered %+v", name, res)
		}
	}
}

// Options.OwnState (the launcher's $XDG_RUNTIME_DIR/tego) reaches both checks: an alternate beneath it is refused
// when the person answers and at delivery.
func TestAskReadAlternateRefusedFromTheLaunchersOwnState(t *testing.T) {
	x := newAskReadFixture(t)
	runtimeOwn := filepath.Join(x.dir, "xdg", "tego")
	if err := os.MkdirAll(runtimeOwn, 0o700); err != nil {
		t.Fatal(err)
	}
	mirror := filepath.Join(runtimeOwn, "last-refusal")
	if err := os.WriteFile(mirror, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var check error
	sink := &testSink{}
	l, err := New(testListener(), x.pol, sink, Options{kernel: x.k, OwnState: []string{runtimeOwn}, Ask: func(_ context.Context, req ask.Request) (ask.Decision, error) {
		_, check = req.Alternates.Check(altOf(t, mirror))
		return alternateDecision(t, mirror), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.closeAskScopes)
	x.open(t, l, x.secret, unix.O_RDONLY)
	if check == nil || !strings.Contains(check.Error(), "tego's own state "+runtimeOwn) {
		t.Fatalf("the check at answer time said %v", check)
	}
	if evs := sink.all(); len(x.k.delivered) != 0 || len(evs) != 1 || evs[0].Reason != record.ReasonAskUnavailable {
		t.Fatalf("delivered %q lines %+v: want the delivery refused too", x.k.delivered, evs)
	}
}

// ADR 0057 D2 at the supervisor: between the person's answer (its check passed on the file they named) and the
// delivery, the agent renames the directory on the way and puts another file at the same path. The delivery uses
// the descriptor the person's command passed, so the agent gets the file the person named, never the one now at
// the path; and the line names that file where it now lies.
func TestAskReadAlternateDeliveredIsTheFileNamedNotThePathRebound(t *testing.T) {
	x := newAskReadFixture(t)
	work := filepath.Join(x.dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	named := filepath.Join(work, "stand-in")
	if err := os.WriteFile(named, []byte("what the person read"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(x.dir, "work.old")
	l, sink, _ := x.loop(t, func(req ask.Request) ask.Decision {
		d := alternateDecision(t, named)
		if _, err := req.Alternates.Check(d.File); err != nil {
			t.Errorf("the check at answer time: %v", err)
		}
		// The agent rebinds the path after the answer.
		if err := os.Rename(work, moved); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(work, 0o700); err != nil {
			t.Error(err)
		}
		if err := os.WriteFile(named, []byte("what the agent put there"), 0o600); err != nil {
			t.Error(err)
		}
		return d
	})
	x.open(t, l, x.secret, unix.O_RDONLY)
	if len(x.k.delivered) != 1 || x.k.delivered[0] != "what the person read" {
		t.Fatalf("delivered %q: want the file the person named", x.k.delivered)
	}
	var p struct {
		Path         string `json:"path"`
		AlternateFor string `json:"alternate_for"`
	}
	if evs := sink.all(); len(evs) != 1 || json.Unmarshal(evs[0].Payload, &p) != nil || p.Path != filepath.Join(moved, "stand-in") || p.AlternateFor != x.secret {
		t.Fatalf("lines %+v: want the delivered file named where it lies", evs)
	}
}

// The alternate's checks, on the real filesystem, as the agent: each refusal says why, and only a plain regular file
// outside every protected path, with one link and the agent's access, passes.
func TestOpenAlternateRefusesWhatTheAgentMustNotGet(t *testing.T) {
	x := newAskReadFixture(t)
	creds, err := sys.ReadTaskCreds(x.k.tid)
	if err != nil {
		t.Fatal(err)
	}
	h := &heldAskOpen{fd: -1, creds: creds, umask: 0o022}
	own := filepath.Join(x.dir, "own")
	contractDir := filepath.Dir(x.pol.Rules.ContractPath)
	for _, d := range []string{own, contractDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"chain":    filepath.Join(own, "chain.log"),
		"contract": filepath.Join(contractDir, "notes.txt"),
		"linked":   filepath.Join(x.dir, "linked"),
		"noaccess": filepath.Join(x.dir, "noaccess"),
	}
	for _, p := range files {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(files["linked"], filepath.Join(x.dir, "linked2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(files["noaccess"], 0); err != nil {
		t.Fatal(err)
	}
	runtimeOwn := filepath.Join(x.dir, "xdg", "tego")
	if err := os.MkdirAll(filepath.Join(runtimeOwn, "r-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	files["runtime"] = filepath.Join(runtimeOwn, "r-1", "last-refusal")
	files["env"] = filepath.Join(x.dir, ".env")
	files["envlocal"] = filepath.Join(x.dir, ".env.local")
	for _, k := range []string{"runtime", "env", "envlocal"} {
		if err := os.WriteFile(files[k], []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A symbolic link, a directory, a fifo and a magic link never reach the supervisor: the person's command refuses
	// them (ask's TestOpenAlternateFileFollowsNoLink); these are what it does pass on.
	refuse := func(p string) string { return alternateRefusal(x.pol.Rules, []string{runtimeOwn}, p, false) }
	for _, tc := range []struct {
		name, path, want string
	}{
		{"a hard link", files["linked"], "2 links"},
		{"procfs", "/proc/" + strconv.Itoa(os.Getpid()) + "/environ", "kernel interface"},
		{"tego's own state", files["chain"], "tego's own state"},
		{"the runtime directories", files["runtime"], "tego's own state " + runtimeOwn},
		{"the contract's directory", files["contract"], "contract file's directory"},
		{"a deny_read entry", filepath.Join(x.nested, "key"), "fs.deny_read["},
		{"the ask_read entry itself", x.secret, "fs.ask_read["},
		{"a .env name", files["env"], "built-in .env list"},
		{"a .env. name", files["envlocal"], "built-in .env list"},
		{"a file the agent cannot read", files["noaccess"], "cannot be opened by the agent as the held open asked"},
	} {
		if os.Geteuid() == 0 && tc.name == "a file the agent cannot read" {
			continue // root reads a mode-0 file
		}
		_, _, err := sysKernel{}.OpenAlternate(h, altOf(t, tc.path), unix.O_RDONLY, true, refuse)
		var why *errAlternate
		if !errors.As(err, &why) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s (%s): %v; want a refusal naming %q", tc.name, tc.path, err, tc.want)
		}
	}
	if _, _, err := (sysKernel{}).OpenAlternate(h, nil, unix.O_RDONLY, true, refuse); err == nil {
		t.Error("no file was taken as an alternate")
	}
	// A file removed after the person named it is refused: the kernel names it "(deleted)".
	gone := filepath.Join(x.dir, "gone")
	if err := os.WriteFile(gone, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ga := altOf(t, gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (sysKernel{}).OpenAlternate(h, ga, unix.O_RDONLY, true, refuse); err == nil {
		t.Error("a removed file was taken as an alternate")
	}
	fd, resolved, err := sysKernel{}.OpenAlternate(h, altOf(t, x.standIn), unix.O_RDONLY, false, refuse)
	if err != nil || resolved != x.standIn {
		t.Fatalf("a good stand-in: %v %q", err, resolved)
	}
	_ = unix.Close(fd)
	// A stand-in the agent wrote beneath a write entry in the project is not refused for the contract's directory.
	out := filepath.Join(contractDir, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	inProject := filepath.Join(out, "stand-in")
	if err := os.WriteFile(inProject, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.writable(out)
	if _, resolved, err := (sysKernel{}).OpenAlternate(h, altOf(t, inProject), unix.O_RDONLY, true, refuse); err != nil || resolved != inProject {
		t.Fatalf("a stand-in beneath a write entry in the project: %v %q", err, resolved)
	}
}

// The alternate's flags: a held read is reopened read-only and an open asking to write is no read; a held write
// keeps the agent's access mode, append and truncate, drops create and exclusive, and truncates only at delivery,
// never at the check made when the person answers.
func TestAlternateFlagsFollowTheHeldOpen(t *testing.T) {
	if _, err := alternateFlags(unix.O_RDWR, true, false); err == nil {
		t.Fatal("a held read took a read-write alternate")
	}
	if _, err := alternateFlags(unix.O_RDONLY, false, false); err == nil {
		t.Fatal("a held write took a read-only alternate")
	}
	got, err := alternateFlags(unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, false, false)
	if err != nil || got&unix.O_ACCMODE != unix.O_WRONLY || got&unix.O_APPEND == 0 || got&(unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW) != 0 {
		t.Fatalf("held write flags %#x %v", got, err)
	}
	x := newAskReadFixture(t)
	creds, err := sys.ReadTaskCreds(x.k.tid)
	if err != nil {
		t.Fatal(err)
	}
	h := &heldAskOpen{fd: -1, creds: creds, umask: 0o022}
	x.writable(x.standIn)
	refuse := func(p string) string { return alternateRefusal(x.pol.Rules, nil, p, true) }
	stand := altOf(t, x.standIn)
	if _, _, err = (sysKernel{}).OpenAlternate(h, stand, unix.O_WRONLY|unix.O_TRUNC, true, refuse); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(x.standIn); string(b) != "fake credentials" {
		t.Fatalf("the check truncated the alternate: %q", b)
	}
	fd, _, err := sysKernel{}.OpenAlternate(h, stand, unix.O_WRONLY|unix.O_TRUNC|unix.O_CREAT|unix.O_EXCL, false, refuse)
	if err != nil {
		t.Fatal(err)
	}
	fl, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	_ = unix.Close(fd)
	if b, _ := os.ReadFile(x.standIn); len(b) != 0 || fl&unix.O_ACCMODE != unix.O_WRONLY {
		t.Fatalf("the delivery did not honour the agent's flags: %q %#x", b, fl)
	}
	if _, _, err := (sysKernel{}).OpenAlternate(h, stand, unix.O_RDWR, false, refuse); err != nil {
		t.Fatalf("a read-write held write: %v", err)
	}
}

// For a held write the alternate may be no deny_write target either.
func TestAlternateRefusalForAWriteNamesDenyWriteTargets(t *testing.T) {
	rt := &agent.RuleTable{
		FS:        []agent.FSRule{{Path: "/w", Resolved: "/w", Kind: agent.FSWrite}},
		DenyWrite: []agent.FSRule{{Path: "/w/.githooks-x", Resolved: "/w/.githooks-x", Kind: agent.FSDenyWrite, BuiltIn: true}},
	}
	if why := alternateRefusal(rt, nil, "/w/.githooks-x/pre-commit", true); !strings.Contains(why, "no write reaches") {
		t.Fatalf("a write alternate into a deny_write target: %q", why)
	}
	if why := alternateRefusal(rt, nil, "/w/.githooks-x/pre-commit", false); why != "" {
		t.Fatalf("a read alternate of a deny_write target is a read anyone may make: %q", why)
	}
	rt.FS = append(rt.FS, agent.FSRule{Path: "/", Resolved: "/", Kind: agent.FSImplicit})
	if why := alternateRefusal(rt, nil, "/w/x", true); why != "" {
		t.Fatalf("fs: {}'s write guard refused every alternate: %q", why)
	}
}

// ADR 0057 D2, for a held write: a write alternate lies beneath a write entry or an fs.ask scope, and is of no
// built-in deny_write class by its names, wherever it lies: a git hook in a repository no entry covers, harness
// settings outside the scope, a shell startup file or the per-user git config in a home that is no write entry
// are refused, though the compiled deny_write sets name none of them. A read alternate of the same files is a read.
// And the contract file's directory (the project root) refuses no file beneath a write entry, read or write: those
// bytes are the agent's own, and R10 keeps the contract file out of every write entry.
func TestWriteAlternateLiesWhereTheContractLetsTheAgentWrite(t *testing.T) {
	rt := &agent.RuleTable{
		ContractPath: "/p/agent.yaml",
		Home:         "/home/u",
		FS:           []agent.FSRule{{Path: "/p/out", Resolved: "/p/out", Kind: agent.FSWrite}, {Path: "/p/agent.yaml", Resolved: "/p/agent.yaml", Kind: agent.FSImplicit}},
		FSAsk:        []agent.FSRule{{Path: "/p/held", Resolved: "/p/held", Kind: agent.FSAsk}, {Path: "/srv/held", Resolved: "/srv/held", Kind: agent.FSAsk}},
	}
	for _, tc := range []struct {
		path  string
		write bool
		want  string
	}{
		{"/p/out/stand-in", true, ""},
		{"/p/out/stand-in", false, ""},
		{"/srv/held/other", true, ""},
		{"/p/notes.txt", false, "contract file's directory /p, beneath no write entry"},
		{"/p/held/other", true, "contract file's directory /p, beneath no write entry"},
		{"/w/otherrepo/.git/hooks/pre-commit", true, "is git hooks, which runs code outside the run"},
		{"/w/otherrepo/.git/hooks/pre-commit", false, ""},
		{"/w/elsewhere/.claude/settings.json", true, "is harness settings"},
		{"/p/out/.claude/settings.json", true, "is harness settings"},
		{"/srv/held/.git/config", true, "is git config"},
		{"/home/u/.bashrc", true, "is shell startup"},
		{"/home/u/.config/git/config", true, "is git config"},
		{"/home/u/.config/autostart/x.desktop", true, "outside every write entry and fs.ask scope"},
		{"/home/u/.ssh/authorized_keys", true, "fs.deny_read["},
		{"/w/plain", true, "outside every write entry and fs.ask scope"},
		{"/w/plain", false, ""},
	} {
		rt.DenyReadPatterns = []agent.DenyReadPattern{{Pattern: "/home/u/.ssh", Rule: "fs.deny_read[/home/u/.ssh]"}}
		got := alternateRefusal(rt, nil, tc.path, tc.write)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s (write %v): %q; want %q", tc.path, tc.write, got, tc.want)
		}
	}
}

// ADR 0057 D2: a file a declared deny_read glob names, or a path of the built-in list, is never an alternate though it
// was not there when the table compiled (RuleTable.DenyReadPatterns), read or write.
func TestAlternateRefusedByADenyReadPatternCreatedLater(t *testing.T) {
	rt := &agent.RuleTable{
		FS:               []agent.FSRule{{Path: "/home/u", Resolved: "/home/u", Kind: agent.FSWrite}},
		DenyReadPatterns: []agent.DenyReadPattern{{Pattern: "/home/u/keys/*.pem", Rule: "fs.deny_read[~/keys/*.pem]"}, {Pattern: "/home/u/.netrc", Rule: "fs.deny_read[/home/u/.netrc]"}},
	}
	for _, write := range []bool{false, true} {
		for p, rule := range map[string]string{"/home/u/keys/new.pem": "fs.deny_read[~/keys/*.pem]", "/home/u/.netrc": "fs.deny_read[/home/u/.netrc]"} {
			if why := alternateRefusal(rt, nil, p, write); !strings.Contains(why, "is named by "+rule) {
				t.Errorf("%s (write %v): %q", p, write, why)
			}
		}
		if why := alternateRefusal(rt, nil, "/home/u/keys/new.txt", write); why != "" {
			t.Errorf("a file no pattern names (write %v): %q", write, why)
		}
	}
}

// An fs.ask write-open answered with an alternate writes into the stand-in, never the target: the descriptor
// delivered is the stand-in opened with the agent's write flags (truncate included), and the line names it with
// the target it stands for. A write alternate inside a deny_write target is refused at delivery.
func TestAskWriteAlternateWritesIntoTheStandIn(t *testing.T) {
	x := newAskReadFixture(t)
	scope := filepath.Join(x.dir, "held")
	if err := os.Mkdir(scope, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(scope, "config")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.pol.Rules.FSAsk = []agent.FSRule{{Path: scope, Resolved: scope, Kind: agent.FSAsk, Raw: scope}}
	x.writable(x.standIn) // a write alternate lies where the contract lets the agent write (ADR 0057 D2)
	var check error
	l, sink, asked := x.loop(t, func(req ask.Request) ask.Decision {
		_, check = req.Alternates.Check(altOf(t, x.standIn))
		return alternateDecision(t, x.standIn)
	})
	x.open(t, l, target, unix.O_WRONLY|unix.O_TRUNC)
	if len(*asked) != 1 || (*asked)[0].Op != "open" || check != nil {
		t.Fatalf("asked %+v, the check said %v: an fs.ask write keeps op open and takes an alternate", *asked, check)
	}
	if b, _ := os.ReadFile(x.standIn); len(b) != 0 {
		t.Fatalf("the stand-in was not opened with the agent's O_TRUNC: %q", b)
	}
	if len(x.k.accmode) != 1 || x.k.accmode[0] != unix.O_WRONLY || len(x.k.completed) != 0 {
		t.Fatalf("delivered modes %v, completed the target %v: want the stand-in, write-only", x.k.accmode, x.k.completed)
	}
	if b, _ := os.ReadFile(target); string(b) != "original" {
		t.Fatalf("the target changed: %q", b)
	}
	evs := sink.all()
	var p struct {
		Path         string `json:"path"`
		AlternateFor string `json:"alternate_for"`
	}
	if len(evs) != 1 || json.Unmarshal(evs[0].Payload, &p) != nil || p.Path != x.standIn || p.AlternateFor != target {
		t.Fatalf("lines %+v", evs)
	}

	// The same answer with the stand-in inside a deny_write target is refused at delivery, and nothing written.
	hooks := filepath.Join(x.dir, "hooks")
	if err := os.Mkdir(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(hooks, "pre-commit")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	x.pol.Rules.DenyWrite = []agent.FSRule{{Path: hooks, Resolved: hooks, Kind: agent.FSDenyWrite, BuiltIn: true}}
	l2, sink2, _ := x.loop(t, func(ask.Request) ask.Decision { return alternateDecision(t, hook) })
	x.open(t, l2, target, unix.O_WRONLY|unix.O_TRUNC)
	if evs := sink2.all(); len(evs) != 1 || evs[0].Reason != record.ReasonAskUnavailable {
		t.Fatalf("a deny_write stand-in: %+v", evs)
	}
	if b, _ := os.ReadFile(hook); string(b) != "#!/bin/sh\n" {
		t.Fatalf("the deny_write target was truncated: %q", b)
	}
}

// tego's own files a run may read (RuleTable.OwnReadable: the user registry's agents/ and skills/, agent-contract.md
// R26) are held for a person like any file under an fs.ask_read entry, and the approval completes the read: a plain
// read of them is allowed, so a held one is not refused read-denied. They are never a write
// alternate, even beneath a write entry, and are a read alternate like any readable file.
func TestTheReadableOwnStateIsHeldForReadsAndKeptFromWrites(t *testing.T) {
	x := newAskReadFixture(t)
	x.pol.Rules.OwnReadable = []string{x.vault}
	l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true, By: "uid:1 pid:2"} })
	x.open(t, l, x.secret, unix.O_RDONLY|unix.O_CLOEXEC)
	if evs := sink.all(); len(*asked) != 1 || len(x.k.completed) != 1 || len(evs) != 1 || evs[0].Verdict != record.VerdictAllow {
		t.Fatalf("a held read beneath the readable own state: asked %d, completed %v, lines %+v; want asked and completed", len(*asked), x.k.completed, evs)
	}
	rt := &agent.RuleTable{
		FS:          []agent.FSRule{{Path: "/w", Resolved: "/w", Kind: agent.FSWrite}},
		OwnReadable: []string{"/w/registry/agents"},
	}
	if why := alternateRefusal(rt, nil, "/w/registry/agents/retriever.yaml", true); !strings.Contains(why, "tego's own state") {
		t.Fatalf("a write alternate into the user registry: %q", why)
	}
	if why := alternateRefusal(rt, nil, "/w/registry/agents/retriever.yaml", false); why != "" {
		t.Fatalf("a read alternate of a file any run may read: %q", why)
	}
}

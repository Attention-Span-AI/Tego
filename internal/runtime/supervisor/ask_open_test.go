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
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func TestAskOpenActualFilesystemEffectIsDistinctFromDescriptorDelivery(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	if e := os.WriteFile(p, []byte("before"), 0600); e != nil {
		t.Fatal(e)
	}
	k := sysKernel{} // real unavailable delivery endpoint, no fake filesystem
	h, err := k.PrepareAskOpen(pathQuery{tid: selfTask(t), dirfd: atFDCWD, path: p, joined: p}, unix.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(h.fd)
	if _, err = k.CompleteAskOpen(1, h, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("exclusive existing open: %v", err)
	}
	var delivery *askOpenDeliveryError
	if errors.As(err, &delivery) {
		t.Fatal("exclusive refusal falsely claimed completed open")
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "before" {
		t.Fatalf("exclusive failure changed file %q %v", b, err)
	}
	fd, err := k.CompleteAskOpen(1, h, unix.O_WRONLY|unix.O_TRUNC, 0600)
	if fd >= 0 || !errors.As(err, &delivery) || !errors.Is(err, unix.EBADF) {
		t.Fatalf("completed open without FD delivery fd%d err%v", fd, err)
	}
	if b, err := os.ReadFile(p); err != nil || len(b) != 0 {
		t.Fatalf("actual truncate effect absent %q %v", b, err)
	}
	newPath := filepath.Join(dir, "new")
	created, err := k.PrepareAskOpen(pathQuery{tid: selfTask(t), dirfd: atFDCWD, path: newPath, joined: newPath}, unix.O_WRONLY|unix.O_CREAT)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(created.fd)
	created.umask = 0077
	if _, err = k.CompleteAskOpen(1, created, unix.O_WRONLY|unix.O_CREAT, 0666); !errors.As(err, &delivery) {
		t.Fatalf("actual creation failure phase: %v", err)
	}
	if st, err := os.Stat(newPath); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("created target identity umask %v %v", st, err)
	}
}

type withdrawnOpenKernel struct{ *heldTestKernel }

func (k *withdrawnOpenKernel) CompleteAskOpen(id uint64, h *heldAskOpen, flags int, _ uint32) (int, error) {
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(h.fd), unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	_ = unix.Close(fd)
	k.mu.Lock()
	k.stale[id] = true
	k.mu.Unlock()
	return -1, &askOpenDeliveryError{unix.ENOENT}
}

func TestAskOpenWithdrawnDeliveryRecordsAuthorizedEffectWithoutSuccess(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	if err := os.WriteFile(p, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := (sysKernel{}).PrepareAskOpen(pathQuery{tid: selfTask(t), dirfd: atFDCWD, path: p, joined: p}, unix.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(h.fd)
	f := newFake()
	k := &withdrawnOpenKernel{&heldTestKernel{fakeKernel: f, held: h}}
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Record = agent.RecordOff
	pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
	sink := &testSink{}
	l, err := New(testListener(), pol, sink, Options{kernel: k, Ask: func(context.Context, ask.Request) (ask.Decision, error) { return ask.Decision{Approved: true}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer l.closeAskScopes()
	n := notifFor(nrFor(t, "openat"), 42, argCWD, 0, unix.O_WRONLY|unix.O_TRUNC)
	if !l.askOpen(n, &reader{l: l, n: n}, pathQuery{tid: 42, dirfd: atFDCWD, path: p, joined: p}, unix.O_WRONLY|unix.O_TRUNC, fsDecided{rule: ruleUnmatched, verdict: record.VerdictRefused, enforce: true}) {
		t.Fatal("held open not handled")
	}
	if !n.gone || n.answered {
		t.Fatal("withdrawn target received fabricated completion")
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Kind != record.KindFS || evs[0].Authority != record.AuthorityHuman || evs[0].Verdict != record.VerdictAllow {
		t.Fatalf("authorized side-effect events %+v", evs)
	}
	var payload struct {
		OperationCompleted bool   `json:"operation_completed"`
		FDDelivered        bool   `json:"fd_delivered"`
		ResultUnknown      bool   `json:"result_unknown"`
		SyscallRet         *int64 `json:"syscall_ret"`
	}
	if err := json.Unmarshal(evs[0].Payload, &payload); err != nil || !payload.OperationCompleted || payload.FDDelivered || !payload.ResultUnknown || payload.SyscallRet != nil {
		t.Fatalf("fabricated target outcome %+v %v", payload, err)
	}
	if b, err := os.ReadFile(p); err != nil || len(b) != 0 {
		t.Fatalf("actual authorized effect missing %q %v", b, err)
	}
}

func TestAskOpenPinsRealRegularAndAbsentLeaf(t *testing.T) {
	tid := selfTask(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "existing")
	if err := os.WriteFile(p, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	k := sysKernel{}
	for _, tc := range []struct {
		path    string
		flags   int
		missing string
	}{{p, unix.O_WRONLY, ""}, {filepath.Join(dir, "new"), unix.O_CREAT | unix.O_WRONLY, "new"}} {
		h, e := k.PrepareAskOpen(pathQuery{tid: tid, dirfd: atFDCWD, path: tc.path, joined: tc.path}, tc.flags)
		if e != nil {
			t.Fatal(e)
		}
		if h.resolved != tc.path || h.missing != tc.missing {
			t.Fatalf("held %+v", h)
		}
		_ = unix.Close(h.fd)
	}
	for _, p := range []string{dir, "/dev/null"} {
		h, e := k.PrepareAskOpen(pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: p}, unix.O_WRONLY)
		if h != nil {
			_ = unix.Close(h.fd)
		}
		if !errors.Is(e, unix.EOPNOTSUPP) {
			t.Fatalf("special %s: %v", p, e)
		}
	}
}

func TestAskScopeRejectsReplacementAndPinsMissingParent(t *testing.T) {
	dir := t.TempDir()
	scope := filepath.Join(dir, "scope")
	if e := os.Mkdir(scope, 0700); e != nil {
		t.Fatal(e)
	}
	r := agent.FSRule{Path: scope, Resolved: scope, Kind: agent.FSAsk}
	l := &Loop{}
	if e := l.pinAskScopes(&agent.RuleTable{FSAsk: []agent.FSRule{r}}); e != nil {
		t.Fatal(e)
	}
	defer l.closeAskScopes()
	if !l.askScopeValid(&r, filepath.Join(scope, "leaf")) {
		t.Fatal("valid scope refused")
	}
	if e := os.Rename(scope, scope+"-old"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(scope, 0700); e != nil {
		t.Fatal(e)
	}
	if l.askScopeValid(&r, filepath.Join(scope, "leaf")) {
		t.Fatal("replacement scope granted")
	}
	l.closeAskScopes()
	missing := filepath.Join(scope, "literal")
	r = agent.FSRule{Path: missing, Resolved: missing, Kind: agent.FSAsk}
	if e := l.pinAskScopes(&agent.RuleTable{FSAsk: []agent.FSRule{r}}); e != nil {
		t.Fatal(e)
	}
	if !l.askScopeValid(&r, missing) || l.askScopeValid(&r, missing+"/descendant") {
		t.Fatal("absent literal became subtree")
	}
}

// TestOpenApprovalIsHeldAsAnOpen pins the hold a file-open approval carries to the approver (`tego ask`
// prints it before the op) and into the ask line (ask-4): the open syscall is held, whatever the contract's
// ask.hold, which places network asks only, says. Both callers of completeHeldAskOpen, an fs.ask write-open
// and a gate-raised read open, labelled it "connect", a network hold, on a file path.
func TestOpenApprovalIsHeldAsAnOpen(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	if e := os.WriteFile(p, []byte("untouched"), 0600); e != nil {
		t.Fatal(e)
	}
	h, e := (sysKernel{}).PrepareAskOpen(pathQuery{tid: selfTask(t), dirfd: atFDCWD, path: p, joined: p}, unix.O_WRONLY)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(h.fd)
	for _, tc := range []struct {
		name string
		hold agent.AskHold
		gate bool
	}{
		{"fs.ask under hold connect", agent.AskHoldConnect, false},
		{"fs.ask under hold first_write", agent.AskHoldFirstWrite, false},
		{"fs.ask under hold request", agent.AskHoldRequest, false},
		{"gate-raised read", agent.AskHoldConnect, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			k := &heldTestKernel{fakeKernel: f, held: h}
			pol := testPolicy(nil, nil, nil)
			pol.Rules.AskConfig = &agent.AskConfig{Hold: tc.hold, Timeout: agent.Duration(time.Second), MaxPending: 4}
			flags := unix.O_WRONLY
			if tc.gate {
				pol.Rules.FS = append(pol.Rules.FS, agent.FSRule{Path: dir, Resolved: dir, Kind: agent.FSImplicit})
				pol.Rules.Workdir = dir
				pol.Rules.Gate = testGate(t, gate.ReadMatches, "file", 70)
				flags = unix.O_RDONLY
			} else {
				pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
			}
			var requests []ask.Request
			l, e := New(testListener(), pol, &testSink{}, Options{kernel: k, Ask: func(_ context.Context, req ask.Request) (ask.Decision, error) {
				requests = append(requests, req)
				return ask.Decision{Approved: true}, nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			defer l.closeAskScopes()
			f.put(0x10000, cstr(p))
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000, uint64(flags)))
			if len(requests) != 1 || k.completed != 1 {
				t.Fatalf("asks %+v completed %d: want one approved open", requests, k.completed)
			}
			if got := requests[0]; got.Op != record.FSOpen || got.Hold != ask.HoldOpen || got.Target != p {
				t.Fatalf("approval asked as %q %q %q, want %q %q %q", got.Hold, got.Op, got.Target, ask.HoldOpen, record.FSOpen, p)
			}
		})
	}
}

type heldTestKernel struct {
	*fakeKernel
	held      *heldAskOpen
	completed int
}

func (k *heldTestKernel) PrepareAskOpen(pathQuery, int) (*heldAskOpen, error) {
	fd, e := unix.Dup(k.held.fd)
	if e != nil {
		return nil, e
	}
	h := *k.held
	h.fd = fd
	return &h, nil
}
func (k *heldTestKernel) CompleteAskOpen(uint64, *heldAskOpen, int, uint32) (int, error) {
	k.completed++
	return 8, nil
}

func TestAskOpenRootFallbackApprovesDescriptorOnlyAndProtectedWins(t *testing.T) {
	tid := selfTask(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	if e := os.WriteFile(p, []byte("untouched"), 0600); e != nil {
		t.Fatal(e)
	}
	h, e := (sysKernel{}).PrepareAskOpen(pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: p}, unix.O_WRONLY)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(h.fd)
	for _, deny := range []bool{false, true} {
		f := newFake()
		k := &heldTestKernel{fakeKernel: f, held: h}
		pol := testPolicy(nil, nil, nil)
		pol.Rules.Tier = backend.TierCgroup
		pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
		if deny {
			pol.Rules.AskDenyWrite = []agent.FSRule{{Path: p, Resolved: p, Kind: agent.FSDenyWrite, BuiltIn: true}}
		}
		asked := 0
		sink := &testSink{}
		l, e := New(testListener(), pol, sink, Options{kernel: k, Ask: func(context.Context, ask.Request) (ask.Decision, error) {
			asked++
			return ask.Decision{Approved: true}, nil
		}})
		if e != nil {
			t.Fatal(e)
		}
		n := notifFor(nrFor(t, "openat"), 42, argCWD, 0, unix.O_WRONLY)
		r := &reader{l: l, n: n}
		q := pathQuery{tid: 42, dirfd: atFDCWD, path: p, joined: p}
		if !l.askOpen(n, r, q, unix.O_WRONLY, fsDecided{rule: ruleUnmatched, verdict: record.VerdictRefused, enforce: true}) {
			t.Fatal("root fallback bypassed ask handler")
		}
		l.closeAskScopes()
		if deny {
			if asked != 0 || k.completed != 0 {
				t.Fatal("protected target reached approval")
			}
			res, _ := f.lastResp()
			if res.Flags != 0 || res.Error != -int32(unix.EACCES) {
				t.Fatalf("refusal %+v", res)
			}
		} else {
			if asked != 1 || k.completed != 1 || !n.answered || len(f.responses) != 0 {
				t.Fatalf("asked=%d completed=%d answered=%v responses=%d", asked, k.completed, n.answered, len(f.responses))
			}
		}
	}
}

func TestAskHeldWithdrawnNotificationCannotReturnApproval(t *testing.T) {
	f := newFake()
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	n := notifFor(nrFor(t, "connect"), 42)
	l.ask = func(ctx context.Context, _ ask.Request) (ask.Decision, error) {
		f.mu.Lock()
		f.stale[n.id] = true
		f.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("withdrawal did not cancel ask")
		}
		return ask.Decision{Approved: true}, nil
	}
	d, e := l.askHeld(n, ask.Request{})
	if e == nil || d.Approved || !n.gone {
		t.Fatalf("stale approval %+v %v gone=%v", d, e, n.gone)
	}
}

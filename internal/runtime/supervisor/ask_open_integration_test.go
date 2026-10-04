// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// The filter belongs only to an expendable locked OS thread. The ordinary
// parent receives its actual notification and executes the production held
// walk and ADDFD+SEND path. No process-wide filter or account anchor is used.
func TestAskOpenActualAtomicCompletionAfterSymlinkChanges(t *testing.T) {
	testHeldOpenCompletion(t, false)
}

func TestGateReadActualAtomicCompletionAfterSymlinkChanges(t *testing.T) {
	testHeldOpenCompletion(t, true)
}

func testHeldOpenCompletion(t *testing.T, readGate bool) {
	flags := unix.O_WRONLY | unix.O_TRUNC | unix.O_CLOEXEC
	if readGate {
		flags = unix.O_RDONLY | unix.O_CLOEXEC
	}
	dir := t.TempDir()
	a, b, link := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "link")
	if e := os.WriteFile(a, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(b, []byte("untouched"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(a, link); e != nil {
		t.Fatal(e)
	}
	type readyResult struct {
		ln  *sys.FD
		err error
	}
	ready := make(chan readyResult, 1)
	type openResult struct {
		fd  int
		err error
	}
	opened := make(chan openResult, 1)
	var actor func()
	actor = func() {
		runtime.LockOSThread()
		if unix.Gettid() == unix.Getpid() {
			go actor()
			runtime.UnlockOSThread()
			return
		}
		if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
			ready <- readyResult{nil, e}
			return
		}
		raw, e := bpf.Assemble([]bpf.Instruction{bpf.LoadAbsolute{Off: 0, Size: 4}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(unix.SYS_OPENAT), SkipFalse: 1}, bpf.RetConstant{Val: unix.SECCOMP_RET_USER_NOTIF}, bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}})
		if e != nil {
			ready <- readyResult{nil, e}
			return
		}
		ln, e := sys.Strict(sys.SeccompNewListenerFD(raw))
		ready <- readyResult{ln, e}
		if e != nil {
			return
		}
		file, e := unix.Open(link, flags, 0)
		opened <- openResult{file, e}
		// Exiting locked destroys this thread and its private filter.
	}
	go actor()
	r := <-ready
	if r.err != nil {
		t.Fatalf("actual listener: %v", r.err)
	}
	defer r.ln.Close() //nolint:errcheck // New took it and no Run closes it; a second Close is a no-op
	var n int
	if e := r.ln.Borrow(func(fd int) error {
		var e error
		n, e = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 3000)
		return e
	}); e != nil || n == 0 {
		t.Fatalf("actual pending open: n=%d err=%v", n, e)
	}
	var raw sys.SeccompNotif
	if e := r.ln.Borrow(func(fd int) error { return sys.SeccompNotifRecv(fd, &raw) }); e != nil {
		t.Fatal(e)
	}
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Tier = backend.TierLandlock
	pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
	if readGate {
		pol.Rules.FSAsk = nil
		pol.Rules.Workdir = dir
		pol.Rules.Gate = testGate(t, gate.ReadMatches, "a", 70)
		pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Second), MaxPending: 4}
	}
	queued := make(chan struct{}, 1)
	var once sync.Once
	runDir := t.TempDir()
	broker, e := ask.New(runDir, ask.Options{UID: uint32(os.Getuid()), Timeout: time.Second, Authorize: func(ask.Peer) error { return nil }, Emit: func(e ask.Event) error {
		if e.Kind == "ask" {
			once.Do(func() { queued <- struct{}{} })
		}
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	sink := &testSink{}
	l, e := New(r.ln, pol, sink, Options{Ask: broker.Request})
	if e != nil {
		t.Fatal(e)
	}
	defer l.closeAskScopes()
	handled := make(chan struct{})
	go func() { l.handle(newNotif(&raw)); close(handled) }()
	select {
	case <-queued:
	case <-time.After(3 * time.Second):
		t.Fatal("held open did not reach broker")
	}
	select {
	case got := <-opened:
		t.Fatalf("open finished before approval %+v", got)
	default:
	}
	if got, e := os.ReadFile(a); e != nil || string(got) != "original" {
		t.Fatalf("preapproval changed original %q: %v", got, e)
	}
	if e = os.Remove(link); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(b, link); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var pending []ask.Summary
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		pending, e = ask.ListFor(ctx, runDir, os.Getpid())
		if e != nil {
			t.Fatal(e)
		}
		if len(pending) == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(pending) != 1 {
		t.Fatal("ask not published")
	}
	if _, e = ask.AnswerFor(ctx, runDir, os.Getpid(), pending[0].AskID, true, false); e != nil {
		t.Fatal(e)
	}
	var got openResult
	select {
	case got = <-opened:
	case <-time.After(3 * time.Second):
		t.Fatal("ADDFD did not complete open")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	defer unix.Close(got.fd)
	if readGate {
		var data [16]byte
		count, e := unix.Read(got.fd, data[:])
		if e != nil || string(data[:count]) != "original" {
			t.Fatalf("approved held read %q %v", data[:count], e)
		}
	} else if _, e = unix.Write(got.fd, []byte("approved")); e != nil {
		t.Fatal(e)
	}
	select {
	case <-handled:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish")
	}
	want := "approved"
	if readGate {
		want = "original"
	}
	if data, e := os.ReadFile(a); e != nil || string(data) != want {
		t.Fatalf("frozen inode %q: %v", data, e)
	}
	if data, e := os.ReadFile(b); e != nil || string(data) != "untouched" {
		t.Fatalf("replacement inode %q: %v", data, e)
	}
	ev := sink.one(t)
	var outcome struct {
		GateFields
		OperationCompleted bool   `json:"operation_completed"`
		FDDelivered        bool   `json:"fd_delivered"`
		ResultUnknown      bool   `json:"result_unknown"`
		SyscallRet         *int64 `json:"syscall_ret"`
	}
	if e := json.Unmarshal(ev.Payload, &outcome); e != nil || ev.Kind != record.KindFS || ev.Authority != record.AuthorityHuman || ev.Verdict != record.VerdictAllow || !outcome.OperationCompleted || !outcome.FDDelivered || outcome.ResultUnknown || outcome.SyscallRet == nil || *outcome.SyscallRet != int64(got.fd) {
		t.Fatalf("actual ADDFD outcome %+v event=%+v err=%v", outcome, ev, e)
	}
	if readGate && (outcome.Score == nil || *outcome.Score != 70 || outcome.GateFacts != "copied_syscall") {
		t.Fatalf("actual read gate metadata%+v", outcome)
	}
}

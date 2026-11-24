// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/askproto"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func localRoot() Peer {
	return Peer{UID: 0, PID: os.Getpid(), StartBootNS: 10, UserNamespace: record.InitialUserNamespace, Cgroup: "/outside", CgroupNS: 1}
}

func localBroker(t *testing.T, change func(*Options)) (*Broker, string) {
	t.Helper()
	return testBroker(t, func(o *Options) {
		o.OwnerOnly = &OwnerOnlyAuthority{AgentUID: 1001, Check: func() error { return nil }, readSnapshot: func(p Peer, authorize func(Peer) error) (Peer, error) { return p, authorize(p) }}
		o.Timeout = 5 * time.Second
		o.Authorize = func(p Peer) error {
			if p.Cgroup != "/outside" || p.CgroupNS != 1 {
				return ErrUnauthorized
			}
			return nil
		}
		// Unit fixtures establish cgroup facts without root/kernel operations.
		if change != nil {
			change(o)
		}
	})
}

func localHold(t *testing.T, b *Broker) (string, <-chan Decision) {
	t.Helper()
	ready := make(chan string, 1)
	old := b.opts.Pending
	b.opts.Pending = func(r Request) {
		ready <- r.AskID
		if old != nil {
			old(r)
		}
	}
	done := make(chan Decision, 1)
	go func() { d, _ := b.Request(t.Context(), testRequest()); done <- d }()
	select {
	case id := <-ready:
		return id, done
	case <-time.After(time.Second):
		t.Fatal("ask not published")
	}
	return "", done
}

func TestLocalRolesAnswersRequireIndependentRoot(t *testing.T) {
	for _, approve := range []bool{false, true} {
		for _, which := range []string{"agent uid", "other uid", "private namespace", "namespace unknown", "start unknown", "governed root", "unknown cgroup", "unknown cgroup namespace"} {
			t.Run(which+"/approve="+map[bool]string{false: "no", true: "yes"}[approve], func(t *testing.T) {
				b, _ := localBroker(t, nil)
				id, done := localHold(t, b)
				p := localRoot()
				switch which {
				case "agent uid":
					p.UID = 1001
				case "other uid":
					p.UID = 1002
				case "private namespace":
					p.UserNamespace++
				case "namespace unknown":
					p.UserNamespace = 0
				case "start unknown":
					p.StartBootNS = 0
				case "governed root":
					p.Cgroup = "/tego/run"
				case "unknown cgroup":
					p.Cgroup = ""
				case "unknown cgroup namespace":
					p.CgroupNS = 0
				}
				if _, err := b.answer(t.Context(), id, approve, false, nil, p); !errors.Is(err, askproto.ErrOwnerOnly) {
					t.Fatalf("unauthorized answer: %v", err)
				}
				if !b.Waiting() || len(b.list()) != 1 {
					t.Fatal("unauthorized answer consumed ask")
				}
				d, err := b.answer(t.Context(), id, approve, false, nil, localRoot())
				if err != nil || d.Approved != approve || d.Actor == nil || d.Actor.Role != "owner" || d.Actor.UID != 0 || d.Actor.StartBootNS != 10 {
					t.Fatalf("root once: %+v %v", d, err)
				}
				if got := <-done; got.Actor == nil || got.Approved != approve {
					t.Fatalf("consumer: %+v", got)
				}
			})
		}
	}
}

func TestLocalRolesOnlyOnceNoAlternate(t *testing.T) {
	for _, which := range []string{"always approve", "always deny", "alternate"} {
		t.Run(which, func(t *testing.T) {
			b, _ := localBroker(t, nil)
			id, done := localHold(t, b)
			var alt *AlternateFile
			if which == "alternate" {
				alt = &AlternateFile{Named: "/not-opened"}
			}
			if _, err := b.answer(t.Context(), id, which == "always approve", which != "alternate", alt, localRoot()); !errors.Is(err, askproto.ErrOwnerOnly) {
				t.Fatal(err)
			}
			if !b.Waiting() {
				t.Fatal("unsupported answer consumed ask")
			}
			if _, err := b.answer(t.Context(), id, false, false, nil, localRoot()); err != nil {
				t.Fatal(err)
			}
			<-done
		})
	}
}

func TestLocalRolesSingleWinnerAndDurableAttribution(t *testing.T) {
	recorded, unblock := make(chan Event, 1), make(chan struct{})
	release := sync.OnceFunc(func() { close(unblock) })
	defer release()
	b, _ := localBroker(t, func(o *Options) {
		o.Emit = func(e Event) error {
			if e.Kind == "answer" {
				recorded <- e
				<-unblock
			}
			return nil
		}
	})
	id, done := localHold(t, b)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			d, err := b.answer(t.Context(), id, true, false, nil, localRoot())
			if err == nil && d.Approved {
				winners.Add(1)
			} else if !errors.Is(err, ErrNotPending) {
				t.Errorf("answer: %v", err)
			}
		})
	}
	e := <-recorded
	if e.Decision.Actor == nil || e.Decision.Actor.Validate() != nil {
		t.Fatal("missing authenticated attribution")
	}
	select {
	case <-done:
		t.Fatal("effect released before durable record")
	default:
	}
	release()
	wg.Wait()
	if winners.Load() != 1 || !(<-done).Approved {
		t.Fatal("not exactly one approval/effect")
	}
}

func TestLocalRolesAuthorityLossKeepsPending(t *testing.T) {
	var lost atomic.Bool
	b, _ := localBroker(t, func(o *Options) {
		o.OwnerOnly.Check = func() error {
			if lost.Load() {
				return os.ErrNotExist
			}
			return nil
		}
	})
	id, done := localHold(t, b)
	lost.Store(true)
	if _, err := b.answer(t.Context(), id, true, false, nil, localRoot()); !errors.Is(err, askproto.ErrApprovalPolicyChanged) || !b.Waiting() {
		t.Fatalf("lost source consumed ask: %v", err)
	}
	lost.Store(false)
	if _, err := b.answer(t.Context(), id, false, false, nil, localRoot()); err != nil {
		t.Fatal(err)
	}
	<-done
}

func TestLocalRolesRecordFailureAndAuthorityLossNeverRelease(t *testing.T) {
	for _, which := range []string{"write", "source after recording", "cancel during recording", "shutdown during recording", "deadline during recording"} {
		t.Run(which, func(t *testing.T) {
			entered, resume := make(chan struct{}), make(chan struct{})
			var lost atomic.Bool
			b, _ := localBroker(t, func(o *Options) {
				o.OwnerOnly.Check = func() error {
					if lost.Load() {
						return os.ErrNotExist
					}
					return nil
				}
				o.Emit = func(e Event) error {
					if e.Kind == "answer" {
						close(entered)
						<-resume
						if which == "write" {
							return os.ErrPermission
						}
					}
					return nil
				}
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ready := make(chan string, 1)
			b.opts.Pending = func(r Request) { ready <- r.AskID }
			done := make(chan Decision, 1)
			go func() { d, _ := b.Request(ctx, testRequest()); done <- d }()
			id := <-ready
			answered := make(chan struct{})
			go func() { _, _ = b.answer(t.Context(), id, true, false, nil, localRoot()); close(answered) }()
			<-entered
			switch which {
			case "source after recording":
				lost.Store(true)
			case "cancel during recording":
				cancel()
			case "shutdown during recording":
				b.shutdown()
			case "deadline during recording":
				b.mu.Lock()
				b.pending[id].started = time.Now().Add(-time.Minute)
				b.mu.Unlock()
			}
			close(resume)
			<-answered
			wantReason := ReasonUnavailable
			if which == "deadline during recording" {
				wantReason = ReasonTimeout
			}
			if d := <-done; d.Approved || d.Reason != wantReason {
				t.Fatalf("released after %s: %+v", which, d)
			}
		})
	}
}

func TestLocalRolesSystemCausesAndLateAnswers(t *testing.T) {
	for _, which := range []string{"timeout", "cancelled", "shutdown", "shutdown after choice"} {
		t.Run(which, func(t *testing.T) {
			var event Event
			ready := make(chan string, 1)
			b, _ := localBroker(t, func(o *Options) {
				o.TimeoutStands = true
				o.Pending = func(r Request) { ready <- r.AskID }
				o.Emit = func(e Event) error {
					if e.Kind == "answer" {
						event = e
					}
					return nil
				}
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan Decision, 1)
			go func() { d, _ := b.Request(ctx, testRequest()); done <- d }()
			id := <-ready
			switch which {
			case "timeout":
				b.mu.Lock()
				b.timeoutLocked(b.pending[id])
				b.mu.Unlock()
			case "cancelled":
				cancel()
			case "shutdown":
				b.shutdown()
			case "shutdown after choice":
				b.mu.Lock()
				p := b.pending[id]
				p.answerPeer = localRoot()
				d := Decision{AskID: id, Approved: true, By: "uid:0 pid:" + strconv.Itoa(os.Getpid()), AnswerAuthority: record.AnswerAuthority{Actor: &record.LocalApprovalActor{PID: os.Getpid(), StartBootNS: 10, UserNamespace: record.InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}}}
				b.chooseLocked(p, d)
				b.closed = true
				b.mu.Unlock()
			}
			d := <-done
			want := which
			if which == "shutdown after choice" {
				want = "shutdown"
			}
			if d.Approved || d.Always || event.Decision.Actor != nil || event.Decision.SystemCause != want {
				t.Fatalf("system attribution: %+v %+v", d, event.Decision)
			}
			if _, err := b.answer(t.Context(), id, true, false, nil, localRoot()); !errors.Is(err, ErrNotPending) {
				t.Fatalf("late answer: %v", err)
			}
		})
	}
}

func TestLocalRolesSocketRefusesSameUIDWithoutConsumption(t *testing.T) {
	b, dir := testBroker(t, func(o *Options) {
		o.OwnerOnly = &OwnerOnlyAuthority{AgentUID: 1001, Check: func() error { return nil }}
	})
	id, done := localHold(t, b)
	// This host test is an actual same-UID socket exchange. It performs no root operation.
	_, err := AnswerFor(t.Context(), dir, os.Getpid(), id, true, false)
	if !errors.Is(err, askproto.ErrOwnerOnly) || !strings.Contains(err.Error(), "root from a terminal outside any governed run") || !b.Waiting() {
		t.Fatalf("socket answer: %v", err)
	}
	b.shutdown()
	<-done
}

func TestLocalRolesSocketIdentityDiagnostics(t *testing.T) {
	for _, which := range []string{"unreadable", "private", "stale start"} {
		t.Run(which, func(t *testing.T) {
			original, originalNS := identify, userNamespace
			defer func() { identify, userNamespace = original, originalNS }()
			var calls atomic.Int32
			identify = func(c *net.UnixConn) (Peer, uint64, error) {
				p, start, err := original(c)
				if which == "stale start" && calls.Add(1) == 2 {
					start++
				}
				return p, start, err
			}
			userNamespace = func(int) (uint64, error) {
				if which == "unreadable" {
					return 0, os.ErrPermission
				}
				if which == "private" {
					return record.InitialUserNamespace + 1, nil
				}
				return record.InitialUserNamespace, nil
			}
			b, dir := testBroker(t, func(o *Options) {
				o.OwnerOnly = &OwnerOnlyAuthority{AgentUID: 1001, Check: func() error { return nil }}
			})
			id, done := localHold(t, b)
			_, err := AnswerFor(t.Context(), dir, os.Getpid(), id, true, false)
			if !errors.Is(err, askproto.ErrOwnerOnly) || !b.Waiting() {
				t.Fatalf("diagnostic %s consumed ask: %v", which, err)
			}
			b.shutdown()
			<-done
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLocalRolesLegacyWireBytes(t *testing.T) {
	req := testRequest()
	req.AskID = "q-00000000000000000000000000000000"
	d := Decision{AskID: req.AskID, Approved: true, By: "uid:1001 pid:42", AfterS: 1.5}
	rb, _ := json.Marshal(req.wire())
	db, _ := json.Marshal(d.wire())
	if string(rb) != `{"ask_id":"q-00000000000000000000000000000000","op":"connect","target":"127.0.0.1:443","rule":"net.ask[0]","hold":"connect","pid":`+strconv.Itoa(os.Getpid())+`,"tid":`+strconv.Itoa(os.Getpid())+`}` {
		t.Fatalf("legacy request bytes changed: %s", rb)
	}
	if string(db) != `{"ask_id":"q-00000000000000000000000000000000","approved":true,"by":"uid:1001 pid:42","after_s":1.5}` {
		t.Fatalf("legacy decision bytes changed: %s", db)
	}
}

func TestLocalRolesTransferredSocketRefused(t *testing.T) {
	const helper = "TEGO_LOCAL_ROLES_TRANSFER"
	if os.Getenv(helper) == "1" {
		proof := os.NewFile(4, "packet-proof")
		defer func() { _ = proof.Close() }()
		file := os.NewFile(3, "transferred-client")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		raw, _ := json.Marshal(command{Action: "list", Nonce: os.Getenv(helper + "_NONCE")})
		if _, err := conn.Write(raw); err != nil {
			t.Fatal(err)
		}
		var buf [1024]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		var r response
		if err := json.Unmarshal(buf[:n], &r); err != nil || r.Code != askproto.CodeOwnerOnly {
			t.Fatalf("transferred packet accepted: %s %v", buf[:n], err)
		}
		// Signal the checked packet before the race runtime's process-exit delay.
		if _, err := proof.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, dir := testBroker(t, func(o *Options) {
		o.OwnerOnly = &OwnerOnlyAuthority{AgentUID: 1001, Check: func() error { return nil }}
	})
	id, done := localHold(t, b)
	pinned, path, err := socketDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pinned.Close() }()
	c, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	hello, err := readResponse(c)
	if err != nil {
		t.Fatal(err)
	}
	passed, err := c.File()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = passed.Close() }()
	proofR, proofW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proofR.Close(); _ = proofW.Close() }()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLocalRolesTransferredSocketRefused$")
	cmd.Env = append(os.Environ(), helper+"=1", helper+"_NONCE="+hello.Ready)
	cmd.ExtraFiles = []*os.File{passed, proofW}
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = proofW.Close() // only the helper now holds the write end
	_ = proofR.SetReadDeadline(time.Now().Add(time.Second))
	var proof [1]byte
	n, proofErr := proofR.Read(proof[:])
	waiting := b.Waiting()
	_, detailErr := b.detail(id)
	b.shutdown()
	<-done
	waitErr := cmd.Wait() // reap only after the pending assertion's facts are captured
	if waitErr != nil {
		t.Fatalf("transfer helper: %s %v", &output, waitErr)
	}
	if proofErr != nil || n != 1 || proof[0] != 1 {
		t.Fatalf("packet proof: n=%d proof=%v err=%v", n, proof, proofErr)
	}
	if !waiting || detailErr != nil {
		t.Fatalf("transferred packet consumed ask: waiting=%v detail=%v", waiting, detailErr)
	}
}

// A root answer that names a via ("dashboard") would put " dashboard" after the exact "uid:0 pid:N" the record's
// actor rule requires, and the writer would refuse the line and end the run. Under the floor such an answer is
// refused before any selection, so the request stays pending and the same root answers it without a via.
func TestLocalRolesRefusesAViaBeforeSelection(t *testing.T) {
	for _, approve := range []bool{false, true} {
		t.Run("approve="+map[bool]string{false: "no", true: "yes"}[approve], func(t *testing.T) {
			var recorded atomic.Int32
			b, _ := localBroker(t, func(o *Options) { o.Emit = func(Event) error { recorded.Add(1); return nil } })
			id, done := localHold(t, b)
			before := recorded.Load() // the ask's own line is already written
			p := localRoot()
			p.Via = askproto.ViaDashboard
			if _, err := b.answer(t.Context(), id, approve, false, nil, p); !errors.Is(err, askproto.ErrOwnerOnly) {
				t.Fatalf("a root answer with a via: %v, want the owner-only refusal", err)
			}
			if !b.Waiting() || len(b.list()) != 1 || recorded.Load() != before {
				t.Fatalf("the refused answer was selected or recorded (waiting %v, %d lines, was %d)", b.Waiting(), recorded.Load(), before)
			}
			d, err := b.answer(t.Context(), id, approve, false, nil, localRoot())
			if err != nil || d.Actor == nil || d.By != "uid:0 pid:"+strconv.Itoa(os.Getpid()) {
				t.Fatalf("the same root without a via: %+v %v", d, err)
			}
			<-done
		})
	}
}

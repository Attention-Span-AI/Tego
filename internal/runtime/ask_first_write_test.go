// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// firstWriteRunner is a runner whose run cgroup is the test's own, with a live
// broker and relay pool for hold: first_write, max_pending 1.
func firstWriteRunner(t *testing.T, timeout time.Duration) (*runner, string) {
	t.Helper()
	const id = "r-00000000-000000000000a-askfwx"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "ask-test"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	cg, err := unifiedAskCgroup(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	r := newTestRunner(Deps{Clock: fixedClock{at: time.Now()}, Enforce: tierBackend{backend.TierLandlock, backend.Matrix(backend.TierLandlock)}})
	r.writer, r.dir, r.cg = w, dir, cgroup.Cgroup{Path: "/sys/fs/cgroup" + cg, ID: 1}
	r.rt = &agent.RuleTable{Contract: &agent.Contract{Name: "ask-first-write"}, Record: agent.RecordSummary,
		AskConfig: &agent.AskConfig{Hold: agent.AskHoldFirstWrite, Timeout: agent.Duration(timeout), MaxPending: 1}}
	r.handle, r.notifyFD = tier1Handle{}, sys.InertForTest(3)
	if err = r.startAsk(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.stopAsk(); _ = w.Close(record.RunEndPayload{Reason: record.RunEndExit}) })
	return r, dir
}

// firstWriteSend reserves a relay for req, connects a fresh socket to it, writes
// the first bytes and waits until the relay ends the connection.
func firstWriteSend(t *testing.T, r *runner, req ask.Request, dst netip.AddrPort) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	ap, release, err := r.askRelays.Reserve(context.Background(), req, dst, false, fd, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err = unix.Connect(fd, &unix.SockaddrInet4{Addr: ap.Addr().As4(), Port: int(ap.Port())}); err != nil {
		t.Fatal(err)
	}
	if _, err = unix.Write(fd, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	tv := unix.NsecToTimeval((10 * time.Second).Nanoseconds())
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	if n, err := unix.Read(fd, make([]byte, 8)); n > 0 || err == unix.EAGAIN {
		t.Fatalf("relay delivered or never ended: n=%d err=%v", n, err)
	}
}

// ledgerLines returns "kind op reason" for the ask, answer and refused lines.
func ledgerLines(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for line := range bytes.SplitSeq(bytes.TrimSpace(data), []byte("\n")) {
		var ev record.Event
		if err = json.Unmarshal(line, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Kind != record.KindAsk && ev.Kind != record.KindAnswer && ev.Kind != record.KindRefused && ev.Kind != record.KindNet {
			continue
		}
		var p struct {
			Op     string `json:"op"`
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(line, &p) // payload members are spliced into the line
		out = append(out, strings.TrimSpace(string(ev.Kind)+" "+p.Op+" "+p.Reason))
	}
	return out
}

// exitedThread returns the id of a thread of this process that has exited.
// A goroutine that exits locked to its thread ends that thread, except the
// main thread, which Go wedges instead; a goroutine landing there holds it
// until the return so the next one lands elsewhere.
func exitedThread(t *testing.T) int {
	t.Helper()
	held := make(chan struct{})
	defer close(held)
	for range 16 {
		tid := make(chan int)
		go func() {
			goruntime.LockOSThread()
			id := unix.Gettid()
			tid <- id
			if id == unix.Getpid() {
				<-held
				goruntime.UnlockOSThread()
			}
		}()
		dead := <-tid
		if dead == os.Getpid() {
			continue
		}
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat("/proc/" + strconv.Itoa(dead)); os.IsNotExist(err) {
				return dead
			}
			if time.Now().After(deadline) {
				t.Fatal("locked thread did not exit")
			}
		}
	}
	t.Fatal("no thread other than the main one")
	return 0
}

// A first_write relay asks only at the agent's first delivery, after the
// connect returned and its allow line was written. Every way that delivery can
// end without a recorded answer must still leave a refusal (SEMANTICS §6:
// capacity exhaustion and the rest record ask-unavailable), and the thread
// that made the connect need not outlive it: the relay authenticated the
// socket itself, so membership is re-checked by the process.
func TestFirstWriteDeliveryRecordsEveryEnd(t *testing.T) {
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dst := closed.Addr().(*net.TCPAddr).AddrPort()
	_ = closed.Close()
	pid := os.Getpid()
	req := ask.Request{Op: "connect", Target: dst.String(), Rule: "net.ask[tcp://" + dst.String() + "]", Hold: "first_write", PID: pid, TID: pid}

	t.Run("broker at capacity", func(t *testing.T) {
		r, dir := firstWriteRunner(t, 2*time.Second)
		// An open ask fills the broker's max_pending 1, so the delivery's own
		// ask is refused before any ask line exists.
		filled := make(chan struct{})
		go func() {
			defer close(filled)
			_, _ = r.askRequest(t.Context(), ask.Request{Op: record.FSOpen, Target: "/x", Rule: "fs.ask[/x]", Hold: ask.HoldOpen, PID: pid, TID: pid})
		}()
		for deadline := time.Now().Add(5 * time.Second); len(ledgerLines(t, dir)) == 0; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("filler ask not recorded")
			}
		}
		firstWriteSend(t, r, req, dst)
		<-filled
		want := []string{"ask open", "refused first_write ask-unavailable", "answer open"}
		if got := ledgerLines(t, dir); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("ledger %q, want %q", got, want)
		}
	})

	t.Run("exited connecting thread", func(t *testing.T) {
		r, dir := firstWriteRunner(t, 200*time.Millisecond)
		// The connecting thread has exited by the first write; its process
		// lives, so the human is asked (and here never answers).
		req := req
		req.TID = exitedThread(t)
		firstWriteSend(t, r, req, dst)
		want := []string{"ask connect", "answer connect", "refused first_write ask-timeout"}
		if got := ledgerLines(t, dir); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("ledger %q, want %q", got, want)
		}
	})
}

// An approved first delivery records its outcome on a human-authority net
// line, as an approved open records operation_completed and fd_delivered:
// the answer authorizes an attempt, not a delivery (spec/record/v1). Under
// record: off only an outcome that failed is kept.
func TestFirstWriteApprovedDeliveryRecordsOutcome(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordSummary, agent.RecordOff} {
		const id = "r-00000000-000000000000a-askfwo"
		dir := filepath.Join(t.TempDir(), id)
		w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "ask-test"}, ledger.WithAnchor(nopAnchor{}))
		if err != nil {
			t.Fatal(err)
		}
		if err = w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Tier: "landlock"}); err != nil {
			t.Fatal(err)
		}
		r := newTestRunner(Deps{Clock: fixedClock{at: time.Now()}})
		r.writer, r.cg, r.rt = w, cgroup.Cgroup{ID: 1}, &agent.RuleTable{Record: mode}
		req := ask.Request{AskID: "q-00112233445566778899aabbccddeeff", Op: "connect", Target: "192.0.2.7:443", Rule: "net.ask[tcp://192.0.2.7:443]", Hold: "first_write", PID: os.Getpid(), TID: os.Getpid()}
		approved := ask.Decision{AskID: req.AskID, Approved: true, By: "uid:1000 pid:1"}
		r.emitFirstWrite(ask.Delivery{Request: req, Decision: approved})
		r.emitFirstWrite(ask.Delivery{Request: req, Decision: approved, Connected: true})
		r.emitFirstWrite(ask.Delivery{Request: req, Decision: approved, Connected: true, Delivered: true})
		// A recorded denial already has emitAsk's mirror; nothing more is written.
		r.emitFirstWrite(ask.Delivery{Request: req, Decision: ask.Decision{AskID: req.AskID, Reason: ask.ReasonDenied}})
		if err = w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, ev := range events(t, dir) {
			if err = ev.Validate(); err != nil {
				t.Fatal(err)
			}
			if ev.Kind == record.KindRefused {
				t.Fatalf("recorded denial refused twice: %s", ev.Payload)
			}
			if ev.Kind != record.KindNet {
				continue
			}
			var p struct {
				Dst               string `json:"dst"`
				Hold              string `json:"hold"`
				UpstreamConnected bool   `json:"upstream_connected"`
				Delivered         bool   `json:"delivered"`
			}
			if err = json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatal(err)
			}
			got = append(got, fmt.Sprintf("%s %s %s %s connected=%t delivered=%t", ev.Verdict, ev.Authority, p.Dst, p.Hold, p.UpstreamConnected, p.Delivered))
		}
		want := []string{
			"allow human 192.0.2.7:443 first_write connected=false delivered=false",
			"allow human 192.0.2.7:443 first_write connected=true delivered=false",
		}
		if mode != agent.RecordOff {
			want = append(want, "allow human 192.0.2.7:443 first_write connected=true delivered=true")
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("record %s outcomes:\n%s\nwant:\n%s", mode, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

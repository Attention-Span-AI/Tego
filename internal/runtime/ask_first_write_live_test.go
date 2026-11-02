// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// firstWriteSendUnless is firstWriteSend through Reserve with refused, the live block naming the destination.
func firstWriteSendUnless(t *testing.T, r *runner, req ask.Request, dst netip.AddrPort, refused func() string) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Error(err)
		return
	}
	defer unix.Close(fd)
	ap, release, err := r.askRelays.Reserve(context.Background(), req, dst, false, fd, refused)
	if err != nil {
		t.Error(err)
		return
	}
	defer release()
	if err = unix.Connect(fd, &unix.SockaddrInet4{Addr: ap.Addr().As4(), Port: int(ap.Port())}); err != nil {
		t.Error(err)
		return
	}
	if _, err = unix.Write(fd, []byte("hello")); err != nil {
		t.Error(err)
		return
	}
	tv := unix.NsecToTimeval((10 * time.Second).Nanoseconds())
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Error(err)
		return
	}
	if n, err := unix.Read(fd, make([]byte, 8)); n > 0 || err == unix.EAGAIN {
		t.Errorf("relay delivered or never ended: n=%d err=%v", n, err)
	}
}

// firstWriteRefusedRules is the rule of every refused line in the run's ledger.
func firstWriteRefusedRules(t *testing.T, dir string) []string {
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
		if ev.Kind == record.KindRefused {
			out = append(out, ev.Rule)
		}
	}
	return out
}

// TestFirstWriteLiveBlockRecordsTheBlock: under ask.hold first_write the person is asked by the relay at the agent's
// first write, and a live block naming the destination outranks that ask as it outranks a held connect's:
// a block in force at the first write refuses the delivery unasked, under the block's rule; one that lands while the
// person decides takes the request back (answered ask-unavailable by cancelled, which emitAsk's mirror refuses); and an
// approval that comes back after the block landed is refused under the block's rule, never recorded as a delivery.
func TestFirstWriteLiveBlockRecordsTheBlock(t *testing.T) {
	const rule = "live.block[net:api.example.com]"
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dst := closed.Addr().(*net.TCPAddr).AddrPort()
	_ = closed.Close()
	pid := os.Getpid()
	req := ask.Request{Op: "connect", Target: dst.String(), Rule: "net.ask[tcp://" + dst.String() + "]", Hold: "first_write", PID: pid, TID: pid}

	t.Run("in force at the first write", func(t *testing.T) {
		r, dir := firstWriteRunner(t, time.Minute)
		firstWriteSendUnless(t, r, req, dst, func() string { return rule })
		want := []string{"refused first_write net-not-allowed"}
		if got := ledgerLines(t, dir); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("ledger %q, want %q", got, want)
		}
		if got := firstWriteRefusedRules(t, dir); len(got) != 1 || got[0] != rule {
			t.Fatalf("refused rules %q, want %s", got, rule)
		}
	})

	t.Run("lands while the person decides", func(t *testing.T) {
		r, dir := firstWriteRunner(t, time.Minute)
		var blocked atomic.Bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			firstWriteSendUnless(t, r, req, dst, func() string {
				if blocked.Load() {
					return rule
				}
				return ""
			})
		}()
		for deadline := time.Now().Add(5 * time.Second); len(ledgerLines(t, dir)) == 0; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the first write was never asked about")
			}
		}
		blocked.Store(true)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the first write was still asked about 5 s after a block of its destination landed")
		}
		want := []string{"ask connect", "answer connect", "refused first_write ask-unavailable"}
		if got := ledgerLines(t, dir); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("ledger %q, want %q", got, want)
		}
	})

	t.Run("an approval after the block", func(t *testing.T) {
		r, dir := firstWriteRunner(t, time.Minute)
		r.emitFirstWrite(ask.Delivery{Request: req, Decision: ask.Decision{AskID: "q-1", Approved: true, By: "uid:1 pid:2"}, Blocked: rule})
		want := []string{"refused first_write net-not-allowed"}
		if got := ledgerLines(t, dir); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("ledger %q, want %q", got, want)
		}
		if got := firstWriteRefusedRules(t, dir); len(got) != 1 || got[0] != rule {
			t.Fatalf("refused rules %q, want %s", got, rule)
		}
	})
}

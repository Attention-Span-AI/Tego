// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The held read, end to end in this process: the supervisor over the fake kernel holds the open through the real
// broker, and a person answers over the broker's real socket. An alternate inside a deny_read is refused at answer
// time by the open's own check (the request stays pending), a good one is delivered read-only, and with --always
// the next identical read is given the same stand-in at once, recorded as its own pair by standing:<ask_id>.
func TestAskReadThroughTheRealBroker(t *testing.T) {
	x := newAskReadFixture(t)
	var mu sync.Mutex
	var lines []ask.Event
	runDir := t.TempDir()
	broker, err := ask.New(runDir, ask.Options{UID: uint32(os.Getuid()), Timeout: 10 * time.Second,
		Authorize: func(ask.Peer) error { return nil },
		Emit: func(e ask.Event) error {
			mu.Lock()
			defer mu.Unlock()
			lines = append(lines, e)
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	sink := &testSink{}
	l, err := New(testListener(), x.pol, sink, Options{kernel: x.k, Ask: broker.Request})
	if err != nil {
		t.Fatal(err)
	}
	defer l.closeAskScopes()
	read := func() <-chan struct{} {
		done := make(chan struct{})
		x.addr += 0x2000
		x.f.put(0x10000+x.addr, cstr(x.secret))
		n := notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000+x.addr, unix.O_RDONLY)
		go func() { l.handle(n); close(done) }()
		return done
	}
	first := read()
	var held ask.Summary
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && held.AskID == ""; time.Sleep(5 * time.Millisecond) {
		items, err := ask.ListFor(context.Background(), runDir, os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if len(items) == 1 {
			held = items[0]
		}
	}
	if held.Op != ask.OpRead || held.Hold != ask.HoldOpen {
		t.Fatalf("held %+v: want a held read", held)
	}
	_, err = ask.AlternateFor(context.Background(), runDir, os.Getpid(), held.AskID, altOf(t, filepath.Join(x.nested, "key")), true)
	if !errors.Is(err, ask.ErrBadAlternate) || !strings.Contains(err.Error(), "fs.deny_read[") {
		t.Fatalf("an alternate inside a deny_read: %v", err)
	}
	if items, _ := ask.ListFor(context.Background(), runDir, os.Getpid()); len(items) != 1 {
		t.Fatal("the read stopped being pending after a refused alternate")
	}
	d, err := ask.AlternateFor(context.Background(), runDir, os.Getpid(), held.AskID, altOf(t, x.standIn), true)
	if err != nil || d.Alternate != x.standIn || !d.Always {
		t.Fatalf("the always alternate = %+v, %v", d, err)
	}
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the held read was not completed")
	}
	select {
	case <-read():
	case <-time.After(5 * time.Second):
		t.Fatal("the identical read was held again")
	}
	x.k.mu.Lock()
	delivered := append([]string(nil), x.k.delivered...)
	x.k.mu.Unlock()
	if len(delivered) != 2 || delivered[0] != "fake credentials" || delivered[1] != "fake credentials" {
		t.Fatalf("delivered %q: want the stand-in twice", delivered)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 4 || lines[1].Decision.Alternate != x.standIn || lines[3].Decision.By != "standing:"+held.AskID || lines[3].Decision.Alternate != x.standIn {
		t.Fatalf("broker lines %+v", lines)
	}
	human := 0
	for _, ev := range sink.all() {
		if ev.Kind == record.KindFS && ev.Authority == record.AuthorityHuman {
			human++
		}
	}
	if human != 2 {
		t.Fatalf("%d human fs lines, want 2", human)
	}
}

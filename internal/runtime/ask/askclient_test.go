// SPDX-License-Identifier: Apache-2.0

package ask_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// askClientDirect is internal/askclient, the client tego-control links, called directly in askproto's types.
var askClientDirect = wireClient{
	list: func(ctx context.Context, dir string, pid int) (any, error) { return askclient.List(ctx, dir, pid) },
	detail: func(ctx context.Context, dir string, pid int, id string) (any, error) {
		return askclient.Detail(ctx, dir, pid, id)
	},
	answer: func(ctx context.Context, dir string, pid int, id string, approve, always bool) (any, error) {
		return askclient.Answer(ctx, dir, pid, id, approve, always)
	},
	alternate: func(ctx context.Context, dir string, pid int, id string, alt *ask.AlternateFile, always bool) (any, error) {
		return askclient.Alternate(ctx, dir, pid, id, alt.Named, alt, always)
	},
}

// TestAskWireGoldenThroughAskclient: the client tego-control links exchanges the frames recorded from e47e1ba4, byte
// for byte, and returns the same values, called directly rather than through this package's wrappers.
func TestAskWireGoldenThroughAskclient(t *testing.T) {
	compareWireGolden(t, "askclient", runWireGolden(t, askClientDirect))
}

// TestAskClientAgainstBroker: an in-process broker answers through internal/askclient for list, detail, answer and
// always, and each refusal reaches the client as its askproto sentinel: not-pending, standing-full, standing-busy,
// no-alternate and unauthorized.
func TestAskClientAgainstBroker(t *testing.T) {
	ctx := context.Background()
	pid := os.Getpid()
	w := newWireBroker(t, nil)

	if got, err := askclient.List(ctx, w.dir, pid); err != nil || len(got) != 0 {
		t.Fatalf("list of an empty broker = %v, %v", got, err)
	}
	id, done := w.hold(t, connectReq("127.0.0.1:443"))
	t.Run("list", func(t *testing.T) {
		got, err := askclient.List(ctx, w.dir, pid)
		if err != nil || len(got) != 1 || got[0].AskID != id || got[0].Target != "127.0.0.1:443" || got[0].PID != 4242 {
			t.Fatalf("list = %+v, %v", got, err)
		}
	})
	t.Run("detail", func(t *testing.T) {
		got, err := askclient.Detail(ctx, w.dir, pid, id)
		if err != nil || got.AskID != id || got.Op != "connect" || got.Hold != "connect" || got.Rule != "net.ask[0]" {
			t.Fatalf("detail = %+v, %v", got, err)
		}
	})
	t.Run("no-alternate", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "alt")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		alt, err := ask.OpenAlternateFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = alt.Close() }()
		if _, err := askclient.Alternate(ctx, w.dir, pid, id, alt.Named, alt, false); !errors.Is(err, askproto.ErrNoAlternate) {
			t.Fatalf("an alternate for a held connect = %v, want ErrNoAlternate", err)
		}
	})
	t.Run("answer", func(t *testing.T) {
		d, err := askclient.Answer(ctx, w.dir, pid, id, true, false)
		if err != nil || !d.Approved || d.AskID != id || !strings.HasPrefix(d.By, "uid:") || d.Always {
			t.Fatalf("answer = %+v, %v", d, err)
		}
		settle(t, done)
	})
	t.Run("not-pending", func(t *testing.T) {
		if _, err := askclient.Answer(ctx, w.dir, pid, id, true, false); !errors.Is(err, askproto.ErrNotPending) {
			t.Fatalf("a second answer = %v, want ErrNotPending", err)
		}
		if _, err := askclient.Detail(ctx, w.dir, pid, id); !errors.Is(err, askproto.ErrNotPending) {
			t.Fatalf("detail of an answered request = %v, want ErrNotPending", err)
		}
	})
	t.Run("always", func(t *testing.T) {
		id, done := w.hold(t, connectReq("10.0.0.1:443"))
		d, err := askclient.Answer(ctx, w.dir, pid, id, true, true)
		if err != nil || !d.Approved || !d.Always || !strings.HasSuffix(d.By, " always") {
			t.Fatalf("always = %+v, %v", d, err)
		}
		settle(t, done)
		if later, err := w.b.Request(ctx, connectReq("10.0.0.1:443")); err != nil || !later.Approved || !strings.HasPrefix(later.By, "standing:"+id) {
			t.Fatalf("a later request for the key = %+v, %v; want the standing answer", later, err)
		}
	})
	t.Run("standing-full", func(t *testing.T) {
		for i := 1; i < ask.MaxStanding; i++ {
			id, done := w.hold(t, connectReq(fmt.Sprintf("10.3.%d.%d:443", i/256, i%256)))
			if _, err := askclient.Answer(ctx, w.dir, pid, id, false, true); err != nil {
				t.Fatalf("standing answer %d: %v", i, err)
			}
			settle(t, done)
		}
		id, done := w.hold(t, connectReq("10.4.0.1:443"))
		if _, err := askclient.Answer(ctx, w.dir, pid, id, true, true); !errors.Is(err, askproto.ErrStandingFull) {
			t.Fatalf("an always past the bound = %v, want ErrStandingFull", err)
		}
		if _, err := askclient.Answer(ctx, w.dir, pid, id, true, false); err != nil {
			t.Fatalf("the request stays pending, answerable once: %v", err)
		}
		settle(t, done)
	})
	t.Run("standing-busy", func(t *testing.T) {
		release, blocked := make(chan struct{}), make(chan struct{})
		var once sync.Once
		busy := newWireBroker(t, func(o *ask.Options) {
			o.Emit = func(ev ask.Event) error {
				if ev.Kind == "answer" && strings.HasSuffix(ev.Decision.By, " always") {
					once.Do(func() { close(blocked) })
					<-release
				}
				return nil
			}
		})
		one, oneDone := busy.hold(t, connectReq("127.0.0.1:443"))
		two, twoDone := busy.hold(t, connectReq("127.0.0.1:443"))
		go func() { _, _ = askclient.Answer(ctx, busy.dir, pid, one, true, true) }()
		<-blocked
		_, err := askclient.Answer(ctx, busy.dir, pid, two, false, true)
		close(release)
		if !errors.Is(err, askproto.ErrStandingBusy) {
			t.Fatalf("a second always for the key being recorded = %v, want ErrStandingBusy", err)
		}
		settle(t, oneDone)
		settle(t, twoDone)
	})
	t.Run("unauthorized", func(t *testing.T) {
		closed := newWireBroker(t, func(o *ask.Options) { o.Authorize = func(ask.Peer) error { return errors.New("in the run's cgroup") } })
		if _, err := askclient.List(ctx, closed.dir, pid); !errors.Is(err, askproto.ErrUnauthorized) {
			t.Fatalf("a peer the run refuses = %v, want ErrUnauthorized", err)
		}
	})
}

// TestAskClientRefusesWrongServerPID: the client sends nothing to a server whose SO_PEERCRED pid is not the
// launcher the run's lock proved (expectedPID), as a replacement pathname socket would be: the call is
// ErrUnauthorized, and the held request is still pending, unanswered. A pid that is no process is refused before
// any dial.
func TestAskClientRefusesWrongServerPID(t *testing.T) {
	ctx := context.Background()
	w := newWireBroker(t, nil)
	id, done := w.hold(t, connectReq("127.0.0.1:443"))
	other := os.Getppid() // a live process that is not the server
	for name, call := range map[string]func(pid int) error{
		"list":   func(pid int) error { _, err := askclient.List(ctx, w.dir, pid); return err },
		"detail": func(pid int) error { _, err := askclient.Detail(ctx, w.dir, pid, id); return err },
		"answer": func(pid int) error { _, err := askclient.Answer(ctx, w.dir, pid, id, true, true); return err },
	} {
		for _, pid := range []int{other, 0, -1} {
			if err := call(pid); !errors.Is(err, askproto.ErrUnauthorized) {
				t.Errorf("%s with server pid %d expected: %v, want ErrUnauthorized", name, pid, err)
			}
		}
	}
	got, err := askclient.List(ctx, w.dir, os.Getpid())
	if err != nil || len(got) != 1 || got[0].AskID != id {
		t.Fatalf("after the refused calls the request must still be held: %+v, %v", got, err)
	}
	select {
	case d := <-done:
		t.Fatalf("a refused call answered the request: %+v", d)
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := askclient.Answer(ctx, w.dir, os.Getpid(), id, false, false); err != nil {
		t.Fatal(err)
	}
	settle(t, done)
}

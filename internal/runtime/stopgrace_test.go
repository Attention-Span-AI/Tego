// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestStopMarkerCarriesTheGrace: the grace `tego stop --grace` asks for reaches the launcher's hook
// through the marker, and an empty marker (no --grace, or an older binary) asks for none.
func TestStopMarkerCarriesTheGrace(t *testing.T) {
	dir := t.TempDir()
	if err := RequestStopGrace(dir, 90*time.Second); err != nil {
		t.Fatal(err)
	}
	if !StopRequested(dir) {
		t.Fatal("no marker")
	}
	if g := StopRequestGrace(dir); g != 90*time.Second {
		t.Fatalf("StopRequestGrace = %v, want 1m30s", g)
	}
	if err := RequestStopGrace(dir, time.Second); !errors.Is(err, ErrStopRequested) {
		t.Fatalf("second request: %v, want ErrStopRequested", err)
	}
	if g := StopRequestGrace(dir); g != 90*time.Second {
		t.Fatalf("a second stop changed the first one's grace to %v", g)
	}
	plain := t.TempDir()
	if err := RequestStop(plain); err != nil {
		t.Fatal(err)
	}
	if g := StopRequestGrace(plain); g != 0 {
		t.Fatalf("an empty marker asked for %v", g)
	}
	if g := StopRequestGrace(t.TempDir()); g != 0 {
		t.Fatalf("no marker asked for %v", g)
	}
	if err := RequestStopGrace(t.TempDir(), -time.Second); err == nil {
		t.Fatal("a negative grace was written")
	}
}

// TestStopMarkerThatIsNoRequest: anything but one positive duration in a regular file is no request,
// so the machine's stop_grace applies — including a symlink, which a root launcher must not follow.
func TestStopMarkerThatIsNoRequest(t *testing.T) {
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("1h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, plant := range map[string]func(p string) error{
		"garbage":   func(p string) error { return os.WriteFile(p, []byte("soon\n"), 0o600) },
		"zero":      func(p string) error { return os.WriteFile(p, []byte("0s\n"), 0o600) },
		"negative":  func(p string) error { return os.WriteFile(p, []byte("-5s\n"), 0o600) },
		"oversized": func(p string) error { return os.WriteFile(p, make([]byte, 1024), 0o600) },
		"symlink":   func(p string) error { return os.Symlink(target, p) },
		"directory": func(p string) error { return os.Mkdir(p, 0o700) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := plant(filepath.Join(dir, StopRequestFile)); err != nil {
				t.Fatal(err)
			}
			if g := StopRequestGrace(dir); g != 0 {
				t.Fatalf("StopRequestGrace = %v, want 0", g)
			}
		})
	}
}

// TestConcurrentStopsPlaceOneMarker: two `tego stop`s that both passed the existence check both renamed their marker
// into place, and the second replaced the first's grace while the first had been told its request stood. The marker
// is linked into place now: one stop places it, every other is ErrStopRequested, and the marker holds the winner's
// grace.
func TestConcurrentStopsPlaceOneMarker(t *testing.T) {
	for range 20 {
		dir := t.TempDir()
		const n = 16
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() { errs[i] = RequestStopGrace(dir, time.Duration(i+1)*time.Second) })
		}
		wg.Wait()
		won := -1
		for i, err := range errs {
			switch {
			case err == nil && won >= 0:
				t.Fatalf("stops %d and %d both placed a marker", won, i)
			case err == nil:
				won = i
			case !errors.Is(err, ErrStopRequested):
				t.Fatalf("stop %d: %v", i, err)
			}
		}
		if won < 0 {
			t.Fatal("no stop placed a marker")
		}
		if g := StopRequestGrace(dir); g != time.Duration(won+1)*time.Second {
			t.Fatalf("marker grace %v, want the winner's %v", g, time.Duration(won+1)*time.Second)
		}
		if names, _ := os.ReadDir(dir); len(names) != 2 {
			t.Fatalf("the run directory holds %d entries, want the marker and persistent publication lock", len(names))
		}
	}
}

// Legacy publishers must share the transaction, rather than borrowing a marker
// from an in-flight stop whose actual signal delivery subsequently fails.
func TestStopGraceTransactionSerializesLegacyPublisher(t *testing.T) {
	dir := t.TempDir()
	entered, release := make(chan struct{}), make(chan struct{})
	failed := make(chan error, 1)
	denied := errors.New("delivery refused")
	go func() {
		failed <- RequestStopGraceThen(t.Context(), dir, time.Second, func(existing bool) error {
			close(entered)
			<-release
			return denied
		})
	}()
	<-entered
	legacy := make(chan error, 1)
	go func() { legacy <- RequestStopGrace(dir, 9*time.Second) }()
	select {
	case err := <-legacy:
		close(release)
		<-failed
		t.Fatalf("legacy publisher escaped failed delivery: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-failed; !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if err := <-legacy; err != nil {
		t.Fatal(err)
	}
	if got := StopRequestGrace(dir); got != 9*time.Second {
		t.Fatalf("grace=%v, want successful legacy request", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	if err := RequestStopGraceThen(ctx, dir, 3*time.Second, func(bool) error { called = true; return nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("cancelled request err=%v called=%v", err, called)
	}
}

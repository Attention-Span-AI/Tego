// SPDX-License-Identifier: Apache-2.0

package status

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// baseMono is the monotonic reading fixedClock stamps every event of write's runs with.
var baseMono = uint64(base.UnixNano())

// publish returns a write step that publishes v to the run's activity sidecar, as the launcher's budget watcher
// does for the activity it counted without a line.
func publish(t *testing.T, v uint64) func(*ledger.Writer) {
	return func(w *ledger.Writer) {
		a, err := w.OpenActivity()
		if err != nil {
			t.Fatalf("OpenActivity: %v", err)
		}
		t.Cleanup(func() { _ = a.Close() })
		if err := a.Publish(v); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
}

func steps(fns ...func(*ledger.Writer)) func(*ledger.Writer) {
	return func(w *ledger.Writer) {
		for _, fn := range fns {
			fn(w)
		}
	}
}

// TestASidecarNewerThanTheLedgerIsActivity is limits-check-doctor-cli.md R9 with the activity sidecar: a run whose
// last line is 10 s old but whose watcher counted activity 1 s ago (a record: off run busy with allowed work, a
// streamed model response) is idle 1 s, as the watcher measures it, not stalled; idle_from says which source the
// idle was measured from, and Since is that reading on the wall clock.
func TestASidecarNewerThanTheLedgerIsActivity(t *testing.T) {
	dir := write(t, true, steps(runStart("2s"), publish(t, baseMono+uint64(9*time.Second))), nil)
	s := deriveMono(t, dir, base.Add(10*time.Second), 0, baseMono+uint64(10*time.Second))
	if s.St != Running || s.Idle != time.Second || s.IdleClock != ClockMonotonic || s.IdleFrom != IdleFromActivity {
		t.Fatalf("state %q idle %s (%s, from %s), want running, 1s monotonic from %s",
			s.St, s.Idle, s.IdleClock, s.IdleFrom, IdleFromActivity)
	}
	if s.SinceMonoNS != baseMono+uint64(9*time.Second) || !s.Since.Equal(base.Add(9*time.Second)) {
		t.Fatalf("since %s (%d), want the sidecar's reading %s", s.Since, s.SinceMonoNS, base.Add(9*time.Second))
	}

	// The same run with no sidecar is what status said before it existed: stalled, from the ledger.
	plain := write(t, true, runStart("2s"), nil)
	s = deriveMono(t, plain, base.Add(10*time.Second), 0, baseMono+uint64(10*time.Second))
	if s.St != Stalled || s.Idle != 10*time.Second || s.IdleFrom != IdleFromLedger {
		t.Fatalf("no sidecar: state %q idle %s from %s, want stalled, 10s from %s", s.St, s.Idle, s.IdleFrom, IdleFromLedger)
	}
}

// TestASidecarKeepsAnOpenRequestWaitingModel: R10 is reached once the sidecar takes R9 out of the way, so a run
// whose model is streaming its answer reads waiting model, not stalled.
func TestASidecarKeepsAnOpenRequestWaitingModel(t *testing.T) {
	dir := write(t, true, steps(runStart("2s"), func(w *ledger.Writer) {
		appendEvent(w, record.KindSSLRequest, record.SSLRequestPayload{Method: "POST", Path: "/v1/messages"})
	}, publish(t, baseMono+uint64(29*time.Second))), nil)
	s := deriveMono(t, dir, base.Add(30*time.Second), 0, baseMono+uint64(30*time.Second))
	if s.St != WaitingModel || s.IdleFrom != IdleFromActivity {
		t.Fatalf("state %q from %s, want %q from %s", s.St, s.IdleFrom, WaitingModel, IdleFromActivity)
	}
}

// TestASidecarIsUsedOnlyWhenItCanBeCompared: the sidecar's reading is a monotonic one, comparable only within the
// boot of a live writer (R9's argument for the lock), so it is ignored without the lock, past the clock's own
// reading, below the ledger's newest activity, and when it is not one whole reading.
func TestASidecarIsUsedOnlyWhenItCanBeCompared(t *testing.T) {
	now, nowMono := base.Add(10*time.Second), baseMono+uint64(10*time.Second)
	t.Run("no lock", func(t *testing.T) {
		dir := write(t, true, steps(runStart("2s"), publish(t, nowMono-1)), nil)
		r, err := ledger.OpenReader(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		s, err := Derive(r, false, now, 0, WithMonoNow(func() uint64 { return nowMono }))
		if err != nil {
			t.Fatal(err)
		}
		if s.IdleFrom != IdleFromLedger || s.SinceMonoNS != baseMono {
			t.Fatalf("an unlocked run read idle from %s at %d, want the ledger's %d", s.IdleFrom, s.SinceMonoNS, baseMono)
		}
	})
	t.Run("past the clock", func(t *testing.T) {
		dir := write(t, true, steps(runStart("2s"), publish(t, nowMono+uint64(time.Hour))), nil)
		if s := deriveMono(t, dir, now, 0, nowMono); s.IdleFrom != IdleFromLedger || s.St != Stalled {
			t.Fatalf("a reading past the clock: state %q from %s, want stalled from the ledger", s.St, s.IdleFrom)
		}
	})
	t.Run("older than the ledger", func(t *testing.T) {
		dir := write(t, true, steps(runStart("2s"), publish(t, baseMono-uint64(time.Second))), nil)
		if s := deriveMono(t, dir, now, 0, nowMono); s.IdleFrom != IdleFromLedger || s.Idle != 10*time.Second {
			t.Fatalf("an older reading: idle %s from %s, want 10s from the ledger", s.Idle, s.IdleFrom)
		}
	})
	t.Run("not a whole reading", func(t *testing.T) {
		dir := write(t, true, runStart("2s"), nil)
		writeFile(t, filepath.Join(dir, ledger.ActivityFile), []byte("12345678"))
		if s := deriveMono(t, dir, now, 0, nowMono); s.IdleFrom != IdleFromLedger || s.St != Stalled {
			t.Fatalf("a short sidecar: state %q from %s, want stalled from the ledger", s.St, s.IdleFrom)
		}
	})
	t.Run("born", func(t *testing.T) {
		s, err := DeriveBorn(t.TempDir(), now)
		if err != nil {
			t.Fatal(err)
		}
		if s.IdleFrom != IdleFromLedger {
			t.Fatalf("a run with no ledger reads idle from %q, want %s", s.IdleFrom, IdleFromLedger)
		}
	})
}

// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationLedgerCeilingEndsTheRun: a run whose ledger reaches the machine's
// record.max_run_bytes (64 KiB here) is ended as a limit, exit 124, with a limit line
// which=ledger_bytes and run_end reason limit, which a unit's Restart=on-failure restarts as a new run on a new
// ledger; run_start.limits says the ceiling it ran under, and the ledger still verifies against its anchor.
func TestIntegrationLedgerCeilingEndsTheRun(t *testing.T) {
	const ceiling = 64 << 10
	f := newFixtureWithMachine(t, contractFor("iledgercap", []string{"/bin/sleep"}, []string{"/bin/sleep"}),
		func(m *config.Machine) {
			m.Record.MaxRunBytes = config.Ceiling[config.ByteSize]{Value: ceiling, Bounded: true}
		})
	deps := f.deps(t, nil)
	// A line every millisecond: the ceiling is reached in about a second, long before the agent's own end.
	deps.Capture = []source.Source{&usageSource{every: time.Millisecond, tokens: 1}}
	res, err := Run(context.Background(), f.rt, []string{"/bin/sleep", "60"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndLimit || res.ExitCode != identity.ExitLimit {
		t.Fatalf("result %+v, want limit/124", res)
	}
	dir := runDirs(t, f.root)[0]
	evs := events(t, dir)
	lim := limitEvent(t, evs)
	if lim.Which != record.LimitLedgerBytes || lim.Ceiling != ceiling || lim.Value < ceiling {
		t.Fatalf("limit payload %+v, want ledger_bytes at or over %d", lim, ceiling)
	}
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil || start.Limits == nil || start.Limits.LedgerBytes == nil ||
		*start.Limits.LedgerBytes != ceiling || start.RecordMinor < record.MinorLedgerCap {
		t.Fatalf("run_start limits %+v, record_minor %d (%v)", start.Limits, start.RecordMinor, err)
	}
	var end record.RunEndPayload
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil || end.Reason != record.RunEndLimit ||
		end.ExitCode != identity.ExitLimit {
		t.Fatalf("run_end %+v (%v), want limit/124", end, err)
	}
	if _, err := ledger.VerifyRunDir(context.Background(), dir,
		ledger.NewFileChainAnchor(ledger.DefaultAnchorPath(dir))); err != nil {
		t.Fatalf("the ledger a ceiling ended does not verify: %v", err)
	}
	// The watcher reads the size at each event and each Tick, so the ledger passes the ceiling by the lines in flight.
	st, err := os.Stat(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("events.jsonl %d bytes at the end, ceiling %d, limit line at %v", st.Size(), ceiling, lim.Value)
}

// blobSource stores one body beside the run's Writer, as the uprobe source does, and emits nothing. It stores it
// after the run's first lines are on disk and the agent has gone quiet, so no line the pipeline observes follows it,
// and records how many lines events.jsonl held at that moment.
type blobSource struct {
	size  int
	delay time.Duration

	done  chan struct{}
	err   error
	lines int
}

// Name identifies the source in the run's logs.
func (s *blobSource) Name() string { return "blob-test" }

// Start stores the body, after delay, through the store a source of its own would hold.
func (s *blobSource) Start(ctx context.Context, run source.RunRef, _ source.Sink) error {
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		select {
		case <-ctx.Done():
			s.err = ctx.Err()
			return
		case <-time.After(s.delay):
		}
		b, err := os.ReadFile(filepath.Join(run.Dir, ledger.EventsFile))
		if err != nil {
			s.err = err
			return
		}
		s.lines = bytes.Count(b, []byte{'\n'})
		_, _, s.err = ledger.NewCountedBlobRepository(run.Dir, run.BlobBytes).PutStream(bytes.NewReader(make([]byte, s.size)))
	}()
	return nil
}

// Stop waits for the store to end.
func (s *blobSource) Stop() error {
	if s.done != nil {
		<-s.done
	}
	return nil
}

// Gaps reports nothing uncovered.
func (s *blobSource) Gaps() []source.Gap { return nil }

// TestIntegrationLedgerCeilingCountsBlobs: a body stored beside the Writer counts against record.max_run_bytes, though
// events.jsonl stays far under it. The body is stored after the run's last observed line, so no line carries the run
// past the ceiling: the once-a-second check ends it, and the limit line is the first one after the store.
func TestIntegrationLedgerCeilingCountsBlobs(t *testing.T) {
	const ceiling = 64 << 10
	f := newFixtureWithMachine(t, contractFor("iledgerblob", []string{"/bin/sleep"}, []string{"/bin/sleep"}),
		func(m *config.Machine) {
			m.Record.MaxRunBytes = config.Ceiling[config.ByteSize]{Value: ceiling, Bounded: true}
		})
	deps := f.deps(t, nil)
	src := &blobSource{size: ceiling + 1, delay: 500 * time.Millisecond}
	deps.Capture = []source.Source{src}
	res, err := Run(context.Background(), f.rt, []string{"/bin/sleep", "60"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndLimit || res.ExitCode != identity.ExitLimit {
		t.Fatalf("result %+v, want limit/124", res)
	}
	if src.err != nil {
		t.Fatalf("the source's store: %v", src.err)
	}
	dir := runDirs(t, f.root)[0]
	evs := events(t, dir)
	if lim := limitEvent(t, evs); lim.Which != record.LimitLedgerBytes || lim.Value < ceiling {
		t.Fatalf("limit payload %+v, want ledger_bytes at or over %d", lim, ceiling)
	}
	// A line observed after the store would have ended the run itself, so the Tick would be untested.
	if src.lines < 1 || src.lines >= len(evs) || evs[src.lines].Kind != record.KindLimit {
		t.Fatalf("events.jsonl held %d lines at the store, and line %d of %d is not the limit: a line came between",
			src.lines, src.lines+1, len(evs))
	}
	if st, err := os.Stat(filepath.Join(dir, ledger.EventsFile)); err != nil || st.Size() >= ceiling {
		t.Fatalf("events.jsonl %v (%v): the test wants it under the ceiling", st, err)
	}
}

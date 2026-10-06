// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// TestComputeStreamsAHugeLedger is limits-check-doctor-cli.md E10 (§6 case 10) for drift.Compute: over a ledger
// of tens of thousands of events the live heap stays O(1) beyond the running aggregates, because the events are
// streamed through ledger.Reader.Iter and never held. The ledger here is 60k exec lines (well over 20 MB on
// disk); the heap is sampled while Compute runs, and its peak growth over the pre-run baseline must stay a
// fraction of the file. A ReadAll-style implementation holds every decoded event at once and blows through it.
func TestComputeStreamsAHugeLedger(t *testing.T) {
	const lines = 60_000
	var b strings.Builder
	for i := 1; i <= lines; i++ {
		b.WriteString(execLine(i, "exec[python3.12]", "allow", "/usr/bin/python3.12", false))
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	fileSize := int64(b.Len())
	b.Reset()

	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		tick := time.NewTicker(500 * time.Microsecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	rep, err := Compute(r, fixtureTable())
	close(stop)
	<-done
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if rep == nil {
		t.Fatal("no report")
	}

	growth := int64(peak.Load()) - int64(base.HeapAlloc)
	t.Logf("file %d bytes, peak heap growth %d bytes", fileSize, growth)
	if limit := fileSize / 2; growth > limit {
		t.Errorf("heap grew by %d bytes over a %d-byte ledger (limit %d): Compute is holding events, not streaming them",
			growth, fileSize, limit)
	}
}

// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestShutdownClearsTheLiveEntryOnlyOnceTheScopeIsReleased: when a source's Stop
// outlasts shutdown's wait, the handle's release and the scope's removal go to a goroutine, but the live entry
// had already been cleared. A launcher that exited before that goroutine left the scope, and a root launcher its
// record, with nothing listing the run, so no sweep ever met it. The entry now goes after the release, on the same
// goroutine: while it waits the run is still listed, for the next sweep's ended hook.
func TestShutdownClearsTheLiveEntryOnlyOnceTheScopeIsReleased(t *testing.T) {
	const runID = "r-00000000-000000000000f-l4live"
	root := t.TempDir()
	runDir := filepath.Join(root, runID)
	w, err := ledger.Open(runDir, record.RunRef{ID: runID, Agent: "shutdown-live"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.MarkLive(root, runID); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "cgroup"}); err != nil {
		t.Fatal(err)
	}
	listed := func() bool {
		ids, err := ledger.LiveEntries(root)
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(ids, runID)
	}
	h := &raceHandle{}
	stuck := &readingSource{plainSource: plainSource{name: "observe"}, release: make(chan struct{}), handle: h}
	g, _ := newGroup(context.Background())
	cgroups := &fakeCgroups{root: t.TempDir()}
	scope := filepath.Join(cgroups.root, "run.scope")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &runner{
		log: slog.New(slog.DiscardHandler), group: g, writer: w, handle: h, queue: NewQueue(8),
		stopWait: 20 * time.Millisecond, sources: []source.Source{stuck},
		cgm: cgroups, cg: cgroup.Cgroup{Path: scope},
		dir: runDir, id: runID, listed: true,
	}
	_ = r.shutdown(context.Background())
	if !listed() {
		t.Fatal("the entry was cleared while the scope's release still waits on a Stop: a launcher that exits now leaves a scope nothing lists")
	}
	close(stuck.release)
	deadline := time.Now().Add(5 * time.Second)
	for listed() || !h.isClosed() {
		if time.Now().After(deadline) {
			t.Fatalf("after the Stop returned: listed %v, handle closed %v; want the release, then the clear", listed(), h.isClosed())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

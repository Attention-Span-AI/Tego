// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"log/slog"
	"path/filepath"
	"testing"

	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestPurgeOrphanNeedsRootsRecord: run_start is ledger data its owner writes, so a planted run directory named after
// another user's live run, its run_start carrying a real bpf_hash and cgroup id 0 (which skips PurgeRun's alive
// check), must not unpin that run's links under a root sweep. The purge runs only for a directory root's record says
// root launched.
func TestPurgeOrphanNeedsRootsRecord(t *testing.T) {
	rootMarksIn(t)
	const id = "r-00000000-000000000000a-purge0"
	ledgerRoot := t.TempDir()
	w := openRun(t, ledgerRoot, id)
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "cgroup", BPFHash: "abc123"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	truncateRunEnd(t, filepath.Join(ledgerRoot, id))

	var purged []cgroupenforce.PurgeOptions
	prev := purgeRun
	t.Cleanup(func() { purgeRun = prev })
	purgeRun = func(o cgroupenforce.PurgeOptions) (cgroupenforce.PurgeResult, error) {
		purged = append(purged, o)
		return cgroupenforce.PurgeResult{}, nil
	}
	o := sweepOptions{log: slog.New(slog.DiscardHandler), marks: rootMarkDir}
	ref := record.RunRef{ID: id, Agent: "tester"}
	dir := filepath.Join(ledgerRoot, id)

	purgeOrphan(o, pathDir(filepath.Join(ledgerRoot, ref.ID)), ref, rootMarkDir.launched(pathDir(dir)))
	if len(purged) != 0 {
		t.Fatalf("a directory with no root launch record was purged: %+v", purged)
	}
	if err := writeRootMark(dir, id); err != nil {
		t.Fatal(err)
	}
	purgeOrphan(o, pathDir(filepath.Join(ledgerRoot, ref.ID)), ref, rootMarkDir.launched(pathDir(dir)))
	if len(purged) != 1 || purged[0].RunID != id || purged[0].Hash != "abc123" {
		t.Fatalf("a root-launched run was not purged: %+v", purged)
	}
	sweeperUID = func() int { return 1000 }
	purgeOrphan(o, pathDir(filepath.Join(ledgerRoot, ref.ID)), ref, true)
	if len(purged) != 1 {
		t.Fatalf("a sweeper that is not root purged: %+v", purged)
	}
}

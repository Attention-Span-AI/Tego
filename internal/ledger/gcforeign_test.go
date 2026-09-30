// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestGCAgesOutAForeignLostRunPastRetention: GC kept a lost run another host minted
// before it looked at its age, so retention never removed it, and SweepLive never cleared its entry. A machine id
// that changes (a reinstall keeping /home, a cloned image) makes every run of this host foreign, and they stayed
// forever. A foreign lost run is still never swept, but past retention it is removed with nothing written to
// it, and SweepLive then clears its entry; a foreign lost run within retention keeps its directory, its ledger
// and its entry.
func TestGCAgesOutAForeignLostRunPastRetention(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	foreign := WithForeignRun(func(string) bool { return true })
	hooked := 0
	hook := WithSweepHook(func(context.Context, sys.Lender, record.RunRef) error { hooked++; return nil })

	old := func(at time.Time, rand6 string) record.RunRef {
		w, ref := openLive(t, root, at, rand6)
		if err := MarkLive(root, ref.ID); err != nil {
			t.Fatal(err)
		}
		startRun(t, w, 1)
		die(w)
		return ref
	}
	aged := old(fixedStart, "frgn11")
	young := old(fixedStart.Add(365*24*time.Hour), "frgn12")
	now := WithNow(func() time.Time { return fixedStart.Add(365*24*time.Hour + time.Hour) })

	rep, err := GC(context.Background(), root, 24*time.Hour, false, foreign, hook, now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rep.Deleted, aged.ID) {
		t.Fatalf("a year-old lost run of another host was kept past a one-day retention: %+v", rep)
	}
	if slices.Contains(rep.Deleted, young.ID) || slices.Contains(rep.Swept, young.ID) || hooked != 0 {
		t.Fatalf("a foreign lost run within retention was removed or swept: %+v, hooks %d", rep, hooked)
	}
	if last, _ := lastOf(t, filepath.Join(root, young.ID)); last == record.KindRunEnd {
		t.Fatal("run_end appended to another host's run")
	}

	if _, err := SweepLive(context.Background(), root, foreign, hook); err != nil {
		t.Fatal(err)
	}
	if listed(t, root, aged.ID) {
		t.Error("the entry of a foreign run retention removed is still listed: nothing would ever clear it")
	}
	if !listed(t, root, young.ID) {
		t.Error("the entry of a foreign run that is still there was cleared: it is its own host's to clear")
	}
}

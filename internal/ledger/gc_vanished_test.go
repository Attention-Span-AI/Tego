// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// vanishingRepo removes the run's directory as Lock is called, as a concurrent gc's removal between State
// and Lock would.
type vanishingRepo struct {
	RunRepository
	root string
}

func (v vanishingRepo) Lock(ctx context.Context, id string, run record.RunRef) (*Writer, error) {
	if err := os.RemoveAll(filepath.Join(v.root, id)); err != nil {
		return nil, err
	}
	return v.RunRepository.Lock(ctx, id, run)
}

// TestGCReportsARunRemovedMidSweepAsDeleted: a lost run that a concurrent gc removes between State and the
// sweep's Lock has its retention outcome; it is not Kept.
func TestGCReportsARunRemovedMidSweepAsDeleted(t *testing.T) {
	root := t.TempDir()
	ref := makeRun(t, root, fixedStart, "vm0001", StateLost)
	rd, err := openDir(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	o := &gcOptions{now: func() time.Time { return fixedStart }}
	rep := Report{Errors: map[string]error{}}
	held := pinnedRepository(root, rd)
	repo := vanishingRepo{held, root}
	if err := gcRun(context.Background(), repo, held, ref, time.Hour, false, o, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Kept) != 0 || len(rep.Deleted) != 1 || rep.Deleted[0] != ref.ID {
		t.Fatalf("Kept %v Deleted %v, want the vanished run Deleted", rep.Kept, rep.Deleted)
	}
}

// TestRunTimeFallbackReadsTheLastLine: an id whose time36 does not parse takes the last line's ts, read from
// the tail; a damaged line earlier in the ledger does not cut the answer short.
func TestRunTimeFallbackReadsTheLastLine(t *testing.T) {
	root := t.TempDir()
	ref := makeRun(t, root, fixedStart, "rt0001", StateEnded)
	dir := filepath.Join(root, ref.ID)
	rd, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	var want time.Time
	for e, err := range rd.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		want = e.TS
	}
	_ = rd.Close()
	path := filepath.Join(dir, EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range data {
		if c == '\n' { // damage the second line's first byte
			data[i+1] = '#'
			break
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory whose name carries no time36 takes the fallback.
	const id = "r-00000000-0000000000000-aaaaaa"
	if err := os.Rename(dir, filepath.Join(root, id)); err != nil {
		t.Fatal(err)
	}
	got := runTime(&fsRunRepository{root: root}, id)
	if !got.Equal(want) {
		t.Fatalf("runTime = %v, want the last line's ts %v", got, want)
	}
}

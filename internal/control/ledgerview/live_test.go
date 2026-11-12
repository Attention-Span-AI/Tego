// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// liveGap is a launcher's confirming gap line for one live-block change.
func liveGap(run string, seq int, ts time.Time, why, op string, serial int) string {
	return line(run, "probe", seq, ts, "gap", fmt.Sprintf(
		`"what":"enforce","why":"%s","live_block":{"op":"%s","kind":"path","value":"/p/data","rule":"live.block[path:/p/data]","by":"uid:1000 pid:9 cli","serial":%d,"at":"2026-10-27T12:00:00Z"}`,
		why, op, serial))
}

func TestLiveFactsFromGapLines(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	held := "r-aaaa-0001-heldxx"
	writeRun(t, root, held,
		line(held, "probe", 0, t0, "run_start", `"tier":"landlock","command":["sh"],"fs_reads":{"reads":"held","why":"contract"}`),
		line(held, "probe", 1, t0.Add(time.Second), "fs", `"op":"open","path":"/p/data"`),
		liveGap(held, 2, t0.Add(2*time.Second), "live-block-added", "add", 1),
		// A gap about something else, and one the launcher could not read: neither confirms a serial.
		line(held, "probe", 3, t0.Add(3*time.Second), "gap", `"what":"record","why":"no-price-table"`),
		line(held, "probe", 4, t0.Add(4*time.Second), "gap", `"what":"enforce","why":"live-block-unreadable"`),
		liveGap(held, 5, t0.Add(5*time.Second), "live-block-removed", "remove", 2),
		liveGap(held, 6, t0.Add(6*time.Second), "live-block-added", "add", 3))
	watch := "r-aaaa-0002-watchx"
	writeRun(t, root, watch,
		line(watch, "probe", 0, t0, "run_start", `"tier":"observe","command":["sh"],"fs_reads":{"reads":"direct","why":"records-only"},"reads_notified":{"notified":false,"why":"records-only"}`),
		liveGap(watch, 1, t0.Add(time.Second), "live-block-added", "add", 1),
		line(watch, "probe", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	direct := "r-aaaa-0003-direct"
	writeRun(t, root, direct,
		line(direct, "probe", 0, t0, "run_start", `"tier":"landlock","command":["sh"],"fs_reads":{"reads":"direct","why":"none-nested"},"reads_notified":{"notified":false,"why":"reason-off"}`))

	r, err := LoadRun(root, held)
	if err != nil {
		t.Fatal(err)
	}
	f := LiveFactsOf(r)
	if f.Observe || !f.ReadsSeen || f.Ended {
		t.Fatalf("held run facts = %+v", f.Facts)
	}
	if f.Confirmed != 3 || f.ConfirmedSeq != 6 {
		t.Fatalf("Confirmed = %d at #%d, want 3 at #6", f.Confirmed, f.ConfirmedSeq)
	}
	for _, c := range []struct {
		serial uint64
		seq    uint64
		ok     bool
	}{{1, 2, true}, {2, 5, true}, {3, 6, true}, {4, 0, false}} {
		if seq, ok := f.Since(c.serial); seq != c.seq || ok != c.ok {
			t.Errorf("Since(%d) = #%d %v, want #%d %v", c.serial, seq, ok, c.seq, c.ok)
		}
	}
	if got := f.Status("path", 3).State; got != livestatus.InForce {
		t.Errorf("path at serial 3 = %s, want in force", got)
	}
	if got := f.Status("exec", 4).State; got != livestatus.Waiting {
		t.Errorf("exec at serial 4 = %s, want waiting", got)
	}
	// The same version's facts are built once: a second call returns what the first built.
	if g := LiveFactsOf(r); g.Confirmed != f.Confirmed || len(g.confirms) != len(f.confirms) {
		t.Errorf("second LiveFactsOf = %+v", g)
	}

	w, err := LoadRun(root, watch)
	if err != nil {
		t.Fatal(err)
	}
	if f := LiveFactsOf(w); !f.Observe || !f.Ended || f.Confirmed != 1 {
		t.Fatalf("watched run facts = %+v confirmed %d", f.Facts, f.Confirmed)
	}

	d, err := LoadRun(root, direct)
	if err != nil {
		t.Fatal(err)
	}
	f = LiveFactsOf(d)
	if f.ReadsSeen || f.Observe || f.Confirmed != 0 {
		t.Fatalf("direct run facts = %+v confirmed %d", f.Facts, f.Confirmed)
	}
	if got := f.Status("path", 1).State; got != livestatus.Waiting {
		t.Errorf("unconfirmed path = %s, want waiting", got)
	}
	if got := f.Status("path", 0).State; got != livestatus.Partial {
		t.Errorf("confirmed path on a direct-reads run = %s, want partial", got)
	}
}

// TestLiveFactsFollowAppends: a gap line appended to a run is a new version, whose facts see it.
func TestLiveFactsFollowAppends(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	run := "r-aaaa-0004-growxx"
	start := line(run, "probe", 0, t0, "run_start", `"tier":"landlock","command":["sh"]`)
	writeRun(t, root, run, start)
	s := Open(root)
	r, err := s.Run(run)
	if err != nil {
		t.Fatal(err)
	}
	if f := LiveFactsOf(r); f.Confirmed != 0 {
		t.Fatalf("before: Confirmed = %d", f.Confirmed)
	}
	fh, err := os.OpenFile(filepath.Join(root, run, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteString(liveGap(run, 1, t0.Add(time.Second), "live-block-added", "add", 1)); err != nil {
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = s.Run(run)
	if err != nil {
		t.Fatal(err)
	}
	if f := LiveFactsOf(r); f.Confirmed != 1 || f.ConfirmedSeq != 1 {
		t.Fatalf("after: Confirmed = %d at #%d, want 1 at #1", f.Confirmed, f.ConfirmedSeq)
	}
}

// TestLiveFactsSayAnUnreadableStart: lines with no run_start this build reads (another kind first, or a run_start
// whose payload does not decode) are StartUnreadable, so the lift page never tells such a run to try again; no line
// at all is a run still starting (the review's S1).
func TestLiveFactsSayAnUnreadableStart(t *testing.T) {
	for name, c := range map[string]struct {
		evs        []Event
		unreadable bool
	}{
		"no line":              {nil, false},
		"a gap first":          {[]Event{{Kind: string(record.KindGap), Raw: `{"what":"record","why":"x"}`}}, true},
		"a run_start not json": {[]Event{{Kind: string(record.KindRunStart), Raw: `{`}}, true},
		"a run_start":          {[]Event{{Kind: string(record.KindRunStart), Raw: `{"tier":"landlock"}`}}, false},
	} {
		f := liveFactsOf(c.evs)
		if f.StartUnreadable != c.unreadable || (f.Started && f.StartUnreadable) {
			t.Errorf("%s: %+v", name, f.Facts)
		}
	}
}

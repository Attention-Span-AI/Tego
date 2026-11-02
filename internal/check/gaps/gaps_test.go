// SPDX-License-Identifier: Apache-2.0

package gaps

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// gap builds one gap event with the given payload.
func gap(t *testing.T, p record.GapPayload) *record.Event {
	t.Helper()
	e := &record.Event{Kind: record.KindGap}
	if err := e.SetPayload(p); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestTallyGroupsByWhatWhy: events of one (what, why) are one entry whatever binary they name, the
// dropped counts add up, binaries are deduplicated and sorted, and non-gap events are ignored.
func TestTallyGroupsByWhatWhy(t *testing.T) {
	var tl Tally
	tl.Add(gap(t, record.GapPayload{What: "capture", Why: "no-openssl", Binary: "/usr/bin/gh"}))
	tl.Add(gap(t, record.GapPayload{What: "capture", Why: "no-openssl", Binary: "/usr/bin/curl"}))
	tl.Add(gap(t, record.GapPayload{What: "capture", Why: "no-openssl", Binary: "/usr/bin/gh"}))
	tl.Add(gap(t, record.GapPayload{What: "record", Why: "channel-full", Count: 12}))
	tl.Add(gap(t, record.GapPayload{What: "record", Why: "channel-full", Count: 3}))
	tl.Add(&record.Event{Kind: record.KindExec})
	tl.Add(nil)
	want := []Count{
		{What: "capture", Why: "no-openssl", Events: 3, Binaries: []string{"/usr/bin/curl", "/usr/bin/gh"}},
		{What: "record", Why: "channel-full", Events: 2, Lost: 15},
	}
	if got := tl.Counts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("counts = %+v\nwant %+v", got, want)
	}
	if got, want := Line(tl.Counts()), "capture/no-openssl x3 (in /usr/bin/curl, /usr/bin/gh); record/channel-full x2 (15 events lost)"; got != want {
		t.Fatalf("line = %q\nwant %q", got, want)
	}
}

// TestLineSaysNone: a run with no gap says so, rather than printing nothing a reader could take for
// a view that does not show gaps.
func TestLineSaysNone(t *testing.T) {
	var tl Tally
	if tl.Counts() != nil {
		t.Fatal("an empty tally has no counts")
	}
	if got := Line(nil); got != "none" {
		t.Fatalf("line = %q, want none", got)
	}
}

// TestLineCapsBinaries: the rendered line names at most three binaries per entry and counts the rest.
func TestLineCapsBinaries(t *testing.T) {
	c := []Count{{What: "capture", Why: "no-openssl", Events: 5, Binaries: []string{"/a", "/b", "/c", "/d", "/e"}}}
	if got, want := Line(c), "capture/no-openssl x5 (in /a, /b, /c, +2 more)"; got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
}

// TestUndecodableGapIsStillCounted: a gap whose payload does not decode is still a gap; it is
// counted as unknown rather than dropped from the one line that reports gaps.
func TestUndecodableGapIsStillCounted(t *testing.T) {
	var tl Tally
	tl.Add(&record.Event{Kind: record.KindGap, Payload: []byte(`{"what":7}`)})
	got := tl.Counts()
	if len(got) != 1 || got[0].What != Unknown || got[0].Why != Unknown || got[0].Events != 1 {
		t.Fatalf("counts = %+v", got)
	}
}

// TestMerge sums per-run tallies for an aggregated report.
func TestMerge(t *testing.T) {
	a := []Count{{What: "capture", Why: "h2", Events: 1, Binaries: []string{"/usr/bin/gh"}}}
	b := []Count{
		{What: "capture", Why: "h2", Events: 2, Binaries: []string{"/usr/bin/gh", "/usr/bin/node"}},
		{What: "record", Why: "channel-full", Events: 1, Lost: 4},
	}
	want := []Count{
		{What: "capture", Why: "h2", Events: 3, Binaries: []string{"/usr/bin/gh", "/usr/bin/node"}},
		{What: "record", Why: "channel-full", Events: 1, Lost: 4},
	}
	if got := Merge(a, b); !reflect.DeepEqual(got, want) {
		t.Fatalf("merge = %+v\nwant %+v", got, want)
	}
}

// TestFixtureGaps is the frozen run's own gap line (docs/P0-DESIGN.md §10): the capture gap for
// /usr/bin/gh and the supervisor's dropped-event gap.
func TestFixtureGaps(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	var tl Tally
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		tl.Add(e)
	}
	got := Line(tl.Counts())
	want := "capture/no-openssl x1 (in /usr/bin/gh); record/channel-full x1 (12 events lost)"
	if got != want {
		t.Fatalf("fixture gap line = %q\nwant %q", got, want)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		what, why string
		want      Class
	}{
		{record.GapEnforce, record.GapRunPaused, Live},
		{record.GapEnforce, record.GapPauseFailed, Live},
		{record.GapEnforce, record.GapMCPToolChanged, Live},
		{record.GapEnforce, record.GapModelRouteChanged, Live},
		{record.GapEnforce, record.GapLiveBlockLost, Missed},
		{record.GapEnforce, record.GapLiveBlockUnreadable, Missed},
		{record.GapCapture, "no-openssl", Capture},
		{record.GapRecord, "no-price-table", Price},
		{record.GapRecord, "price-table-version-mismatch", Price},
		{record.GapRecord, "unpriced-model", Price},
		{record.GapRecord, "channel-full", Missed},
		// A mode tego gave back to the owner of its own file lost no action; the same why under another what is not it.
		{record.GapRecord, record.GapOwnStateModeRestored, Restored},
		{record.GapEnforce, record.GapOwnStateModeRestored, Missed},
		{Unknown, Unknown, Missed},
		{"a-what-from-a-newer-tego", "x", Missed},
	}
	for _, c := range cases {
		if got := Classify(c.what, c.why); got != c.want {
			t.Errorf("Classify(%s, %s) = %d, want %d", c.what, c.why, got, c.want)
		}
	}
}

func TestWordsSayWhatHappened(t *testing.T) {
	cases := []struct {
		name string
		in   []Count
		want string
	}{
		{"no gap", nil, ""},
		{"only a person's changes", []Count{
			{What: record.GapEnforce, Why: record.GapRunPaused, Events: 2},
			{What: record.GapEnforce, Why: record.GapRunResumed, Events: 1},
		}, "no action known to be missing; the run was paused (2 times); the run was resumed"},
		{"a pause that failed is not called a pause", []Count{{What: record.GapEnforce, Why: record.GapPauseFailed, Events: 1}},
			"no action known to be missing; a pause could not be put in force; the run kept running"},
		{"one missed", []Count{{What: record.GapEnforce, Why: record.GapLiveBlockLost, Events: 1}},
			"1 gap in the record (counts are a minimum)"},
		{"missed with a drop count", []Count{{What: record.GapRecord, Why: "channel-full", Events: 2, Lost: 12}},
			"2 gaps in the record (counts are a minimum, 12 events lost)"},
		{"capture and price say no action is missing", []Count{
			{What: record.GapCapture, Why: "no-openssl", Events: 2},
			{What: record.GapRecord, Why: "no-price-table", Events: 1},
		}, "no action known to be missing; token counts may be low (2 capture gaps); the cost is not estimated (no price for a model)"},
		{"all at once", []Count{
			{What: record.GapCapture, Why: "no-openssl", Events: 1},
			{What: record.GapEnforce, Why: record.GapRunPaused, Events: 1},
			{What: record.GapRecord, Why: "ringbuf-full", Events: 1, Lost: 3},
		}, "1 gap in the record (counts are a minimum, 3 events lost); token counts may be low (1 capture gap); the run was paused"},
		// The modes tego gave back are no missing action, so the next run of an agent that took them reads complete.
		{"restored modes are no missing action", []Count{{What: record.GapRecord, Why: record.GapOwnStateModeRestored, Events: 4}},
			"no action known to be missing; tego restored the modes of 4 of its own files"},
		{"one restored mode beside a missed gap", []Count{
			{What: record.GapRecord, Why: "channel-full", Events: 1},
			{What: record.GapRecord, Why: record.GapOwnStateModeRestored, Events: 1},
		}, "1 gap in the record (counts are a minimum); tego restored the mode of one of its own files"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Words(c.in, false); got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

// TestWordsOfACutOffRun: a run with no run_end may lack more than its gap lines say, so its words never say that no
// action is known to be missing, and say so with no gap line at all.
func TestWordsOfACutOffRun(t *testing.T) {
	const cut = "the record has no end, so it may stop short of what the run did"
	cases := []struct {
		name string
		in   []Count
		want string
	}{
		{"no gap", nil, cut},
		{"only a person's change", []Count{{What: record.GapEnforce, Why: record.GapRunPaused, Events: 1}}, cut + "; the run was paused"},
		{"a capture gap", []Count{{What: record.GapCapture, Why: "no-openssl", Events: 1}}, cut + "; token counts may be low (1 capture gap)"},
		{"a missed gap", []Count{{What: record.GapRecord, Why: "channel-full", Events: 1}}, "1 gap in the record (counts are a minimum); " + cut},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Words(c.in, true); got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

// TestLiveWordsCoverEveryLiveChange: a live change with no words would print its why bare.
func TestLiveWordsCoverEveryLiveChange(t *testing.T) {
	for why := range liveChanges {
		if _, ok := LiveWords(why); !ok {
			t.Errorf("no words for %s", why)
		}
	}
}

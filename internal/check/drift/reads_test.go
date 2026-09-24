// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// readsTable declares one deny_read, one watch and one write entry, so the write is the entry a
// reads-blind run can still see used or not.
func readsTable() *agent.RuleTable {
	return &agent.RuleTable{
		Contract: &agent.Contract{Name: "tester"},
		FS: []agent.FSRule{
			{Path: "/home/u/secrets", Raw: "~/secrets", Kind: agent.FSDenyRead},
			{Path: "/home/u/notes", Raw: "~/notes", Kind: agent.FSWatch},
			{Path: "/home/u/out", Raw: "./out", Kind: agent.FSWrite},
			// A built-in entry is never the author's, so it is left out of every list.
			{Path: "/home/u/.ssh", Kind: agent.FSDenyRead, BuiltIn: true},
		},
	}
}

// readsRun writes one run whose run_start carries caps and whose body is the given events, and
// computes its drift report against readsTable.
func readsRun(t *testing.T, caps map[string]bool, body ...*record.Event) *Report {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "r-00000000-000000000000a-aaaaaa")
	w, err := ledger.Open(dir, record.RunRef{ID: filepath.Base(dir), Agent: "tester"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock", Capabilities: caps}); err != nil {
		t.Fatalf("run_start: %v", err)
	}
	for _, e := range body {
		if err := w.Append(e); err != nil {
			t.Fatalf("append %s: %v", e.Kind, err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("close: %v", err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	rep, err := Compute(r, readsTable())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	return rep
}

// TestReadsBlindRunLeavesDenyReadUnobservable: a tier-1 run records no reads
// (record.reads_mmap_chmod false, gap why=unprivileged-tier), so a deny_read or watch entry with no
// event is not observable, not "declared, never used", and it is not drift. Before the fix every
// such entry was reported unused and drift exited 1, which invited deleting a protection the kernel
// had just enforced.
func TestReadsBlindRunLeavesDenyReadUnobservable(t *testing.T) {
	for name, tc := range map[string]struct {
		caps map[string]bool
		body func(t *testing.T) []*record.Event
	}{
		"capability false": {caps: map[string]bool{string(backend.CapRecordReads): false}},
		"gap only": {body: func(t *testing.T) []*record.Event {
			return []*record.Event{gapEvent(t, record.GapPayload{What: "record", Why: "unprivileged-tier"})}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			var body []*record.Event
			if tc.body != nil {
				body = tc.body(t)
			}
			rep := readsRun(t, tc.caps, body...)
			if want := []string{"fs.deny_read[~/secrets]", "fs.watch[~/notes]"}; !slices.Equal(rep.UnobservableFS, want) {
				t.Errorf("UnobservableFS = %v, want %v", rep.UnobservableFS, want)
			}
			// The write entry is still one a blind run could see used, so it stays undone and drifts.
			if want := []string{"fs.write[./out]"}; !slices.Equal(rep.Undone, want) {
				t.Errorf("Undone = %v, want %v", rep.Undone, want)
			}
			if !rep.Drifted() {
				t.Error("the unused write entry must still drift")
			}
		})
	}
}

// TestReadsBlindRunAloneIsNoDrift: with only read-only entries undone, a blind run does not drift.
func TestReadsBlindRunAloneIsNoDrift(t *testing.T) {
	write := &record.Event{
		Kind: record.KindFS, Source: record.SourceSupervisor, PID: 1, TID: 1,
		Rule: "fs.write[./out]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule,
		Attr: &record.Attribution{Confidence: "unattributed", Method: "none"},
	}
	if err := write.SetPayload(record.FSPayload{Op: "open", Path: "/home/u/out/a"}); err != nil {
		t.Fatal(err)
	}
	rep := readsRun(t, map[string]bool{string(backend.CapRecordReads): false}, write)
	if len(rep.Undone) != 0 || rep.Drifted() {
		t.Fatalf("Undone = %v, drifted %v; a reads-blind run's deny_read and watch entries are not drift", rep.Undone, rep.Drifted())
	}
}

// TestRunThatRecordsReadsStillReportsUnused: when the run could record reads (record: full, or a
// capability line that says so), an untouched deny_read or watch entry is undone as before.
func TestRunThatRecordsReadsStillReportsUnused(t *testing.T) {
	rep := readsRun(t, map[string]bool{string(backend.CapRecordReads): true})
	if len(rep.UnobservableFS) != 0 {
		t.Fatalf("UnobservableFS = %v, want none", rep.UnobservableFS)
	}
	if want := []string{"fs.deny_read[~/secrets]", "fs.watch[~/notes]", "fs.write[./out]"}; !slices.Equal(rep.Undone, want) {
		t.Fatalf("Undone = %v, want %v", rep.Undone, want)
	}
}

// TestAggregateKeepsUnobservableFS: one blind run leaves an entry no run used open for the agent,
// as R17 does for an MCP server.
func TestAggregateKeepsUnobservableFS(t *testing.T) {
	blind := readsRun(t, map[string]bool{string(backend.CapRecordReads): false})
	seeing := readsRun(t, map[string]bool{string(backend.CapRecordReads): true})
	agg, err := Aggregate([]*Report{seeing, blind})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"fs.deny_read[~/secrets]", "fs.watch[~/notes]"}; !slices.Equal(agg.UnobservableFS, want) {
		t.Errorf("UnobservableFS = %v, want %v", agg.UnobservableFS, want)
	}
	if want := []string{"fs.write[./out]"}; !slices.Equal(agg.Undone, want) {
		t.Errorf("Undone = %v, want %v", agg.Undone, want)
	}
}

// TestRecordOffRunLeavesEntriesUnobservable: a record: off run writes record.exec_open_connect false and keeps
// only refusals, so a declared entry with no event is not "declared, never used" and is not drift.
func TestRecordOffRunLeavesEntriesUnobservable(t *testing.T) {
	caps := map[string]bool{string(backend.CapRecordExecOpenNet): false, string(backend.CapRecordReads): false}
	rep := readsRun(t, caps)
	if len(rep.Undone) != 0 || rep.Drifted() {
		t.Fatalf("Undone = %v, drifted %v; want none", rep.Undone, rep.Drifted())
	}
	if want := []string{"fs.write[./out]"}; !slices.Equal(rep.UnobservableRecord, want) {
		t.Errorf("UnobservableRecord = %v, want %v", rep.UnobservableRecord, want)
	}
	seeing := readsRun(t, map[string]bool{string(backend.CapRecordExecOpenNet): true, string(backend.CapRecordReads): true})
	agg, err := Aggregate([]*Report{seeing, rep})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"fs.write[./out]"}; !slices.Equal(agg.UnobservableRecord, want) {
		t.Errorf("aggregate UnobservableRecord = %v, want %v", agg.UnobservableRecord, want)
	}
	if agg.Drifted() {
		t.Errorf("aggregate drifted: Undone = %v", agg.Undone)
	}
}

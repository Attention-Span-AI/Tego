// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// liveChangesRun writes an ended run whose ledger holds a live block, a pause and a resume made from the dashboard,
// and, with withGap, a real gap (capture/no-openssl). It returns the run's id.
func liveChangesRun(t *testing.T, root string, withGap bool) string {
	t.Helper()
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "tester"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{
		Command: []string{"true"}, Cwd: "/", Tier: "landlock", TegoVersion: "test", Kernel: "test",
		ContractHash: strings.Repeat("a", 64), LauncherPID: 1, LauncherStartNS: 1, RecordMinor: record.MinorLiveModes,
	}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 27, 20, 31, 51, 0, time.UTC)
	by := "uid:1000 pid:9 dashboard"
	gs := []record.GapPayload{
		{What: record.GapEnforce, Why: record.GapLiveBlockAdded, LiveBlock: &record.LiveBlockChange{Op: record.LiveOpAdd,
			Kind: record.LiveKindExec, Value: "ls", Rule: record.LiveRule(record.LiveKindExec, "ls"), By: by, Serial: 1, At: at}},
		{What: record.GapEnforce, Why: record.GapRunPaused, LiveControl: &record.LiveControlChange{Op: record.LiveOpPause, By: by, Serial: 2, At: at}},
		{What: record.GapEnforce, Why: record.GapRunResumed, LiveControl: &record.LiveControlChange{Op: record.LiveOpResume, By: by, Serial: 3, At: at}},
	}
	if withGap {
		gs = append(gs, record.GapPayload{What: record.GapCapture, Why: "no-openssl", Binary: "/usr/bin/gh"})
	}
	for _, g := range gs {
		e := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: 1, TID: 1}
		if err := e.SetPayload(g); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestStatusLiveChangesAreNotGaps: a block, a pause and a resume are a person's live changes, not coverage the run
// lacked, so status prints them as "live changes", never under "gaps": --all names each run's real gaps and its live
// changes on their own lines, and one run says "gaps: none" beside its live changes. drift splits them the same way.
func TestStatusLiveChangesAreNotGaps(t *testing.T) {
	root := gcRoot(t)
	onlyLive := liveChangesRun(t, root, false)
	both := liveChangesRun(t, root, true)
	const changes = "enforce/live-block-added x1; enforce/run-paused x1; enforce/run-resumed x1"

	code, out, errs := run(t, "status", "--all")
	if code != identity.ExitOK {
		t.Fatalf("status --all: exit %d: %s", code, errs)
	}
	for _, want := range []string{
		"live changes " + onlyLive + ": " + changes + "\n",
		"gaps " + both + ": capture/no-openssl x1 (in /usr/bin/gh)\n",
		"live changes " + both + ": " + changes + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status --all lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "gaps "+onlyLive) || strings.Contains(out, "live-block-added x1 (") ||
		strings.Contains(out, ": capture/no-openssl x1 (in /usr/bin/gh); enforce/") {
		t.Errorf("status --all printed a live change as a gap:\n%s", out)
	}

	code, out, errs = run(t, "status", onlyLive)
	if code != identity.ExitOK {
		t.Fatalf("status %s: exit %d: %s", onlyLive, code, errs)
	}
	if !strings.Contains(out, "\ngaps: none\nlive changes: "+changes+"\n") {
		t.Errorf("status of one run:\n%s\nwant gaps: none, then live changes: %s", out, changes)
	}
	// QA PW-2: the same run in words, as the receipt and the dashboard say it.
	const words = "no action known to be missing; a live block was added; the run was paused; the run was resumed"
	if !strings.Contains(out, "\nin words: "+words+"\n") {
		t.Errorf("status of one run:\n%s\nwant in words: %s", out, words)
	}
	code, out, errs = run(t, "status", onlyLive, "--json")
	if code != identity.ExitOK {
		t.Fatalf("status --json: exit %d: %s", code, errs)
	}
	if !strings.Contains(out, `"gap_words":"`+words+`"`) {
		t.Errorf("status --json lacks gap_words: %s", out)
	}
	code, out, errs = run(t, "status", both)
	if code != identity.ExitOK {
		t.Fatalf("status %s: exit %d: %s", both, code, errs)
	}
	if want := "\nin words: no action known to be missing; token counts may be low (1 capture gap); a live block was added; the run was paused; the run was resumed\n"; !strings.Contains(out, want) {
		t.Errorf("status of a run with a capture gap:\n%s\nwant %s", out, want)
	}

	code, out, errs = run(t, "drift", filepath.Join(root, both))
	if code != identity.ExitOK && code != identity.ExitFinding {
		t.Fatalf("drift: exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "gaps: capture/no-openssl x1 (in /usr/bin/gh)\nlive changes: "+changes+"\n") {
		t.Errorf("drift:\n%s\nwant the gap, then live changes: %s", out, changes)
	}
}

// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTheAgentCannotReadTheLedgerButReadsItsReason: every run's events.jsonl and blobs were readable from inside any
// run, a stricter run's agent reading what a looser one recorded. The ledger root is now read-denied (agent-contract
// R6a), and the harness channel it held, last-refusal.json, reaches the agent through TEGO_REASON, a copy in the
// run's runtime directory (REASON-CHANNEL §2).
func TestTheAgentCannotReadTheLedgerButReadsItsReason(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
	f := newFixture(t, contractFor("ledgerread", []string{"/bin/sh"},
		[]string{"/bin/sh", "/usr/bin/sh", "/bin/cat", "/usr/bin/cat", "/bin/sleep", "/usr/bin/sleep"}))
	other := filepath.Join(f.root, "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "events.jsonl"), []byte("another run's record\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, f.root)
	script := filepath.Join(f.dir, "probe.sh")
	body := `#!/bin/sh
if cat "$1/events.jsonl" >out/other.read 2>out/other.err; then echo read-other > out/other; else echo refused-other > out/other; fi
echo x > "$2" 2>out/forbidden.err
[ -n "$TEGO_REASON" ] || exit 0
i=0
while [ ! -s "$TEGO_REASON" ] && [ $i -lt 100 ]; do sleep 0.05; i=$((i+1)); done
cat "$TEGO_REASON" > out/reason.json 2>out/reason.err
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	forbidden := filepath.Join(f.dir, "forbidden")
	if _, err := Run(context.Background(), f.rt, []string{"/bin/sh", script, other, forbidden}, f.deps(t, nil)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := readFileString(filepath.Join(f.out, "other")); strings.TrimSpace(got) != "refused-other" {
		t.Errorf("reading another run's events.jsonl: %q, want refused-other", got)
	}
	raw, err := os.ReadFile(filepath.Join(f.out, "reason.json"))
	if os.Geteuid() == 0 {
		// A root launcher makes no runtime directory, so the run has no readable copy and TEGO_REASON is
		// unset (REASON-CHANNEL §2); a live root run's directory was never readable to the dropped agent.
		if err == nil {
			t.Errorf("a root run wrote a reason copy: %s", raw)
		}
		return
	}
	if err != nil || len(raw) == 0 {
		t.Fatalf("no reason through TEGO_REASON (%v): %s", err, readFileString(filepath.Join(f.out, "reason.err")))
	}
	var p record.RefusedPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("reason.json: %v: %s", err, raw)
	}
	if p.Reason != record.ReasonWriteOutsideContract {
		t.Errorf("reason %q, want %q (%s)", p.Reason, record.ReasonWriteOutsideContract, raw)
	}
	// The copy read from inside the run is a whole v1 reason file (ADR 0061): its seq is a refused line's, its
	// count and recent list the run's refusals so far.
	rf, err := reason.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("reason.json is not a v1 reason file: %v: %s", err, raw)
	}
	var dir string
	for _, d := range runDirs(t, f.root) {
		if d != other {
			dir = d
		}
	}
	var refused []*record.Event
	for _, e := range events(t, dir) {
		if e.Kind != record.KindRunStart && strings.Contains(e.Rule, f.root) && e.Verdict == record.VerdictAllow {
			t.Errorf("the ledger records an allowed action under the ledger root: %s %s", e.Kind, e.Rule)
		}
		if e.Kind == record.KindRefused {
			refused = append(refused, e)
		}
	}
	if rf.Run != filepath.Base(dir) || rf.Refusals == 0 || rf.Refusals > uint64(len(refused)) || len(rf.Recent) == 0 {
		t.Fatalf("from inside the run: run %s, %d refusals, %d recent; the ledger of %s has %d refused lines",
			rf.Run, rf.Refusals, len(rf.Recent), filepath.Base(dir), len(refused))
	}
	// The agent read the file while the run went on, so it may be older than the ledger's last refused line, never
	// other than the line it names.
	line := refused[rf.Refusals-1]
	if rf.Seq != line.Seq || rf.Reason != line.Reason || rf.Recent[len(rf.Recent)-1].Seq != rf.Seq {
		t.Errorf("seq %d (%s), want the ledger's refused line %d's: seq %d (%s)", rf.Seq, rf.Reason, rf.Refusals,
			line.Seq, line.Reason)
	}
	for i, e := range rf.Recent {
		if want := refused[int(rf.Refusals)-len(rf.Recent)+i]; e.Seq != want.Seq || e.Reason != want.Reason {
			t.Errorf("recent[%d] seq %d (%s), want %d (%s)", i, e.Seq, e.Reason, want.Seq, want.Reason)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAskOneBadArgumentNamesBothKinds (QG-11): a single argument that is neither a run id nor an ask id says so.
func TestAskOneBadArgumentNamesBothKinds(t *testing.T) {
	gcRoot(t)
	code, out, errs := run(t, "ask", "nonsense")
	if code != identity.ExitUsage || out != "" ||
		!strings.Contains(errs, `tego ask: "nonsense" is neither a run id (r-…) nor an ask id (q-…)`) || !strings.Contains(errs, "[usage]") {
		t.Errorf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// askLedger writes a closed run whose ledger holds the given lines after run_start.
func askLedger(t *testing.T, lines []*record.Event) (dir, id string) {
	t.Helper()
	root := gcRoot(t)
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id = string(rid)
	dir = filepath.Join(root, id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "tester"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "landlock", RecordMinor: record.Minor}); err != nil {
		t.Fatal(err)
	}
	for _, e := range lines {
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
	return dir, id
}

// askLine is the launcher's line for ask q (emitAsk's shape).
func askLine(t *testing.T, q string) *record.Event {
	t.Helper()
	e := &record.Event{Kind: record.KindAsk, Source: record.SourceSupervisor}
	if err := e.SetPayload(map[string]any{"ask_id": q, "hold": "open", "op": "open", "target": "/h/.config/telemetry/token",
		"ask_rule": "fs.ask_read[/h/.config/telemetry/]"}); err != nil {
		t.Fatal(err)
	}
	return e
}

// answerLine is the launcher's answer line for ask q (emitAsk's shape).
func answerLine(t *testing.T, q string, approved bool, reason string, afterS float64) *record.Event {
	t.Helper()
	e := &record.Event{Kind: record.KindAnswer, Source: record.SourceSupervisor}
	p := map[string]any{"ask_id": q, "by": "uid:1000", "after_s": afterS, "approved": approved, "op": "open",
		"target": "/h/.config/telemetry/token", "ask_rule": "fs.ask_read[/h/.config/telemetry/]"}
	if reason != "" {
		p["answer_reason"] = reason
	}
	if err := e.SetPayload(p); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestAskOfAnEndedRunSaysTheRecordedAnswer (QG-11): `tego ask <ended run> <ask_id>` prints the answer and its line
// from the ledger, exit 0; an ask that was never answered says the run ended first; an id the ledger does not hold
// keeps "has ended", exit 1.
func TestAskOfAnEndedRunSaysTheRecordedAnswer(t *testing.T) {
	const denied, approved, unanswered, unknown = "q-0123456789abcdef0123456789abcd01", "q-0123456789abcdef0123456789abcd02",
		"q-0123456789abcdef0123456789abcd03", "q-0123456789abcdef0123456789abcd04"
	_, id := askLedger(t, []*record.Event{
		askLine(t, denied), answerLine(t, denied, false, "ask-denied", 0.077),
		askLine(t, approved), answerLine(t, approved, true, "", 12.4),
		askLine(t, unanswered),
	})
	for _, tc := range []struct{ q, want string }{
		{denied, denied + ": no longer waits: denied by uid:1000 after 77 ms, line #2\n"},
		{approved, approved + ": no longer waits: approved by uid:1000 after 12 s, line #4\n"},
		{unanswered, unanswered + ": no longer waits: asked on line #5 and never answered: its run ended while it waited, so the operation was refused\n"},
	} {
		if code, out, errs := run(t, "ask", id, tc.q); code != identity.ExitOK || out != tc.want {
			t.Errorf("tego ask %s: exit %d stdout %q stderr %q, want %q", tc.q, code, out, errs, tc.want)
		}
	}
	code, out, _ := run(t, "ask", id, denied, "--json")
	var got struct {
		Run      string    `json:"run"`
		AskID    string    `json:"ask_id"`
		Recorded askRecord `json:"recorded"`
	}
	if code != identity.ExitOK || json.Unmarshal([]byte(out), &got) != nil || got.Run != id || got.AskID != denied ||
		got.Recorded.AnswerSeq != 2 || got.Recorded.AnswerReason != "ask-denied" || got.Recorded.By != "uid:1000" {
		t.Errorf("--json: exit %d %q", code, out)
	}
	if code, _, errs := run(t, "ask", id, unknown); code != identity.ExitFinding || !strings.Contains(errs, id+" has ended; nothing waits for an answer") {
		t.Errorf("an id the ledger does not hold: exit %d stderr %q", code, errs)
	}
}

// TestAskOfAWatchRunSaysItTakesNone (QG-11): a live watch run serves no ask socket; `tego ask <run>` says a watch run
// takes no approvals rather than "no pending approvals", and --json keeps its empty list.
func TestAskOfAWatchRunSaysItTakesNone(t *testing.T) {
	root := gcRoot(t)
	const id = "r-3f9c2a1b-0dllq06ts7502-k7m2pc"
	dir := filepath.Join(root, id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "watch-codex"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Abandon() })
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"codex"}, Cwd: "/", Tier: "observe", RecordMinor: record.Minor}); err != nil {
		t.Fatal(err)
	}
	start, err := tegoruntime.StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteLockInfo([]byte((tegoruntime.LockInfo{PID: os.Getpid(), StartBootNS: start}).String())); err != nil {
		t.Fatal(err)
	}
	want := id + " is a watch run, and a watch run takes no approvals: tego watch records what the agent does and holds nothing for an answer\n"
	if code, out, errs := run(t, "ask", id); code != identity.ExitOK || out != want {
		t.Errorf("tego ask <watch run>: exit %d stdout %q stderr %q", code, out, errs)
	}
	if code, out, _ := run(t, "ask", id, "--json"); code != identity.ExitOK || !strings.Contains(out, `"pending":[]`) {
		t.Errorf("tego ask <watch run> --json: exit %d %q", code, out)
	}
}

// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// askReadTable is a table with one fs.ask_read entry and the ask configuration compile gives it.
func askReadTable() *agent.RuleTable {
	return &agent.RuleTable{
		Contract:  &agent.Contract{Name: "ask-read", FS: &agent.FSSection{AskRead: []string{"/vault"}}},
		Record:    agent.RecordSummary,
		AskConfig: &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4},
		FS:        []agent.FSRule{{Path: "/vault", Resolved: "/vault", Kind: agent.FSDenyRead, AskRead: true, Raw: "/vault"}},
	}
}

// Only tier 1's supervisor holds a read: a run of an fs.ask_read table at any other tier, the observe backend
// included, is refused before it starts rather than run with its asks silently turned into refusals.
func TestAskReadRefusedWithoutTierLandlock(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierObserve, backend.TierCgroup, backend.TierBPFLSM} {
		err := validateAskRequest(askReadTable(), Deps{Enforce: tierBackend{tier, backend.Matrix(tier)}})
		if !errors.Is(err, ask.ErrUnavailable) {
			t.Errorf("tier %s: %v; want the run refused", tier, err)
		}
	}
	if err := validateAskRequest(askReadTable(), Deps{Enforce: tierBackend{backend.TierLandlock, backend.Matrix(backend.TierLandlock)}}); err != nil {
		t.Fatalf("tier landlock: %v", err)
	}
	// Declared entries with no compiled configuration are refused, as fs.ask's are.
	rt := askReadTable()
	rt.AskConfig = nil
	if err := validateAskRequest(rt, Deps{Enforce: tierBackend{backend.TierLandlock, backend.Matrix(backend.TierLandlock)}}); !errors.Is(err, ask.ErrUnavailable) {
		t.Fatalf("ask_read without its configuration: %v", err)
	}
}

// An alternate is recorded additively: the ask line names the requested path, op read; the answer line names the
// alternate, approves nothing and gives no refusal reason; both validate as v1 lines.
func TestAlternateAnswerLineNamesTheAlternate(t *testing.T) {
	const id = "r-00000000-000000000000a-askxyz"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "ask-test"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	r := &runner{writer: w, deps: Deps{Clock: fixedClock{at: time.Now()}}, cg: cgroup.Cgroup{ID: 1}}
	req := ask.Request{AskID: "q-00112233445566778899aabbccddeeff", Op: ask.OpRead, Target: "/home/u/.aws/credentials", Rule: "fs.ask_read[~/.aws/credentials]", Hold: ask.HoldOpen, PID: os.Getpid(), TID: os.Getpid()}
	if err = r.emitAsk(ask.Event{Kind: "ask", Request: req}); err != nil {
		t.Fatal(err)
	}
	if err = r.emitAsk(ask.Event{Kind: "answer", Request: req, Decision: ask.Decision{AskID: req.AskID, By: "uid:1000 pid:7 always", Always: true, Alternate: "/home/u/fake-credentials", AlternateDev: 2049, AlternateIno: 4242, AfterS: 2}}); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	var askLine, answerLine map[string]any
	for _, ev := range events(t, dir) {
		if err = ev.Validate(); err != nil {
			t.Fatal(err)
		}
		switch ev.Kind {
		case record.KindAsk:
			_ = json.Unmarshal(ev.Payload, &askLine)
		case record.KindAnswer:
			_ = json.Unmarshal(ev.Payload, &answerLine)
		}
	}
	if askLine["target"] != "/home/u/.aws/credentials" || askLine["op"] != "read" || askLine["hold"] != "open" || askLine["alternate"] != nil {
		t.Fatalf("the ask line %v: want the requested path, op read", askLine)
	}
	// ADR 0057 D1: the operation as asked was not approved, and the alternate, its identity and the person's
	// authority are in the line.
	if answerLine["alternate"] != "/home/u/fake-credentials" || answerLine["approved"] != false || answerLine["answer_reason"] != nil ||
		!strings.HasSuffix(answerLine["by"].(string), " always") || answerLine["target"] != "/home/u/.aws/credentials" ||
		answerLine["alternate_dev"] != float64(2049) || answerLine["alternate_ino"] != float64(4242) {
		t.Fatalf("the answer line %v: want the alternate and its identity, approved false, no reason", answerLine)
	}
}

// ADR 0057 D4: run_start names each built-in deny_read entry the table's fs.ask_read entries relax, and carries
// nothing (the key absent) when there is none.
func TestRunStartNamesTheRelaxedBuiltIns(t *testing.T) {
	if got := askReadRelaxes(nil); got != nil {
		t.Fatalf("no relaxed entry: %+v, want nil so the key is absent", got)
	}
	in := []agent.AskReadRelax{{Rule: "fs.ask_read[~/.netrc]", BuiltIn: "/home/u/.netrc", How: agent.AskReadReplaces}, {Rule: "fs.ask_read[~/.aws/credentials]", BuiltIn: "/home/u/.aws", How: agent.AskReadInside}}
	got := askReadRelaxes(in)
	want := []record.AskReadRelax{{Rule: "fs.ask_read[~/.netrc]", BuiltIn: "/home/u/.netrc", How: "replaces"}, {Rule: "fs.ask_read[~/.aws/credentials]", BuiltIn: "/home/u/.aws", How: "inside"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("askReadRelaxes = %+v, want %+v", got, want)
	}
	b, err := json.Marshal(record.RunStartPayload{AskReadRelaxes: got})
	if err != nil || !strings.Contains(string(b), `"ask_read_relaxes":[{"rule":"fs.ask_read[~/.netrc]","builtin":"/home/u/.netrc","how":"replaces"},`) {
		t.Fatalf("run_start = %s, %v", b, err)
	}
	if b, _ = json.Marshal(record.RunStartPayload{}); strings.Contains(string(b), "ask_read_relaxes") {
		t.Fatalf("an empty run_start names relaxes: %s", b)
	}
}

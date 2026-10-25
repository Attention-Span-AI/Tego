// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// agent-contract.md R27, ADR 0062: run_start.harness came after contract_source, so a reader of a ledger at 14 or later
// knows an absent harness means a run provisioned for no harness, and one below 14 cannot tell.
func TestRecordMinorCoversTheHarness(t *testing.T) {
	if MinorHarness != 14 || Minor < MinorHarness || MinorHarness <= MinorContractSource {
		t.Fatalf("Minor %d, MinorHarness %d: harness is 14, after contract_source at 13", Minor, MinorHarness)
	}
	b, err := json.Marshal(HarnessStart{Name: "generic", Why: HarnessWhyNoProvisioner})
	if err != nil || string(b) != `{"name":"generic","provisioned":false,"why":"no-provisioner"}` {
		t.Fatalf("an unprovisioned harness = %s (%v)", b, err)
	}
	b, err = json.Marshal(RunStartPayload{})
	if err != nil || strings.Contains(string(b), "harness") {
		t.Fatalf("a run_start with no harness writes it: %s (%v)", b, err)
	}
}

// TestReadmeNamesTheHarnessMinor: the record README documents run_start.harness at the revision the writer stamps.
func TestReadmeNamesTheHarnessMinor(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "At `record_minor` " + strconv.Itoa(MinorHarness) + " ("
	i := strings.Index(string(b), want)
	if i < 0 || !strings.Contains(string(b[i:min(len(b), i+400)]), "`run_start` also carries the optional `harness`") {
		t.Fatalf("spec/record/v1/README.md does not say run_start.harness is written at record_minor %d (%q)", MinorHarness, want)
	}
	for _, why := range []string{HarnessWhyNoProvisioner, HarnessWhyReasonUnavailable, HarnessWhyHookRefused, HarnessWhyHookNotGranted} {
		if !strings.Contains(string(b), "`"+why+"`") {
			t.Errorf("README does not name harness why %s", why)
		}
	}
	// The gap a run without a reason file writes has its own entry among the gap kinds, at the same minor.
	gap := "`what=" + GapRecord + " why=" + HarnessWhyReasonUnavailable + "` (additive at `record_minor` " + strconv.Itoa(MinorHarness) + ")"
	if !strings.Contains(string(b), gap) {
		t.Errorf("README has no gap entry %s", gap)
	}
}

// TestHarnessFixture reads spec/record/v1/fixtures/harness.jsonl through Decode, Validate and Chain alone: run_start
// carries harness at record_minor 14 with its hook-state grant among runtime_grants, and the grant's rule names the
// line it allowed.
func TestHarnessFixture(t *testing.T) {
	events := readFixture(t, "harness.jsonl")
	var start RunStartPayload
	if len(events) == 0 || events[0].Kind != KindRunStart || events[0].DecodePayload(&start) != nil {
		t.Fatalf("no run_start in harness.jsonl")
	}
	h := start.Harness
	if start.RecordMinor != MinorHarness || h == nil || h.Name != "claude-code" || !h.Provisioned || h.Why != "" ||
		len(h.Files) != 1 || h.StateDir == "" || h.ReasonFile == "" {
		t.Fatalf("run_start harness %+v at record_minor %d", h, start.RecordMinor)
	}
	grant := "fs.harness-state[" + h.StateDir + "]"
	if len(start.RuntimeGrants) != 1 || start.RuntimeGrants[0] != grant {
		t.Fatalf("runtime_grants %v, want [%s]", start.RuntimeGrants, grant)
	}
	if events[1].Rule != grant || events[1].Verdict != VerdictAllow {
		t.Fatalf("the hook-state write is %+v", events[1])
	}
	if last := events[len(events)-1]; last.Kind != KindRunEnd {
		t.Fatalf("harness.jsonl ends with %s", last.Kind)
	}
}

// ADR 0064: run_start.harness.hook and the launcher's grant of it came at record_minor 20, a revision after
// fs.deny_write at 19 (the next free one when it merged, TestRecordMinorsAreContiguous), so a reader of a ledger at that
// revision or later knows an absent hook means a provision that named none.
func TestRecordMinorCoversTheHarnessHook(t *testing.T) {
	if Minor < MinorHarnessHook || MinorHarnessHook <= MinorUserDenyWrite {
		t.Fatalf("Minor %d, MinorHarnessHook %d: the harness hook is a revision after fs.deny_write at %d", Minor, MinorHarnessHook, MinorUserDenyWrite)
	}
	b, err := json.Marshal(HarnessStart{Name: "claude-code", Provisioned: true, Hook: &HarnessHook{Argv: []string{"/opt/tego/bin/tego", "hook"}, Granted: true}})
	if err != nil || string(b) != `{"name":"claude-code","provisioned":true,"hook":{"argv":["/opt/tego/bin/tego","hook"],"granted":true}}` {
		t.Fatalf("a granted hook = %s (%v)", b, err)
	}
	b, err = json.Marshal(HarnessStart{Name: "generic", Why: HarnessWhyHookWritable, Hook: &HarnessHook{Argv: []string{"/x"}}})
	if err != nil || string(b) != `{"name":"generic","provisioned":false,"why":"harness-hook-writable","hook":{"argv":["/x"],"granted":false}}` {
		t.Fatalf("a dropped hook = %s (%v)", b, err)
	}
}

// TestHarnessHookFixture reads spec/record/v1/fixtures/harness-hook.jsonl through Decode, Validate and Chain alone: an
// allow-list contract's run at record_minor 20 whose launcher granted its hook's exact argv (ADR 0064): harness.hook
// granted, exec.harness-hook[<tego>] among runtime_grants, the hook's exec allowed under it and another argv of the
// same binary refused under it.
func TestHarnessHookFixture(t *testing.T) {
	events := readFixture(t, "harness-hook.jsonl")
	var start RunStartPayload
	if len(events) != 4 || events[0].Kind != KindRunStart || events[0].DecodePayload(&start) != nil {
		t.Fatalf("harness-hook.jsonl: %d events", len(events))
	}
	h := start.Harness
	if start.RecordMinor != MinorHarnessHook || h == nil || !h.Provisioned || h.Hook == nil || !h.Hook.Granted || len(h.Hook.Argv) != 7 {
		t.Fatalf("run_start harness %+v at record_minor %d", h, start.RecordMinor)
	}
	grant := "exec.harness-hook[" + h.Hook.Argv[0] + "]"
	if len(start.RuntimeGrants) != 2 || start.RuntimeGrants[1] != grant {
		t.Fatalf("runtime_grants %v, want the hook-state grant and %s", start.RuntimeGrants, grant)
	}
	var ran, refused ExecPayload
	if events[1].DecodePayload(&ran) != nil || events[1].Rule != grant || events[1].Verdict != VerdictAllow || !slices.Equal(ran.Argv, h.Hook.Argv) {
		t.Fatalf("the hook's exec is %+v %+v", events[1], ran)
	}
	if events[2].DecodePayload(&refused) != nil || events[2].Rule != grant || events[2].Verdict != VerdictRefused ||
		events[2].Reason != ReasonExecNotAllowed || refused.CommandList != "unlisted" || slices.Equal(refused.Argv, h.Hook.Argv) {
		t.Fatalf("the other exec is %+v %+v", events[2], refused)
	}
}

// TestReadmeNamesTheHarnessHookMinor: the record README documents run_start.harness.hook, the grant's runtime rule and
// the new why at the revision the writer stamps.
func TestReadmeNamesTheHarnessHookMinor(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "At `record_minor` " + strconv.Itoa(MinorHarnessHook) + " ("
	i := strings.Index(string(b), want)
	if i < 0 {
		t.Fatalf("spec/record/v1/README.md has no %q", want)
	}
	text := string(b[i:min(len(b), i+2400)])
	for _, s := range []string{"`harness.hook`", "`exec.harness-hook[", "`" + HarnessWhyHookWritable + "`"} {
		if !strings.Contains(text, s) {
			t.Errorf("README's record_minor %d entry does not name %s", MinorHarnessHook, s)
		}
	}
}

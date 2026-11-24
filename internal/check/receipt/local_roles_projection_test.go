// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestLocalRolesReceiptAuthorityRequiresCompleteRunStart(t *testing.T) {
	authority := `{"mode":"owner_only","sha256":"` + strings.Repeat("ab", 32) + `","agent_uid":1001}`
	for _, tc := range []struct {
		name, key, value string
		want             bool
	}{
		{"valid", "local_approval_authority", authority, true},
		{"folded-key", "Local_approval_authority", authority, false},
		{"extra-member", "local_approval_authority", strings.TrimSuffix(authority, "}") + `,"extra":true}`, false},
		{"folded-member", "local_approval_authority", strings.Replace(authority, `"mode"`, `"Mode"`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := json.RawMessage(`{"record_minor":37,"` + tc.key + `":` + tc.value + `}`)
			r := ledgerOf(t, []line{{kind: record.KindRunStart, payload: payload}})
			rc, err := Compute(t.Context(), r, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if got := rc.LocalApprovalAuthority != nil; got != tc.want {
				t.Fatalf("authority projected=%v, want %v from %s", got, tc.want, payload)
			}
		})
	}
}

func TestLocalRolesReceiptAttributionRequiresRevisionAndCompleteAnswer(t *testing.T) {
	actor := &record.LocalApprovalActor{PID: 42, StartBootNS: 10, UserNamespace: record.InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}
	for _, tc := range []struct {
		name     string
		minor    int
		approved bool
		reason   string
		noFloor  bool // run_start carries no local_approval_authority
		want     bool
	}{
		{"below-minor", 31, true, "", false, false}, {"valid", 37, true, "", false, true}, {"invalid-denial", 37, false, "", false, false}, {"invalid-approval", 37, true, "ask-timeout", false, false},
		// An actor on an answer of a run that never started under the floor is not root's answer (a rewritten line).
		{"valid-line-without-the-floor", 37, true, "", true, false}, {"valid-line-without-the-floor-at-41", record.MinorEveryLaunch, true, "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// ledgerOf deliberately uses the legacy serializer so an invalid or
			// below-revision payload reaches the projection just as edited data can.
			start := record.RunStartPayload{RecordMinor: tc.minor, Tier: "landlock"}
			if !tc.noFloor {
				start.LocalApprovalAuthority = &record.LocalApprovalAuthority{Mode: "owner_only", SHA256: strings.Repeat("ab", 32), AgentUID: 1001}
			}
			r := ledgerOf(t, []line{{kind: record.KindRunStart, payload: start}, {kind: record.KindAsk, payload: map[string]any{"ask_id": "q-local"}}, {kind: record.KindAnswer, payload: map[string]any{"ask_id": "q-local", "approved": tc.approved, "answer_reason": tc.reason, "by": "uid:0 pid:42", "actor": actor}}})
			rc, err := Compute(t.Context(), r, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if got := rc.Asks.List[0].Actor != nil; got != tc.want {
				t.Fatalf("attribution=%v, want %v", got, tc.want)
			}
			var out bytes.Buffer
			if err := rc.JSON(&out); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(out.Bytes(), []byte(`"actor"`)) != tc.want {
				t.Fatalf("copied unvalidated attribution: %s", &out)
			}
		})
	}
}

func TestLocalRolesReceiptRecordedApprovalCanHaveRefusedEffect(t *testing.T) {
	actor := &record.LocalApprovalActor{PID: 42, StartBootNS: 10, UserNamespace: record.InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}
	r := ledgerOf(t, []line{
		{kind: record.KindRunStart, payload: record.RunStartPayload{RecordMinor: 37, Tier: "landlock", LocalApprovalAuthority: &record.LocalApprovalAuthority{Mode: "owner_only", SHA256: strings.Repeat("ab", 32), AgentUID: 1001}}},
		{kind: record.KindAsk, payload: map[string]any{"ask_id": "q-local", "op": "read", "target": "/data/file"}},
		{kind: record.KindAnswer, payload: map[string]any{"ask_id": "q-local", "approved": true, "by": "uid:0 pid:42", "actor": actor}},
		{kind: record.KindFS, verdict: record.VerdictRefused, rule: "fs.ask_read[/data/file]", reason: record.ReasonAskUnavailable, payload: map[string]any{"op": "open", "path": "/data/file", "errno": 13}},
	})
	rc, err := Compute(t.Context(), r, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rc.Asks.Approved != 1 || rc.Refusals.Total != 1 || rc.Asks.List[0].DeliveryNote == "" {
		t.Fatalf("selection/effect lost: %+v", rc)
	}
	var text, wire bytes.Buffer
	if err := rc.Text(&text); err != nil {
		t.Fatal(err)
	}
	if err := rc.JSON(&wire); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "approval recorded; operation completion is separate") || !strings.Contains(wire.String(), `"delivery_note"`) {
		t.Fatalf("unqualified approval: text=%s json=%s", &text, &wire)
	}
}

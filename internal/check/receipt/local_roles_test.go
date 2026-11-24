// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestLocalRolesReceiptAuthorityAndActors(t *testing.T) {
	for _, cause := range []string{"root", "timeout"} {
		t.Run(cause, func(t *testing.T) {
			authority := &record.LocalApprovalAuthority{Mode: "owner_only", SHA256: strings.Repeat("ab", 32), AgentUID: 1001}
			answer := map[string]any{"ask_id": "q-local", "by": "uid:0 pid:42", "approved": true, "after_s": 1}
			want := "root (uid 0), role Owner, pid 42"
			if cause == "root" {
				answer["actor"] = &record.LocalApprovalActor{PID: 42, StartBootNS: 10, UserNamespace: record.InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}
			} else {
				answer["by"], answer["approved"], answer["system_cause"], answer["answer_reason"] = "timeout", false, "timeout", "ask-timeout"
				want = "system: timeout"
			}
			r := ledgerOf(t, []line{{kind: record.KindRunStart, payload: record.RunStartPayload{RecordMinor: record.MinorLocalRoles, Tier: "landlock", LocalApprovalAuthority: authority}}, {kind: record.KindAsk, at: time.Second, payload: map[string]any{"ask_id": "q-local", "op": "read", "target": "/data/file"}}, {kind: record.KindAnswer, at: 2 * time.Second, payload: answer}})
			rc, err := Compute(t.Context(), r, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if rc.LocalApprovalAuthority == nil || len(rc.Asks.List) != 1 || ApprovalIdentity(rc.Asks.List[0].AnswerAuthority) != want {
				t.Fatalf("projection: %+v", rc)
			}
			var out bytes.Buffer
			if err := rc.Text(&out); err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{"Local approval authority: root-only", "root from a terminal outside any governed run", want} {
				if !strings.Contains(out.String(), text) {
					t.Fatalf("missing %q: %s", text, &out)
				}
			}
		})
	}
}

func TestLocalRolesLegacyIdentityIsNotInferred(t *testing.T) {
	if got := ApprovalIdentity(record.AnswerAuthority{}); got != "actor and role: not recorded" {
		t.Fatal(got)
	}
	a := record.AnswerAuthority{Actor: &record.LocalApprovalActor{UID: 1001, Role: "owner"}}
	if ApprovalIdentity(a) != "actor and role: not recorded" {
		t.Fatal("counterfeit role shown as Owner")
	}
	r := ledgerOf(t, []line{start("off", true), {kind: record.KindAsk, payload: record.AskPayload{AskID: "q-old", Hold: "open"}}, {kind: record.KindAnswer, payload: map[string]any{"ask_id": "q-old", "by": "uid:0 pid:42", "approved": true}}})
	rc, err := Compute(t.Context(), r, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := rc.JSON(&out); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"actor"`, `"system_cause"`, `"local_approval_authority"`} {
		if strings.Contains(out.String(), field) {
			t.Fatalf("legacy bytes gained %s", field)
		}
	}
}

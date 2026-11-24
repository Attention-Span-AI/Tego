// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"strings"
	"testing"
)

func TestLocalRolesReadModelPinsAuthority(t *testing.T) {
	st := newRunState("r-local", "/unused")
	st.take(Event{Kind: "run_start", Raw: `{"record_minor":37,"local_approval_authority":{"mode":"owner_only","sha256":"` + strings.Repeat("ab", 32) + `","agent_uid":1001}}`})
	st.take(Event{Kind: "ask", AskID: "q-local", askOp: "read", askTarget: "/data/file"})
	if q, _ := st.asks.Get("q-local"); st.b.LocalApprovalAuthority == nil || !q.OwnerOnly {
		t.Fatal("managed authority lost from pending view")
	}
	legacy := newRunState("r-old", "/unused")
	legacy.take(Event{Kind: "run_start", Raw: strings.ReplaceAll(st.b.Events[0].Raw, `"record_minor":37`, `"record_minor":31`)})
	if legacy.b.LocalApprovalAuthority != nil {
		t.Fatal("older record minor claimed local authority")
	}
	if got := ApprovalIdentity(record.AnswerAuthority{}); got != "actor and role: not recorded" {
		t.Fatal(got)
	}
	actor := &record.LocalApprovalActor{PID: 42, StartBootNS: 10, UserNamespace: record.InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}
	if got := ApprovalIdentity(record.AnswerAuthority{Actor: actor}); got != "root (uid 0), role Owner, pid 42" {
		t.Fatal(got)
	}
}

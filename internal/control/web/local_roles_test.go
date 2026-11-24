// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"html/template"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestLocalRolesDashboardAuthenticatedPOSTRefuses(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	csrf := csrfOf(t, s, c, "/approvals")
	old := answerAsk
	defer func() { answerAsk = old }()
	calls := 0
	answerAsk = func(context.Context, string, string, string, bool, bool) (runact.Answered, error) {
		calls++
		return runact.Answered{}, askproto.ErrOwnerOnly
	}
	for _, decision := range []string{"approve", "deny"} {
		w := post(s, "/approvals/answer", url.Values{"csrf": {csrf}, "run": {harmRun}, "ask": {testAsk}, "decision": {decision}}, own, own+"/approvals", c)
		body := follow(t, s, c, w)
		if !strings.Contains(body, "only root may answer once") || !strings.Contains(body, "root from a terminal outside any governed run") || !strings.Contains(body, "request remains pending") {
			t.Fatalf("refusal: %s", body)
		}
	}
	if calls != 2 {
		t.Fatal("valid session/CSRF/Origin did not reach shared authority")
	}
}

func TestLocalRolesDashboardSharedIdentity(t *testing.T) {
	actor := &record.LocalApprovalActor{PID: 42, StartBootNS: 10, UserNamespace: record.InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}
	for _, tc := range []struct {
		a    record.AnswerAuthority
		want string
	}{{record.AnswerAuthority{Actor: actor}, "root (uid 0), role Owner, pid 42"}, {record.AnswerAuthority{SystemCause: "timeout"}, "system: timeout"}} {
		a := tc.a
		payload := map[string]any{"approved": a.Actor != nil, "by": "uid:0 pid:42"}
		if a.Actor != nil {
			payload["actor"] = a.Actor
		} else {
			payload["system_cause"], payload["by"], payload["answer_reason"] = a.SystemCause, "timeout", "ask-timeout"
		}
		raw, _ := json.Marshal(payload)
		e := ledgerview.Event{Kind: "answer", Raw: string(raw), RecordMinor: record.MinorLocalRoles, LocalFloor: true}
		if got := shownOp(e); !strings.Contains(got, tc.want) || ledgerview.ApprovalIdentity(a) != tc.want {
			t.Fatalf("timeline identity: %s", got)
		}
	}
	if ledgerview.ApprovalIdentity(record.AnswerAuthority{}) != "actor and role: not recorded" {
		t.Fatal("old answer acquired a role")
	}
}

func TestLocalRolesApprovalCardNamesRootTerminal(t *testing.T) {
	// Rendering uses the same form data as the normal approvals page.
	a := ledgerview.Ask{Run: harmRun, AskID: testAsk, Op: "read", OwnerOnly: true, TS: time.Now()}
	data := funcs["askForm"].(func(ledgerview.Ask, string) map[string]any)(a, "csrf")
	var out strings.Builder
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	if err := pages["approvals"].ExecuteTemplate(&out, "askform", data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Only root may answer once") || !strings.Contains(out.String(), "root from a terminal outside any governed run") || strings.Contains(out.String(), "--always") || strings.Contains(out.String(), "type=\"submit\"") {
		t.Fatalf("managed card: %s", &out)
	}
	a.OwnerOnly = false
	personalAskForm(t, funcs["askForm"].(func(ledgerview.Ask, string) map[string]any)(a, "csrf"))
}

// personalAskForm compares against the pre-floor template bytes, under the same
// renderer. The reference is copied verbatim from the base commit.
func personalAskForm(t *testing.T, data map[string]any) {
	t.Helper()
	base, err := os.ReadFile("testdata/roles-personal-askform.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	old, err := template.New("layout.tmpl").Funcs(funcs).ParseFS(assets, "templates/layout.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Parse(string(base)); err != nil {
		t.Fatal(err)
	}
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	var before, after strings.Builder
	if err := old.ExecuteTemplate(&before, "askform", data); err != nil {
		t.Fatal(err)
	}
	if err := pages["approvals"].ExecuteTemplate(&after, "askform", data); err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("personal approval form bytes changed: before=%q after=%q", before.String(), after.String())
	}
}

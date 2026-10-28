// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var credMCPDir = filepath.Join(fixturesDir, "credmcp")

// TestRecordMinorCoversCredentialsAndMCPTools: the vault's and the MCP relay's fields are revision 25, the next free
// one after the live controls' 24 (TestRecordMinorsAreContiguous), and this build writes it.
func TestRecordMinorCoversCredentialsAndMCPTools(t *testing.T) {
	if MinorCredentialsAndMCPTools != 25 || MinorLiveControl != 24 || Minor < MinorCredentialsAndMCPTools {
		t.Fatalf("Minor %d, MinorCredentialsAndMCPTools %d", Minor, MinorCredentialsAndMCPTools)
	}
	b, err := json.Marshal(NetPayload{Op: "http_request", Proto: "http", Dst: "127.0.0.1:9511", Credential: &CredentialUse{Name: "openai", Version: 2}})
	if err != nil || !strings.Contains(string(b), `"credential":{"name":"openai","version":2}`) {
		t.Fatalf("a net line with a credential = %s (%v)", b, err)
	}
	for _, r := range credMCPReasons {
		if !r.Valid() || !slices.Contains(Reasons, r) {
			t.Errorf("reason %q is not in the closed set", r)
		}
	}
	for rule, want := range map[string]bool{"credential[openai]": true, "mcp[files].tools.deny[x]": true,
		"mcp[files].tools.allow": true, "mcp[files].live[x]": true, "mcp[files].relay": true, "mcp[files]": false,
		"net.allow[x]": false, "mcp[a].other": false} {
		if credMCPRule(rule) != want {
			t.Errorf("credMCPRule(%q) = %v", rule, !want)
		}
	}
}

// credDoc is one document of spec/record/v1/fixtures/credmcp: the envelope's kind, source, rule, verdict, authority
// and reason, the ledger's revision and the payload.
type credDoc struct {
	Kind      Kind            `json:"kind"`
	Minor     int             `json:"minor"`
	Source    Source          `json:"source"`
	Rule      string          `json:"rule"`
	Verdict   Verdict         `json:"verdict"`
	Authority Authority       `json:"authority"`
	Reason    Reason          `json:"reason"`
	Payload   json.RawMessage `json:"payload"`
}

func credEvent(t *testing.T, path string) (*Event, int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d credDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("%s: %v", filepath.Base(path), err)
	}
	e := &Event{V: Version, Kind: d.Kind, Source: d.Source, Run: "r-00000000-000000000000a-aaaaaa", Agent: "retriever",
		TS: time.Date(2026, 10, 27, 12, 3, 1, 0, time.UTC), Rule: d.Rule, Verdict: d.Verdict, Authority: d.Authority,
		Reason: d.Reason, Payload: d.Payload}
	if e.Kind.IsAction() {
		e.Attr = Unattributed()
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("%s: the envelope the harness built is not valid: %v", filepath.Base(path), err)
	}
	return e, d.Minor
}

// TestCredentialMCPFieldFixtures: every valid document of fixtures/credmcp passes ValidateAt at its revision; every
// invalid one is refused with the code its file name starts with, and below-minor, field-case, credential and
// mcp-tool each have one. Validate alone, which knows no revision, passes every one of them.
func TestCredentialMCPFieldFixtures(t *testing.T) {
	valid, _ := filepath.Glob(filepath.Join(credMCPDir, "valid", "*.json"))
	invalid, _ := filepath.Glob(filepath.Join(credMCPDir, "invalid", "*.json"))
	if len(valid) < 6 || len(invalid) < 12 {
		t.Fatalf("%d valid and %d invalid fixtures; want at least 6 and 12", len(valid), len(invalid))
	}
	for _, f := range valid {
		e, minor := credEvent(t, f)
		if err := e.ValidateAt(minor); err != nil {
			t.Errorf("%s: refused: %v", filepath.Base(f), err)
		}
		if _, err := e.MarshalLineAt(minor); err != nil {
			t.Errorf("%s: MarshalLineAt refused: %v", filepath.Base(f), err)
		}
	}
	seen := map[string]bool{}
	for _, f := range invalid {
		code, _, _ := strings.Cut(filepath.Base(f), ".")
		seen[code] = true
		e, minor := credEvent(t, f)
		err := e.ValidateAt(minor)
		if got := FieldCode(err); got != code {
			t.Errorf("%s: %v [%s], want [%s]", filepath.Base(f), err, got, code)
		}
		if err != nil && !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: %v is not ErrInvalidEvent", filepath.Base(f), err)
		}
	}
	for _, c := range []string{"below-minor", "field-case", "credential", "mcp-tool"} {
		if !seen[c] {
			t.Errorf("no invalid fixture of fixtures/credmcp shows [%s]", c)
		}
	}
}

// TestCredentialMCPBelowAndAtTheRevision: each new reason, rule, field and why passes at 25 and is refused
// [below-minor] at 24; a line of revision 24 with none of them passes at 24.
func TestCredentialMCPBelowAndAtTheRevision(t *testing.T) {
	ts := time.Date(2026, 10, 27, 12, 3, 1, 0, time.UTC)
	net := func(verdict Verdict, reason Reason, p NetPayload) *Event {
		e := &Event{V: Version, Kind: KindNet, Source: SourceForwarder, Run: "r-00000000-000000000000a-aaaaaa", Agent: "a",
			TS: ts, Rule: "credential[openai]", Verdict: verdict, Authority: AuthorityRule, Reason: reason, Attr: Unattributed()}
		if err := e.SetPayload(p); err != nil {
			t.Fatal(err)
		}
		return e
	}
	p := NetPayload{Op: "http_request", Proto: "http", Dst: "127.0.0.1:9511", Host: "127.0.0.1"}
	withCred := p
	withCred.Credential = &CredentialUse{Name: "openai", Version: 1}
	mcp := func(rule string, verdict Verdict, reason Reason) *Event {
		e := &Event{V: Version, Kind: KindMCP, Source: SourceProxy, Run: "r-00000000-000000000000a-aaaaaa", Agent: "a",
			TS: ts, Rule: rule, Verdict: verdict, Authority: AuthorityRule, Reason: reason, Attr: Unattributed()}
		if err := e.SetPayload(MCPPayload{Name: "files", Transport: "stdio", Tool: "delete_file"}); err != nil {
			t.Fatal(err)
		}
		return e
	}
	gap := &Event{V: Version, Kind: KindGap, Source: SourceProxy, Run: "r-00000000-000000000000a-aaaaaa", Agent: "a", TS: ts}
	if err := gap.SetPayload(GapPayload{What: GapEnforce, Why: GapMCPToolChanged, MCPTool: &MCPToolChange{Server: "files",
		Tool: "delete_file", Decision: MCPToolDeny, By: "uid:1000 pid:2 dashboard", Serial: 1, At: ts}}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]*Event{
		"injected":            net(VerdictAllow, "", withCred),
		"not-allowed":         net(VerdictRefused, ReasonCredentialNotAllowed, withCred),
		"revoked":             net(VerdictRefused, ReasonCredentialRevoked, withCred),
		"unavailable":         net(VerdictRefused, ReasonCredentialUnavailable, NetPayload{Op: "http_request", Proto: "http", Dst: "x:1", Credential: &CredentialUse{Name: "gone"}}),
		"rule-only":           net(VerdictAllow, "", p),
		"mcp-denied":          mcp("mcp[files].tools.deny[delete_file]", VerdictRefused, ReasonMCPToolDenied),
		"mcp-live":            mcp("mcp[files].live[delete_file]", VerdictAllow, ""),
		"mcp-relay":           mcp("mcp[files].relay", VerdictRefused, ReasonExecNotAllowed),
		"mcp-tool-changed":    gap,
		"mcp-allow-not-list":  mcp("mcp[files].tools.allow", VerdictRefused, ReasonMCPToolDenied),
		"mcp-ask-rule-answer": mcp("mcp[files].tools.ask[write_file]", VerdictAllow, ""),
	}
	for name, e := range cases {
		if err := e.ValidateAt(MinorCredentialsAndMCPTools); err != nil {
			t.Errorf("%s at 25: %v", name, err)
		}
		if got := FieldCode(e.ValidateAt(MinorLiveControl)); got != "below-minor" {
			t.Errorf("%s at 24: [%s], want [below-minor]", name, got)
		}
	}
	plain := mcp("mcp[files]", VerdictAllow, "")
	if err := plain.ValidateAt(MinorLiveControl); err != nil {
		t.Errorf("a plain mcp line at 24: %v", err)
	}
	// An injected request names the version it used.
	zero := withCred
	zero.Credential = &CredentialUse{Name: "openai"}
	if got := FieldCode(net(VerdictAllow, "", zero).ValidateAt(Minor)); got != "credential" {
		t.Errorf("an allowed line without a version: [%s]", got)
	}
}

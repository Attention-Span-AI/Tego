// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// generateCredentialMCP writes spec/record/v1/fixtures/credential-mcp.jsonl through the real Writer: a run at
// record_minor 25 (MinorCredentialsAndMCPTools, ADR 0126). The forwarder injects credential fake v1 into a request to
// its allowed endpoint, refuses the stand-in on another listener (credential-not-allowed), injects v2 after a rotation
// and refuses after the revocation (credential-revoked); the MCP relay allows read_file, refuses delete_file under
// tools.deny with its refused mirror, records a person's live switch of write_file to deny, and refuses write_file
// under the live rule.
func generateCredentialMCP(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 952_345_000_000, time.Millisecond)
	w, err := Open(dir, testRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	start := startPayload()
	start.Command = []string{"python3", "agent.py"}
	start.RecordMinor = record.MinorCredentialsAndMCPTools
	launcher := uint32(1000)
	start.LauncherUID = &launcher
	start.FSReads = &record.FSReads{Reads: record.FSReadsDirect, Why: record.FSReadsWhyNoneNested}
	start.ReadsNotified = &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyFull}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	req := func(authority string, version int, reason record.Reason) {
		verdict := record.VerdictAllow
		if reason != "" {
			verdict = record.VerdictRefused
		}
		p := record.NetPayload{Op: "http_request", Proto: "http", Dst: "127.0.0.1:41000", Host: "127.0.0.1",
			HTTPAuthority: authority, Method: "POST", Path: "/v1/messages",
			Credential: &record.CredentialUse{Name: "fake", Version: version}}
		f.emit(time.Millisecond, f.action(record.KindNet, record.SourceForwarder, fxTID, "credential[fake]", verdict,
			reason, record.Unattributed(), p))
	}
	req("127.0.0.1:9511", 1, "")
	req("127.0.0.1:9512", 1, record.ReasonCredentialNotAllowed)
	req("127.0.0.1:9511", 2, "")
	req("127.0.0.1:9511", 2, record.ReasonCredentialRevoked)
	call := func(tool, rule string, reason record.Reason) {
		verdict := record.VerdictAllow
		if reason != "" {
			verdict = record.VerdictRefused
		}
		f.emit(time.Millisecond, f.action(record.KindMCP, record.SourceProxy, fxTID, rule, verdict, reason, record.Unattributed(),
			record.MCPPayload{Name: "files", Transport: "stdio", Tool: tool}))
		if reason != "" {
			m := f.plain(record.KindRefused, record.SourceProxy, fxPID, fxTID, record.RefusedPayload{Op: "tools/call",
				Target: "files " + tool, Reason: reason, Rule: rule})
			m.Rule, m.Reason = rule, reason
			f.emit(0, m)
		}
	}
	call("read_file", "mcp[files].tools.allow[read_file]", "")
	call("delete_file", "mcp[files].tools.deny[delete_file]", record.ReasonMCPToolDenied)
	f.emit(time.Millisecond, f.plain(record.KindGap, record.SourceProxy, 48211, 48211, record.GapPayload{What: record.GapEnforce,
		Why: record.GapMCPToolChanged, MCPTool: &record.MCPToolChange{Server: "files", Tool: "write_file", Decision: record.MCPToolDeny,
			By: "uid:1000 pid:51234 dashboard", Serial: 1, At: fixedStart.Add(3 * time.Second).UTC()}}))
	call("write_file", "mcp[files].live[write_file]", record.ReasonMCPToolDenied)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0,
		Supervisor: record.Supervisor{Notifications: 3}}); err != nil {
		t.Fatal(err)
	}
}

// TestCredentialMCPFixtureFrozen regenerates credential-mcp.jsonl and compares it byte for byte with the committed
// file; -update rewrites it. The Writer encodes every line at the run's revision, so the fixture also shows the new
// lines pass ValidateAt at 25; read at 24, every new line is refused [below-minor].
func TestCredentialMCPFixtureFrozen(t *testing.T) {
	root := t.TempDir()
	generateCredentialMCP(t, filepath.Join(root, testRef.ID), &memAnchor{})
	got := readFile(t, filepath.Join(root, testRef.ID, EventsFile))
	path := filepath.Join(fixturesDir, "credential-mcp.jsonl")
	if *updateFixtures {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("credential-mcp.jsonl: %v (run with -update to generate)", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("credential-mcp.jsonl differs from the generator output; run go test ./internal/ledger -run TestCredentialMCPFixtureFrozen -update")
	}
	n := 0
	for _, line := range bytes.Split(bytes.TrimSpace(got), []byte("\n")) {
		e, err := record.Decode(line)
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind == record.KindRunStart || e.Kind == record.KindRunEnd || e.Rule == "mcp[files].tools.allow[read_file]" {
			continue
		}
		n++
		if record.FieldCode(e.ValidateAt(record.MinorLiveControl)) != "below-minor" {
			t.Errorf("line %d (%s %s) passes at 24", e.Seq, e.Kind, e.Rule)
		}
	}
	if n < 8 {
		t.Fatalf("%d new lines", n)
	}
}

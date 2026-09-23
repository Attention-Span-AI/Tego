// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// driftContract declares what the frozen fixture's run used, plus one entry and one MCP server it
// never touched, so the report has an undone entry to show. Its paths are relative: they resolve
// against the run's own cwd from run_start (runWithContract points it at the run directory, where
// the test creates them), never against the directory drift is invoked from.
const driftContract = `version: 0
name: retriever
command: ["sh", "agent.py"]
mcp:
  - name: fs
    command: ["sh"]
  - name: postgres
    command: ["sh"]
models:
  - { provider: anthropic, host: api.anthropic.com, port: 443 }
fs:
  write: ["./out"]
  watch: ["./config"]
exec:
  allow: ["jq"]
`

// fixtureBytes is the frozen v1 fixture ledger.
func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

// runWithContract is fixtureRun plus the contract.yaml copy a real run directory carries, with the
// fixture's run_start cwd (/home/u/proj, a machine that is not this one) replaced by the run
// directory itself. Only Decode reads the line, never the chain verifier, so the edit is invisible
// to drift except where it is meant to be seen: the directory relative entries resolve against.
func runWithContract(t *testing.T, contract string) string {
	t.Helper()
	dir := fixtureRun(t)
	events := filepath.Join(dir, ledger.EventsFile)
	data, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	const cwd = `"cwd":"/home/u/proj"`
	if !strings.Contains(string(data), cwd) {
		t.Fatalf("the fixture's run_start no longer carries %s", cwd)
	}
	data = []byte(strings.Replace(string(data), cwd, `"cwd":"`+dir+`"`, 1))
	if err := os.WriteFile(events, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.ContractFile), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestDriftAgainstTheFixture: declared versus observed computed from the
// frozen ledger and the run's own contract copy, with the declared-but-unused entries named.
func TestDriftAgainstTheFixture(t *testing.T) {
	// The contract allows exec[jq], which compiles only where PATH finds a jq, and where it does not, every
	// entry reads as undeclared. The KVM guest of make vm-root-test has none, and neither need a runner or a
	// developer's box, so the test brings its own: drift never runs it.
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "jq"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := runWithContract(t, driftContract)
	for _, sub := range []string{"out", "config"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(t.TempDir()) // anywhere but the run's cwd: the report must not depend on it
	code, out, errs := run(t, "drift", dir)
	if code != identity.ExitFinding { // R25: the run refused an action and used rules it never declared
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	flat := columns(out)
	for _, want := range []string{
		"RUN r-3f9c2a1b-0dllq06ts7400-k7m2pq",
		"AGENT retriever",
		"ACTIONS 32",
		// declared and used, declared and not, used and never declared
		"fs fs.write[./out] yes 10 0 0 0",
		"fs fs.watch[./config] yes 0 0 0 0",
		"fs fs.deny_read[~/.ssh] no 0 0 1 0",
		"net models[anthropic] yes 1 0 0 0",
		"mcp mcp[fs] yes 3 0 0 0",
		"declared, never used: exec[jq], fs.watch[./config]",
		"unused mcp servers: mcp[postgres]",
		// What the record could not see, under the verdict it qualifies
		"gaps: capture/no-openssl x1 (in /usr/bin/gh); record/channel-full x1 (12 events lost)",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	// The compiler's own additions — the built-in deny_read list, the implicit
	// exec grant for the agent's command — are not the author's declarations
	// and stay out of the report unless the run used them.
	if strings.Contains(flat, "fs.deny_read[/") || strings.Contains(flat, "exec[sh]") {
		t.Errorf("compiler-added entries leaked into the report:\n%s", out)
	}
}

// columns collapses tabwriter padding so a test asserts on a row's content, not on how wide the
// widest rule name happened to be on this machine.
func columns(out string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(out, "\n", " \n ")), " ")
}

// TestDriftJSON pins the --json object: one per invocation, empty lists as [] (§6 case 22).
func TestDriftJSON(t *testing.T) {
	dir := fixtureRun(t)
	code, out, errs := run(t, "drift", dir, "--json")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d stderr %s", code, errs)
	}
	var got driftJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got.Run != "r-3f9c2a1b-0dllq06ts7400-k7m2pq" || got.Agent != "retriever" || got.Runs != 1 {
		t.Errorf("identity: %+v", got)
	}
	if got.Actions != 32 || len(got.Rules) != 12 || !got.Drift {
		t.Errorf("counts: actions %d rules %d drift %v", got.Actions, len(got.Rules), got.Drift)
	}
	// No contract.yaml copy: every observed rule is undeclared and there is nothing to compare
	// the hash against (§6 case 23).
	if got.CurrentHash != "" || got.HashChanged {
		t.Errorf("hash: %q %v", got.CurrentHash, got.HashChanged)
	}
	for _, r := range got.Rules {
		if r.Declared {
			t.Errorf("%q declared without a contract", r.Rule)
		}
	}
	if !strings.Contains(out, `"undone":[]`) || !strings.Contains(out, `"unused_mcp":[]`) ||
		!strings.Contains(out, `"unobservable_fs":[]`) || !strings.Contains(out, `"unobservable_record":[]`) {
		t.Errorf("empty lists must render as []:\n%s", out)
	}
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Errorf("--json is one object on one line:\n%s", out)
	}
}

// TestDriftAggregate sums two runs of one agent under a shared ledger root (R17).
func TestDriftAggregate(t *testing.T) {
	root := t.TempDir()
	data := fixtureBytes(t)
	first := filepath.Join(root, "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	second := filepath.Join(root, "r-3f9c2a1b-0dllq06ts7400-k7m2pr")
	for _, dir := range []string{first, second} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := run(t, "drift", first, "--aggregate", "--json")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d stderr %s", code, errs)
	}
	var got driftJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got.Runs != 2 || got.Run != "" || got.Agent != "retriever" {
		t.Errorf("identity: %+v", got)
	}
	if got.Actions != 64 {
		t.Errorf("actions %d, want 64", got.Actions)
	}
	for _, r := range got.Rules {
		if r.Rule == "exec[rg]" && r.Allow != 6 {
			t.Errorf("exec[rg] allow %d, want 6", r.Allow)
		}
	}
}

// TestDriftAggregateAcceptsATrailingSlash is the same aggregation over the path shell completion
// actually produces. The ledger root was taken as filepath.Dir of the argument as typed, and
// filepath.Dir("<root>/<run>/") is the run directory itself: os.ReadDir then found no run-shaped
// entry in it, so --aggregate silently reported the one run it was given as the agent's total.
func TestDriftAggregateAcceptsATrailingSlash(t *testing.T) {
	root := t.TempDir()
	data := fixtureBytes(t)
	first := filepath.Join(root, "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	second := filepath.Join(root, "r-3f9c2a1b-0dllq06ts7400-k7m2pr")
	for _, dir := range []string{first, second} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := run(t, "drift", first+string(os.PathSeparator), "--aggregate", "--json")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d stderr %s", code, errs)
	}
	var got driftJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got.Runs != 2 || got.Actions != 64 {
		t.Errorf("runs %d actions %d, want 2 and 64: the trailing slash lost the agent's other run", got.Runs, got.Actions)
	}
}

// TestDriftCleanRun is the exit-0 half of R25: nothing declared, nothing recorded, no drift. The ledger is
// run_start alone: an empty events.jsonl is no run record at all, 125 (TestNoRunRecordIsAnError).
func TestDriftCleanRun(t *testing.T) {
	dir := t.TempDir()
	start, _, _ := strings.Cut(string(fixtureBytes(t)), "\n")
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), []byte(start+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "drift", dir)
	if code != identity.ExitOK {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if !strings.Contains(out, "no rules declared and none recorded") {
		t.Errorf("stdout %q", out)
	}
}

// TestDriftUsage covers the argument and failure paths (R25).
func TestDriftUsage(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"no run", []string{"drift"}, identity.ExitUsage, "[usage]"},
		{"two runs", []string{"drift", "a", "b"}, identity.ExitUsage, "[usage]"},
		// A directory with no run record in it is the caller's mistake, a usage error; it was 125 [io].
		{"no record", []string{"drift", filepath.Join(t.TempDir())}, identity.ExitUsage, "holds no events.jsonl [usage]"},
		{"events: no record", []string{"events", t.TempDir()}, identity.ExitUsage, "holds no events.jsonl [usage]"},
		{"measure: no record", []string{"measure", t.TempDir()}, identity.ExitUsage, "holds no events.jsonl [usage]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errs := run(t, tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit %d want %d: %q", code, tc.wantCode, errs)
			}
			if !strings.Contains(errs, tc.wantErr) {
				t.Fatalf("stderr %q lacks %q", errs, tc.wantErr)
			}
		})
	}
}

// TestDriftTornLedger is §6 case 3: a torn middle line is fatal and named, never guessed past.
func TestDriftTornLedger(t *testing.T) {
	dir := t.TempDir()
	lines := strings.Split(strings.TrimSuffix(string(fixtureBytes(t)), "\n"), "\n")
	lines[4] = `{"v":1,"seq":4,"kind":`
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run(t, "drift", dir)
	if code != identity.ExitError {
		t.Fatalf("exit %d: %q", code, errs)
	}
	if !strings.Contains(errs, "tego drift:") {
		t.Fatalf("stderr %q", errs)
	}
}

// TestDriftNamesAContractCopyErrorOnce: a contract copy that no longer loads or compiles was reported with
// its diagnostic's code rendered into the message and appended again, "[schema] [schema]". The code is the
// diagnostic's own and appears once.
func TestDriftNamesAContractCopyErrorOnce(t *testing.T) {
	for name, contract := range map[string]string{
		"no longer loads":    "version: 0\nname: retriever\ncommand: [\"sh\"]\nbogus: 1\n",
		"no longer compiles": "version: 0\nname: retriever\ncommand: [\"sh\"]\nfs:\n  deny_read: [\"/nonexistent-tego-dir/x\"]\n",
	} {
		dir := runWithContract(t, contract)
		_, _, errs := run(t, "drift", dir)
		var line string
		for l := range strings.Lines(errs) {
			if strings.Contains(l, "contract.yaml no longer") {
				line = l
			}
		}
		if line == "" {
			t.Errorf("%s: no contract.yaml line in:\n%s", name, errs)
			continue
		}
		if n := strings.Count(line, " ["); n != 1 {
			t.Errorf("%s: %d codes on %q", name, n, line)
		}
	}
}

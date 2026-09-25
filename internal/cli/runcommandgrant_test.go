// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// grantRun writes a finished run whose run_start carries grant as run_command_grant ("" for none) and returns
// its id.
func grantRun(t *testing.T, grant string) string {
	t.Helper()
	root := gcRoot(t)
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"echo"}, Cwd: "/", Tier: "landlock",
		ContractHash: strings.Repeat("a", 64), RunCommandGrant: grant}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return string(id)
}

// TestStatusAndEventsShowTheRunCommandGrant: in the views, the command given after
// `--` is granted for the whole run, and the contract hash does not cover it, so `tego status` and `tego
// events` show run_start.run_command_grant where they show run_start's details, and say nothing of one for a
// run that had none.
func TestStatusAndEventsShowTheRunCommandGrant(t *testing.T) {
	id := grantRun(t, "/usr/bin/echo")
	code, out, errs := run(t, "status", id)
	if code != identity.ExitOK {
		t.Fatalf("status: exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "\nrun command grant: /usr/bin/echo ") {
		t.Errorf("status lacks the run command grant:\n%s", out)
	}
	code, out, errs = run(t, "status", "--json", id)
	if code != identity.ExitOK {
		t.Fatalf("status --json: exit %d: %s", code, errs)
	}
	var got struct {
		Grant string `json:"run_command_grant"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.Grant != "/usr/bin/echo" {
		t.Errorf("status --json run_command_grant = %q (%v):\n%s", got.Grant, err, out)
	}
	code, out, errs = run(t, "events", id)
	if code != identity.ExitOK {
		t.Fatalf("events: exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "run_command_grant=/usr/bin/echo") {
		t.Errorf("events' run_start line lacks the grant:\n%s", out)
	}

	id = grantRun(t, "")
	_, out, _ = run(t, "status", id)
	_, evs, _ := run(t, "events", id)
	if strings.Contains(out+evs, "run command grant") || strings.Contains(out+evs, "run_command_grant") {
		t.Errorf("a run with no grant shows one:\n%s\n%s", out, evs)
	}
}

// TestDriftRecompilesWithTheRunCommand: drift recompiled the run's contract without
// the command the run was given on its command line, so the table it compared the record with lacked the
// run's own command, and every run started with one drifted. It recompiles with run_start.run_command_grant,
// and a ledger from before that field falls back to run_start.command[0].
func TestDriftRecompilesWithTheRunCommand(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := runWithContract(t, "version: 0\nname: retriever\ncommand: [\"sh\"]\nexec: {}\n")
	events := filepath.Join(dir, ledger.EventsFile)
	data, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	const cwd = `"cwd":"`
	withGrant := strings.Replace(string(data), cwd, `"run_command_grant":"`+tool+`",`+cwd, 1)
	if err := os.WriteFile(events, []byte(withGrant), 0o600); err != nil {
		t.Fatal(err)
	}
	o := origin(t, dir)
	if o.runCommand != tool {
		t.Fatalf("origin.runCommand = %q, want run_start's run_command_grant %q", o.runCommand, tool)
	}
	rt, _ := contractTable(t.Context(), dir, o, &machineOnce{stderr: io.Discard}, io.Discard)
	if rt == nil {
		t.Fatal("the run's contract did not recompile")
	}
	if rt.RunCommandGrant != tool {
		t.Fatalf("drift's table does not grant the run's command %s: %+v", tool, rt.Exec)
	}

	if err := os.WriteFile(events, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if o := origin(t, dir); o.runCommand != "python3" {
		t.Errorf("an older run_start with no run_command_grant: runCommand = %q, want command[0] python3", o.runCommand)
	}
	// A ledger at record_minor 1 omits the field only when nothing was granted: no fallback.
	current := strings.Replace(string(data), cwd, `"record_minor":1,`+cwd, 1)
	if err := os.WriteFile(events, []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}
	if o := origin(t, dir); o.runCommand != "" {
		t.Errorf("a current run_start with no run_command_grant: runCommand = %q, want none granted", o.runCommand)
	}
}

// origin reads a run directory's runOrigin.
func origin(t *testing.T, dir string) runOrigin {
	t.Helper()
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	o, err := readRunOrigin(r)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

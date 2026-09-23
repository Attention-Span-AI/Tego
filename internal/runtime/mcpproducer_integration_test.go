// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationMCPUnusedIsReachable is C4 end to end: in a tier-1 run whose supervisor answers the
// agent's execve, run_start names the exec-derived MCP producer, a declared server whose command the
// agent runs is recorded as started, and the idle one is not. That is the half of R15 the engine
// owns: with parsers["mcp"] written, drift can call the idle server unused rather than not observable,
// which internal/check/drift's own tests pin over a ledger of this shape (the engine never imports the
// read side, so the two halves are tested on their own sides of that line).
func TestIntegrationMCPUnusedIsReachable(t *testing.T) {
	truePath, err := filepath.EvalSymlinks("/bin/true")
	if err != nil {
		t.Skipf("no /bin/true: %v", err)
	}
	shPath, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skipf("no /bin/sh: %v", err)
	}
	contract := fmt.Sprintf(`version: 0
name: imcp
command: [%q]
tier: landlock
mcp:
  - name: started
    command: [%q, "mcp-started"]
  - name: idle
    command: [%q, "mcp-idle"]
fs:
  write: ["./out/"]
exec:
  allow: [%q, %q]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
record: summary
`, shPath, truePath, truePath, shPath, truePath)
	f := newFixture(t, contract)
	res, err := Run(context.Background(), f.rt, []string{shPath, "-c", truePath + " mcp-started"}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("result %+v, want exit 0", res)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	evs := events(t, dirs[0])
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	if start.Parsers["mcp"] != MCPProducerExec {
		t.Fatalf("run_start.parsers = %v, want mcp=%s", start.Parsers, MCPProducerExec)
	}
	var started []string
	for _, e := range evs {
		if e.Kind == record.KindMCP {
			started = append(started, e.Rule)
		}
	}
	if !slices.Equal(started, []string{"mcp[started]"}) {
		t.Fatalf("mcp events %v, want one for mcp[started] (%v)", started, kinds(evs))
	}
}

// TestIntegrationMCPStartThroughADotDotSpelling: a declared server whose command[0] is a symlink in the project
// (tools/mcpsrv -> true), started through a harmless "..", is recorded as started, and its exec line names
// tools/mcpsrv as spelled, not the link's target. At the tip of that round the line named true and no mcp line was
// written, so drift read a server that ran as one that never started.
func TestIntegrationMCPStartThroughADotDotSpelling(t *testing.T) {
	truePath, err := filepath.EvalSymlinks("/bin/true")
	if err != nil {
		t.Skipf("no /bin/true: %v", err)
	}
	shPath, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skipf("no /bin/sh: %v", err)
	}
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(project, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(truePath, filepath.Join(project, "tools", "mcpsrv")); err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: imcpdotdot
command: [%q]
tier: landlock
mcp:
  - name: srv
    command: ["./tools/mcpsrv", "--x"]
fs:
  write: ["./out/"]
exec:
  allow: [%q]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
record: full
`, shPath, shPath)
	f := newFixtureIn(t, project, contract, nil)
	res, err := Run(context.Background(), f.rt, []string{shPath, "-c", project + "/tools/../tools/mcpsrv --x"}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("result %+v, want exit 0", res)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	evs := events(t, dirs[0])
	var started, execs []string
	for _, e := range evs {
		switch e.Kind {
		case record.KindMCP:
			started = append(started, e.Rule)
		case record.KindExec:
			var p record.ExecPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			execs = append(execs, p.Path)
		}
	}
	if !slices.Equal(started, []string{"mcp[srv]"}) {
		t.Errorf("mcp events %v, want one for mcp[srv] (%v)", started, kinds(evs))
	}
	if want := filepath.Join(project, "tools", "mcpsrv"); !slices.Contains(execs, want) {
		t.Errorf("exec lines name %v, want %s among them: the server's command as spelled", execs, want)
	}
}

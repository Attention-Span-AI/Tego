// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationCLIRunsTheContractsCommand: `tego run a.yaml` with no command after the contract was a usage error,
// exit 2, though the contract names its command. It now runs the contract's command:.
func TestIntegrationCLIRunsTheContractsCommand(t *testing.T) {
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("icmd", []string{"/bin/sh", "-c", "echo from-contract > out/who"}, []string{"/bin/sh"}))
	cfg := writeMachineConfig(t, f)
	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"))
	run.Dir = f.dir
	run.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("tego run with no command: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(f.out, "who"))
	if err != nil || strings.TrimSpace(string(got)) != "from-contract" {
		t.Fatalf("the contract's command did not run: %q %v\n%s", got, err, out)
	}
	if g := runCommandGrant(t, f.root); g != "" {
		t.Errorf("run_start.run_command_grant = %q for a run of the contract's own command, want absent", g)
	}
}

// runCommandGrant is run_start.run_command_grant of the one run under root.
func runCommandGrant(t *testing.T, root string) string {
	t.Helper()
	dirs := runDirs(t, root)
	if len(dirs) != 1 {
		t.Fatalf("want one run under %s, have %v", root, dirs)
	}
	evs := events(t, dirs[0])
	if len(evs) == 0 || evs[0].Kind != record.KindRunStart {
		t.Fatalf("the run's first event is not run_start: %v", evs)
	}
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	// The absence of the field is meaningful only at this revision: an older ledger's reader falls back.
	if start.RecordMinor != record.Minor {
		t.Errorf("run_start.record_minor = %d, want %d", start.RecordMinor, record.Minor)
	}
	return start.RunCommandGrant
}

// TestIntegrationCLICommandIsGrantedForItsRun is L6's second half: a command given on the command line is the
// launching user's choice, not the agent's, and is admitted as the run's own command for that run, though the
// contract's exec.allow does not name it. It was refused at execve, exit 126.
func TestIntegrationCLICommandIsGrantedForItsRun(t *testing.T) {
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("icligrant", []string{"/bin/true"}, []string{"/bin/true"}))
	cfg := writeMachineConfig(t, f)
	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/echo", "from-cli")
	run.Dir = f.dir
	run.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
	out, err := run.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "from-cli") {
		t.Fatalf("tego run -- /bin/echo: %v\n%s", err, out)
	}
	// The grant is not in the contract hash, so run_start carries it for drift and every later reader.
	if g := runCommandGrant(t, f.root); g != "/bin/echo" {
		t.Errorf("run_start.run_command_grant = %q, want /bin/echo", g)
	}
}

// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationRunStartBestEffortListsGateCells is ADR 0041 D7's run half: a run whose gate opens (D) cells
// (here an `fs.read matches` read gate and an `exec matches` gate) names them in run_start's best_effort, at
// record_minor 6 or later, so a reader of the ledger alone learns which gate decisions were copied-syscall
// best effort. The contract has no net: section, so tier landlock's unix-only state adds host_sockets/datagram
// (ADR 0070); a run with no gate under host_sockets: true writes no best_effort at all.
func TestIntegrationRunStartBestEffortListsGateCells(t *testing.T) {
	bin := tegoBinary(t)
	for _, tc := range []struct {
		name, gate string
		want       []string
	}{
		{"gated", "gate:\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n    - 'exec matches \"rm -rf\"': 95\n",
			[]string{agent.BestEffortGateFSReadOpen, agent.BestEffortGateFSReadMove, agent.BestEffortGateExec,
				agent.BestEffortHostSocketsDatagram}},
		{"ungated", "", []string{agent.BestEffortHostSocketsDatagram}},
		{"ungated, host_sockets: true", "host_sockets: true\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, contractFor("ibesteffort", []string{"/bin/true"}, []string{"/bin/true"})+tc.gate)
			cfg := writeMachineConfig(t, f)
			run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"))
			run.Dir = f.dir
			run.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
			if out, err := run.CombinedOutput(); err != nil {
				t.Fatalf("tego run: %v\n%s", err, out)
			}
			dirs := runDirs(t, f.root)
			if len(dirs) != 1 {
				t.Fatalf("want one run under %s, have %v", f.root, dirs)
			}
			evs := events(t, dirs[0])
			if len(evs) == 0 || evs[0].Kind != record.KindRunStart {
				t.Fatalf("the run's first event is not run_start: %v", evs)
			}
			var start record.RunStartPayload
			if err := evs[0].DecodePayload(&start); err != nil {
				t.Fatal(err)
			}
			if start.RecordMinor < record.MinorBestEffort {
				t.Errorf("run_start.record_minor = %d, want at least %d", start.RecordMinor, record.MinorBestEffort)
			}
			if !slices.Equal(start.BestEffort, tc.want) {
				t.Errorf("run_start.best_effort = %v, want %v", start.BestEffort, tc.want)
			}
		})
	}
}

// TestIntegrationDenyWriteBestEffortAtLandlock is ADR 0041 D1 (a) at tier landlock, unprivileged, through the real
// binary: a contract whose fs.write is a repository (out/, holding .git/hooks and .git/config, both built-in
// deny_write targets) runs by default. The agent's write of a hook is refused by the supervisor (R15c), the rest
// of the agent runs, and run_start's best_effort names deny_write/default, since no decision plane decides the
// targets here. The same contract under fs.assurance: kernel is refused before the agent starts, exit 125, naming
// fs.assurance and the decision plane it needs, and leaves no run behind. Before ADR 0041 D1 the default run was
// refused as well (exit 125), so this tier could not run a repository-root contract at all.
func TestIntegrationDenyWriteBestEffortAtLandlock(t *testing.T) {
	bin := tegoBinary(t)
	contract := strings.Replace(contractFor("idenywrite", []string{"/bin/sh", "-c",
		"echo x > out/.git/hooks/pre-commit; echo done > out/done"}, []string{"/bin/sh"}), "record: summary\n", "record: full\n", 1)
	f := newFixture(t, contract)
	for _, d := range []string{"hooks", "objects", "refs"} {
		if err := os.MkdirAll(filepath.Join(f.out, ".git", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{".git/HEAD": "ref: refs/heads/main\n", ".git/config": "[core]\n"} {
		if err := os.WriteFile(filepath.Join(f.out, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	agentOwns(t, f.out)
	cfg := writeMachineConfig(t, f)
	run := func() (int, string) {
		t.Helper()
		cmd := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"))
		cmd.Dir = f.dir
		cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatalf("tego run: %v\n%s", err, out)
		}
		return cmd.ProcessState.ExitCode(), string(out)
	}

	code, out := run()
	if code != 0 {
		t.Fatalf("best effort: tego run exit %d, want 0:\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(f.out, ".git", "hooks", "pre-commit")); !os.IsNotExist(err) {
		t.Errorf("the agent wrote a git hook: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.out, "done")); err != nil {
		t.Errorf("the agent did not run on past the refused hook: %v\n%s", err, out)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("want one run under %s, have %v", f.root, dirs)
	}
	evs := events(t, dirs[0])
	if len(evs) == 0 || evs[0].Kind != record.KindRunStart {
		t.Fatalf("the run's first event is not run_start: %v", evs)
	}
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	// No net: section: tier landlock's unix-only state lists its datagram cell first (ADR 0070).
	if want := []string{agent.BestEffortHostSocketsDatagram, agent.BestEffortDenyWrite}; start.Tier != "landlock" ||
		!slices.Equal(start.BestEffort, want) {
		t.Errorf("run_start tier %s best_effort %v, want landlock and %v", start.Tier, start.BestEffort, want)
	}
	hooks := "fs.deny_write[" + filepath.Join(f.out, ".git", "hooks") + "]"
	if !slices.ContainsFunc(evs, func(e *record.Event) bool {
		return e.Kind == record.KindFS && e.Verdict == record.VerdictRefused && e.Rule == hooks
	}) {
		t.Errorf("no refused fs line under %s", hooks)
	}

	strict := strings.Replace(contract, "  write: [\"./out/\"]\n", "  write: [\"./out/\"]\n  assurance: kernel\n", 1)
	if strict == contract {
		t.Fatal("the contract has no write entry to add fs.assurance beside")
	}
	if err := os.WriteFile(filepath.Join(f.dir, "agent.yaml"), []byte(strict), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.out, "done")); err != nil {
		t.Fatal(err)
	}
	code, out = run()
	if code != 125 || !strings.Contains(out, "fs.assurance: kernel") || !strings.Contains(out, "decision plane") {
		t.Errorf("fs.assurance: kernel: tego run exit %d, want 125 naming fs.assurance and the decision plane:\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(f.out, "done")); !os.IsNotExist(err) {
		t.Errorf("the agent ran under fs.assurance: kernel at tier landlock: %v", err)
	}
	if dirs := runDirs(t, f.root); len(dirs) != 1 {
		t.Errorf("the refused run left a run behind: %v", dirs)
	}
}

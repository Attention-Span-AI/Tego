// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCompileAndRunAgreeOnDenyWrite is ADR 0041 D1 (a) and D8's "compile and run agree" (findings plane-1 and
// spec-2) through the commands themselves, on an unprivileged machine that offers tier landlock alone: a contract
// whose fs.write is a repository root (its .git/hooks and .git/config in the built-in deny_write set) is compiled
// with `tego compile` and run with `tego run`, the runtime stubbed where it would start the child.
//
//   - By default (fs.assurance best-effort) both pass, pinned to tier landlock or left to the machine: compile
//     exits 0 with a warning per target, and the run reaches the runtime at tier landlock. Before ADR 0041 D1
//     the run exited 125 and compile, pinned, refused too.
//   - Under fs.assurance: kernel, pinned to tier landlock, compile is a contract error (exit 1) and the run exits
//     125 before the runtime, both naming fs.assurance and the fix; left to the machine, compile warns (exit 0:
//     another machine may load a plane) and the run exits 125 [tier-unavailable] with the fix.
func TestCompileAndRunAgreeOnDenyWrite(t *testing.T) {
	requireLandlockABI(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "runs")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	// The project lies apart from tego's own directory (the config, the ledger root, the chain anchor), which no
	// write entry may hold.
	project := t.TempDir()
	work := filepath.Join(project, "work")
	for _, d := range []string{"hooks", "objects", "refs"} {
		if err := os.MkdirAll(filepath.Join(work, ".git", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{".git/HEAD": "ref: refs/heads/main\n", ".git/config": "[core]\n"} {
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder, prevFailed := probeMachine, anchorPath, startRun, captureFor, recorderFor, startFailed
	t.Cleanup(func() {
		probeMachine, anchorPath, startRun, captureFor, recorderFor, startFailed = prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder, prevFailed
	})
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	recorderFor = func(*agent.RuleTable, *slog.Logger) func(string) (source.Source, error) { return nil }
	startFailed = func(*doctor.Report) {}
	var started backend.Tier
	startRun = func(_ context.Context, rt *agent.RuleTable, _ []string, deps tegoruntime.Deps) (tegoruntime.Result, error) {
		started = deps.Enforce.Tier()
		return tegoruntime.Result{}, nil
	}

	for _, tc := range []struct {
		name, tier, assurance string
		compile, run          int
		want                  []string // in both commands' stderr, or the run's when it refuses
	}{
		{"best effort, pinned landlock", "tier: landlock\n", "", identity.ExitOK, identity.ExitOK, []string{"best effort"}},
		{"best effort, auto", "", "", identity.ExitOK, identity.ExitOK, []string{"best effort"}},
		{"kernel, pinned landlock", "tier: landlock\n", "  assurance: kernel\n", identity.ExitFinding, identity.ExitLauncher,
			[]string{"fs.assurance: kernel", "decision plane"}},
		{"kernel, auto", "", "  assurance: kernel\n", identity.ExitOK, identity.ExitLauncher,
			[]string{"fs.assurance: kernel", "kernel decision plane", "[tier-unavailable]"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contract := filepath.Join(project, "agent.yaml")
			body := "version: 0\nname: denywrite\ncommand: [\"true\"]\n" + tc.tier + "fs:\n  write: [\"" + work + "\"]\n" + tc.assurance
			if err := os.WriteFile(contract, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			code, _, errs := run(t, "compile", contract, "--offline")
			if code != tc.compile || !strings.Contains(errs, "fs.deny_write["+filepath.Join(work, ".git", "hooks")+"]") {
				t.Errorf("tego compile: exit %d, want %d naming the hooks target:\n%s", code, tc.compile, errs)
			}
			started = ""
			var stderr bytes.Buffer
			code = runRun(context.Background(), runOptions{contract: contract, command: []string{"true"}, offline: true}, &stderr)
			out := stderr.String()
			if code != tc.run {
				t.Fatalf("tego run: exit %d, want %d:\n%s", code, tc.run, out)
			}
			if (tc.run == identity.ExitOK) != (started == backend.TierLandlock) {
				t.Errorf("tego run exit %d reached the runtime at tier %q", code, started)
			}
			for _, w := range tc.want {
				if tc.run != identity.ExitOK && !strings.Contains(out, w) {
					t.Errorf("the refused run does not say %q:\n%s", w, out)
				}
				if tc.run == identity.ExitOK && !strings.Contains(errs, w) {
					t.Errorf("compile does not say %q:\n%s", w, errs)
				}
			}
		})
	}
}

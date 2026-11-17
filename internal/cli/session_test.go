// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// terminalRunOutput captures the command's actual stderr while selecting its terminal presentation.
// The runtime remains the test's stand-in; no agent process is launched.
func terminalRunOutput(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	oldErr, oldTTY := os.Stderr, stderrIsTerminal
	os.Stderr, stderrIsTerminal = f, func() bool { return true }
	defer func() { os.Stderr, stderrIsTerminal = oldErr, oldTTY }()
	var out strings.Builder
	code := mainWith(t.Context(), append([]string{"tego", "run"}, args...), &out, os.Stderr, []Command{cmdRun()})
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), string(b)
}

func TestTerminalRunEndDisclosures(t *testing.T) {
	for _, tc := range []string{"verified", "unverified", "unchecked", "receipt-error", "record-off", "nonzero", "signal", "lost-end", "reads-unknown"} {
		t.Run(tc, func(t *testing.T) {
			root, anchor := summaryHarness(t)
			id := summaryLedger(t, root, anchor)
			res := tegoruntime.Result{RunID: id, Reason: record.RunEndExit}
			switch tc {
			case "unverified":
				p := filepath.Join(root, id, "events.jsonl")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				b = []byte(strings.Replace(string(b), "/w/proj/out.txt", "/w/proj/bad.txt", 1))
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt-error":
				if err := os.Remove(filepath.Join(root, id, "events.jsonl")); err != nil {
					t.Fatal(err)
				}
			case "signal":
				res.Reason = record.RunEndSignal
			}
			var expected *endSummary
			startRun = func(_ context.Context, rt *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
				expected = summarizeRun(t.Context(), d.Config, d.AnchorPath, res, rt.Record)
				// These receipt states exercise presentation independently of the record builder.
				switch tc {
				case "unchecked":
					expected.chain = "chain not checked (no chain anchor)"
				case "nonzero":
					n := 3
					expected.rc.ExitCode = &n
				case "signal":
					expected.rc.ExitCode = nil
					expected.rc.EndReason = record.RunEndSignal
					expected.rc.Signal = 15
				case "lost-end":
					expected.rc.Ended = false
				case "reads-unknown":
					expected.rc.ReadsNotified = nil
				}
				return res, nil
			}
			// For receipt-only states use ended directly; other cases exercise the command's selection too.
			if tc == "unchecked" || tc == "nonzero" || tc == "signal" || tc == "lost-end" || tc == "reads-unknown" {
				// Reuse the stub's construction with its configured machine.
				m, _, err := loadMachine(config.TrustWarn)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = startRun(t.Context(), &agent.RuleTable{Record: agent.RecordSummary}, nil, tegoruntime.Deps{Config: m, AnchorPath: anchor})
				var b strings.Builder
				(&runTerminal{}).ended(&b, "minimal", expected)
				if got := b.String(); strings.Contains(got, "✓") || !strings.Contains(got, expected.text()+expected.readsLine()) {
					t.Fatalf("lost disclosure:\n%s\nwant:\n%s", got, expected.text()+expected.readsLine())
				}
				return
			}
			args := []string{"testdata/minimal.yaml", "--offline"}
			if tc == "record-off" {
				args = append(args, "--record", "off")
			}
			code, _, got := terminalRunOutput(t, args...)
			if code != identity.ExitOK {
				t.Fatalf("exit %d:\n%s", code, got)
			}
			if tc == "verified" {
				want := "\n  ✓ Session " + sessionName("minimal", id) + " ended · 2 actions blocked\n      Details: tego session show " + sessionName("minimal", id) + "\n"
				if !strings.HasSuffix(got, want) {
					t.Fatalf("verified footer changed:\n%s", got)
				}
			} else if strings.Contains(got, "✓ Session") || !strings.Contains(got, expected.text()+expected.readsLine()) {
				t.Fatalf("lost disclosure:\n%s\nwant:\n%s", got, expected.text()+expected.readsLine())
			}
		})
	}
}

func TestTerminalRunKeepsHeldLabelDisclosures(t *testing.T) {
	summaryHarness(t)
	notes := []string{
		"fs.apparmor_assume_root_namespace: true accepts hidden-ancestor risk when namespace depth is unreadable; run_start.best_effort records apparmor/assumed-root-namespace",
		"AppArmor namespace depth is unreadable (permission denied): file completions return EACCES / Permission denied (held-label-unavailable); expose readable securityfs from the root AppArmor policy namespace, or have the container administrator accept hidden-ancestor risk with fs.apparmor_assume_root_namespace: true",
		"the host's security modules could not be read (permission denied); a file open that tego checks and makes for the agent is refused when its security labels cannot be verified; permit lsm_list_modules in the outer seccomp filter or expose readable /sys/kernel/security/lsm",
	}
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		for _, s := range notes {
			d.Warn(tegoruntime.WarnHeldLabel, s)
		}
		d.Warn(tegoruntime.WarnDenyReadFrozen, "frozen-directory informational note")
		return tegoruntime.Result{}, nil
	}
	code, _, got := terminalRunOutput(t, "testdata/minimal.yaml", "--offline")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, got)
	}
	for _, s := range notes {
		if want := "note: tego run: " + s + " [held-label]\n"; !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "frozen-directory informational note") {
		t.Errorf("ordinary frozen-directory note became noisy:\n%s", got)
	}
}

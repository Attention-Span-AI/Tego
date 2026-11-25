// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
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
				want := "\n  ✓ Session " + sessionName("minimal", id) + " ended · 2 actions refused\n      Details: tego session show " + sessionName("minimal", id) + "\n"
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

func TestTerminalRunAlwaysNamesRulesFile(t *testing.T) {
	for _, v := range []string{"TEGO_HOST_KIND", "WSL_DISTRO_NAME", "TEGO_ON_MAC"} {
		t.Setenv(v, "") // a Windows PC's run line names no link (TestTerminalRunOnWindowsGivesNoDeadLink)
	}
	old := stderrIsTerminal
	stderrIsTerminal = func() bool { return true }
	t.Cleanup(func() { stderrIsTerminal = old })
	m := config.Builtin()
	m.Home = t.TempDir()
	path := filepath.Join(m.Home, "edited.yaml")
	for _, body := range []string{
		"version: 0\nname: handmade\n# Chosen in tego start: Base development rules\n",
		"# Chosen in tego start: Base development rules\nversion: 0\nname: edited\nfs:\n  write: [/other/]\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		q := quietRun(runOptions{}, m, &record.ContractSource{Path: path}, &outputWriter{dst: os.Stderr})
		if q == nil {
			t.Fatal("terminal mode not selected")
		}
		var b strings.Builder
		err := sessionStarted(&agent.RuleTable{Contract: &agent.Contract{Name: "helper"}}, &b, q, nil)(tegoruntime.StartedRun{ID: identity.RunID("r-519c2703-0dmw7w54wuixg-naw97n")})
		want := "\n  ✓ Started session helper-w97n · rules ~/edited.yaml (setup name from file comment: \"Base development rules\")\n      Watch it live: http://127.0.0.1:8484/runs/r-519c2703-0dmw7w54wuixg-naw97n\n\n"
		if err != nil || b.String() != want {
			t.Fatalf("start: %v\ngot %q\nwant %q", err, b.String(), want)
		}
	}
}

// On a Windows PC the loopback address printed inside Tego's Linux does not reach the dashboard from a Windows browser,
// so the line says how to open it instead of giving a link that fails.
func TestTerminalRunOnWindowsGivesNoDeadLink(t *testing.T) {
	old := stderrIsTerminal
	stderrIsTerminal = func() bool { return true }
	t.Cleanup(func() { stderrIsTerminal = old })
	for _, c := range []struct {
		env, want string
	}{
		{"windows", "      Watch it live: open it with: tego dashboard (from Windows)\n"},
		{"", "      Watch it live: http://127.0.0.1:8484/runs/r-519c2703-0dmw7w54wuixg-naw97n\n"},
	} {
		t.Setenv("TEGO_HOST_KIND", c.env)
		t.Setenv("WSL_DISTRO_NAME", "")
		t.Setenv("TEGO_ON_MAC", "")
		m := config.Builtin()
		m.Home = t.TempDir()
		q := quietRun(runOptions{}, m, nil, &outputWriter{dst: os.Stderr})
		if q == nil {
			t.Fatal("terminal mode not selected")
		}
		var b strings.Builder
		if err := sessionStarted(&agent.RuleTable{Contract: &agent.Contract{Name: "helper"}}, &b, q, nil)(tegoruntime.StartedRun{ID: identity.RunID("r-519c2703-0dmw7w54wuixg-naw97n")}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), c.want) || (c.env == "windows") == strings.Contains(b.String(), "http://127.0.0.1") {
			t.Errorf("host %q: %q, want %q", c.env, b.String(), c.want)
		}
	}
}

// TestRunLegacyOutput pins both streams to 421d678's run.go and runsummary.go output.
// The fixtures were captured with those files overlaid from git show, with only the minted id normalized.
func TestRunLegacyOutput(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		name := "pipe"
		if verbose {
			name = "verbose"
		}
		t.Run(name, func(t *testing.T) {
			root, _ := summaryHarness(t)
			t.Setenv("TEGO_HINTS", "on")
			var id string
			startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
				id = summaryLedger(t, root, d.AnchorPath)
				if d.Started != nil {
					if err := d.Started(tegoruntime.StartedRun{ID: identity.RunID(id)}); err != nil {
						return tegoruntime.Result{}, err
					}
				}
				d.Warn(tegoruntime.WarnHeldLabel, "label note")
				d.Warn(tegoruntime.WarnDenyReadFrozen, "frozen-directory note")
				_, _ = io.WriteString(d.Stdio.Out, "agent stdout\n")
				_, _ = io.WriteString(d.Stdio.Err, "agent stderr\n")
				return tegoruntime.Result{RunID: id, Reason: record.RunEndExit}, nil
			}
			outR, outW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			errR, errW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer outR.Close()
			defer errR.Close()
			oldOut, oldErr, oldTTY := os.Stdout, os.Stderr, stderrIsTerminal
			os.Stdout, os.Stderr = outW, errW
			stderrIsTerminal = func() bool { return verbose }
			defer func() { os.Stdout, os.Stderr, stderrIsTerminal = oldOut, oldErr, oldTTY }()
			// The rules pin what the check before the run would otherwise say about this build or this
			// environment; the streams pinned here are the run's own.
			// The built-in deny_read scan for .env files walks the contract's folder and the working directory under a time
			// limit of its own (2 s), and says so on stderr when it runs out: this package's folder holds hundreds of
			// files, so on a host whose disk is busy the walk ran out and the golden stderr differed. The run is made from a
			// folder that holds the contract and nothing else, so the walk is of one file and its time is nobody's guess.
			golden, err := filepath.Abs("testdata")
			if err != nil {
				t.Fatal(err)
			}
			contract, err := os.ReadFile(filepath.Join(golden, "run-legacy.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			workDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(workDir, "run-legacy.yaml"), contract, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(workDir)
			// The note that explains a start slower than a second ("preparing enforcement ...") is the product's own and
			// is not in these goldens; a host whose disk is busy took longer than that to reach the stubbed start, and
			// the note landed in stderr. The test pins a run's output, not how long the host takes to start one.
			oldWait := startupWaitAfter
			startupWaitAfter = time.Hour
			defer func() { startupWaitAfter = oldWait }()
			args := []string{"tego", "run", "run-legacy.yaml", "--offline"}
			if verbose {
				args = append(args, "-v")
			}
			code := mainWith(t.Context(), args, os.Stdout, os.Stderr, []Command{cmdRun()})
			_ = outW.Close()
			_ = errW.Close()
			out, err := io.ReadAll(outR)
			if err != nil {
				t.Fatal(err)
			}
			errs, err := io.ReadAll(errR)
			if err != nil {
				t.Fatal(err)
			}
			if code != identity.ExitOK {
				t.Fatalf("exit %d: %s", code, errs)
			}
			errs = []byte(strings.ReplaceAll(strings.ReplaceAll(string(errs), id, "<run>"), shortRun(root, id), "<short-run>"))
			streams := map[string]string{"stdout": string(out), "stderr": strings.ReplaceAll(string(errs), id, "<run>")}
			for stream, got := range streams {
				path := filepath.Join(golden, "run-421d678-"+name+"-"+stream+".golden")
				if *updateGolden {
					if err := os.WriteFile(path, []byte(got), 0644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if got != string(want) {
					t.Errorf("%s differs from 421d678:\ngot %q\nwant %q", stream, got, want)
				}
			}
		})
	}
}

func TestQuietRunUsesStderrTerminalRule(t *testing.T) {
	old := stderrIsTerminal
	defer func() { stderrIsTerminal = old }()
	stderrIsTerminal = func() bool { return true }
	m := config.Builtin()
	t.Setenv("CI", "true")
	// stdout is a pipe in this test invocation. By the PR's explicit rule only stderr selects quietRun.
	if quietRun(runOptions{}, m, nil, &outputWriter{dst: os.Stderr}) == nil {
		t.Fatal("stderr terminal must select terminal mode even in CI with stdout piped")
	}
	for _, o := range []runOptions{{verbose: true}, {cmd: "tego watch"}} {
		if quietRun(o, m, nil, &outputWriter{dst: os.Stderr}) != nil {
			t.Fatal("verbose or --cmd selected terminal mode")
		}
	}
	stderrIsTerminal = func() bool { return false }
	if quietRun(runOptions{}, m, nil, &outputWriter{dst: os.Stderr}) != nil {
		t.Fatal("piped stderr selected terminal mode")
	}
}

// Every qualification of the summary must also prevent an unqualified success footer.
func TestTerminalFooterSummaryDisclosures(t *testing.T) {
	zero := 0
	cases := []struct {
		name   string
		change func(*endSummary)
		want   string
	}{
		{"receipt-error", func(s *endSummary) { s.rc = nil; s.err = errors.New("unreadable") }, "summary not available (unreadable)"},
		{"chain-unchecked", func(s *endSummary) { s.chain = "chain not checked (no anchor)" }, "chain not checked (no anchor)"},
		{"chain-invalid", func(s *endSummary) { s.chain = "chain does not verify (changed)" }, "chain does not verify (changed)"},
		{"record-off", func(s *endSummary) { s.recordOff = true }, recordOffClause},
		{"runtime-outcome", func(s *endSummary) { s.how = "signalled" }, "tego run:"},
		{"no-end", func(s *endSummary) { s.rc.Ended = false }, "still running"},
		{"nonzero", func(s *endSummary) { n := 3; s.rc.ExitCode = &n }, "exited with code 3"},
		{"signal", func(s *endSummary) { s.rc.ExitCode = nil; s.rc.EndReason = record.RunEndSignal; s.rc.Signal = 15 }, "ended by signal 15"},
		{"reads-unknown", func(s *endSummary) { s.rc.ReadsNotified = nil }, readsLineUnknown},
		{"reads-off", func(s *endSummary) { s.rc.ReadsNotified = &record.ReadsNotified{Why: record.ReadsNotifiedWhyReasonOff} }, readsLineReasonOff},
		{"reads-unsupervised", func(s *endSummary) {
			s.rc.ReadsNotified = &record.ReadsNotified{Why: record.ReadsNotifiedWhyNoSupervisor}
		}, readsLineNoSupervisor},
	}
	// Include an unfamiliar code: new record/refusal gap reasons must not need a second footer guard.
	for _, gap := range []receipt.CoverageGap{
		{Field: "record", Code: receipt.CodeMissedActions, Why: "some actions were missed"},
		{Field: "record", Code: receipt.CodeRecordUncertain, Why: "recording is uncertain"},
		{Field: "refusals", Code: receipt.CodeRulesUncertain, Why: "the rules may not have held"},
		{Field: "record", Code: "future-code", Why: "a future qualification\x1b[2J"},
	} {
		cases = append(cases, struct {
			name   string
			change func(*endSummary)
			want   string
		}{
			gap.Code, func(s *endSummary) { s.rc.Coverage = receipt.Coverage{Gaps: []receipt.CoverageGap{gap}} }, record.Printable(gap.Why),
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &endSummary{run: "r-519c2703-0dmw7w54wuixg-naw97n", chain: "chain verified", rc: &receipt.Receipt{
				Ended: true, EndReason: record.RunEndExit, ExitCode: &zero,
				ReadsNotified: &record.ReadsNotified{Notified: true}, Coverage: receipt.Coverage{Complete: true},
			}}
			tc.change(s)
			var out strings.Builder
			if (&runTerminal{}).ended(&out, "helper", s) || strings.Contains(out.String(), "✓") {
				t.Fatalf("qualified run got success footer: %s", out.String())
			}
			if want := s.text() + s.readsLine(); out.String() != want || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("lost disclosure %q:\n%s\nfull summary:\n%s", tc.want, out.String(), want)
			}
		})
	}
}

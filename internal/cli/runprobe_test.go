// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
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

// cappedAt is the built-in machine config with a concrete tier, which is both its ceiling and its pin.
func cappedAt(tier string) *config.Machine {
	m := config.Builtin()
	m.Tier.Bounded = true
	m.Tier.Value.Auto = false
	m.Tier.Value.Tier = tier
	return m
}

// pinnedTable is autoTable with the contract's own tier: set.
func pinnedTable(tier string) *agent.RuleTable {
	rt := autoTable()
	rt.Contract.Tier = agent.TierPin(tier)
	return rt
}

// TestRunAtTierLandlockLoadsNoProgram is ACC-F2-probe-per-run's test at the command: a run pinned at tier
// landlock — by --tier, by the contract or by the machine config — selects from a report whose D2, D6, D7 and
// D8 were never run, so it loads no BPF program and makes no fanotify group. Every root run used to take the
// whole of doctor.Run first, 228 bpf(2) calls and about 3 s for `--tier landlock -- true` on Ubuntu 24.04's
// 6.8 in the KVM guest, which failed kill test 4 at tier landlock as root (the acceptance run of 2026-09-23).
func TestRunAtTierLandlockLoadsNoProgram(t *testing.T) {
	requireLandlockABI(t)
	for name, c := range map[string]struct {
		o  runOptions
		m  *config.Machine
		rt *agent.RuleTable
	}{
		"--tier landlock":        {runOptions{tier: "landlock"}, config.Builtin(), autoTable()},
		"contract tier landlock": {runOptions{}, config.Builtin(), pinnedTable("landlock")},
		"machine tier landlock":  {runOptions{}, cappedAt("landlock"), autoTable()},
	} {
		var stderr bytes.Buffer
		b, _, rep, code := selectBackend(context.Background(), c.o, c.m, c.rt, &stderr)
		if b == nil {
			t.Skipf("%s: this machine offers no tier landlock (exit %d):\n%s", name, code, stderr.String())
		}
		if b.Tier() != backend.TierLandlock {
			t.Errorf("%s: selected %s", name, b.Tier())
		}
		for _, r := range rep.Results {
			switch r.ID {
			case doctor.CheckBTF, doctor.CheckLSM, doctor.CheckPrograms, doctor.CheckFanotify:
				if !strings.HasPrefix(r.Detail, "not probed by tego run") {
					t.Errorf("%s: %s ran for a run that can only be at tier landlock: %s", name, r.ID, r.Detail)
				}
			default:
				if strings.HasPrefix(r.Detail, "not probed") {
					t.Errorf("%s: tier landlock's own check %s was not run", name, r.ID)
				}
			}
		}
	}
}

// TestRunProbesTheReachOfItsSelection: selection asks the derivation for exactly the tiers it can pick or has
// to explain — a named tier as itself, auto as far as root and this build allow — so a refusal is still
// explained in doctor's words and a pinned-low run pays for nothing above its pin.
func TestRunProbesTheReachOfItsSelection(t *testing.T) {
	requireLandlockABI(t)
	var asked []backend.Tier
	prev := probeMachine
	probeMachine = func(_ context.Context, _ *config.Machine, reach backend.Tier) (*doctor.Report, error) {
		asked = append(asked, reach)
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	t.Cleanup(func() { probeMachine = prev })
	auto := backend.TierLandlock
	switch {
	case os.Geteuid() != 0:
	case enforce.Buildable(backend.TierBPFLSM) == nil:
		auto = backend.TierBPFLSM // tier bpflsm is built with the objects (TIER3-PLAN T7)
	case enforce.Buildable(backend.TierCgroup) == nil:
		auto = backend.TierCgroup
	}
	for _, c := range []struct {
		name string
		o    runOptions
		m    *config.Machine
		rt   *agent.RuleTable
		want backend.Tier
	}{
		{"--tier landlock", runOptions{tier: "landlock"}, config.Builtin(), autoTable(), backend.TierLandlock},
		{"--tier cgroup", runOptions{tier: "cgroup"}, config.Builtin(), autoTable(), backend.TierCgroup},
		{"--tier bpflsm", runOptions{tier: "bpflsm"}, config.Builtin(), autoTable(), backend.TierBPFLSM},
		{"contract landlock", runOptions{}, config.Builtin(), pinnedTable("landlock"), backend.TierLandlock},
		{"contract cgroup", runOptions{}, config.Builtin(), pinnedTable("cgroup"), backend.TierCgroup},
		{"machine landlock", runOptions{}, cappedAt("landlock"), autoTable(), backend.TierLandlock},
		{"--tier landlock against a contract cgroup", runOptions{tier: "landlock"}, config.Builtin(), pinnedTable("cgroup"), backend.TierCgroup},
		{"auto", runOptions{}, config.Builtin(), autoTable(), auto},
	} {
		asked = nil
		var stderr bytes.Buffer
		selectBackend(context.Background(), c.o, c.m, c.rt, &stderr)
		if len(asked) != 1 || asked[0] != c.want {
			t.Errorf("%s: probed at reach %v, want %s", c.name, asked, c.want)
		}
	}
}

// TestRunDropsTheCachedAnswerItCouldNotStartFrom: a run that could not start hands the report it selected from
// to startFailed, which removes a cached probe answer that report was read from (doctor's
// TestRunAtReachCgroupReadsTheCacheAsRoot holds DiscardCache to that); a run that started does not.
func TestRunDropsTheCachedAnswerItCouldNotStartFrom(t *testing.T) {
	requireLandlockABI(t)
	var probed *doctor.Report
	prevProbe := probeMachine
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		probed = &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}
		return probed, nil
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(base, "runs")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	prevAnchor, prevRun, prevCapture, prevRecorder, prevFailed := anchorPath, startRun, captureFor, recorderFor, startFailed
	t.Cleanup(func() {
		probeMachine, anchorPath, startRun, captureFor, recorderFor, startFailed = prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder, prevFailed
	})
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	recorderFor = func(*agent.RuleTable, *slog.Logger) func(string) (source.Source, error) { return nil }
	var dropped []*doctor.Report
	startFailed = func(rep *doctor.Report) { dropped = append(dropped, rep) }

	for _, fail := range []bool{true, false} {
		dropped = nil
		startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
			if fail {
				return tegoruntime.Result{}, errors.New("prepare: load trace_proc: operation not permitted")
			}
			return tegoruntime.Result{}, nil
		}
		var stderr bytes.Buffer
		code := runRun(context.Background(), runOptions{contract: filepath.Join("testdata", "minimal.yaml"),
			command: []string{"true"}, offline: true}, &stderr)
		switch {
		case fail && (code != identity.ExitLauncher || len(dropped) != 1 || dropped[0] != probed):
			t.Errorf("a run that could not start: exit %d, startFailed called with %v, want once with %p\n%s", code, dropped, probed, stderr.String())
		case !fail && (code != identity.ExitOK || len(dropped) != 0):
			t.Errorf("a run that started: exit %d, startFailed called %d times\n%s", code, len(dropped), stderr.String())
		}
	}
}

// TestRunTierFlagTakesAutoAndRefusesObserve: --tier auto was refused although
// auto is what a contract's tier: says for "no pin", and --tier observe, which the usage error listed among
// the tiers, failed as exit 125 [tier-unavailable]. auto selects as if no --tier were given; observe is a
// usage error naming --observe.
func TestRunTierFlagTakesAutoAndRefusesObserve(t *testing.T) {
	requireLandlockABI(t)
	var stderr bytes.Buffer
	b, _, _, code := selectBackend(context.Background(), runOptions{tier: "auto"}, config.Builtin(), autoTable(), &stderr)
	if b == nil {
		t.Fatalf("--tier auto: exit %d:\n%s", code, stderr.String())
	}
	var plain bytes.Buffer
	if want, _, _, _ := selectBackend(context.Background(), runOptions{}, config.Builtin(), autoTable(), &plain); want == nil || want.Tier() != b.Tier() {
		t.Errorf("--tier auto selected %s, no --tier %v", b.Tier(), want)
	}
	for tier, want := range map[string]string{
		"observe": "--tier observe: observe enforces nothing and is not a tier; run with --observe",
		"quantum": `--tier "quantum" is not auto, landlock, cgroup or bpflsm`,
	} {
		stderr.Reset()
		b, _, _, code := selectBackend(context.Background(), runOptions{tier: tier}, config.Builtin(), autoTable(), &stderr)
		if b != nil || code != identity.ExitUsage || !strings.Contains(stderr.String(), want) || !strings.Contains(stderr.String(), "[usage]") {
			t.Errorf("--tier %s: exit %d, stderr %q; want 2 with %q", tier, code, stderr.String(), want)
		}
	}
}

// TestRunNamesTheConfigFix: run refused an untrusted machine config with its
// owner and mode but not what to change, which compile and doctor say, and printed an invalid layer as
// "machine config: config: <path>: config: invalid layer".
func TestRunNamesTheConfigFix(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("log:\n  level: info\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg, 0o666); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	code, _, errs := run(t, "run", filepath.Join(dir, "agent.yaml"), "--", "true")
	if code != identity.ExitConfig || !strings.Contains(errs, "[config-untrusted] Make it a regular file owned by root or you") ||
		strings.Contains(errs, "machine config: machine config") {
		t.Errorf("untrusted: exit %d, stderr:\n%s", code, errs)
	}
	if err := os.Chmod(cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("tiers: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs = run(t, "run", filepath.Join(dir, "agent.yaml"), "--", "true")
	if code != identity.ExitConfig || !strings.Contains(errs, "tego run: config: invalid layer: "+cfg+" (its errors are above)") ||
		strings.Contains(errs, "config: "+cfg+": config:") {
		t.Errorf("invalid: exit %d, stderr:\n%s", code, errs)
	}
}

// TestRunHandsTheRecorderTheMachinesLogLevel: the tier-2 recorder was built with ownLogger(nil), pinned at
// info, so its debug line (the process cache, what to read when attribution degrades) never reached tego.log
// however log.level was set.
func TestRunHandsTheRecorderTheMachinesLogLevel(t *testing.T) {
	requireLandlockABI(t)
	prevProbe := probeMachine
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(base, "runs")+"\nlog:\n  level: debug\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	prevAnchor, prevRun, prevCapture, prevRecorder := anchorPath, startRun, captureFor, recorderFor
	t.Cleanup(func() {
		probeMachine, anchorPath, startRun, captureFor, recorderFor = prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder
	})
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	var got *slog.Logger
	recorderFor = func(_ *agent.RuleTable, l *slog.Logger) func(string) (source.Source, error) {
		got = l
		return nil
	}
	startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
		return tegoruntime.Result{}, nil
	}
	var stderr bytes.Buffer
	runRun(context.Background(), runOptions{contract: filepath.Join("testdata", "minimal.yaml"),
		command: []string{"true"}, offline: true}, &stderr)
	if got == nil || !got.Enabled(context.Background(), slog.LevelDebug) {
		t.Errorf("the recorder's logger %v does not pass debug under log.level: debug\n%s", got, stderr.String())
	}
}

// TestCompileInterruptedSaysSo: a compile interrupted before it ran exited 125 with nothing on stderr.
func TestCompileInterruptedSaysSo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := runCompile(ctx, filepath.Join("testdata", "minimal.yaml"), compileRequest{}, &out, &errb)
	if code != identity.ExitError || !strings.Contains(errb.String(), "tego compile: interrupted") {
		t.Errorf("exit %d, stderr %q; want 125 with the interrupted line", code, errb.String())
	}
}

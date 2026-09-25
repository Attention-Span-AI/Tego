// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// pinnedUprobeContract pins capture: uprobe, leaves the tier to the machine and passes ANTHROPIC_BASE_URL, as
// examples/agents/anthropic-sdk-python.yaml does for a gateway.
const pinnedUprobeContract = `version: 0
name: pinned-uprobe
command: ["true"]
models:
  - { provider: anthropic, host: api.anthropic.com, port: 443 }
capture: uprobe
env:
  pass: [PATH, ANTHROPIC_BASE_URL]
`

// TestPinnedUprobeLoweredToTheForwarderSaysSo is the run half of agent-contract R12 for a contract that pins
// capture: uprobe. Compile resolves its unpinned tier to the machine's ceiling without probing the machine,
// sees uprobes, and lets the contract keep ANTHROPIC_BASE_URL. The run then gets tier landlock, as every
// unprivileged run does: the table tops out at the forwarder (agent.AtTier), the forwarder starts, and its base
// URL is written over the contract's value (identity.Env.Apply). That used to happen with nothing said
// anywhere; `tego run` now prints env-runtime-reserved for it, once, on its own stderr.
func TestPinnedUprobeLoweredToTheForwarderSaysSo(t *testing.T) {
	requireLandlockABI(t)
	// A build with tier cgroup, so Compile resolves auto to it and keeps uprobe capture; the machine then
	// offers landlock alone.
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	machineProbe(t, backend.Probe{backend.TierLandlock: true})
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
	contract := filepath.Join(base, "agent.yaml")
	if err := os.WriteFile(contract, []byte(pinnedUprobeContract), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	prevAnchor := anchorPath
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	t.Cleanup(func() { anchorPath = prevAnchor })

	var table *agent.RuleTable
	var overridden string
	prevRun := startRun
	t.Cleanup(func() { startRun = prevRun })
	startRun = func(_ context.Context, rt *agent.RuleTable, _ []string, deps tegoruntime.Deps) (tegoruntime.Result, error) {
		table = rt
		for _, s := range deps.Capture {
			if ls, ok := s.(source.LoopbackSource); ok {
				overridden = ls.Vars()[identity.EnvAnthropicBaseURL]
			}
		}
		stopAll(t, deps.Capture)
		return tegoruntime.Result{}, nil
	}

	var stderr bytes.Buffer
	code := runRun(context.Background(), runOptions{contract: contract, command: []string{"true"}, offline: true}, &stderr)
	if code != identity.ExitOK {
		t.Fatalf("exit %d:\n%s", code, stderr.String())
	}
	if table == nil || table.Tier != backend.TierLandlock || table.Capture != agent.CaptureForwarder || !table.PinsUprobe() {
		t.Fatalf("the run was handed %+v, want the pinned-uprobe table lowered to landlock and the forwarder", table)
	}
	if overridden == "" {
		t.Fatal("no forwarder set ANTHROPIC_BASE_URL: this test no longer describes the lowered run")
	}
	var warned []string
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.Contains(line, "["+agent.CodeEnvRuntimeReserved+"]") {
			warned = append(warned, line)
		}
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "env.pass "+identity.EnvAnthropicBaseURL) ||
		!strings.Contains(warned[0], "tier landlock") {
		t.Fatalf("env-runtime-reserved lines %q, want one naming env.pass %s and the tier that lowered it:\n%s",
			warned, identity.EnvAnthropicBaseURL, stderr.String())
	}
}

// TestForwarderEnvWarningFollowsWhatRuns: the run-time warning is said exactly where the forwarder overrides a
// value Compile let through, with the reason that lowered capture on this run, and nowhere Compile's own warning
// already stands or no forwarder runs. Compile lets a pinned uprobe keep the variable only when it resolved
// capture to uprobe; where it resolved the forwarder itself (a contract pinned at landlock, a machine capture
// ceiling) it has warned already, and a second line for env.set, naming a tier that lowered nothing, was wrong.
func TestForwarderEnvWarningFollowsWhatRuns(t *testing.T) {
	m := config.Builtin()
	models := []agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com", Port: 443}}
	table := func(capture, pinned agent.CaptureMode) *agent.RuleTable {
		rt := captureTable(capture, models)
		rt.Tier = backend.TierBPFLSM
		rt.Contract.Capture = pinned
		rt.Env = []string{"PATH", identity.EnvAnthropicBaseURL}
		rt.Set = map[string]string{identity.EnvAnthropicBaseURL: "https://gateway.example"}
		return rt
	}
	// compiledLowered is the table Compile gives a pinned uprobe it lowered to the forwarder itself: it warned,
	// took the variable out of the pass list and kept env.set's value (agent-contract R12).
	compiledLowered := func(tier backend.Tier) *agent.RuleTable {
		rt := table(agent.CaptureForwarder, agent.CaptureUprobe)
		rt.Tier = tier
		rt.Env = []string{"PATH"}
		return rt
	}
	cases := []struct {
		name     string
		rt       *agent.RuleTable
		compiled agent.CaptureMode
		b        fakeBackend
		want     []string
		why, fix string
	}{
		{"pinned uprobe lowered to landlock", table(agent.CaptureUprobe, agent.CaptureUprobe).AtTier(backend.TierLandlock),
			agent.CaptureUprobe, fakeBackend{tier: backend.TierLandlock, caps: backend.Set{backend.CapCaptureModel: true}},
			[]string{"env.pass " + identity.EnvAnthropicBaseURL, "env.set " + identity.EnvAnthropicBaseURL},
			"does not run at tier landlock", "run at tier cgroup or above"},
		{"pinned uprobe in observe mode", table(agent.CaptureUprobe, agent.CaptureUprobe),
			agent.CaptureUprobe, fakeBackend{tier: backend.TierObserve},
			[]string{"env.pass " + identity.EnvAnthropicBaseURL, "env.set " + identity.EnvAnthropicBaseURL},
			"does not run under --observe", "drop --observe"},
		{"pinned uprobe at a tier whose capabilities have no model capture", table(agent.CaptureUprobe, agent.CaptureUprobe).AtTier(backend.TierCgroup),
			agent.CaptureUprobe, fakeBackend{tier: backend.TierCgroup, caps: backend.Set{}},
			[]string{"env.pass " + identity.EnvAnthropicBaseURL, "env.set " + identity.EnvAnthropicBaseURL},
			"cannot run at tier cgroup on this machine", "capture.model_traffic"},
		{"pinned uprobe where uprobes run", table(agent.CaptureUprobe, agent.CaptureUprobe).AtTier(backend.TierCgroup),
			agent.CaptureUprobe, fakeBackend{tier: backend.TierCgroup, caps: backend.Set{backend.CapCaptureModel: true}}, nil, "", ""},
		{"capture: forwarder, which Compile warned about", table(agent.CaptureForwarder, agent.CaptureForwarder),
			agent.CaptureForwarder, fakeBackend{tier: backend.TierLandlock}, nil, "", ""},
		{"auto lowered to the forwarder, which Compile warned about", table(agent.CaptureUprobe, "").AtTier(backend.TierLandlock),
			agent.CaptureUprobe, fakeBackend{tier: backend.TierLandlock}, nil, "", ""},
		{"pinned uprobe under a contract pinned at landlock, which Compile lowered and warned about",
			compiledLowered(backend.TierLandlock), agent.CaptureForwarder, fakeBackend{tier: backend.TierLandlock}, nil, "", ""},
		{"pinned uprobe under a machine capture ceiling of forwarder, run at tier cgroup",
			compiledLowered(backend.TierCgroup), agent.CaptureForwarder,
			fakeBackend{tier: backend.TierCgroup, caps: backend.Set{backend.CapCaptureModel: true}}, nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sources, _ := selectCapture(tc.rt, m, tc.b)
			defer stopAll(t, sources)
			if tc.want == nil && tc.rt.PinsUprobe() && tc.compiled != agent.CaptureUprobe && len(sources) == 0 {
				t.Fatal("no forwarder started: this case no longer describes a run the forwarder overrides")
			}
			var out bytes.Buffer
			warnForwarderEnv(&out, tc.rt, tc.compiled, tc.b.tier, sources)
			var got []string
			for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
				if line == "" {
					continue
				}
				if strings.HasPrefix(line, "  fix:") {
					if !strings.Contains(line, tc.fix) {
						t.Errorf("fix %q does not say %q", line, tc.fix)
					}
					continue
				}
				if !strings.Contains(line, "["+agent.CodeEnvRuntimeReserved+"]") {
					t.Fatalf("unexpected line %q", line)
				}
				if !strings.Contains(line, tc.why) {
					t.Errorf("line %q does not give the reason %q", line, tc.why)
				}
				named := "an unexpected variable"
				for _, w := range tc.want {
					if strings.Contains(line, w+" ") {
						named = w
					}
				}
				got = append(got, named)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("warned for %v, want %v:\n%s", got, tc.want, out.String())
			}
		})
	}
}

// TestARunAtLandlockIsToldWhatLandlockCannotEnforce is ADR 0019 at run time: an auto contract whose deny_read lies
// beneath its write entry was compiled for bpflsm, so nothing said that the run it got, at landlock, left the secret
// readable. Compile now finds it whenever landlock is reachable and marks it as landlock's; run holds such findings
// until selection and prints them to a run that got that tier, once.
func TestARunAtLandlockIsToldWhatLandlockCannotEnforce(t *testing.T) {
	requireLandlockABI(t)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	machineProbe(t, backend.Probe{backend.TierLandlock: true})
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "runs")
	project := t.TempDir() // apart from tego's own directory, which no write entry may contain
	if err := os.MkdirAll(filepath.Join(project, "out", "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// fs.reads: direct leaves the secret readable at landlock and says so; auto holds the run's reads there and says
	// that instead (ADR 0069). Either finding is landlock's, printed once to a run that got the tier; the held-reads
	// one is a note, which only a verbose run prints (G10).
	for _, tc := range []struct {
		reads, want string
		note        bool
	}{{"direct", "unenforced in the landlock tier", false}, {"auto", "the run's reads are held", true}} {
		for _, verbose := range []bool{false, true} {
			runAtLandlockOnce(t, base, cfg, project, tc.reads, tc.want, verbose, !tc.note || verbose)
		}
	}
}

// runAtLandlockOnce is one fs.reads value, verbose or not, of TestARunAtLandlockIsToldWhatLandlockCannotEnforce.
func runAtLandlockOnce(t *testing.T, base, cfg, project, reads, want string, verbose, printed bool) {
	t.Helper()
	contract := filepath.Join(base, "agent.yaml")
	body := "version: 0\nname: secret-in-out\ncommand: [\"true\"]\nfs:\n  reads: " + reads + "\n  write: [\"" + filepath.Join(project, "out") +
		"/\"]\n  deny_read: [\"" + filepath.Join(project, "out", "keys") + "/\"]\nnet: {}\n"
	if err := os.WriteFile(contract, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	prevAnchor := anchorPath
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	t.Cleanup(func() { anchorPath = prevAnchor })
	prevRun := startRun
	t.Cleanup(func() { startRun = prevRun })
	var tier backend.Tier
	startRun = func(_ context.Context, rt *agent.RuleTable, _ []string, deps tegoruntime.Deps) (tegoruntime.Result, error) {
		tier = rt.Tier
		stopAll(t, deps.Capture)
		return tegoruntime.Result{}, nil
	}

	var stderr bytes.Buffer
	code := runRun(context.Background(), runOptions{contract: contract, command: []string{"true"}, offline: true, verbose: verbose}, &stderr)
	if code != identity.ExitOK || tier != backend.TierLandlock {
		t.Fatalf("exit %d at tier %q:\n%s", code, tier, stderr.String())
	}
	wantN := 0
	if printed {
		wantN = 1
	}
	if n := strings.Count(stderr.String(), want); n != wantN {
		t.Fatalf("fs.reads: %s, verbose %v: the landlock finding %q was printed %d times, want %d:\n%s", reads, verbose, want, n, wantN, stderr.String())
	}
}

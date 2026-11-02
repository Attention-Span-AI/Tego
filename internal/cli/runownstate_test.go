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
	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// userStateFor points this package's machine config and own-log home at a home of the test's own, whose ~/.tego holds
// the per-user config layer as a real home does (config.UserRelPath), and returns that ~/.tego and the layer.
func userStateFor(t *testing.T) (state, layer string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	state = filepath.Join(home, tegoruntime.StateDir)
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	layer = filepath.Join(home, config.UserRelPath)
	if err := os.WriteFile(layer, []byte("version: 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, ownLogName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prevSources, prevHome := machineSources, ownLogHomeOf
	machineSources = func(uid int, secure bool) (config.Sources, string, []config.Diagnostic) {
		src, _, diags := prevSources(uid, secure)
		src.User = layer
		return src, home, diags
	}
	ownLogHomeOf = func(int) string { return home }
	useAnchor(t, filepath.Join(state, ledger.ChainLogFile))
	t.Cleanup(func() {
		machineSources, ownLogHomeOf = prevSources, prevHome
		_ = os.Chmod(state, 0o700) // best effort, so the temporary directory can be removed whatever the test left
	})
	return state, layer
}

// skipAsRoot skips a test of the unprivileged launcher's restore: a root launcher restores no mode, since it reads and
// writes through any (CAP_DAC_OVERRIDE), so the modes these tests take keep it out of nothing
// (TestRestoreOwnStateLeavesWhatIsNotTheLaunchers holds root to that).
func skipAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("a root launcher restores no mode: it reads and writes through any (CAP_DAC_OVERRIDE)")
	}
}

// runUntilTheContract is `tego run` of a contract that does not exist: everything before the compile runs, the machine
// config's load and the restores included, and nothing starts.
func runUntilTheContract(t *testing.T) string {
	t.Helper()
	prevRun := startRun
	t.Cleanup(func() { startRun = prevRun })
	startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
		t.Fatal("a run of a contract that does not exist was started")
		return tegoruntime.Result{}, tegoruntime.ErrDeps
	}
	var stderr bytes.Buffer
	runRun(context.Background(), runOptions{contract: filepath.Join(t.TempDir(), "missing.yaml"), command: []string{"true"},
		offline: true}, &stderr)
	return stderr.String()
}

// TestRunRestoresTheConfigLayerBeforeReadingIt is GAPS C52's ~/.tego: the per-user config layer lives in it, so with
// its mode, or the layer's, taken from its owner the machine config could not be read, and `tego run` was refused
// [config-untrusted] before it restored anything: the next run, and every one after it, whoever had taken the modes (a
// root launcher's agent, which no root launcher restores; an agent whose launcher died). Now the run gives the owner
// their rights back first and reads the config.
func TestRunRestoresTheConfigLayerBeforeReadingIt(t *testing.T) {
	skipAsRoot(t)
	state, layer := userStateFor(t)
	log := filepath.Join(state, ownLogName)
	for _, p := range []string{layer, log, state} { // ~/.tego last: its owner can no longer search it
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
	}
	out := runUntilTheContract(t)
	if strings.Contains(out, "[config-untrusted]") {
		t.Fatalf("the run read the config before it restored ~/.tego and the layer:\n%s", out)
	}
	if strings.Count(out, "["+codeOwnStateMode+"]") != 3 || !strings.Contains(out, state+" had mode 0000") ||
		!strings.Contains(out, layer+" had mode 0000") || !strings.Contains(out, log+" had mode 0000") {
		t.Errorf("the run did not say what it restored:\n%s", out)
	}
	for p, want := range map[string]os.FileMode{state: 0o700, layer: 0o400, log: 0o600} {
		if st, err := os.Lstat(p); err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: %v, mode %v, want %04o", p, err, st.Mode().Perm(), want)
		}
	}
}

// TestRunHandsItsEndTheUserState: a run gives ~/.tego, the config layer and tego.log back at its end too (the
// runtime's restoreRunState), so a mode its agent took from the layer is not left for the commands after it, which
// pass over a layer they cannot read; the CLI hands it the ones it gave back before it read the config.
func TestRunHandsItsEndTheUserState(t *testing.T) {
	requireLandlockABI(t)
	state, _ := userStateFor(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(base, "runs")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	prevProbe, prevRun, prevCapture, prevRecorder := probeMachine, startRun, captureFor, recorderFor
	t.Cleanup(func() {
		probeMachine, startRun, captureFor, recorderFor = prevProbe, prevRun, prevCapture, prevRecorder
	})
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	recorderFor = func(*agent.RuleTable, *slog.Logger) func(string) (source.Source, error) { return nil }
	var got *tegoruntime.OwnState
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, deps tegoruntime.Deps) (tegoruntime.Result, error) {
		got = &deps.UserState
		return tegoruntime.Result{}, nil
	}
	var stderr bytes.Buffer
	runRun(context.Background(), runOptions{contract: filepath.Join("testdata", "minimal.yaml"), command: []string{"true"},
		offline: true}, &stderr)
	want := tegoruntime.OwnState{Home: filepath.Dir(state), Log: filepath.Join(state, ownLogName)}
	if got == nil || *got != want {
		t.Fatalf("the run was handed UserState %+v, want %+v\n%s", got, want, stderr.String())
	}
}

// TestRunLeavesALayerOthersCouldWriteToTheTrustCheck: a layer whose owner lost read and that group or others can
// write gets its owner's read back and nothing else, so the trust check (R20) still refuses it, with its fix: someone
// else could have written it while it was so.
func TestRunLeavesALayerOthersCouldWriteToTheTrustCheck(t *testing.T) {
	skipAsRoot(t)
	_, layer := userStateFor(t)
	if err := os.Chmod(layer, 0o060); err != nil {
		t.Fatal(err)
	}
	out := runUntilTheContract(t)
	if !strings.Contains(out, "group or other writable") || !strings.Contains(out, "[config-untrusted]") {
		t.Errorf("a layer others could write was not refused:\n%s", out)
	}
	if st, err := os.Lstat(layer); err != nil || st.Mode().Perm() != 0o460 {
		t.Errorf("%s: %v, mode %v, want 0460: the owner's read back, the group's bits kept", layer, err, st.Mode().Perm())
	}
}

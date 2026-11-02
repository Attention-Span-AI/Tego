// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// machineProbe makes `run` see a machine whose doctor report offers probe, and records the machine config
// it was asked about. The probe has to be one the derivation can produce for this test binary's build:
// doctor ANDs enforce.Buildable into every tier it offers, so a report offering a tier this build cannot
// construct describes no real machine (see builtProbe).
func machineProbe(t *testing.T, probe backend.Probe) *[]*config.Machine {
	t.Helper()
	var asked []*config.Machine
	prev := probeMachine
	probeMachine = func(_ context.Context, m *config.Machine, _ backend.Tier) (*doctor.Report, error) {
		asked = append(asked, m)
		return &doctor.Report{Tiers: probe}, nil
	}
	t.Cleanup(func() { probeMachine = prev })
	return &asked
}

// buildsTiers describes a build that constructs tiers, each of which this process can get, for the compile of a
// test: builtTiers is what Compile resolves tier: auto to and what compile --test answers in (ADR 0019).
func buildsTiers(t *testing.T, tiers ...backend.Tier) {
	t.Helper()
	autoTiersAre(t, doctor.AutoSet{Tiers: tiers})
}

// autoTiersAre describes the build and machine by doctor.AutoTiers' answer: the tiers an auto run can get, and the
// built tiers it leaves out, which compile --test's header names.
func autoTiersAre(t *testing.T, s doctor.AutoSet) {
	t.Helper()
	prev := autoSet
	autoSet = func() doctor.AutoSet {
		return doctor.AutoSet{Tiers: slices.Clone(s.Tiers), NeedRoot: slices.Clone(s.NeedRoot),
			NeedBPFLSM: slices.Clone(s.NeedBPFLSM)}
	}
	t.Cleanup(func() { autoSet = prev })
}

// builtProbe is what the derivation offers on a root machine whose every probe passes but bpf in lsm=:
// tier landlock, and tier cgroup exactly when this binary embeds the objects.
func builtProbe() (backend.Probe, bool) {
	built := enforce.Buildable(backend.TierCgroup) == nil
	return backend.Probe{backend.TierLandlock: true, backend.TierCgroup: built, backend.TierBPFLSM: false}, built
}

// autoTable is an auto contract as Compile leaves it on an unbounded machine: resolved to the top tier.
func autoTable() *agent.RuleTable {
	return &agent.RuleTable{Tier: backend.TierBPFLSM, Capture: agent.CaptureUprobe, ContractPath: "/p/agent.yaml",
		Contract: &agent.Contract{Name: "a"}}
}

func requireLandlockABI(t *testing.T) {
	t.Helper()
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel, so no backend can be constructed: %v", err)
	}
}

// TestRunSelectsTierTwoFromDoctorsDerivation: a root machine whose
// derivation offers tier cgroup gets tier cgroup from `tego run`, with an auto contract and with
// --tier cgroup. Run used to build its probe from a gate of its own that only ever set landlock, so
// neither could happen, and --tier cgroup was exit 125 [tier-unavailable] even as root.
//
// The report offers tier cgroup only when this binary embeds the objects, as the derivation does; an
// untagged test binary checks the rest here, and the refusal a build without the objects gets is
// TestRunTierRefusalIsDoctorsAccount's, on the real derivation, and internal/doctor's
// TestRunIsRefusedInDoctorsWords, on the derivation for a described machine.
func TestRunSelectsTierTwoFromDoctorsDerivation(t *testing.T) {
	requireLandlockABI(t)
	root, built := builtProbe()
	machineProbe(t, root)
	want := backend.TierLandlock
	if built {
		want = backend.TierCgroup
	}

	var stderr bytes.Buffer
	b, rt, _, code := selectBackend(context.Background(), runOptions{}, config.Builtin(), autoTable(), &stderr)
	if b == nil {
		t.Fatalf("auto contract on a root machine: exit %d\n%s", code, stderr.String())
	}
	if b.Tier() != want || rt.Tier != want {
		t.Errorf("selected %s with a table at %s, want %s for both:\n%s", b.Tier(), rt.Tier, want, stderr.String())
	}
	if !built {
		return
	}
	stderr.Reset()
	b, rt, _, code = selectBackend(context.Background(), runOptions{tier: "cgroup"}, config.Builtin(), autoTable(), &stderr)
	if b == nil || b.Tier() != backend.TierCgroup || rt.Tier != backend.TierCgroup {
		t.Errorf("--tier cgroup on a root machine: %v, exit %d\n%s", b, code, stderr.String())
	}
}

// TestRunTierRefusalIsDoctorsAccount runs selection on this machine's real derivation, and holds it to the
// report `tego doctor` prints: --tier cgroup either runs at tier cgroup, where the report offers it, or is
// refused as a pin of tier cgroup carrying every reason the report lists for it. On an ordinary box with an
// untagged binary that is root and the build; the refusal used to be "no enforcement tier available on this
// machine" there, a false sentence on a machine doctor gives tier landlock, naming neither.
func TestRunTierRefusalIsDoctorsAccount(t *testing.T) {
	rep, err := doctor.Run(context.Background(), config.Builtin(), "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tier == "" {
		t.Skipf("doctor reports no tier on this machine: %v", rep.Missing)
	}
	var stderr bytes.Buffer
	b, _, _, code := selectBackend(context.Background(), runOptions{tier: "cgroup"}, config.Builtin(), autoTable(), &stderr)
	if rep.Tiers[backend.TierCgroup] {
		if b == nil || b.Tier() != backend.TierCgroup {
			t.Errorf("doctor offers cgroup and --tier cgroup gave %v, exit %d\n%s", b, code, stderr.String())
		}
		return
	}
	out := stderr.String()
	if b != nil || code != identity.ExitLauncher {
		t.Fatalf("--tier cgroup, which doctor withholds: %v, exit %d\n%s", b, code, out)
	}
	if !strings.Contains(out, "tier cgroup pinned but not available [tier-unavailable]") || strings.Contains(out, "no enforcement tier") {
		t.Errorf("the refusal does not name tier cgroup, or says no tier is available:\n%s", out)
	}
	for _, reason := range rep.Missing[backend.TierCgroup] {
		if !strings.Contains(out, reason) {
			t.Errorf("the refusal lacks doctor's reason %q:\n%s", reason, out)
		}
	}
	if enforce.Buildable(backend.TierCgroup) != nil && !strings.Contains(out, "build: tier cgroup is not built into this binary") {
		t.Errorf("an untagged binary is refused tier cgroup without naming the build:\n%s", out)
	}
}

// TestRunRefusesWhatDoctorDoesNotOffer: a tier the derivation leaves out is exit 125 before anything is
// created, and --tier never widens the probe.
// identity-config.md R18: a pinned tier the machine does not offer is exit 125 [tier-unavailable] (ExitLauncher), never 211.
func TestRunRefusesWhatDoctorDoesNotOffer(t *testing.T) {
	requireLandlockABI(t)
	machineProbe(t, backend.Probe{backend.TierLandlock: true})
	var stderr bytes.Buffer
	b, _, _, code := selectBackend(context.Background(), runOptions{tier: "cgroup"}, config.Builtin(), autoTable(), &stderr)
	if b != nil || code != identity.ExitLauncher || !strings.Contains(stderr.String(), "tier cgroup pinned but not available [tier-unavailable]") {
		t.Errorf("--tier cgroup on a machine doctor gives landlock: %v, exit %d\n%s", b, code, stderr.String())
	}
	machineProbe(t, backend.Probe{})
	stderr.Reset()
	if b, _, _, code = selectBackend(context.Background(), runOptions{}, config.Builtin(), autoTable(), &stderr); b != nil || code != identity.ExitLauncher {
		t.Errorf("a machine doctor gives no tier: %v, exit %d", b, code)
	}
}

// TestRunAsksDoctorWithTheMachineConfig: runRun hands the derivation the machine config it loaded, so
// the ceiling doctor applies is the one the run obeys, and a derivation offering nothing ends the run at
// selection with exit 125 [tier-unavailable].
func TestRunAsksDoctorWithTheMachineConfig(t *testing.T) {
	asked := machineProbe(t, backend.Probe{})
	t.Setenv("TEGO_CONFIG", "")
	var stderr bytes.Buffer
	code := runRun(context.Background(), runOptions{contract: filepath.Join("testdata", "minimal.yaml"),
		command: []string{"true"}, offline: true}, &stderr)
	if code != identity.ExitLauncher || !strings.Contains(stderr.String(), "[tier-unavailable]") {
		t.Fatalf("exit %d, want 125 [tier-unavailable]:\n%s", code, stderr.String())
	}
	if len(*asked) != 1 || (*asked)[0] == nil {
		t.Fatalf("the derivation was asked %d times with %v, want once with the run's machine config", len(*asked), *asked)
	}
}

// TestRunHandsEveryConsumerTheSelectedTier: an auto contract compiled on an unbounded machine names tier
// bpflsm, and the run's three readers of the table — the capture sources, the kernel recorder and
// runtime.Run — must each be handed it at the tier the run got. The recorder's is the one that matters most
// and the one nothing else checks: it judges every exec the tier-2 programs record with Evaluate at its
// table's tier, and the runtime's own restamp never reaches the table its closure holds, so a table left at
// bpflsm judged tier-2 execs by basename with tier 3's unlisted-script rule (agent-contract.md R15) and could
// record an allow for an exec tier 2 refused. Removing the stamp from selectBackend fails this test.
func TestRunHandsEveryConsumerTheSelectedTier(t *testing.T) {
	requireLandlockABI(t)
	probe, built := builtProbe()
	machineProbe(t, probe)
	want := backend.TierLandlock
	if built {
		want = backend.TierCgroup
	}

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
	prevAnchor := anchorPath
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	t.Cleanup(func() { anchorPath = prevAnchor })

	seen := map[string]*agent.RuleTable{}
	var enforced backend.Tier
	prevRun, prevCapture, prevRecorder := startRun, captureFor, recorderFor
	t.Cleanup(func() { startRun, captureFor, recorderFor = prevRun, prevCapture, prevRecorder })
	captureFor = func(rt *agent.RuleTable, _ *config.Machine, _ enforce.Backend) ([]source.Source, []source.Gap) {
		seen["capture"] = rt
		return nil, nil
	}
	recorderFor = func(rt *agent.RuleTable, _ *slog.Logger) func(string) (source.Source, error) {
		seen["recorder"] = rt
		return nil
	}
	startRun = func(_ context.Context, rt *agent.RuleTable, _ []string, deps tegoruntime.Deps) (tegoruntime.Result, error) {
		seen["runtime"] = rt
		enforced = deps.Enforce.Tier()
		return tegoruntime.Result{}, nil
	}

	var stderr bytes.Buffer
	code := runRun(context.Background(), runOptions{contract: filepath.Join("testdata", "minimal.yaml"),
		command: []string{"true"}, offline: true}, &stderr)
	if code != identity.ExitOK {
		t.Fatalf("exit %d:\n%s", code, stderr.String())
	}
	if enforced != want {
		t.Fatalf("the run was handed a %s backend, want %s", enforced, want)
	}
	for _, reader := range []string{"capture", "recorder", "runtime"} {
		rt := seen[reader]
		if rt == nil {
			t.Errorf("%s was never handed a table", reader)
			continue
		}
		if rt.Tier != want {
			t.Errorf("%s was handed a table at %s, and the run enforces %s", reader, rt.Tier, want)
		}
	}
}

// TestProbeMachineIsDoctorsProbe: the production seam is doctor's own derivation, on this machine as it is,
// so there is no second derivation for the two commands to disagree through. At every reach a run can ask
// for, each tier at or below it is offered and explained exactly as doctor.Run's report offers and explains
// it; the full reach is doctor's report whole.
func TestProbeMachineIsDoctorsProbe(t *testing.T) {
	rep, err := doctor.Run(context.Background(), config.Builtin(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, reach := range backend.Tiers() {
		got, err := probeMachine(context.Background(), config.Builtin(), reach)
		if err != nil {
			t.Fatal(err)
		}
		for _, tier := range backend.Tiers() {
			if !tier.AtOrBelow(reach) {
				continue
			}
			if got.Probe()[tier] != rep.Probe()[tier] || got.WhyNot(tier) != rep.WhyNot(tier) {
				t.Errorf("reach %s: run offers %s=%v (%q), doctor %v (%q)", reach, tier, got.Probe()[tier],
					got.WhyNot(tier), rep.Probe()[tier], rep.WhyNot(tier))
			}
		}
		if reach == backend.TierBPFLSM && (!reflect.DeepEqual(got.Probe(), rep.Probe()) || !reflect.DeepEqual(got.Missing, rep.Missing)) {
			t.Errorf("reach bpflsm: run probes %v missing %v, doctor reports %v missing %v", got.Probe(), got.Missing,
				rep.Probe(), rep.Missing)
		}
	}
}

// TestDoctorReadsTheMachineConfig: doctor ran with no machine config, so a machine
// capped at landlock was reported at whatever it could reach, and R27's "ceiling" line never printed.
func TestDoctorReadsTheMachineConfig(t *testing.T) {
	dir := t.TempDir()
	// A layer whose file or directory is group- or other-writable is skipped (R20), and t.TempDir
	// inherits the process umask.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("tier: landlock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", path)
	code, out, errs := run(t, "doctor", "--json")
	var rep struct {
		Ceiling string
		Tier    string
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("exit %d: %v\n%s\n%s", code, err, out, errs)
	}
	if rep.Ceiling != string(backend.TierLandlock) {
		t.Fatalf("ceiling %q, want the machine config's landlock (stderr %q)", rep.Ceiling, errs)
	}
	if rep.Tier != "" && rep.Tier != string(backend.TierLandlock) {
		t.Errorf("tier %q above the machine's ceiling", rep.Tier)
	}
	if rep.Tier == string(backend.TierLandlock) {
		_, text, _ := run(t, "doctor")
		if !strings.Contains(text, "ceiling: the machine config caps every run at landlock") {
			t.Errorf("no ceiling line:\n%s", text)
		}
	}
}

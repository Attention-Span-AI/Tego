// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var updateRunStartGolden = flag.Bool("update-runstart", false, "rewrite testdata/run_start-no-extras.golden")

// runStartLine writes the run_start of a fixed landlock run through the real writeRunStart and returns its line as
// written. masked gives it with the values that depend on the host or the moment replaced by their key's name (the line's id, ts,
// mono_ns, pid and tid, the launcher's pid and uid) or left out (its passwd name, the nodename and any sudo account,
// which a host may not have), so every other byte is compared.
func runStartLine(t *testing.T, deps Deps) string {
	t.Helper()
	const id = "r-00000000-000000000000a-extra0"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	deps.Enforce = tierBackend{tier: backend.TierLandlock}
	deps.Cwd = "/srv/proj"
	deps.Build = Build{Version: "0.1.0-test", Commit: "c0ffee0", Kernel: "6.17.0-test"}
	r := newTestRunner(deps)
	r.writer = w
	r.cmd = []string{"/bin/true"}
	r.rt = &agent.RuleTable{ContractPath: "/elsewhere/contract.yaml", Contract: &agent.Contract{Name: "retriever"}}
	if err := r.writeRunStart(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return line
}

// masked is line with the values that depend on the host or the moment replaced or left out, as runStartLine says.
func masked(line string) string {
	for _, k := range []string{"id", "ts", "mono_ns", "pid", "tid", "launcher_pid", "launcher_uid"} {
		line = regexp.MustCompile(`"`+k+`":("[^"]*"|[0-9]+)`).ReplaceAllString(line, `"`+k+`":"<`+k+`>"`)
	}
	// Written only when the host has them (a passwd name, a readable nodename, a root launcher under sudo).
	for _, k := range []string{"launcher_user", "host", "sudo_uid", "sudo_user"} {
		line = regexp.MustCompile(`,"`+k+`":("[^"]*"|[0-9]+)`).ReplaceAllString(line, "")
	}
	return line
}

// TestRunStartUnchangedWithoutExtras: with every RunStartExtras block nil, the run_start writeRunStart writes is byte
// for byte the line the launcher wrote before RunStartExtras existed (testdata/run_start-no-extras.golden, recorded
// from that code); the host- and moment-dependent values are masked by key, and every other byte is compared.
func TestRunStartUnchangedWithoutExtras(t *testing.T) {
	got := masked(runStartLine(t, Deps{Labels: map[string]string{}, Environ: []string{}}))
	path := filepath.Join("testdata", "run_start-no-extras.golden")
	if *updateRunStartGolden {
		if err := os.WriteFile(path, []byte(got+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.TrimSuffix(string(want), "\n") {
		t.Fatalf("run_start without extras changed:\n got %s\nwant %s", got, want)
	}
}

// mvpExtras is a RunStartExtras with every block.
func mvpExtras() RunStartExtras {
	return RunStartExtras{
		Deployment: &record.Deployment{ID: "dep_01hzx3k7q9w8e6r5t4y3v2m1n0", Name: "nightly-triage", Revision: 1,
			RevisionHash: strings.Repeat("c4", 32), Instance: 1, Trigger: record.DeployTriggerStart},
		Secrets: []record.SecretUse{{Name: "github", Version: 2, Deliver: record.SecretDeliverEnv, Env: "GITHUB_TOKEN",
			Exposure: record.SecretExposureAgent}},
		Vault:  &record.VaultUse{Peer: record.VaultPeerSameUID, Memory: record.VaultMemoryMlock},
		Shares: []record.ShareUse{{Name: "docs", Path: "/srv/docs", Mode: record.ShareModeRO}},
	}
}

// TestRunStartCarriesTheExtras: writeRunStart writes each RunStartExtras block into run_start as given, beside the
// fields it writes today, which stay as they are. It stands in for the binary whose Minor reaches every block
// (launchMinor): at record.Minor the ledger Writer refuses the line [below-minor].
func TestRunStartCarriesTheExtras(t *testing.T) {
	defer func(m int) { launchMinor = m }(launchMinor)
	launchMinor = record.MinorShares
	x := mvpExtras()
	line := runStartLine(t, Deps{Labels: map[string]string{}, Environ: []string{}, RunStartExtras: x})
	e, err := record.Decode([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	var p record.RunStartPayload
	if err := e.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.Deployment == nil || *p.Deployment != *x.Deployment || len(p.Secrets) != 1 || p.Secrets[0] != x.Secrets[0] ||
		p.Vault == nil || *p.Vault != *x.Vault || len(p.Shares) != 1 || p.Shares[0] != x.Shares[0] {
		t.Fatalf("run_start blocks %+v %+v %+v %+v, want %+v", p.Deployment, p.Secrets, p.Vault, p.Shares, x)
	}
	if p.RecordMinor != record.MinorShares || p.ContractHash == "" || p.Tier != string(backend.TierLandlock) {
		t.Fatalf("the rest of run_start changed: %s", line)
	}
}

// TestRunRefusesExtrasItsMinorDoesNotReach is the fail-closed half: Run validates RunStartExtras at record.Minor, the
// revision this binary stamps, before the run exists. A block whose revision is above Minor (every one, until its
// writer raises Minor) or a malformed block is ErrDeps, exit 125, naming the field, with no ledger root made, so no
// ledger can hold a field its record_minor says the writer did not know. A block Minor reaches gets past the check (the
// run then fails at the child stage that cannot start).
func TestRunRefusesExtrasItsMinorDoesNotReach(t *testing.T) {
	x := mvpExtras()
	for _, tc := range []struct {
		name string
		x    RunStartExtras
		need int // the revision the blocks need; 0 for one refused at every revision
		want string
	}{
		{"deployment", RunStartExtras{Deployment: x.Deployment}, record.MinorDeployment, "run_start.deployment"},
		{"secrets", RunStartExtras{Secrets: x.Secrets, Vault: x.Vault}, record.MinorSecrets, "run_start.secrets"},
		{"shares", RunStartExtras{Shares: x.Shares}, record.MinorShares, "run_start.shares"},
		{"every block", x, record.MinorShares, "run_start.deployment"},
		{"vault alone", RunStartExtras{Vault: x.Vault}, 0, "run_start.vault"},
		{"empty secrets list", RunStartExtras{Secrets: []record.SecretUse{}}, 0, "run_start.secrets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, rt, root := startupFixture(t)
			deps := Deps{Config: m, Cgroups: &fakeCgroups{root: t.TempDir()}, Enforce: &fakeBackend{}, Cwd: root,
				Launcher: &launch.Launcher{Exe: filepath.Join(root, "must-never-start")}, Environ: []string{"PATH=/bin"},
				RunStartExtras: tc.x}
			res, err := Run(context.Background(), rt, []string{"/bin/true"}, deps)
			if tc.need != 0 && record.Minor >= tc.need {
				if err == nil || errors.Is(err, ErrDeps) {
					t.Fatalf("blocks at %d, Minor %d: Run = %v, want the child stage's own failure", tc.need, record.Minor, err)
				}
				return
			}
			if !errors.Is(err, ErrDeps) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run = %v, want ErrDeps naming %q", err, tc.want)
			}
			if tc.need != 0 && !strings.Contains(err.Error(), "[below-minor]") {
				t.Fatalf("Run = %v, want [below-minor]", err)
			}
			if res.ExitCode != identity.ExitLauncher || res.RunID != "" {
				t.Fatalf("result %+v, want exit 125 and no run id", res)
			}
			if _, err := os.Stat(filepath.Join(root, "runs")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the ledger root exists (%v): the extras were checked after mintRun", err)
			}
		})
	}
}

// TestRunStartExtrasAreCopied: Run keeps its own copy of the extras it validated, so a caller that edits its slices or
// blocks after Run started cannot put an unvalidated value in run_start. The test stands in for a binary whose Minor
// reaches every block (launchMinor), passes the extras through newRunner, edits the caller's value in every block,
// and reads the run_start writeRunStart then writes.
func TestRunStartExtrasAreCopied(t *testing.T) {
	defer func(m int) { launchMinor = m }(launchMinor)
	launchMinor = record.MinorShares
	x := mvpExtras()
	x.Deployment.Trigger, x.Deployment.Revision = record.DeployTriggerUpdate, 2
	x.Deployment.Change = &record.DeploymentChange{FromRevision: 1, Class: record.ChangeTighten}
	want := x.clone()
	m, rt, root := startupFixture(t)
	r, err := newRunner(rt, []string{"/bin/true"}, Deps{Config: m, Cgroups: &fakeCgroups{root: t.TempDir()},
		Enforce: tierBackend{tier: backend.TierLandlock}, Cwd: root, Environ: []string{"PATH=/bin"},
		Labels: map[string]string{}, RunStartExtras: x})
	if err != nil {
		t.Fatal(err)
	}
	x.Deployment.ID, x.Deployment.Change.Class, x.Secrets[0].Env, x.Vault.Peer, x.Shares[0].Path = "BOGUS", "loosen",
		"LD_PRELOAD", "root", "/"
	const id = "r-00000000-000000000000a-extra1"
	w, err := ledger.Open(filepath.Join(t.TempDir(), id), record.RunRef{ID: id, Agent: "retriever"},
		ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Abandon() }()
	r.writer = w
	if err := r.writeRunStart(); err != nil {
		t.Fatalf("writeRunStart after the caller edited its extras: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(w.Dir(), ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	e, err := record.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	var p record.RunStartPayload
	if err := e.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	got := RunStartExtras{Deployment: p.Deployment, Secrets: p.Secrets, Vault: p.Vault, Shares: p.Shares}
	if !reflect.DeepEqual(got, want) || p.RecordMinor != record.MinorShares {
		t.Fatalf("run_start carries %+v at %d, want the validated %+v", got, p.RecordMinor, want)
	}
	if z := (RunStartExtras{}).clone(); z.Deployment != nil || z.Secrets != nil || z.Vault != nil || z.Shares != nil {
		t.Fatalf("the zero value's copy is %+v", z)
	}
}

// TestRunStartCwdIsTheKernels: run_start names the working directory the way the run's lines name paths, every symlink
// resolved. From a project reached through a link $PWD spells the link, and os.Getwd answers $PWD: tego learn then saw
// every write outside the workspace and proposed fs.write: [].
func TestRunStartCwdIsTheKernels(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real, link := filepath.Join(base, "real"), filepath.Join(base, "link")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Chdir(link)
	t.Setenv("PWD", link)
	if wd, err := os.Getwd(); err != nil || wd != link {
		t.Fatalf("the test's premise: os.Getwd = %q, %v; want the link's spelling %q", wd, err, link)
	}

	const id = "r-00000000-000000000000a-extra0"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	r := newTestRunner(Deps{Enforce: tierBackend{tier: backend.TierLandlock}})
	r.writer = w
	r.cmd = []string{"/bin/true"}
	r.rt = &agent.RuleTable{ContractPath: "/elsewhere/contract.yaml", Contract: &agent.Contract{Name: "retriever"}}
	if err := r.writeRunStart(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	if !strings.Contains(line, `"cwd":"`+real+`"`) {
		t.Errorf("run_start names another working directory than %q:\n%s", real, line)
	}
}

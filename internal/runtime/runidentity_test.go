// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRunRefusesABadIdentityBeforeTheRunExists is ADR 0073 D2: a parent run that is not a run id, labels that break
// identity.ValidLabels or a role this version does not know are ErrDeps, exit 125, returned before mintRun, so no
// ledger root, run directory or live entry exists. The same Deps with a good identity get past mintRun (the ledger
// root is made) and fail later, at the child stage that cannot start.
func TestRunRefusesABadIdentityBeforeTheRunExists(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Deps)
		want string
	}{
		{"parent run not a run id", func(d *Deps) { d.ParentRun = "r-not-a-run" }, "TEGO_PARENT_RUN"},
		{"parent run with a newline", func(d *Deps) { d.ParentRun = "r-00000000-000000000000a-aaaaaa\n" }, "TEGO_PARENT_RUN"},
		{"label key upper-case", func(d *Deps) { d.Labels = map[string]string{"Team": "x"} }, "label key"},
		{"label under tego.", func(d *Deps) { d.Labels = map[string]string{"tego.run": "x"} }, "reserved"},
		{"label value with a control", func(d *Deps) { d.Labels = map[string]string{"team": "a\x1bb"} }, "control"},
		{"unknown role", func(d *Deps) { d.Role = "judge" }, "role"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, rt, root := startupFixture(t)
			deps := Deps{Config: m, Cgroups: &fakeCgroups{root: t.TempDir()}, Enforce: &fakeBackend{}, Cwd: root,
				Launcher: &launch.Launcher{Exe: filepath.Join(root, "must-never-start")}, Environ: []string{"PATH=/bin"}}
			tc.edit(&deps)
			res, err := Run(context.Background(), rt, []string{"/bin/true"}, deps)
			if !errors.Is(err, ErrDeps) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run = %v, want ErrDeps naming %q", err, tc.want)
			}
			if res.ExitCode != identity.ExitLauncher || res.RunID != "" {
				t.Fatalf("result %+v, want exit 125 and no run id", res)
			}
			if _, err := os.Stat(filepath.Join(root, "runs")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the ledger root exists (%v): the identity was checked after mintRun", err)
			}
		})
	}
	m, rt, root := startupFixture(t)
	_, err := Run(context.Background(), rt, []string{"/bin/true"}, Deps{Config: m, Cgroups: &fakeCgroups{root: t.TempDir()},
		Enforce: &fakeBackend{}, Cwd: root, Launcher: &launch.Launcher{Exe: filepath.Join(root, "must-never-start")},
		Environ: []string{"PATH=/bin"}, ParentRun: "r-00000000-000000000000a-aaaaaa", Role: identity.RoleCheck,
		Labels: map[string]string{"team": "infra"}})
	if err == nil || errors.Is(err, ErrDeps) {
		t.Fatalf("a good identity: Run = %v, want the child stage's own failure", err)
	}
	if _, err := os.Stat(filepath.Join(root, "runs")); err != nil {
		t.Fatalf("a good identity never reached mintRun: %v", err)
	}
}

// TestRunStartCarriesTheRunIdentity is ADR 0073 D1 from the real writeRunStart of a run and of an adoption: run_start
// at MinorRunIdentity carries launcher_uid (0 included, never left out), the passwd name, the host, the parent run,
// labels, role and contract revision a run has, and none of the optional ones a run does not have.
func TestRunStartCarriesTheRunIdentity(t *testing.T) {
	wantHost, herr := os.Hostname()
	if herr != nil || len(wantHost) > identity.MaxHostBytes {
		wantHost = ""
	}
	const parent = "r-00000000-000000000000a-parent"
	for _, tc := range []struct {
		name  string
		deps  Deps
		rev   string
		adopt bool
	}{
		{"run with every field", Deps{ParentRun: parent, Labels: map[string]string{"team": "infra", "ticket": "ops-12"},
			Role: identity.RoleCheck, Environ: []string{"SUDO_UID=4242"}}, "2026.10.25+1", false},
		{"run with none", Deps{Labels: map[string]string{}, Environ: []string{}}, "", false},
		{"adoption", Deps{}, "7", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const id = "r-00000000-000000000000a-ident0"
			dir := filepath.Join(t.TempDir(), id)
			w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithAnchor(nopAnchor{}))
			if err != nil {
				t.Fatal(err)
			}
			deps := tc.deps
			deps.Enforce = tierBackend{tier: backend.TierLandlock}
			r := newTestRunner(deps)
			r.writer = w
			r.rt = &agent.RuleTable{ContractPath: "/elsewhere/contract.yaml", Contract: &agent.Contract{Name: "retriever", Revision: tc.rev}}
			if tc.adopt {
				a := &adoption{r: r, spec: AdoptSpec{Root: adopt.Process{PID: os.Getpid(), Argv: []string{"agent"}}}, env: adopt.Env{Proc: adopt.NewFS("")}}
				err = a.writeRunStart()
			} else {
				err = r.writeRunStart()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			evs := events(t, dir)
			var p record.RunStartPayload
			if len(evs) == 0 || evs[0].DecodePayload(&p) != nil {
				t.Fatal("no run_start")
			}
			first := string(evs[0].Payload)
			if p.RecordMinor < record.MinorRunIdentity || p.LauncherUID == nil || *p.LauncherUID != uint32(os.Getuid()) {
				t.Fatalf("run_start record_minor %d launcher_uid %v, want at least %d and %d: %s", p.RecordMinor, p.LauncherUID,
					record.MinorRunIdentity, os.Getuid(), first)
			}
			if !strings.Contains(first, `"launcher_uid":`+strconv.Itoa(os.Getuid())) {
				t.Fatalf("launcher_uid is not written as a number: %s", first)
			}
			if want, _ := passwdName(uint32(os.Getuid())); p.LauncherUser != want {
				t.Errorf("launcher_user %q, want the passwd name %q", p.LauncherUser, want)
			}
			if p.Host != wantHost {
				t.Errorf("host %q, want %q", p.Host, wantHost)
			}
			// Deps.Environ's SUDO_UID is the agent's template and is never read, as root or not
			// (TestRunStartReadsSudoFromTheLauncherProcess); an unprivileged launcher records none at all.
			if p.SudoUID != nil && *p.SudoUID == 4242 {
				t.Errorf("sudo_uid 4242 was read from Deps.Environ")
			}
			if os.Geteuid() != 0 && (p.SudoUID != nil || p.SudoUser != "") {
				t.Errorf("an unprivileged launcher recorded sudo_uid %v sudo_user %q", p.SudoUID, p.SudoUser)
			}
			if p.ContractRevision != tc.rev {
				t.Errorf("contract_revision %q, want %q", p.ContractRevision, tc.rev)
			}
			if p.ParentRun != tc.deps.ParentRun || p.Role != string(tc.deps.Role) || len(p.Labels) != len(tc.deps.Labels) {
				t.Errorf("parent_run %q role %q labels %v, want %q %q %v", p.ParentRun, p.Role, p.Labels,
					tc.deps.ParentRun, tc.deps.Role, tc.deps.Labels)
			}
			for k, v := range tc.deps.Labels {
				if p.Labels[k] != v {
					t.Errorf("label %s = %q, want %q", k, p.Labels[k], v)
				}
			}
			if len(tc.deps.Labels) == 0 && strings.Contains(first, `"labels"`) {
				t.Errorf("a run with no labels wrote labels: %s", first)
			}
			if tc.rev == "" && strings.Contains(first, `"contract_revision"`) {
				t.Errorf("a contract with no revision wrote contract_revision: %s", first)
			}
		})
	}
}

// TestRunStartReadsSudoFromTheLauncherProcess is ADR 0073 D1's sudo rule: sudo_uid is the SUDO_UID the launcher's
// own process holds, the variable the drop to the invoking account reads (config.InvokingUID), under the drop's gate
// (real and effective uid 0 of the initial user namespace), never the one in Deps.Environ: that is the agent's
// environment template, which an embedder may fill from its own caller, and the record and the drop must not disagree.
func TestRunStartReadsSudoFromTheLauncherProcess(t *testing.T) {
	invoker := uint32(1234)
	for _, tc := range []struct {
		name    string
		creds   launcherProcess
		process string
		want    *uint32
	}{
		{"root under sudo", launcherProcess{ruid: 0, euid: 0, initialNS: true}, "1234", &invoker},
		{"root with no SUDO_UID of its own", launcherProcess{ruid: 0, euid: 0, initialNS: true}, "", nil},
		{"euid 0 of a real uid that is not root", launcherProcess{ruid: 1000, euid: 0, initialNS: true}, "1234", nil},
		{"uid 0 of a child user namespace", launcherProcess{ruid: 0, euid: 0, initialNS: false}, "1234", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := launcherCreds
			t.Cleanup(func() { launcherCreds = saved })
			launcherCreds = func() launcherProcess { return tc.creds }
			t.Setenv(identity.EnvSudoUID, tc.process)
			const id = "r-00000000-000000000000a-sudo00"
			dir := filepath.Join(t.TempDir(), id)
			w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithAnchor(nopAnchor{}))
			if err != nil {
				t.Fatal(err)
			}
			r := newTestRunner(Deps{Enforce: tierBackend{tier: backend.TierLandlock},
				Environ: []string{"PATH=/bin", identity.EnvSudoUID + "=4242"}})
			r.writer = w
			r.rt = &agent.RuleTable{ContractPath: "/elsewhere/contract.yaml", Contract: &agent.Contract{Name: "retriever"}}
			if err := r.writeRunStart(); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			var p record.RunStartPayload
			if evs := events(t, dir); len(evs) == 0 || evs[0].DecodePayload(&p) != nil {
				t.Fatal("no run_start")
			}
			if (p.SudoUID == nil) != (tc.want == nil) || (p.SudoUID != nil && *p.SudoUID != *tc.want) {
				t.Fatalf("sudo_uid %s, want %s (the process's SUDO_UID %q, Deps.Environ's 4242)", uidText(p.SudoUID),
					uidText(tc.want), tc.process)
			}
			if p.LauncherUID == nil || *p.LauncherUID != tc.creds.ruid {
				t.Fatalf("launcher_uid %s, want the real uid %d", uidText(p.LauncherUID), tc.creds.ruid)
			}
		})
	}
}

// uidText is a recorded uid as text, "none" when it is absent.
func uidText(u *uint32) string {
	if u == nil {
		return "none"
	}
	return strconv.FormatUint(uint64(*u), 10)
}

// TestTheAgentsParentRunIsDepsParentRun is RUN-IDENTITY.md's TEGO_PARENT_RUN row: the agent's TEGO_PARENT_RUN is the
// run run_start records as parent_run (Deps.ParentRun, the enclosing run when nested), never a value inherited from
// the launcher's environment, and "" is still set. The runner has no runtime directory, as a root launcher's has none
// (harnessRunner makes one, and skips as root): agentEnv reads none, and the root suites run this too.
func TestTheAgentsParentRunIsDepsParentRun(t *testing.T) {
	const outer, grand = "r-00000000-000000000000a-outer0", "r-00000000-000000000000a-grand0"
	for _, parent := range []string{outer, ""} {
		r := &runner{id: "r-00000000-000000000000a-aaaaaa", rt: tableFor(harnessContract(harness.Auto, nil)),
			cmd: []string{"/bin/sh"}, log: slog.New(slog.DiscardHandler),
			deps: Deps{Environ: []string{"HOME=/nonexistent", "PATH=/usr/bin:/bin"}}}
		r.deps.Environ = append(r.deps.Environ, identity.EnvRunID+"="+outer, identity.EnvParentRun+"="+grand)
		r.deps.ParentRun = parent
		var got []string
		for _, kv := range r.agentEnv() {
			if v, ok := strings.CutPrefix(kv, identity.EnvParentRun+"="); ok {
				got = append(got, v)
			}
		}
		if len(got) != 1 || got[0] != parent {
			t.Errorf("Deps.ParentRun %q: the agent's TEGO_PARENT_RUN is %q, want exactly %q", parent, got, parent)
		}
	}
}

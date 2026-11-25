// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// outsideShell describes, for the setup fixture, a shell outside the user manager's cgroup (an SSH or console login, an
// ordinary WSL shell) whose probe answered pa: the check is made from guide.WhereShell.
func outsideShell(t *testing.T, pa probeAnswer) {
	t.Helper()
	prevProbe, prevInputs := setupProbe, setupInputs
	setupProbe = func(context.Context, *config.Machine) (probeAnswer, error) { return pa, nil }
	setupInputs = func(in *guide.Inputs) {
		prevInputs(in)
		in.As.Where, in.As.InUserCgroup = guide.WhereShell, false
	}
	t.Cleanup(func() { setupProbe, setupInputs = prevProbe, prevInputs })
}

// setupCheckStep is the check step of `tego setup --json`'s object, and its next step.
func setupCheckStep(t *testing.T, out string) (state, fact string, next guide.Next) {
	t.Helper()
	var s guide.State
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("setup --json: %v\n%s", err, out)
	}
	for _, st := range s.Steps {
		if st.ID == guide.StepCheck {
			if st.Fact != nil {
				fact = *st.Fact
			}
			return st.State, fact, s.Next
		}
	}
	t.Fatalf("no check step:\n%s", out)
	return "", "", guide.Next{}
}

// TestSetupOutsideTheManager (ADR 0142, amended 2026-11-19, round 4): a shell outside the user manager's cgroup is no
// blocker where the commands a person runs next open a user scope themselves. When the rehearsal of that entry from
// the shell worked, tego setup exits 0 and its check step is done, saying the shell is outside and that run, watch and
// test open a user scope for each run (checked); the guide goes on to the next step. When the rehearsal failed, the
// step stays blocked with the reason, and the next step is the one fix: open a shell in the manager's cgroup by hand.
// Without a rehearsal (--no-scope), the step stays as it was. Ordinary shells inside the manager are the fixture's own
// golden tests, unchanged.
func TestSetupOutsideTheManager(t *testing.T) {
	t.Run("the rehearsal worked", func(t *testing.T) {
		f := onFixture(t, guidetest.Fresh)
		outsideShell(t, probeAnswer{tier: backend.TierLandlock, outside: true, throughScope: true})
		code, out, errs := run(t, "setup", "--json")
		if code != identity.ExitOK {
			t.Fatalf("exit %d, want 0\n%s\n%s", code, out, errs)
		}
		state, fact, next := setupCheckStep(t, out)
		if state != guide.Done || !strings.Contains(fact, guide.ThroughScopeFact) || strings.Contains(fact, "can try") {
			t.Errorf("check step %s: %q; want done with %q", state, fact, guide.ThroughScopeFact)
		}
		if next.Step == guide.StepCheck || next.Rule == guide.RuleCheckOutside || next.Command == guide.DefaultScope {
			t.Errorf("next is still the check: %+v", next)
		}
		cs, err := guide.ReadChecks(f.Home)
		if err != nil || len(cs) != 1 || cs[0].Tier != "landlock" || !cs[0].ThroughUserScope || cs[0].Cause != "" || cs[0].ScopeError != "" {
			t.Errorf("stored %+v %v", cs, err)
		}
	})
	t.Run("the rehearsal failed", func(t *testing.T) {
		f := onFixture(t, guidetest.Fresh)
		const why = "user scope rehearsal exited 1"
		outsideShell(t, probeAnswer{outside: true, fix: guidetest.OutsideFix, scopeError: why})
		code, out, errs := run(t, "setup", "--json")
		if code != identity.ExitFinding {
			t.Fatalf("exit %d, want 1\n%s\n%s", code, out, errs)
		}
		state, fact, next := setupCheckStep(t, out)
		if state != guide.Blocked || !strings.Contains(fact, "could not open a user scope from it ("+why+")") ||
			strings.Contains(fact, "can try") {
			t.Errorf("check step %s: %q; want blocked with the reason", state, fact)
		}
		if next.Step != guide.StepCheck || next.Rule != guide.RuleCheckOutside || next.Command != guide.DefaultScope {
			t.Errorf("next %+v; want the one fix, %s", next, guide.DefaultScope)
		}
		cs, err := guide.ReadChecks(f.Home)
		if err != nil || len(cs) != 1 || cs[0].Cause != guide.CauseOutsideUserManager || cs[0].ScopeError != why {
			t.Errorf("stored %+v %v", cs, err)
		}
	})
	t.Run("no rehearsal", func(t *testing.T) {
		onFixture(t, guidetest.Fresh)
		outsideShell(t, probeAnswer{outside: true, fix: guidetest.OutsideFix})
		code, out, _ := run(t, "setup", "--json")
		state, fact, _ := setupCheckStep(t, out)
		if code != identity.ExitFinding || state != guide.Blocked || !strings.Contains(fact, "run, watch and test can try a user scope") {
			t.Errorf("exit %d, check step %s: %q", code, state, fact)
		}
	})
}

// TestStartOutsideTheManager: tego start's first lines agree with tego setup. A rehearsal that worked goes on to the
// four steps and says the shell is outside and that run, watch and test open a user scope; one that failed stops with
// the reason.
func TestStartOutsideTheManager(t *testing.T) {
	f := onFixture(t, guidetest.Fresh)
	noLogins(t)
	t.Chdir(f.Home)
	// The agent is not installed and the answer to installing it is no: the guide stops there and installs nothing.
	prevLook, prevInstall := guideLookPath, guideInstall
	t.Cleanup(func() { guideLookPath, guideInstall = prevLook, prevInstall })
	guideLookPath = func(string) (string, error) { return "", errors.New("not found") }
	guideInstall = func(context.Context, string, io.Writer) error {
		t.Error("the guide ran an installer")
		return errors.New("not in a test")
	}
	outsideShell(t, probeAnswer{tier: backend.TierLandlock, outside: true, throughScope: true})
	_, out, _ := runGuide(t, "2\n2\n")
	wantAll(t, "rehearsal worked", out, "This machine can run Tego", "This shell is outside your user manager's cgroup; "+
		"tego run, watch and test open a user scope for each run (checked).", "1/4  Agent")

	outsideShell(t, probeAnswer{outside: true, scopeError: "user scope rehearsal exited 1"})
	code, out, _ := runGuide(t, "")
	if code != identity.ExitFinding {
		t.Errorf("rehearsal failed: exit %d", code)
	}
	wantAll(t, "rehearsal failed", out, "Tego can't supervise agents started from this shell.",
		"tego could not open a user scope from it: user scope rehearsal exited 1")
}

// TestThroughScopeWordsAgree: doctor's verdict, the stored check's fact and tego start say one sentence.
func TestThroughScopeWordsAgree(t *testing.T) {
	if doctor.ThroughScopeFact != guide.ThroughScopeFact {
		t.Errorf("doctor says %q, the guide %q", doctor.ThroughScopeFact, guide.ThroughScopeFact)
	}
}

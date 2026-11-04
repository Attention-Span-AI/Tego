// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The run's warnings carry codes of their own: a consumer keyed on the code must not file the
// held completion's degrade or its label policy as a swap warning, which every runtime warning was printed as. The
// degrade is held-unavailable, the label policy held-label, and the swap cap swap-uncapped (swapgap_test.go).
func TestHeldWarningsCarryTheirOwnCodes(t *testing.T) {
	type warning struct{ code, what string }
	var got []warning
	r := &runner{log: slog.New(slog.DiscardHandler), deps: Deps{Warn: func(code, what string) { got = append(got, warning{code, what}) }}}
	r.deputyUnavailable(errors.New("deputy: no hello"))
	r.warnHeldLabel([]byte("capability,apparmor"), nil)
	r.warnHeldLabel([]byte("capability,landlock"), nil)
	if len(got) != 2 {
		t.Fatalf("warnings %+v: want the degrade's and the label's", got)
	}
	if got[0].code != WarnHeldUnavailable || !strings.Contains(got[0].what, "the open deputy did not start (deputy: no hello)") {
		t.Errorf("degrade warning %+v: want code %s", got[0], WarnHeldUnavailable)
	}
	if got[1].code != WarnHeldLabel || !strings.Contains(got[1].what, "AppArmor") {
		t.Errorf("label warning %+v: want code %s", got[1], WarnHeldLabel)
	}
}

// The label note names the active task-label LSMs and the refusal policy. An
// unreadable module list is never presented as a host with no task labels.
func TestHeldLabelWarning(t *testing.T) {
	for _, tc := range []struct {
		name string
		lsm  string
		err  error
		want []string // substrings; none for no warning
	}{
		{"ubuntu", "lockdown,capability,landlock,yama,apparmor,bpf,ima,evm\n", nil, []string{"on AppArmor a file open that tego checks and makes for the agent requires the same AppArmor profile as the process opening the file; a different or unreadable label refuses it"}},
		{"selinux and smack", "capability,selinux,smack", nil, []string{"on SELinux/Smack", "is refused", "process-specific rules cannot be verified across processes"}},
		{"no labelling lsm", "lockdown,capability,landlock,yama,bpf\n", nil, nil},
		{"unreadable", "", errors.New("no securityfs"), []string{"could not be read (no securityfs)", "refused when its security labels cannot be verified"}},
	} {
		got := heldLabelWarning("gate.completion: held", []byte(tc.lsm), tc.err)
		// The note is the audience's words: no tego term and no repo path a person with an installed binary lacks.
		for _, jargon := range []string{"held open", "held read", "ADR", "docs/"} {
			if strings.Contains(got, jargon) {
				t.Errorf("%s: %q says %q", tc.name, got, jargon)
			}
		}
		if len(tc.want) == 0 {
			if got != "" {
				t.Errorf("%s: warned %q, want nothing", tc.name, got)
			}
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", tc.name, got, w)
			}
		}
	}
}

// A run that holds its reads (ADR 0069) and has no gate starts the deputy for fs.reads: its label warning speaks of a
// file read, never of a gate.completion the contract does not have; a run whose gate holds its opens speaks of a file
// open, which covers writes too.
func TestHeldLabelWarningSaysWhatIsHeld(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rt       *agent.RuleTable
		want     string
		wantNone string
	}{
		{"held reads", &agent.RuleTable{Tier: backend.TierLandlock, Reads: agent.HeldReads{Mode: agent.ReadsHeld}},
			"a file read that tego checks and opens for the agent requires", "gate.completion"},
		{"held gate", &agent.RuleTable{Tier: backend.TierLandlock, Reads: agent.HeldReads{Mode: agent.ReadsDirect},
			Gate: heldLabelGate(t)}, "a file open that tego checks and makes for the agent requires", "file read"},
		{"both", &agent.RuleTable{Tier: backend.TierLandlock, Reads: agent.HeldReads{Mode: agent.ReadsHeld},
			Gate: heldLabelGate(t)}, "a file open that tego checks and makes for the agent requires", "file read"},
	} {
		var got string
		r := &runner{rt: tc.rt, log: slog.New(slog.DiscardHandler), deps: Deps{Warn: func(_, what string) { got = what }}}
		r.warnHeldLabel([]byte("capability,apparmor"), nil)
		if !strings.Contains(got, tc.want) || tc.wantNone != "" && strings.Contains(got, tc.wantNone) {
			t.Errorf("%s: warned %q, want %q and no %q", tc.name, got, tc.want, tc.wantNone)
		}
	}
}

// heldLabelGate is a gate under gate.completion: held whose read rule can escalate.
func heldLabelGate(t *testing.T) *gate.Policy {
	t.Helper()
	g, err := gate.New([]gate.Rule{{Predicate: gate.ReadMatches, Argument: "*.env", Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	return g.WithHeldCompletion()
}

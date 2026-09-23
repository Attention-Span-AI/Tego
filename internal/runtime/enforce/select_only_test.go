// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// why stands in for internal/doctor's Report.WhyNot: one line per tier it was asked about, recorded so a
// test can see which tier Select asked it to explain.
type why struct{ asked []backend.Tier }

func (w *why) of(t backend.Tier) string {
	w.asked = append(w.asked, t)
	return "missing for " + string(t) + ": the reason doctor gives"
}

// refusal is the one error diagnostic of a refused selection.
func refusal(t *testing.T, b Backend, ds []Diagnostic) Diagnostic {
	t.Helper()
	if b != nil {
		t.Fatalf("selected %s, want a refusal", b.Tier())
	}
	for _, d := range ds {
		if d.Severity == identityError {
			if d.Code != backend.CodeTierUnavailable {
				t.Errorf("code %q, want %s", d.Code, backend.CodeTierUnavailable)
			}
			return d
		}
	}
	t.Fatalf("no error diagnostic in %v", ds)
	return Diagnostic{}
}

// TestOnlyNamesTheTierItWasAskedFor: `tego run --tier cgroup` on a machine that offers tier landlock alone
// is refused as a pin of tier cgroup, with the reasons for tier cgroup, not "no enforcement tier available on
// this machine". That sentence is false there, and it is what run printed while it narrowed the probe to an
// empty set and left Select to choose from nothing (identity-config.md §7: "tier <name> pinned but not
// available: <fix>").
func TestOnlyNamesTheTierItWasAskedFor(t *testing.T) {
	withObjects(t, true)
	w := &why{}
	b, ds := Select(machine(""), table(backend.TierBPFLSM, ""), backend.Probe{backend.TierLandlock: true},
		Only(backend.TierCgroup), Explain(w.of))
	d := refusal(t, b, ds)
	if !strings.Contains(d.Message, "tier cgroup pinned but not available") {
		t.Errorf("message %q does not name the tier --tier asked for", d.Message)
	}
	if strings.Contains(d.String(), "no enforcement tier") {
		t.Errorf("%q says no tier is available on a machine that offers landlock", d.String())
	}
	if d.Fix != "missing for cgroup: the reason doctor gives" {
		t.Errorf("fix %q, want the caller's reason for cgroup", d.Fix)
	}
	if len(w.asked) != 1 || w.asked[0] != backend.TierCgroup {
		t.Errorf("asked to explain %v, want [cgroup]", w.asked)
	}

	// A value that is not an enforcement tier is refused as such, never explained as a missing tier.
	b, ds = Select(machine(""), table(backend.TierBPFLSM, ""), backend.Probe{backend.TierLandlock: true},
		Only(backend.TierObserve), Explain(w.of))
	if d := refusal(t, b, ds); !strings.Contains(d.Message, "not a selectable tier") {
		t.Errorf("--tier observe: %q", d.Message)
	}
}

// TestPinnedRefusalLeadsWithTheBuild: a pinned tier this binary does not build is refused with that reason first,
// since no machine can change it. doctor's account put it after every machine fact, behind the prerequisite tiers'
// reasons, and a reader acted on the first ones. The build sentence is not repeated where doctor's account carried it
// too.
func TestPinnedRefusalLeadsWithTheBuild(t *testing.T) {
	withObjects(t, false)
	build := "build: tier cgroup " + notBuiltWhy(backend.TierCgroup)
	doctorWhy := func(t backend.Tier) string {
		return "missing for " + string(t) + ": root: not root; " + "build: tier " + string(t) + " " + notBuiltWhy(t)
	}
	for _, opts := range [][]SelectOption{{Explain(doctorWhy)}, {Only(backend.TierCgroup), Explain(doctorWhy)}} {
		b, ds := Select(machine(""), table(backend.TierBPFLSM, "cgroup"), backend.Probe{backend.TierLandlock: true}, opts...)
		d := refusal(t, b, ds)
		if want := build + "; missing for cgroup: root: not root"; d.Fix != want {
			t.Errorf("fix %q, want %q", d.Fix, want)
		}
	}
}

// TestOnlySelectsTheTierItWasAskedFor: a tier the machine offers is selected when named, never one above it.
func TestOnlySelectsTheTierItWasAskedFor(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	b, ds := Select(machine(""), table(backend.TierBPFLSM, ""), probeRootNoBPF, Only(backend.TierLandlock))
	if b == nil || b.Tier() != backend.TierLandlock {
		t.Fatalf("--tier landlock on a machine offering cgroup: %v %v", b, ds)
	}
	b, ds = Select(machine(""), table(backend.TierBPFLSM, ""), probeRootNoBPF, Only(backend.TierCgroup))
	if b == nil || b.Tier() != backend.TierCgroup {
		t.Fatalf("--tier cgroup on a machine offering it: %v %v", b, ds)
	}
}

// TestExplainCarriesTheReasonOfTheRefusedTier: every refusal Select makes carries the caller's reason for
// the tier that was refused. A contract's own pin is explained as itself; "no enforcement tier" by tier
// landlock's reasons, which every tier inherits; a pin --tier's single offer left out by that offer.
func TestExplainCarriesTheReasonOfTheRefusedTier(t *testing.T) {
	cases := []struct {
		name  string
		pin   string
		probe backend.Probe
		opts  func(*why) []SelectOption
		fix   string
	}{
		{"a contract pin the machine lacks", "cgroup", backend.Probe{backend.TierLandlock: true},
			func(w *why) []SelectOption { return []SelectOption{Explain(w.of)} },
			"missing for cgroup: the reason doctor gives"},
		{"no tier at all", "", backend.Probe{},
			func(w *why) []SelectOption { return []SelectOption{Explain(w.of)} },
			"missing for landlock: the reason doctor gives"},
		{"a contract pin --tier left out", "landlock", backend.Probe{backend.TierLandlock: true, backend.TierCgroup: true},
			func(w *why) []SelectOption { return []SelectOption{Only(backend.TierCgroup), Explain(w.of)} },
			"run without --tier (or with --tier landlock), or change that pin to cgroup"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withObjects(t, true)
			w := &why{}
			b, ds := Select(machine(""), table(backend.TierBPFLSM, tc.pin), tc.probe, tc.opts(w)...)
			if d := refusal(t, b, ds); d.Fix != tc.fix {
				t.Errorf("fix %q, want %q", d.Fix, tc.fix)
			}
		})
	}

	// Without Explain a refusal is what it always was.
	b, ds := Select(machine(""), table(backend.TierBPFLSM, "cgroup"), backend.Probe{backend.TierLandlock: true})
	if d := refusal(t, b, ds); d.Fix != "" || !strings.Contains(d.Message, "tier cgroup pinned but not available") {
		t.Errorf("unexplained refusal: %q, fix %q", d.Message, d.Fix)
	}
}

// TestTierConflictNamesBothTiers: --tier asking for one tier while the contract's tier: or the machine
// config's concrete tier pins another is a conflict between two requests, not a missing tier. The refusal
// used to read "tier landlock pinned but not available" on a machine that offered landlock, which sent the
// operator to fix a tier that was fine. It must name both tiers, never claim the pin is missing, and stay the
// same refusal: exit 125 [tier-unavailable]. When the pinned tier is missing from the machine too (not
// offered, or not built into this binary), the refusal must carry doctor's reason for it and must not offer
// "run without --tier", which meets the same refusal for the pin.
func TestTierConflictNamesBothTiers(t *testing.T) {
	both := backend.Probe{backend.TierLandlock: true, backend.TierCgroup: true}
	landlockOnly := backend.Probe{backend.TierLandlock: true}
	cases := []struct {
		name        string
		m           string
		pin         string
		probe       backend.Probe
		objects     bool
		asked       backend.Tier
		wantPin     backend.Tier
		wantAsked   backend.Tier
		pinnedIsOff bool
	}{
		{"a contract pin", "", "landlock", both, true, backend.TierCgroup, backend.TierLandlock, backend.TierCgroup, false},
		{"a machine pin", "landlock", "", both, true, backend.TierCgroup, backend.TierLandlock, backend.TierCgroup, false},
		{"a machine pin, asked lower", "cgroup", "", both, true, backend.TierLandlock, backend.TierCgroup, backend.TierLandlock, false},
		{"a contract pin the machine lacks", "", "cgroup", landlockOnly, true, backend.TierLandlock, backend.TierCgroup, backend.TierLandlock, true},
		{"a machine pin the machine lacks", "cgroup", "", landlockOnly, true, backend.TierLandlock, backend.TierCgroup, backend.TierLandlock, true},
		{"a pin this binary cannot build", "", "cgroup", both, false, backend.TierLandlock, backend.TierCgroup, backend.TierLandlock, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withObjects(t, tc.objects)
			w := &why{}
			b, ds := Select(machine(tc.m), table(backend.TierBPFLSM, tc.pin), tc.probe, Only(tc.asked), Explain(w.of))
			d := refusal(t, b, ds)
			want := "--tier " + string(tc.wantAsked) + " conflicts with tier " + string(tc.wantPin)
			if !strings.Contains(d.Message, want) {
				t.Errorf("message %q, want it to name both tiers (%q)", d.Message, want)
			}
			if strings.Contains(d.Message, "pinned but not available") {
				t.Errorf("message %q reports the conflict as a missing pin", d.Message)
			}
			if !tc.pinnedIsOff {
				if !strings.Contains(d.Fix, "run without --tier (or with --tier "+string(tc.wantPin)+")") ||
					!strings.Contains(d.Fix, "change that pin to "+string(tc.wantAsked)) {
					t.Errorf("fix %q, want both ways out named", d.Fix)
				}
				if len(w.asked) != 0 {
					t.Errorf("asked doctor why %v is missing; neither tier is", w.asked)
				}
				return
			}
			if !strings.Contains(d.Message, "tier "+string(tc.wantPin)+" is not available on this machine either") {
				t.Errorf("message %q, want it to say the pinned tier is missing here too", d.Message)
			}
			wantFix := "change that pin to " + string(tc.wantAsked) + "; missing for " + string(tc.wantPin) +
				": the reason doctor gives"
			if !tc.objects {
				// A pin this binary cannot build has its build reason first.
				wantFix = "change that pin to " + string(tc.wantAsked) + "; build: tier " + string(tc.wantPin) + " " +
					notBuiltWhy(tc.wantPin) + "; missing for " + string(tc.wantPin) + ": the reason doctor gives"
			}
			if d.Fix != wantFix {
				t.Errorf("fix %q, want %q: the only way out, and doctor's reason for the pin", d.Fix, wantFix)
			}
			if strings.Contains(d.Fix, "without --tier") || strings.Contains(d.Fix, "--tier "+string(tc.wantPin)) {
				t.Errorf("fix %q offers a way out that is refused too", d.Fix)
			}
			if len(w.asked) != 1 || w.asked[0] != tc.wantPin {
				t.Errorf("asked doctor about %v, want [%s]", w.asked, tc.wantPin)
			}
		})
	}
	missing := &TierConflictError{Asked: backend.TierLandlock, Pinned: backend.TierCgroup, PinnedMissing: true}
	if got := missing.Fix(); got != "change that pin to landlock; tier cgroup is not available on this machine" {
		t.Errorf("a missing pin with no reason given: fix %q", got)
	}
	var err error = &TierConflictError{Asked: backend.TierCgroup, Pinned: backend.TierLandlock}
	if !errors.Is(err, backend.ErrTierUnavailable) {
		t.Error("a conflict is not errors.Is ErrTierUnavailable, so it would lose the refusal's exit status")
	}
}

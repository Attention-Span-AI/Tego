// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/test/perf"
)

// nameFake answers the name check's runs: a set run's figures are its clear figures plus the name check's cost
// (miss +20 ns, lead +150, rename +900, a late file refused 600 over its control and 1,800 deep), with a round's
// noise on every figure, and its fill 3 ms over the clear contract's. A set run fails unless the late files and the
// gate exist when it ends.
func nameFake(t *testing.T, s *suite) (launched *[]spec) {
	t.Helper()
	var specs []spec
	n := 0
	sample := func(sp spec) *run {
		n++
		noise := float64(n % 3)
		r := goodSample()
		r.up = time.Duration(40+n%2) * time.Millisecond
		r.res = map[string]float64{"up": 1, "open_0": 1000 + noise, "open_1": 1010 + noise, "rename_0": 3000 + noise}
		r.phases["prepare.fill"] = 10
		if !sp.noBuiltIn {
			r.up += 2 * time.Millisecond
			r.res["open_0"] += 20
			r.res["open_1"] += 150
			r.res["rename_0"] += 900
			r.res["open_2"], r.res["open_3"] = 1500+noise, 2100+noise
			r.res["open_4"], r.res["open_5"] = 1500+noise, 3300+noise
			if len(sp.denyRead) > 0 {
				r.phases["prepare.fill"] = 13
			}
		}
		return r
	}
	s.oneRun = func(sp spec) (*run, error) {
		specs = append(specs, sp)
		return sample(sp), nil
	}
	s.launchRun = func(sp spec) (*run, error) {
		specs = append(specs, sp)
		r := sample(sp)
		r.upCh, r.done = make(chan struct{}), make(chan struct{})
		close(r.upCh)
		close(r.done)
		r.cleanup = func() {
			for _, f := range append(nameLate(), nameGate) {
				if _, err := os.Stat(filepath.Join(s.proj, f)); err != nil {
					delete(r.res, "open_5")
					t.Errorf("released before %s existed: %v", f, err)
				}
			}
		}
		return r, nil
	}
	return &specs
}

// TestNameCheckFiguresAreSetOverClearMedians (ADR 0043 C10): each plane mode's name figures are the median of the
// set runs over the median of the clear runs (miss, lead, rename), or a late file's refusal over its control in the
// same run (refused, deep); the warm start's is the best set start over the best clear one, and fill.name the set
// fill over the clear fill. The set contract carries the built-in list and the refused pairs, the clear one writes
// deny_read: [], and the check leaves no file of its own behind.
func TestNameCheckFiguresAreSetOverClearMedians(t *testing.T) {
	s, out := samplingSuite(t)
	specs := nameFake(t, s)
	s.nameCheck()
	if s.failed {
		t.Fatalf("the name check failed:\n%s", out)
	}
	for _, m := range perf.Modes[1:] {
		for name, want := range map[string]float64{"open.name.miss": 20, "open.name.lead": 150, "rename.dir": 900,
			"open.name.refused": 600, "open.name.refused.deep": 1800} {
			if v := s.got[name+"."+m.Name+"_ns"]; v != want {
				t.Errorf("%s.%s = %v, want %v", name, m.Name, v, want)
			}
		}
		if v := s.got["start.name."+m.Name+".excess_ms"]; v != 2 {
			t.Errorf("start.name.%s = %v, want 2 ms", m.Name, v)
		}
	}
	if v := s.got["fill.name.ms"]; v != 3 {
		t.Errorf("fill.name.ms = %v, want 3", v)
	}
	var set, clear, fill int
	for _, sp := range *specs {
		c := s.contract(sp)
		switch {
		case len(sp.denyRead) > 0:
			fill++
			if strings.Count(c, "secretkey") != nameDeclared || !strings.Contains(c, `"./out/s6/*/secretkey06.pem"`) {
				t.Errorf("the fill contract's globs:\n%s", c)
			}
		case sp.noBuiltIn:
			clear++
			if !strings.Contains(c, "  deny_read: []\n") || slices.Contains(sp.args, "-gate") {
				t.Errorf("a clear run:\n%s", c)
			}
		default:
			set++
			if strings.Contains(c, "deny_read") || !slices.Contains(sp.args, "-gate") ||
				!slices.Contains(sp.args, "!"+filepath.Join(nameDeep(), ".env.local")) || sp.record != "off" {
				t.Errorf("a set run %v:\n%s", sp.args, c)
			}
		}
	}
	if want := *rounds * (len(perf.Modes) - 1); set != want || clear != want+3 || fill != 3 {
		t.Errorf("%d set, %d clear and %d fill runs, want %d, %d (three of them fill's) and 3", set, clear, fill, want, want+3)
	}
	if got := strings.Count(nameDeep(), string(filepath.Separator)) + 1; got != nameDeepLevels {
		t.Errorf("the deep directory is %d levels below the project, want %d", got, nameDeepLevels)
	}
	for _, f := range []string{".envrc", "out/a/b/.env.prod", "out/n01", "out/r1", "out/s0", nameGate, nameLate()[0]} {
		if _, err := os.Stat(filepath.Join(s.proj, f)); !os.IsNotExist(err) {
			t.Errorf("%s is left behind: %v", f, err)
		}
	}
	if !strings.Contains(out.String(), "name-fill") {
		t.Errorf("no name-fill record:\n%s", out)
	}
}

// TestNameCheckFailsWithoutEveryFigure: a set run whose refused loop printed nothing (an open that was let through
// ends openbench) fails the check, and the missing figure is not judged as a value.
func TestNameCheckFailsWithoutEveryFigure(t *testing.T) {
	s, out := samplingSuite(t)
	nameFake(t, s)
	launch := s.launchRun
	s.launchRun = func(sp spec) (*run, error) {
		r, err := launch(sp)
		if sp.mode.Name == "bpflsm" {
			delete(r.res, "open_3")
		}
		return r, err
	}
	s.nameCheck()
	if !s.failed || !strings.Contains(out.String(), "name-fail") {
		t.Fatalf("a set run without its refused figure passed:\n%s", out)
	}
	if _, ok := s.got["open.name.refused.bpflsm_ns"]; ok {
		t.Error("a figure with missing samples was recorded")
	}
	text, failed := s.report(budgetsFor("name", perf.Modes)), s.failed
	if !text || !failed {
		t.Error("the report passed a check with a missing figure")
	}
}

// TestNameBudgetsBelongToTheNameCheck: every C10 budget is judged only when the name check ran.
func TestNameBudgetsBelongToTheNameCheck(t *testing.T) {
	bs := budgetsFor("name", perf.Modes)
	if len(bs) != 6*(len(perf.Modes)-1)+1 {
		t.Fatalf("%d name budgets: %v", len(bs), bs)
	}
	for _, b := range bs {
		if checkOf(b.Name) != "name" || (b.Report && b.Target == 0) {
			t.Errorf("budget %+v", b)
		}
	}
	for _, other := range []string{"open.excess.bpflsm_ns", "fill.rows1000.ms", "start.warm.bpflsm.min_ms"} {
		if checkOf(other) == "name" {
			t.Errorf("%s belongs to the name check", other)
		}
	}
}

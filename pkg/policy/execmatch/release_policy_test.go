// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	compare "github.com/attention-span-ai/tego/test/execmatchdiff"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestReleaseFloorRetainsNpmDecisions(t *testing.T) {
	for _, c := range []struct {
		rule string
		argv []string
		want string
	}{
		{"allow: npm access --all", []string{"npm", "--call", "--all", "access", "operand"}, "refused exec.args[npm]"},
		{"deny: npm access --all", []string{"npm", "--browser", "--all", "access", "operand"}, "refused exec.deny[npm access --all]"},
		{"ask: npm access --all", []string{"npm", "--browser", "--all", "access", "operand"}, "refused exec.ask[npm access --all]"},
		{"allow: npm audit", strings.Fields("npm --searchexclude=x -a --ci-name=x --searchexclude --init-author-url=x -- audit --audit=x --install-strategy=x"), "refused exec.args[npm]"},
	} {
		if got := decide(index(t, c.rule), c.argv...); got != c.want {
			t.Errorf("%s %q: %s, want %s", c.rule, c.argv, got, c.want)
		}
	}
}

func TestReleaseFloorRetainsPatternPrefixHold(t *testing.T) {
	for _, list := range []string{"deny", "ask"} {
		ix := index(t, list+": systemctl -- reboot")
		prefix := execmatch.Facts{Requested: "systemctl", Image: "systemctl", Argv0: "systemctl", Argv: []string{"systemctl", "start"}}
		if r := ix.Decide(&prefix); r.Final && r.Outcome != execmatch.OutcomeRefused {
			t.Errorf("%s compatibility operand could arrive later: %+v", list, r)
		}
		prefix.Argv = append(prefix.Argv, "reboot")
		prefix.ArgvComplete = true
		if r := ix.Decide(&prefix); r.Outcome != execmatch.OutcomeRefused {
			t.Errorf("%s lost compatibility refusal: %+v", list, r)
		}
	}
	ix := index(t, "allow: systemctl -- reboot")
	prefix := execmatch.Facts{Requested: "systemctl", Image: "systemctl", Argv0: "systemctl", Argv: []string{"systemctl", "reboot", "reboot"}}
	if r := ix.Decide(&prefix); r.Final && r.Outcome != execmatch.OutcomeRefused {
		t.Errorf("compatibility allow operand could stop matching later: %+v", r)
	}
	prefix.Argv = append(prefix.Argv, "extra")
	prefix.ArgvComplete = true
	if r := ix.Decide(&prefix); r.Outcome != execmatch.OutcomeRefused {
		t.Errorf("extended compatibility allow must refuse: %+v", r)
	}
}

func TestReleaseFloorRejectsUncompilableAllow(t *testing.T) {
	for _, option := range []string{"--tag", "--registry", "--cache", "--prefix"} {
		entry := "npm " + option + " -- install --future"
		if _, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin()); err == nil || !strings.Contains(err.Error(), entry) || !strings.Contains(err.Error(), "without --") {
			t.Errorf("%q needs actionable retained-parser diagnostic: %v", entry, err)
		}
		for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk} {
			p, err := execmatch.Parse(entry, list, rows.Builtin())
			if err != nil {
				t.Fatal(err)
			}
			ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{})
			argv := strings.Fields(entry)
			f := execmatch.Facts{Requested: "npm", Image: "npm", Argv0: "npm", Argv: argv, ArgvComplete: true}
			if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
				t.Errorf("%s %q: %+v", list, entry, r)
			}
		}
	}
}

func TestMaximumArgvDecisionCost(t *testing.T) {
	ix := index(t, "allow: npm install --global")
	for _, n := range []int{4096, 8192} {
		argv := []string{"npm", "--tag", "--global", "install"}
		for len(argv) < n {
			argv = append(argv, "--")
		}
		bytes := 0
		for _, w := range argv {
			bytes += len(w) + 1
		}
		argv[len(argv)-1] += strings.Repeat("x", (128<<10)-bytes)
		f := execmatch.Facts{Requested: "npm", Image: "npm", Argv0: "npm", Argv: argv, ArgvComplete: true}
		if invs := ix.Interpretations(&f); len(invs) == 0 || ix.Patterns()[0].Match(&invs[0]) != execmatch.MatchDefinite {
			t.Fatal("cost vector no longer exercises a reader disagreement")
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		allocs := testing.AllocsPerRun(1, func() {
			if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
				t.Fatalf("maximum argv admitted: %+v", r)
			}
		})
		runtime.ReadMemStats(&after)
		t.Logf("whole decision args=%d bytes=%d allocs=%.0f allocated=%d two-calls=%s", n, 128<<10, allocs, after.TotalAlloc-before.TotalAlloc, time.Since(start))
		if after.TotalAlloc-before.TotalAlloc > uint64(64*((128<<10)+n*16)) {
			t.Errorf("nonlinear decision bytes: %d", after.TotalAlloc-before.TotalAlloc)
		}
		if allocs > float64(n*4+1024) {
			t.Errorf("nonlinear decision allocation: %.0f allocations for %d arguments", allocs, n)
		}
	}
}

func TestRetainedPatternUsesItsOwnDashMetadata(t *testing.T) {
	const entry = "npm --tag -- install ---force"
	argv := strings.Fields("npm --tag -- install --force")
	for _, list := range []string{"deny", "ask"} {
		if !compare.ReleasedRefuses(entry, list, argv) {
			t.Fatalf("frozen released %s control does not refuse", list)
		}
		if got := decide(index(t, list+": "+entry), argv...); got != "refused exec."+list+"["+entry+"]" {
			t.Errorf("%s lost retained dash reading: %s", list, got)
		}
	}
}

func TestHelperClosureNeedsBothPatternPaths(t *testing.T) {
	row := &execmatch.Row{Tool: "tool", Root: &execmatch.Level{Syntax: execmatch.Syntax{Terminator: execmatch.TerminatorCommand}, Subs: map[string]*execmatch.Level{"run": {}, "helper": {}}}, Closure: map[string][]string{"run": {"helper"}}}
	const entry = "tool -- run"
	argv := []string{"tool", "helper"}
	if !compare.ReleasedRowRefuses(row, entry, argv) {
		t.Fatal("frozen row helper control did not refuse")
	}
	rs := execmatch.NewRows(row)
	p, err := execmatch.Parse(entry, execmatch.ListAllow, rs)
	if err != nil {
		t.Fatal(err)
	}
	ix := execmatch.NewIndex(rs, []*execmatch.Pattern{p}, execmatch.IndexOptions{})
	f := execmatch.Facts{Requested: "tool", Image: "tool", Argv0: "tool", Argv: argv, ArgvComplete: true}
	if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
		t.Fatalf("helper acquired an allowance from one pattern path: %+v", r)
	}
}

func TestReleaseFloorPreservesGlobAdmission(t *testing.T) {
	const entry = "git *[dg]"
	argv := strings.Fields("git -c help.autocorrect=immediate staeg")
	if compare.ReleasedRefuses(entry, "allow", argv) {
		t.Fatal("frozen released glob control no longer admits")
	}
	if got := decide(index(t, "allow: "+entry), argv...); !strings.HasPrefix(got, "allowed ") {
		t.Fatalf("released glob admission was lost: %s", got)
	}
}

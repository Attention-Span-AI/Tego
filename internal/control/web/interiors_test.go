// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

func TestContractsListAndRuleRecovery(t *testing.T) {
	f := newRulesFix(t)
	_, list := f.get(t, "/rules")
	for _, want := range []string{`class="phone-row contract-row"`, "rules-demo", "other-agent", "2 rules files", `href="/rules?c=`} {
		if !strings.Contains(list, want) {
			t.Errorf("list lacks %q", want)
		}
	}
	_, detail := f.get(t, "/rules?run="+rulesRunA)
	for _, want := range []string{`class="phone-cell"`, "Rules file details and other runs", "exceptions named below", `/rules?run=` + rulesRunA + `&amp;rule=exec%5Bgit%5D`} {
		if !strings.Contains(detail, want) {
			t.Errorf("contract lacks %q", want)
		}
	}
	code, rule := f.get(t, "/rules?run="+rulesRunA+"&rule=exec%5Bgit%5D")
	for _, want := range []string{"What does this rule do?", "Can run git", "Exact target", "Rule key", "exec[git]", "Source", "Exact rules file text and compiled rules", "matching event"} {
		if !strings.Contains(rule, want) {
			t.Errorf("rule lacks %q", want)
		}
	}
	if code != http.StatusOK || strings.Contains(rule, rulesCanary) {
		t.Error("rule response failed or exposed a secret")
	}
	if code, _ := f.get(t, "/rules?run="+rulesRunA+"&rule=missing"); code != http.StatusNotFound {
		t.Errorf("unknown rule: %d", code)
	}
	if strings.Contains(detail, "cannot be changed unnoticed") {
		t.Error("record copy promises unqualified tamper detection")
	}
	if strings.Contains(detail, "kernel unless noted") {
		t.Error("Basic contract implies kernel enforcement for every rule")
	}
}

func TestGlossaryNativeSearchAndAliases(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	for _, path := range []string{"/glossary?q=fence", "/glossary?q=NO-SUCH-TERM"} {
		b := get(t, s, c, path)
		if !strings.Contains(b, `method="get"`) || !strings.Contains(b, `name="q"`) || !strings.Contains(b, "Clear search") {
			t.Error("search lacks native recovery")
		}
		if strings.Contains(path, "NO-SUCH") && !strings.Contains(b, "No definition matches") {
			t.Error("missing empty state")
		}
	}
	b := get(t, s, c, "/glossary")
	for _, id := range []string{"policy", "blocked", "basic", "fence", "mcp", "model-route", "watched", "passed-through"} {
		if !strings.Contains(b, `id="`+id+`"`) {
			t.Errorf("missing anchor %s", id)
		}
	}
}

func TestMachineHistoryUsesOnlyExactRuns(t *testing.T) {
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			root := t.TempDir()
			at := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
			finishRun(t, root, harmRun,
				line(harmRun, "machine-history", 0, at, "run_start", `"tier":"`+tier+`","command":["sh"]`),
				line(harmRun, "machine-history", 1, at.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`))
			s := newServer(t, root)
			body := get(t, s, login(t, s), "/machine")
			for _, level := range []string{"landlock", "cgroup", "bpflsm"} {
				start := strings.Index(body, `id="check-`+level+`"`)
				if start < 0 {
					t.Fatalf("missing protection check %s", level)
				}
				summary := body[start:]
				end := strings.Index(summary, "</summary>")
				if end < 0 {
					t.Fatalf("missing protection summary %s", level)
				}
				want := "Not checked"
				if level == tier {
					want = "Used before"
				}
				if !strings.Contains(summary[:end], ">"+want+"</span>") {
					t.Errorf("%s with only a %s run: want %q in summary %s", level, tier, want, summary[:end])
				}
			}
		})
	}
}

func TestRecoveryPagesHaveMainHeading(t *testing.T) {
	s := newServer(t, fixture(t))
	s.cfg.Preview = true
	c := login(t, s)
	for _, path := range []string{"/no-such-page", "/deployments", "/people"} {
		b := do(s, "GET", path, "127.0.0.1:8484", c).Body.String()
		if !strings.Contains(b, "<h1>") || !strings.Contains(b, "Back to the overview") {
			t.Errorf("%s lacks heading or recovery", path)
		}
	}
	for _, page := range []string{signedOutPage, signedOutCodePage} {
		for _, want := range []string{"Open your dashboard safely", "tego dashboard", `class="mark" aria-hidden="true"`, "width:32px;height:32px;background:var(--fg)", "28px", "#FBFAF8", "#0F121F"} {
			if !strings.Contains(page, want) {
				t.Errorf("signed-out lacks %q", want)
			}
		}
	}
}

func TestLiveRuleDetailKeepsExactRemoval(t *testing.T) {
	f := newRulesFix(t)
	if _, err := liveblock.Update(context.Background(), filepath.Join(f.root, rulesRunB), rulesRunB, func(o *liveblock.Overlay) (bool, error) {
		_, ok, err := o.Add(liveblock.KindExec, "/usr/bin/curl", "uid:1000 pid:42 dashboard", time.Now())
		return ok, err
	}); err != nil {
		t.Fatal(err)
	}
	code, body := f.get(t, "/rules?run="+rulesRunB+"&rule=live.block%5Bexec%3A%2Fusr%2Fbin%2Fcurl%5D")
	if code != http.StatusOK {
		t.Fatalf("live rule detail: %d", code)
	}
	for _, want := range []string{"/usr/bin/curl", `action="/runs/` + rulesRunB + `/unblock"`, `name="kind" value="exec"`, `name="value" value="/usr/bin/curl"`, `name="csrf" value="` + f.s.csrf + `"`, `name="back" value="/rules?run=` + rulesRunB + `"`, `data-page>Remove this live block`} {
		if !strings.Contains(body, want) {
			t.Errorf("live detail lacks %q", want)
		}
	}
}

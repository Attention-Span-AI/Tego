// SPDX-License-Identifier: Apache-2.0

package execmatchdiff_test

import (
	"math/rand"
	"os"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
)

// TestReconciliationReleasedComparison keeps the matchfix inputs beside the
// separator/value matrices. The long runner also observes the original complete
// generators in their own package, including private identity and loader facts.
func TestReconciliationReleasedComparison(t *testing.T) {
	counts := map[string]int{}
	for _, complete := range []bool{false, true} {
		for _, option := range []string{"--no-f", "--no-force", "--no-f=true", "--no-force=true"} {
			const entry = "git add --no-f"
			if _, err := old.Parse(entry, old.ListAllow, oldrows.Builtin()); err == nil {
				t.Fatal("released-invalid allow unexpectedly compiles")
			}
			p, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin())
			if err != nil {
				t.Fatal(err)
			}
			ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{})
			f := routeFacts("git", []string{"add", option}, 0)
			f.ArgvComplete = complete
			if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeAllowed {
				t.Fatalf("named exception %s/%v: %+v", option, complete, r)
			}
			counts["named-invalid-allow-keys"]++
		}
	}
	for _, target := range []struct{ verb, typo string }{{"add", "staeg"}, {"init", "init-bd"}, {"fsck", "fsck-objecst"}, {"blame", "pickxae"}, {"widget", "widgte"}} {
		for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk, execmatch.ListAllow} {
			p := newPair(t, "git "+target.verb, list)
			candidates := append(slices.Clone(rows.Builtin().Lookup("git").Builtins), "widget")
			p.sourceCandidates = candidates
			np, _ := execmatch.Parse(p.entry, list, rows.Builtin())
			op, _ := old.Parse(p.entry, old.List(list), oldrows.Builtin())
			p.new = execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{np}, execmatch.IndexOptions{Candidates: execmatch.NewCandidates(candidates, nil)})
			p.old = old.NewIndex(oldrows.Builtin(), []*old.Pattern{op}, old.IndexOptions{Candidates: old.NewCandidates(candidates, nil)})
			for route := 0; route < 4; route++ {
				checkPair(t, p, routeFacts("git", []string{target.typo}, route), counts)
			}
		}
	}
	rng := rand.New(rand.NewSource(0x48142026))
	generated := 1024
	if os.Getenv("TEGO_EXECMATCH_LONG") == "1" {
		generated = 200000
	}
	var pairs []pair
	for _, entry := range []string{"git push ---force", "git add --no-force", "git status", "systemctl -- reboot", "go version", "npm install --global", "cargo build", "systemctl reboot", "pip install", "aws s3 rm"} {
		for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk, execmatch.ListAllow} {
			if _, err := execmatch.Parse(entry, list, rows.Builtin()); err == nil {
				pairs = append(pairs, newPair(t, entry, list))
			}
		}
	}
	words := []string{"--", "x", "--unknown", "", "--force", "--global", "--tag", "--browser", "push", "add", "status", "install", "view", "start", "reboot", "s3", "rm", "---force"}
	for i := 0; i < generated; i++ {
		p := pairs[i%len(pairs)]
		tool := p.new.Patterns()[0].Tool
		var toks []string
		for n := rng.Intn(8); n > 0; n-- {
			toks = append(toks, words[rng.Intn(len(words))])
		}
		f := routeFacts(tool, toks, i%4)
		f.ArgvComplete = i%2 == 0
		checkPair(t, p, f, counts)
	}
	logCounts(t, counts)
}

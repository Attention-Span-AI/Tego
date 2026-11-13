// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// TestTighteningOnly supplies deterministic row-derived inputs to the retained
// before/after overlay check (scripts/check-execmatch-tightening.py). Its ordinary
// run also checks that the guard cannot skip a refusal or an unfinished decision.
// The overlay observes every Decide call in this package and rows, including
// their existing tests and fuzz seeds, rather than duplicating those corpora.
func TestTighteningOnly(t *testing.T) {
	rng := rand.New(rand.NewSource(0x48142026))
	type vocabulary struct {
		row     *execmatch.Row
		words   []string
		indexes []*execmatch.Index
	}
	var vocab []vocabulary
	for _, r := range rows.Builtin().All() {
		set := map[string]bool{"--": true, "x": true, "--unknown": true, "": true}
		var paths []string
		var walk func(*execmatch.Level, []string)
		walk = func(lv *execmatch.Level, path []string) {
			if lv == nil {
				return
			}
			for _, o := range lv.Opts {
				for _, n := range o.Long {
					set["--"+n] = true
				}
				for _, c := range o.Short {
					set["-"+string(c)] = true
				}
				for _, v := range o.Values {
					set[v] = true
				}
			}
			for a := range lv.Alias {
				set[a] = true
			}
			names := make([]string, 0, len(lv.Subs))
			for n := range lv.Subs {
				names = append(names, n)
			}
			slices.Sort(names)
			for _, n := range names {
				set[n] = true
				p := append(slices.Clone(path), n)
				paths = append(paths, strings.Join(p, " "))
				walk(lv.Subs[n], p)
			}
		}
		walk(r.Root, nil)
		words := make([]string, 0, len(set))
		for w := range set {
			words = append(words, w)
		}
		slices.Sort(words)
		if len(paths) == 0 {
			paths = []string{"x"}
		}
		v := vocabulary{row: r, words: words}
		// Independent lists, including constrained allows, for every tool row.
		for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk, execmatch.ListAllow} {
			var ps []*execmatch.Pattern
			for j := 0; j < len(paths) && j < 3; j++ {
				p, err := execmatch.Parse(r.Tool+" "+paths[j], list, rows.Builtin())
				if err != nil {
					t.Fatal(err)
				}
				ps = append(ps, p)
			}
			v.indexes = append(v.indexes, execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{Identities: map[execmatch.ID]string{{Dev: 1, Ino: 1}: r.Tool}}))
		}
		vocab = append(vocab, v)
	}
	var special []*execmatch.Index
	for _, pair := range []struct{ target, typo string }{{"add", "staeg"}, {"init", "init-bd"}, {"fsck", "fsck-objecst"}, {"blame", "pickxae"}} {
		special = append(special, index(t, "deny: git "+pair.target), index(t, "ask: git "+pair.target), index(t, "allow: git "+pair.typo))
	}
	generated := 1024
	if os.Getenv("TEGO_EXECMATCH_LONG") == "1" {
		generated = 200000
	}
	seen := make(map[[32]byte]bool, generated)
	attempted := 0
	for i := 0; len(seen) < generated; i++ {
		if i >= generated*10 {
			t.Fatal("row vocabulary did not produce enough distinct inputs")
		}
		attempted++
		v := vocab[i%len(vocab)]
		tool := v.row.Tool
		ix := v.indexes[(i/len(vocab))%len(v.indexes)]
		argv := []string{tool}
		for n := rng.Intn(10); n > 0; n-- {
			argv = append(argv, v.words[rng.Intn(len(v.words))])
		}
		f := execmatch.Facts{Requested: tool, Image: tool, Argv0: tool, Argv: argv, ArgvComplete: rng.Intn(2) == 0, NodeVersion: "20.19.4"}
		switch (i / len(vocab)) % 10 {
		case 1:
			f.Requested = "x"
			f.Image = "x"
			f.Argv0 = ""
		case 2:
			f.Requested = "x"
			f.Image = "x"
			f.Argv0 = "/usr/bin/" + tool
		case 3:
			f.Requested = "x"
			f.Image = "x"
			f.Argv0 = ""
			f.HasID = true
			f.ID = execmatch.ID{Dev: 1, Ino: 1}
		case 4:
			f.Form = execmatch.FormScript
			f.Requested = "script"
			f.Image = "script"
			f.Argv0 = "script"
			f.Path = "/w/script"
			f.Interp = []execmatch.Stage{{Path: "/usr/bin/" + tool, Image: tool}}
		case 5:
			f.Links = 116
			f.Image = "coreutils"
			f.Requested = "x"
			f.Argv0 = "myutils"
			f.Argv = append([]string{"myutils", tool}, argv[1:]...)
		case 6:
			raw := append([]string{"ld.so", "--argv0", "", "/usr/bin/" + tool}, argv[1:]...)
			at, prog, out := execmatch.LoaderProgram(raw)
			if out != execmatch.LoaderRuns {
				t.Fatal(out)
			}
			f.Requested = "ld.so"
			f.Image = "ld.so"
			f.Argv0 = "ld.so"
			f.Argv = raw
			f.Loaded = &execmatch.Loaded{Path: raw[at], Image: tool, Argv: prog, NodeVersion: f.NodeVersion}
		case 7:
			f.Form = execmatch.FormUnknown
		case 8:
			ix = special[(i/len(vocab))%len(special)]
			typo := []string{"staeg", "init-bd", "fsck-objecst", "pickxae"}[(i/len(vocab)/3)%4]
			f = execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", typo}, ArgvComplete: i%2 == 0}
		case 9:
			f.Requested = "x"
			f.Image = "x"
			f.Argv0 = ""
			f.Argv[0] = "-" + tool
		}
		if i%103 == 0 {
			f = execmatch.Facts{Requested: "s", Image: "s", Argv0: "s", Argv: []string{"s"}, ArgvComplete: i%2 == 0, Form: execmatch.FormScript}
			for j := 0; j < 1+i%20; j++ {
				f.Interp = append(f.Interp, execmatch.Stage{Path: fmt.Sprintf("/w/a%d", j), Image: fmt.Sprintf("b%d", j)})
			}
		}

		var rules []string
		for _, p := range ix.Patterns() {
			rules = append(rules, p.Rule())
		}
		encoded, err := json.Marshal(struct {
			Rules []string
			Facts execmatch.Facts
		}{rules, f})
		if err != nil {
			t.Fatal(err)
		}
		key := sha256.Sum256(encoded)
		if seen[key] {
			continue
		}
		seen[key] = true

		r := ix.Decide(&f)
		full := execmatch.WithoutEarlyGuard(ix, &f)
		if (full.Outcome == execmatch.OutcomeRefused || !full.Final) && !ix.Guarded(&f) {
			t.Fatalf("guard skipped full decision: %+v: %+v", f, full)
		}
		if !ix.Guarded(&f) && (r.Outcome == execmatch.OutcomeRefused || !r.Final) {
			t.Fatal("unguarded result was not final")
		}
	}
	t.Logf("generated=%d distinct inputs, candidates=%d seed=0x48142026 rows=%d", len(seen), attempted, len(vocab))
}

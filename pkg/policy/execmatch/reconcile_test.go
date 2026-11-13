// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

func TestCorrectedBuiltinAliases(t *testing.T) {
	for _, c := range []struct{ alias, target, typo string }{
		{"stage", "add", "staeg"}, {"init-db", "init", "init-bd"},
		{"fsck-objects", "fsck", "fsck-objecst"}, {"fsck-objects", "fsck", "fsck-object"}, {"pickaxe", "blame", "pickxae"},
	} {
		t.Run(c.alias, func(t *testing.T) {
			got, ok := execmatch.Autocorrect(c.typo, execmatch.NewCandidates(rows.Git().Builtins, rows.Git().Common))
			if !ok || got != c.alias {
				t.Fatalf("correction = %q, %v", got, ok)
			}
			for _, list := range []string{"deny", "ask"} {
				for _, spelling := range []string{c.alias, c.target} {
					ix := index(t, list+": git "+spelling)
					for _, tok := range []string{c.alias, c.typo} {
						f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", tok, "-h"}, ArgvComplete: true}
						r := ix.Decide(&f)
						if r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec."+list+"[git "+spelling+"]" {
							t.Errorf("%s %s: %s %q", list, tok, r.Outcome, r.Rule())
						}
					}
				}
			}
			// A corrected reading never admits the token spelling by itself.
			ix := index(t, "allow: git "+c.typo)
			f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", c.typo}, ArgvComplete: true}
			if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
				t.Errorf("literal allow admitted corrected alias: %+v", r)
			}
		})
	}
}

func TestGuardArgv0Fallback(t *testing.T) {
	for _, name := range []string{"git", "/usr/bin/git", "git-push", "-git", "busybox", "python3"} {
		for _, complete := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", name, complete), func(t *testing.T) {
				ix := index(t, "deny: git push")
				argv := []string{name, "push"}
				if name == "busybox" {
					argv = []string{name, "git", "push"}
				}
				if name == "python3" {
					argv = []string{name, "git", "push"}
				}
				f := execmatch.Facts{Requested: "x", Image: "x", Argv: argv, ArgvComplete: complete}
				if !ix.Guarded(&f) {
					t.Fatal("argv[0] fallback was not guarded")
				}
				if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[git push]" {
					t.Errorf("%q: %+v", argv, r)
				}
			})
		}
	}
}

func TestLoaderExplicitEmptyArgv0(t *testing.T) {
	for _, opts := range [][]string{{"--argv0", ""}, {"--argv0="}, {"--argv0", "old", "--argv0="}, {"--argv0=old", "--argv0", ""}} {
		argv := append(append([]string{"ld.so"}, opts...), "/usr/bin/git", "status")
		i, prog, out := execmatch.LoaderProgram(argv)
		if out != execmatch.LoaderRuns || i != len(argv)-2 || !slices.Equal(prog, []string{"", "status"}) {
			t.Errorf("%q: %d %q %v", argv, i, prog, out)
		}
	}
}

func TestLoaderEmptyArgv0KeepsOperandReading(t *testing.T) {
	// git's argv[0] dispatch, and Node's raw argv[0] prescan, must both keep
	// the former operand reading as well as the loader's actual empty value.
	for _, c := range []struct {
		path, image, rule string
		args              []string
	}{
		{"/usr/bin/git-status", "git", "git status", nil},
		{"/usr/bin/reboot", "systemctl", "systemctl reboot", nil},
		{"--env-file=x", "node", "git push", []string{"-e", "0"}},
	} {
		t.Run(c.image, func(t *testing.T) {
			ix := index(t, "deny: "+c.rule)
			f := execmatch.Facts{Requested: "ld.so", Image: "ld.so", Argv0: "ld.so", ArgvComplete: true,
				Loaded: &execmatch.Loaded{Path: c.path, Image: c.image, Argv: append([]string{""}, c.args...)}}
			before := *f.Loaded
			before.Argv = append([]string{c.path}, c.args...)
			old := f
			old.Loaded = &before
			if r := ix.Decide(&old); r.Outcome != execmatch.OutcomeRefused {
				t.Fatalf("control did not refuse: %+v", r)
			}
			if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
				t.Errorf("empty argv[0] lost refusal: %+v", r)
			}
		})
	}
	// Keep the loader's former raw head in multicall interpreter scans too.
	t.Run("multicall", func(t *testing.T) {
		ix := index(t, "deny: node --version")
		f := execmatch.Facts{Requested: "ld.so", Image: "ld.so", Argv0: "ld.so", ArgvComplete: true,
			Loaded: &execmatch.Loaded{Path: "--env-file=node", Image: "ls", Links: 116, Argv: []string{""}}}
		old := f
		loaded := *f.Loaded
		loaded.Argv = []string{loaded.Path}
		old.Loaded = &loaded
		if r := ix.Decide(&old); r.Outcome != execmatch.OutcomeRefused {
			t.Fatalf("old operand control: %+v", r)
		}
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
			t.Fatalf("lost multicall operand refusal: %+v", r)
		}

	})

}

func TestDerivedSubcommandsResolveAliases(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, mode := range []string{"prefix"} {
			t.Run(fmt.Sprintf("%s/nested=%v", mode, nested), func(t *testing.T) {
				leaf := &execmatch.Level{Opts: []execmatch.Opt{{Name: "flag", Long: []string{"flag"}}}}
				lv := &execmatch.Level{Subs: map[string]*execmatch.Level{"canonical": leaf}, Alias: map[string]string{"alias": "canonical"}}
				var args []string
				lv.SubPrefix = true
				args = []string{"alia", "--flag"}
				root := lv
				want := []string{"canonical"}
				if nested {
					root = &execmatch.Level{Subs: map[string]*execmatch.Level{"parent": lv}}
					args = append([]string{"parent"}, args...)
					want = append([]string{"parent"}, want...)
				}
				row := &execmatch.Row{Tool: "tool", Root: root}
				rs := execmatch.NewNormalizer(row, nil).Normalize(args)
				if len(rs) != 1 || !slices.Equal(rs[0].Path, want) || len(rs[0].Hits) == 0 || rs[0].Hits[len(rs[0].Hits)-1].Opt == nil {
					t.Fatalf("%q: %+v", args, rs)
				}
			})
		}
	}
	for _, target := range []string{"canonical", "group canonical"} {
		t.Run("corrected/"+target, func(t *testing.T) {
			leaf := &execmatch.Level{Opts: []execmatch.Opt{{Name: "flag", Long: []string{"flag"}}}}
			root := &execmatch.Level{Subs: map[string]*execmatch.Level{"canonical": leaf}, Alias: map[string]string{"alias": "chain", "chain": target}}
			if strings.Contains(target, " ") {
				root.Subs = map[string]*execmatch.Level{"group": {Subs: map[string]*execmatch.Level{"canonical": leaf}}}
			}
			row := &execmatch.Row{Tool: "tool", Root: root, Autocorrect: true}
			nz := execmatch.NewNormalizer(row, execmatch.NewCandidates([]string{"alias"}, nil))
			direct := nz.Normalize([]string{"alias", "--flag"})
			corrected := nz.Normalize([]string{"alais", "--flag"})
			if len(direct) != 1 || len(corrected) != 2 {
				t.Fatalf("direct=%+v corrected=%+v", direct, corrected)
			}
			found := false
			for _, r := range corrected {
				if r.Corrected {
					found = true
					if !slices.Equal(r.Path, direct[0].Path) || len(r.Hits) != 1 || r.Hits[0].Opt != direct[0].Hits[0].Opt {
						t.Errorf("corrected=%+v direct=%+v", r, direct[0])
					}
				}
			}
			if !found {
				t.Fatal("correction reading missing")
			}
		})
	}

	// This subtest is replayed separately on both overlays: the surrounding
	// regressions intentionally fail on the baseline. It exercises preparation
	// and matching together, keyed by the same raw loader vector.
	t.Run("loader-corpus", func(t *testing.T) {
		for _, c := range []struct {
			path, image, rule string
			args              []string
			links             uint64
		}{
			{"/usr/bin/git-status", "git", "git status", nil, 0},
			{"/usr/bin/git-stage", "git", "git add", nil, 0},
			{"/usr/bin/reboot", "systemctl", "systemctl reboot", nil, 0},
			{"--env-file=x", "node", "git push", []string{"-e", "0"}, 0},
			{"--env-file=node", "ls", "node --version", nil, 116},
		} {
			for _, list := range []string{"deny", "ask", "allow"} {
				for _, complete := range []bool{false, true} {
					ix := index(t, list+": "+c.rule)
					argv := append([]string{"ld.so", "--argv0", "", "--", c.path}, c.args...)
					at, prog, out := execmatch.LoaderProgram(argv)
					if out != execmatch.LoaderRuns {
						t.Fatal(out)
					}
					f := execmatch.Facts{Requested: "ld.so", Image: "ld.so", Argv0: "ld.so", Argv: argv, ArgvComplete: complete,
						Loaded: &execmatch.Loaded{Path: argv[at], Image: c.image, Links: c.links, Argv: prog}}
					r := ix.Decide(&f)
					want := execmatch.OutcomeRefused
					if c.links != 0 && list == "allow" {
						want = execmatch.OutcomeNone // the allow does not guard a supplied multicall reading
					}
					// The audit compares the released answers independently. Ordinary
					// tests and the new overlay must also meet these fixed outcomes.
					if os.Getenv("TEGO_EXECMATCH_SIDE") != "old" && r.Outcome != want {
						t.Errorf("%s %s complete=%v: %+v, want %s", list, c.path, complete, r, want)
					}
				}
			}
		}
	})

	t.Run("rule-corpus", func(t *testing.T) {
		for _, c := range []struct{ target, typo string }{{"add", "staeg"}, {"init", "init-bd"}, {"fsck", "fsck-objecst"}, {"blame", "pickxae"}} {
			for _, contract := range [][]string{
				{"deny: git " + c.target}, {"ask: git " + c.target}, {"allow: git " + c.typo},
				{"allow: git status", "deny: git " + c.target}, {"allow: git status", "ask: git " + c.target},
				{"allow: git", "deny: git " + c.target}, {"allow: git " + c.target},
			} {
				ix := index(t, contract...)
				for _, token := range []string{c.typo, c.typo + "\xff"} {
					for _, complete := range []bool{false, true} {
						f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", token}, ArgvComplete: complete}
						r := ix.Decide(&f)
						if os.Getenv("TEGO_EXECMATCH_SIDE") != "old" && r.Outcome != execmatch.OutcomeRefused {
							t.Errorf("%v token=%q complete=%v: %+v", contract, token, complete, r)
						}
					}
				}
			}
		}
	})

	t.Run("nested-correction-stays-root-only", func(t *testing.T) {
		child := &execmatch.Level{Subs: map[string]*execmatch.Level{"canonical": {}}, Alias: map[string]string{"alias": "canonical"}}
		row := &execmatch.Row{Tool: "tool", Autocorrect: true, Root: &execmatch.Level{Subs: map[string]*execmatch.Level{"parent": child}}}
		nz := execmatch.NewNormalizer(row, execmatch.NewCandidates([]string{"alias"}, nil))
		for _, c := range []struct{ token, want string }{{"alias", "canonical"}, {"alais", "alais"}} {
			rs := nz.Normalize([]string{"parent", c.token})
			if len(rs) != 1 || rs[0].Corrected || !slices.Equal(rs[0].Path, []string{"parent", c.want}) {
				t.Fatalf("%s: %+v", c.token, rs)
			}
		}
	})

}

func TestPatternTotalWordBoundary(t *testing.T) {
	for _, n := range []int{32, 33, 34} {
		entry := "tool" + strings.Repeat(" x", n-1)
		_, err := execmatch.Parse(entry, execmatch.ListDeny, rows.Builtin())
		if (err == nil) != (n <= 33) {
			t.Errorf("%d total words: %v", n, err)
		}
	}
}

// Every configured default and option-driven subcommand is walked at every
// level, including interpreter fallbacks. The released rows use canonical
// targets here; custom alias targets are exercised above.
func TestDerivedRowTargets(t *testing.T) {
	levels, defaults, options, prefixes, corrections := 0, 0, 0, 0, 0
	var walk func(string, *execmatch.Level, []execmatch.Opt)
	walk = func(tool string, lv *execmatch.Level, inherited []execmatch.Opt) {
		if lv == nil {
			return
		}
		levels++
		check := func(target string) {
			t.Helper()
			if _, ok := lv.Subs[target]; !ok {
				t.Errorf("%s: configured derived name %q is not canonical", tool, target)
			}
			if _, ok := lv.Alias[target]; ok {
				t.Errorf("%s: derived name %q is also an alias", tool, target)
			}
			if lv.Fold != nil && lv.Fold(target) != target {
				t.Errorf("%s: derived name %q changes under direct-name folding", tool, target)
			}
		}
		if lv.Default != "" {
			defaults++
			check(lv.Default)
		}
		for _, o := range lv.Opts {
			if o.AsSub != "" {
				options++
				check(o.AsSub)
			}
		}
		// A persistent parent's option is resolved against the current level,
		// not its defining level. Check that alias-sensitive route too.
		for _, o := range inherited {
			if o.AsSub != "" && lv.Subs != nil {
				if _, canonical := lv.Subs[o.AsSub]; !canonical {
					if _, alias := lv.Alias[o.AsSub]; alias {
						t.Errorf("%s: inherited AsSub %q needs alias resolution", tool, o.AsSub)
					}
				}
			}
		}
		persistent := slices.Clone(inherited)
		for _, o := range lv.Opts {
			if o.Persistent {
				persistent = append(persistent, o)
			}
		}
		if lv.SubPrefix {
			prefixes++
		}
		names := make([]string, 0, len(lv.Subs))
		for n := range lv.Subs {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			walk(tool+" "+n, lv.Subs[n], persistent)
		}
		if lv.Wild != nil {
			walk(tool+" *", lv.Wild, persistent)
		}
	}
	for _, r := range rows.Builtin().All() {
		if r.Autocorrect {
			corrections++
			if r.Tool != "git" {
				t.Errorf("new correction row needs audit: %s", r.Tool)
			}
		}
		walk(r.Tool, r.Root, nil)
		if r.Interp != nil && r.Interp.Fallback != nil {
			walk(r.Tool+" fallback", r.Interp.Fallback.Root, nil)
		}
	}
	if corrections != 1 || defaults == 0 || options == 0 || prefixes == 0 {
		t.Fatal("derived-name inventory unexpectedly empty")
	}
	t.Logf("levels=%d defaults=%d option targets=%d prefix levels=%d correction rows=%d", levels, defaults, options, prefixes, corrections)
}

func TestGuardInterpretationBound(t *testing.T) {
	ix := index(t, "deny: git push")
	f := execmatch.Facts{Requested: "s", Image: "s", Argv0: "s", Argv: []string{"s"}, ArgvComplete: true, Form: execmatch.FormScript}
	for i := 0; i < 20; i++ {
		f.Interp = append(f.Interp, execmatch.Stage{Path: fmt.Sprintf("/w/a%d", i), Image: fmt.Sprintf("b%d", i)})
	}
	full := execmatch.WithoutEarlyGuard(ix, &f)
	if !full.Overflow || full.Outcome != execmatch.OutcomeRefused {
		t.Fatalf("control did not overflow: %+v", full)
	}
	if !ix.Guarded(&f) {
		t.Fatal("guard skipped full interpretation overflow")
	}
	if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || !r.Overflow || r.Rule() != execmatch.RuleCommandUnresolved {
		t.Errorf("full overflow was not applied: %+v", r)
	}
}

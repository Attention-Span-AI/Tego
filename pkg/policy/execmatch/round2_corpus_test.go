// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	compare "github.com/attention-span-ai/tego/test/execmatchdiff"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// TestRound2ComparisonCorpus journals source contracts, including parse errors,
// on each frozen matcher. An invalid entry is a compile refusal, not an empty
// index. Keys contain source inputs rather than the compiled reading under test.
func TestRound2ComparisonCorpus(t *testing.T) {
	dir := os.Getenv("TEGO_EXECMATCH_JOURNAL")
	// The ordinary observer cannot journal an entry the old or new parser rejects.
	// Record this entire corpus here, including valid entries, with identical keys.
	t.Setenv("TEGO_EXECMATCH_JOURNAL", "")
	var file *os.File
	if dir != "" {
		var err error
		file, err = os.Create(filepath.Join(dir, fmt.Sprintf("round2-parse-%d.jsonl", os.Getpid())))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
	}
	id := execmatch.ID{Dev: 1, Ino: 2}
	calls := 0
	record := func(class, entry string, list execmatch.List, f execmatch.Facts, identity string, candidates []string, exact []string) {
		t.Helper()
		source := struct {
			Class, Entry      string
			List              execmatch.List
			Facts             execmatch.Facts
			Identity          string
			Candidates, Exact []string
		}{class, entry, list, f, identity, candidates, exact}
		raw, err := json.Marshal(source)
		if err != nil {
			t.Fatal(err)
		}
		key := fmt.Sprintf("%x", sha256.Sum256(raw))
		var p *execmatch.Pattern
		if exact != nil {
			p = execmatch.ExactPattern("hook", entry, exact)
		} else {
			p, err = execmatch.Parse(entry, list, rows.Builtin())
		}
		valid := err == nil
		var result execmatch.Result
		if valid {
			opts := execmatch.IndexOptions{}
			if identity != "" {
				opts.Identities = map[execmatch.ID]string{id: identity}
			}
			if candidates != nil {
				opts.Candidates = execmatch.NewCandidates(candidates, rows.Builtin().Lookup("git").Common)
			}
			result = execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, opts).Decide(&f)
		} else {
			result = execmatch.Result{Outcome: execmatch.OutcomeRefused, List: list, Final: true, K: len(f.Argv)}
		}
		if _, checkErr := compare.CheckSourceCase(entry, uint8(list), f, identity, candidates, exact, valid, uint8(result.Outcome), result.Final, uint8(result.List)); checkErr != nil {
			t.Fatal(checkErr)
		}
		rule := result.Rule()
		if !valid {
			rule = "rule-invalid"
		}
		calls++
		if file != nil {
			// Class is input metadata, so it is also checked for equality on both legs.
			err = json.NewEncoder(file).Encode(map[string]any{"Key": key, "IndexSignature": class, "Class": class, "CompileValid": valid, "Outcome": result.Outcome, "List": result.List, "Final": result.Final, "Unlisted": result.Unlisted, "Overflow": result.Overflow, "Guarded": result.Guarded, "K": result.K, "Rule": rule, "Tool": result.Tool, "Via": result.Via.String(), "Match": result.Match.String(), "Facts": f, "Patterns": []string{entry}})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	facts := func(tool string, args ...string) execmatch.Facts {
		return execmatch.Facts{Requested: tool, Image: tool, Argv0: tool, Argv: append([]string{tool}, args...), ArgvComplete: true}
	}
	for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
		for _, complete := range []bool{false, true} {
			for _, pair := range [][2]string{{"stage", "staeg"}, {"init-db", "init-bd"}, {"fsck-objects", "fsck-object"}, {"pickaxe", "pickxae"}, {"widget", "widgte"}} {
				cand := append(slices.Clone(rows.Builtin().Lookup("git").Builtins), "widget")
				for _, name := range []string{pair[0], pair[1]} {
					f := facts("git", name)
					f.ArgvComplete = complete
					for _, entry := range []string{"git " + pair[0], "git " + pair[1]} {
						record("04/correction", entry, list, f, "", cand, nil)
					}
				}
			}
			for _, entry := range []string{"git add --no-f", "git add --no-force", "git add --force"} {
				for _, option := range []string{"--no-f", "--no-force", "--force", "--no-f=true", "--no-force=true"} {
					f := facts("git", "add", option)
					f.ArgvComplete = complete
					record("14/negated-prefix", entry, list, f, "", nil, nil)
				}
			}
			for _, pair := range [][3]string{{"cargo", "+nightly", "build"}, {"cargo", "+stable", "build"}, {"gcloud", "alpha", "compute"}, {"gcloud", "beta", "compute"}} {
				for _, selector := range []string{pair[1], "other"} {
					f := facts(pair[0], selector, pair[2])
					f.ArgvComplete = complete
					record("15/selector", pair[0]+" "+pair[1]+" "+pair[2], list, f, "", nil, nil)
				}
			}
			for _, pair := range [][3]string{{"git", "push", "force"}, {"go", "test", "v"}} {
				for _, prefix := range []string{"-", "--", "---"} {
					for _, invPrefix := range []string{"-", "--", "---"} {
						for _, value := range []string{"", "=true"} {
							f := facts(pair[0], pair[1], invPrefix+pair[2]+value)
							f.ArgvComplete = complete
							record("16/introducer", pair[0]+" "+pair[1]+" "+prefix+pair[2]+value, list, f, "", nil, nil)
						}
					}
				}
			}
			for _, stage := range []bool{false, true} {
				f := facts("x", "-r")
				f.ArgvComplete = complete
				f.HasID = true
				f.ID = id
				f.Argv0 = "lt-rm"
				f.Argv[0] = "lt-rm"
				if stage {
					f = facts("script", "-r")
					f.ArgvComplete = complete
					f.Form = execmatch.FormScript
					f.Path = "script"
					f.Interp = []execmatch.Stage{{Path: "/tmp/lt-rm", Image: "x", HasID: true, ID: id}}
				}
				record("11/mapped-strip", "rm -r", list, f, "coreutils", nil, nil)
				f = facts("script")
				f.ArgvComplete = complete
				f.Form = execmatch.FormScript
				f.Path = "script"
				f.Interp = []execmatch.Stage{{Path: "/tmp/xrebootx", Image: "systemctl"}}
				record("05/stage-origin", "systemctl reboot", list, f, "", nil, nil)
			}
			f := facts("git", "push", "--force")
			f.ArgvComplete = complete
			record("07/compatibility", "git --forc push", list, f, "", nil, nil)
		}
	}
	for _, stage := range []bool{false, true} {
		for _, mapped := range []bool{false, true} {
			for _, complete := range []bool{false, true} {
				for _, arg := range []string{"-r", "--force", "x"} {
					f := facts("coreutils", arg)
					f.Argv0 = "lt-rm"
					f.Argv[0] = "lt-rm"
					identity := ""
					if mapped {
						f.Requested = "x"
						f.Image = "x"
						f.ID = id
						f.HasID = true
						identity = "coreutils"
					}
					grant := slices.Clone(f.Argv)
					if stage {
						f = facts("script")
						f.Path = "script"
						f.Form = execmatch.FormScript
						image := "coreutils"
						if mapped {
							image = "x"
						}
						f.Interp = []execmatch.Stage{{Path: "/tmp/lt-rm", Image: image, ID: id, HasID: mapped}}
						grant = []string{"script", "script"}
					}
					f.ArgvComplete = complete
					record("06/exact-strip", "rm", execmatch.ListAllow, f, identity, nil, grant)
				}
			}
		}
		f := facts("x", "list")
		f.ID = id
		f.HasID = true
		grant := []string{"x", "install"}
		if stage {
			f = facts("script")
			f.Path = "script"
			f.Form = execmatch.FormScript
			f.Interp = []execmatch.Stage{{Path: "/tmp/x", Image: "x", Arg: "install", ID: id, HasID: true}}
			grant = []string{"script", "install", "script"}
		}
		record("10/compatibility", "pip3", execmatch.ListAllow, f, "pip3", nil, grant)
	}
	for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
		for _, complete := range []bool{false, true} {
			for _, c := range [][4]string{{"cargo", "+nightly", "+stable", "build"}, {"cargo", "+stable", "+nightly", "build"}, {"gcloud", "alpha", "beta", "compute"}, {"gcloud", "beta", "preview", "compute"}} {
				f := facts(c[0], c[2], c[3])
				f.ArgvComplete = complete
				record("15/selector-cross-variant", c[0]+" "+c[1]+" "+c[3], list, f, "", nil, nil)
			}
		}
	}
	for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk} {
		for _, complete := range []bool{false, true} {
			for _, entry := range []string{"git add --no-f", "git add --no-force"} {
				for _, raw := range []string{"--n", "--no", "--no-", "-no-f", "--for", "--force"} {
					for _, before := range []bool{false, true} {
						f := facts("git", "add", raw)
						if before {
							f = facts("git", raw, "add")
						}
						f.ArgvComplete = complete
						record("14/raw-negative-ambiguity", entry, list, f, "", nil, nil)
					}
				}
			}
		}
	}

	for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
		for _, complete := range []bool{false, true} {
			for _, raw := range []string{"--for", "---for", "--f", "---f"} {
				f := facts("git", "push", raw)
				f.ArgvComplete = complete
				record("16/raw-prefix", "git push ---force", list, f, "", nil, nil)
			}
		}
	}

	for _, option := range []string{"--tag", "--cache", "--prefix", "--registry", "--browser"} {
		entry := "npm " + option + " -- install --future"
		for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
			record("retained-compile-floor", entry, list, facts("npm", option, "--", "install", "--future"), "", nil, nil)
		}
	}
	for _, option := range []string{"--tag", "--cache", "--prefix", "--registry"} {
		for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
			record("retained-pattern-dash-metadata", "npm "+option+" -- install ---force", list, facts("npm", option, "--", "install", "--force"), "", nil, nil)
		}
	}
	for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
		record("released-glob-admission-control", "git *[dg]", list, facts("git", "-c", "help.autocorrect=immediate", "staeg"), "", nil, nil)
	}
	t.Logf("round2 source contract/facts inputs=%d", calls)
}

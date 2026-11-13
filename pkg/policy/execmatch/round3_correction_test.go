// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"os"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// round3Edits enumerates one unit insertion, deletion, substitution or adjacent
// transposition over the reviewer's command-name alphabet. Autocorrect below
// applies Git's different costs (swap 0, substitute 2, insert 1, delete 3), its
// threshold, common-prefix exclusions and unique-best requirement afterwards.
func round3Edits(s string, emit func(string)) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz-"
	for i := 0; i <= len(s); i++ {
		for j := range len(alphabet) {
			emit(s[:i] + alphabet[j:j+1] + s[i:])
		}
		if i < len(s) {
			emit(s[:i] + s[i+1:])
			for j := range len(alphabet) {
				if alphabet[j] != s[i] {
					emit(s[:i] + alphabet[j:j+1] + s[i+1:])
				}
			}
		}
		if i+1 < len(s) && s[i] != s[i+1] {
			emit(s[:i] + s[i+1:i+2] + s[i:i+1] + s[i+2:])
		}
	}
}

func round3Typos(target string) map[string]uint8 {
	seen := make(map[string]uint8)
	var first []string
	round3Edits(target, func(tok string) {
		if tok != target && seen[tok] == 0 {
			seen[tok] = 1
			first = append(first, tok)
		}
	})
	for _, one := range first {
		round3Edits(one, func(tok string) {
			if tok != target && seen[tok] == 0 {
				seen[tok] = 2
			}
		})
	}
	return seen
}

func TestRound3CorrectionGenerator(t *testing.T) {
	got := round3Typos("stage")
	one := 0
	for _, edits := range got {
		if edits == 1 {
			one++
		}
	}
	// Five deletions, 5*26 substitutions, 6*27-5 distinct insertions
	// and four adjacent transpositions. The target's bytes are distinct.
	if one != 296 {
		t.Fatalf("one-edit inventory=%d, want 296", one)
	}
	for _, c := range []struct {
		token string
		edits uint8
	}{
		{"stag", 1}, {"stagex", 1}, {"stxge", 1}, {"staeg", 1},
		{"stagxx", 2}, {"stxgx", 2}, {"tasge", 2},
	} {
		if got[c.token] != c.edits {
			t.Errorf("%q: %d edits, want %d", c.token, got[c.token], c.edits)
		}
	}
	if _, ok := got["stage"]; ok {
		t.Fatal("unmodified target is not a misspelling")
	}
}

// TestRound3CorrectionSweep retains every one- and two-edit token, over a-z and
// hyphen, selected by the port for the four built-in aliases and every row-known
// external command, plus the supplied unknown helper widget. Empty tokens and
// leading dashes cannot stand as the command word and are excluded. This is finite
// edit coverage, not a fuzz or host-Git test.
func TestRound3CorrectionSweep(t *testing.T) {
	rowSet := rows.Builtin()
	row := rowSet.Lookup("git")
	if len(row.Root.Alias) != 4 {
		t.Fatal("root alias inventory changed; update the named correction targets")
	}
	builtin := execmatch.NewCandidates(row.Builtins, row.Common)
	helpers := slices.Clone(row.Builtins)
	for name := range row.Root.Subs {
		helpers = append(helpers, name)
	}
	helpers = append(helpers, "widget")
	helperInventory := execmatch.NewCandidates(helpers, row.Common)
	prefixes := [][]string{nil, {"-c", "help.autocorrect=immediate"}, {"-C", "d", "--git-dir=x", "-c", "a=b", "--no-pager"}}
	type correctionTarget struct {
		target, canonical, witness string
		helper                     bool
	}
	targets := []correctionTarget{
		{"stage", "add", "staeg", false},
		{"init-db", "init", "init-bd", false},
		{"fsck-objects", "fsck", "fsck-objecst", false},
		{"pickaxe", "blame", "pickxae", false},
		{"widget", "widget", "widgte", true},
	}
	var external []string
	for name := range row.Root.Subs {
		if !builtin.Has(name) {
			external = append(external, name)
		}
	}
	slices.Sort(external)
	for _, name := range external {
		targets = append(targets, correctionTarget{target: name, canonical: name, helper: true})
	}
	t.Logf("targets=%d (aliases=4 row external=%d unknown helper=1)", len(targets), len(external))
	for _, c := range targets {
		t.Run(c.target, func(t *testing.T) {
			// Each target owns its generated tokens, patterns and normalizer;
			// the shared row and candidate inventories are immutable. Let the
			// test runner use its bounded worker pool for the exhaustive sweep.
			t.Parallel()
			inventory := builtin
			if c.helper {
				inventory = helperInventory
				if builtin.Has(c.target) {
					t.Fatal("helper fixture must be absent from the built-in inventory")
				}
			} else if row.Root.Alias[c.target] != c.canonical {
				t.Fatal("alias fixture no longer names its canonical target")
			}
			if c.witness != "" {
				if target, ok := execmatch.Autocorrect(c.witness, inventory); !ok || target != c.target {
					t.Fatalf("witness %q corrected to %q, %v", c.witness, target, ok)
				}
			}
			deny, err := execmatch.Parse("git "+c.canonical, execmatch.ListDeny, rowSet)
			if err != nil {
				t.Fatal(err)
			}
			ask, err := execmatch.Parse("git "+c.canonical, execmatch.ListAsk, rowSet)
			if err != nil {
				t.Fatal(err)
			}
			// Once the full inventory has selected this target, a singleton
			// inventory selects it too. Its normalizer traverses the same row
			// branches without repeating an inventory-wide distance scan for
			// each grammar context and list. The witnesses below compare the
			// complete decision using the full candidate inventory as well.
			singleton := execmatch.NewCandidates([]string{c.target}, nil)
			nz := execmatch.NewNormalizer(row, singleton)
			generated := round3Typos(c.target)
			tokens := make([]string, 0, len(generated))
			for tok := range generated {
				tokens = append(tokens, tok)
			}
			slices.Sort(tokens)
			var corrected [3]int
			witnessSeen := false
			for _, tok := range tokens {
				if os.Getenv("TEGO_EXECMATCH_LONG") != "1" && corrected[1] >= 2 && corrected[2] >= 2 && witnessSeen {
					break
				}
				if tok == "" || tok[0] == '-' {
					continue
				}
				if os.Getenv("TEGO_EXECMATCH_LONG") != "1" && corrected[generated[tok]] >= 2 && tok != c.witness {
					continue
				}
				// A known row word is a direct command, not a misspelling.
				if _, known := row.Root.Subs[tok]; known {
					continue
				}
				if _, known := row.Root.Alias[tok]; known {
					continue
				}
				// A target that cannot pass the score threshold alone cannot
				// win in the full inventory. Reject it before the full scan.
				if _, ok := execmatch.Autocorrect(tok, singleton); !ok {
					continue
				}
				if target, ok := execmatch.Autocorrect(tok, inventory); !ok || target != c.target {
					continue
				}
				corrected[generated[tok]]++
				if c.witness == "" {
					c.witness = tok
				}
				witnessSeen = witnessSeen || tok == c.witness
				// This is the parsed form of an allow entry naming the
				// literal unknown word. It has no options or operands.
				allow := execmatch.Pattern{Tool: "git", Row: row, List: execmatch.ListAllow, Path: []string{tok}}
				for _, prefix := range prefixes {
					toks := append(slices.Clone(prefix), tok)
					wantHits := 0
					if len(prefix) > 0 {
						wantHits = 1
					}
					if len(prefix) > 2 {
						wantHits = 4
					}
					for _, open := range []bool{false, true} {
						rs := nz.NormalizeOpen(toks, open)
						if len(rs) != 2 {
							t.Fatalf("%q open=%v: expected literal and corrected readings: %+v", toks, open, rs)
						}
						literal, correction := false, false
						for _, r := range rs {
							want, located := []string{tok}, true
							if r.Corrected {
								want = []string{c.canonical}
								if c.target == "submodule" {
									// A complete submodule command defaults to status;
									// a prefix can still name a different operation.
									if open {
										located = false
									} else {
										want = append(want, "status")
									}
								}
								correction = true
							} else {
								literal = true
							}
							if !slices.Equal(r.Path, want) || r.Located != located || r.Unlocatable || r.UnknownBefore || len(r.Hits) != wantHits {
								t.Fatalf("%q open=%v: lost target or grammar: %+v", toks, open, r)
							}
						}
						if !literal || !correction {
							t.Fatalf("%q open=%v: literal=%v correction=%v", toks, open, literal, correction)
						}
						inv := execmatch.Invocation{Tool: "git", Row: row, Tokens: toks, Readings: rs, Open: open}
						for _, p := range []*execmatch.Pattern{deny, ask} {
							if match := p.Match(&inv); match != execmatch.MatchAmbiguous {
								t.Fatalf("%s %q open=%v: match=%s", p.List, toks, open, match)
							}
						}
						if match := allow.Match(&inv); match != execmatch.MatchNone {
							t.Fatalf("allow literal %q open=%v: match=%s", toks, open, match)
						}
					}
				}
			}
			if corrected[1] == 0 || corrected[2] == 0 || !witnessSeen {
				t.Fatalf("sweep omitted edit class or witness: %v witness=%v", corrected, witnessSeen)
			}
			t.Logf("generated=%d corrected one-edit=%d two-edit=%d grammar contexts=6 lists=3", len(generated), corrected[1], corrected[2])
			for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk, execmatch.ListAllow} {
				entry := "git " + c.canonical
				if list == execmatch.ListAllow {
					entry = "git " + c.witness
				}
				p, err := execmatch.Parse(entry, list, rowSet)
				if err != nil {
					t.Fatal(err)
				}
				ix := execmatch.NewIndex(rowSet, []*execmatch.Pattern{p}, execmatch.IndexOptions{Candidates: inventory})
				for _, prefix := range prefixes {
					argv := append(append([]string{"git"}, prefix...), c.witness)
					for _, complete := range []bool{false, true} {
						f := execmatch.Facts{Requested: "x", Image: "x", Argv: argv, ArgvComplete: complete}
						if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
							t.Fatalf("%s %q complete=%v: %+v", list, argv, complete, r)
						}
					}
				}
			}
		})
	}
}

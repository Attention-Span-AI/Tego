// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// prefixGeneric is the option-like vocabulary every row is read with: empty words, `-` and `--`, plus-forms (sh's
// +x, +c and +c0), combined short options, unknown long options with and without a value, and operands that name a
// tool a contract rules (rm) or a script path.
var prefixGeneric = []string{"", "", "-", "--", "+x", "+c", "+0", "+c0", "-c", "-e", "-x", "-0", "-cx", "-xc", "-abc",
	"-rf", "-r", "-f", "--x", "--x=1", "--zz", "x", "rm", "./rm", "a=b", "alias.x"}

// prefixRow is one row's vocabulary and the contracts it is read under; row is nil for a tool with no row (generic).
type prefixRow struct {
	tool      string
	row       *execmatch.Row
	vocab     []string
	contracts [][]string
	ixs       []*execmatch.Index
}

// prefixRows builds every built-in row's vocabulary (prefixGeneric, its first subcommand names and each spelling of its
// top-level options, up to a bound) and the contracts that parse for it: deny, ask and allow entries on the row's own
// tool, bare and with a subcommand and an operand, and deny, ask and allow entries on rm, which the interpreter and
// multicall rows dispatch to. Two tools with no row (env, mytool) are read as generic tools.
func prefixRows(t testing.TB) []prefixRow {
	t.Helper()
	var out []prefixRow
	var tools []string
	for _, r := range Builtin().All() {
		tools = append(tools, r.Tool)
	}
	for _, tool := range append(tools, "env", "mytool") {
		pr := prefixRow{tool: tool, row: Builtin().Lookup(tool), vocab: slices.Clone(prefixGeneric)}
		r := pr.row
		if r == nil {
			r = &execmatch.Row{Tool: tool}
		}
		var sub string
		if r.Root != nil && len(r.Root.Subs) > 0 {
			names := make([]string, 0, len(r.Root.Subs))
			for n := range r.Root.Subs {
				names = append(names, n)
			}
			slices.Sort(names)
			sub = names[0]
			pr.vocab = append(pr.vocab, names[:min(len(names), 6)]...)
		}
		if r.Root != nil {
			n := 0
			for _, o := range r.Root.Opts {
				special := o.Rewrite != nil || o.Stop || o.Ends || o.EndsAttached || o.AsSub != "" ||
					r.Interp != nil && (slices.Contains(r.Interp.Code, o.Name) || o.Name == r.Interp.Module ||
						slices.Contains(r.Interp.CodeUnless, o.Name) || slices.Contains(r.Interp.Preload, o.Name))
				if !special && n >= 6 {
					continue
				}
				n++
				for _, c := range []byte(o.Short) {
					pr.vocab = append(pr.vocab, "-"+string(c))
				}
				for _, l := range o.Long {
					pr.vocab = append(pr.vocab, "--"+l)
				}
			}
		}
		cands := [][]string{
			{"deny: rm -r"}, {"ask: rm"}, {"allow: rm -f", "deny: rm -r"},
			{"deny: " + tool}, {"allow: " + tool}, {"allow: " + tool, "deny: rm -r"},
			{"deny: " + tool + " x"}, {"ask: " + tool + " x"}, {"allow: " + tool + " x"},
		}
		if sub != "" {
			cands = append(cands, []string{"deny: " + tool + " " + sub}, []string{"ask: " + tool + " " + sub},
				[]string{"allow: " + tool + " " + sub}, []string{"deny: " + tool + " " + sub + " x"},
				[]string{"allow: " + tool + " " + sub + " x"}, []string{"allow: " + tool + " " + sub, "deny: rm -r"})
		}
		for _, c := range cands {
			if ix, ok := tryRules(c); ok {
				pr.contracts, pr.ixs = append(pr.contracts, c), append(pr.ixs, ix)
			}
		}
		if len(pr.ixs) < 3 {
			t.Fatalf("row %s: only %d contracts parse", tool, len(pr.ixs))
		}
		out = append(out, pr)
	}
	return out
}

// tryRules is rules without a test: false when an entry does not parse for its row (an operand the row reads as
// something else).
func tryRules(entries []string) (*execmatch.Index, bool) {
	var ps []*execmatch.Pattern
	for _, e := range entries {
		list, body, _ := strings.Cut(e, ": ")
		l := map[string]execmatch.List{"allow": execmatch.ListAllow, "deny": execmatch.ListDeny, "ask": execmatch.ListAsk}[list]
		p, err := execmatch.Parse(body, l, Builtin())
		if err != nil {
			return nil, false
		}
		ps = append(ps, p)
	}
	return execmatch.NewIndex(Builtin(), ps, execmatch.IndexOptions{}), true
}

// prefixHolds is the staged read's property (ADR 0048 (3)) for one exec: a decision made on a prefix of its argv that
// says Final and does not refuse is the whole argv's decision. A Final none or allow on a prefix ends the supervisor's
// read, so a whole argv that a rule refuses would run unread.
func prefixHolds(ix *execmatch.Index, f *execmatch.Facts) string {
	whole := ix.Decide(f)
	for k := 0; k < len(f.Argv); k++ {
		p := *f
		p.Argv, p.ArgvComplete = f.Argv[:k], false
		r := ix.Decide(&p)
		if r.Final && r.Outcome != execmatch.OutcomeRefused && (r.Outcome != whole.Outcome || r.Rule() != whole.Rule()) {
			return fmt.Sprintf("prefix of %d: %s %s Final, whole argv: %s %s", k, r.Outcome, r.Rule(), whole.Outcome, whole.Rule())
		}
	}
	return ""
}

// prefixFacts is an exec of the row's tool by name with argv[0] given and tokens after it.
func prefixFacts(tool, argv0 string, toks []string) execmatch.Facts {
	argv := append([]string{argv0}, toks...)
	return execmatch.Facts{NodeVersion: "20.19.4", Requested: tool, Path: tool, Image: tool, Argv0: argv0, Argv: argv, ArgvComplete: true}
}

// TestPrefixFinalHoldsEveryRow is prefixHolds for every built-in row under every contract prefixRows gives it, at
// every prefix length: each vector of up to two tokens of its vocabulary with argv[0] the tool's name, and 250 seeded
// vectors of up to 10 tokens, every other one with argv[0] empty. -short leaves the pairs out.
func TestPrefixFinalHoldsEveryRow(t *testing.T) {
	prs := prefixRows(t)
	rng := rand.New(rand.NewPCG(48, 3))
	checked := 0
	for _, pr := range prs {
		type vec struct {
			argv0 string
			toks  []string
		}
		var vecs []vec
		for _, a := range pr.vocab {
			vecs = append(vecs, vec{pr.tool, []string{a}})
			if testing.Short() {
				continue
			}
			for _, b := range pr.vocab {
				vecs = append(vecs, vec{pr.tool, []string{a, b}})
			}
		}
		for n := range 250 {
			v := vec{pr.tool, make([]string, 1+rng.IntN(10))}
			if n%2 == 1 {
				v.argv0 = ""
			}
			for i := range v.toks {
				v.toks[i] = pr.vocab[rng.IntN(len(pr.vocab))]
			}
			vecs = append(vecs, v)
		}
	contracts:
		for i, ix := range pr.ixs {
			for _, v := range vecs {
				f := prefixFacts(pr.tool, v.argv0, v.toks)
				if why := prefixHolds(ix, &f); why != "" {
					// The first vector per contract: one cause shows as many vectors.
					t.Errorf("row %s, %v, argv %q: %s", pr.tool, pr.contracts[i], f.Argv, why)
					continue contracts
				}
				checked++
			}
		}
	}
	t.Logf("%d tools, %d execs checked at every prefix length", len(prs), checked)
}

// TestPrefixCodeBeforeItsEnd: an interpreter that has read its code option still reads options until its first
// operand, and each option it does not list forks the readings; past MaxReadings the whole vector is refused
// command-unresolved. So a prefix that has read the code option is not final until no option can follow. The first
// vector is the one a staged-read fuzz found (2026-11-11): sh with argv[0] "", +c0, five +0 and a last empty word.
func TestPrefixCodeBeforeItsEnd(t *testing.T) {
	ix := rules(t, "deny: rm -r")
	sh := []string{"", "+c0", "+0", "+0", "+0", "+0", "+0", ""}
	q7 := []string{"-Q", "-Q", "-Q", "-Q", "-Q", "-Q", "-Q", "y"}
	cases := []execmatch.Facts{
		{Requested: "perl", Image: "perl", Argv: append([]string{"perl", "-e", "x"}, q7...)},
		{Requested: "ruby", Image: "ruby", Argv: append([]string{"ruby", "-e", "x"}, q7...)},
		{Requested: "busybox", Image: "busybox", Argv: append([]string{"busybox", "sh", "-c"}, q7...)},
	}
	for _, name := range []string{"sh", "bash", "dash", "zsh", "ksh"} {
		cases = append(cases, execmatch.Facts{Requested: name, Path: name, Image: "0", Argv: sh},
			execmatch.Facts{Requested: name, Image: name, Argv: append([]string{name, "-c"}, q7...)})
	}
	for _, f := range cases {
		f.ArgvComplete = true
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != execmatch.RuleCommandUnresolved {
			t.Errorf("%s %q: whole vector %s, want refused %s", f.Requested, f.Argv, decided(r), execmatch.RuleCommandUnresolved)
		}
		if why := prefixHolds(ix, &f); why != "" {
			t.Errorf("%s %q: %s", f.Requested, f.Argv, why)
		}
	}
}

// FuzzPrefixFinalHolds is prefixHolds over any row, contract and vector of its vocabulary (prefixRows): plan's bytes
// pick the row, the contract, argv[0] and up to 16 words.
func FuzzPrefixFinalHolds(f *testing.F) {
	prs := prefixRows(f)
	shRow := slices.IndexFunc(prs, func(pr prefixRow) bool { return pr.tool == "sh" })
	vocabAt := func(pr prefixRow, s string) byte { return byte(slices.Index(pr.vocab, s)) }
	sh := prs[shRow]
	f.Add([]byte{byte(shRow), 0, 1, vocabAt(sh, "+c0"), vocabAt(sh, "+0"), vocabAt(sh, "+0"), vocabAt(sh, "+0"),
		vocabAt(sh, "+0"), vocabAt(sh, "+0"), vocabAt(sh, "")})
	f.Add([]byte{0, 0, 0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, plan []byte) {
		if len(plan) < 3 || len(plan) > 19 {
			return
		}
		pr := prs[int(plan[0])%len(prs)]
		i := int(plan[1]) % len(pr.ixs)
		argv0 := pr.tool
		if plan[2]%2 == 1 {
			argv0 = ""
		}
		toks := make([]string, 0, len(plan)-3)
		for _, b := range plan[3:] {
			toks = append(toks, pr.vocab[int(b)%len(pr.vocab)])
		}
		fx := prefixFacts(pr.tool, argv0, toks)
		if why := prefixHolds(pr.ixs[i], &fx); why != "" {
			t.Fatalf("row %s, %v, argv %q: %s", pr.tool, pr.contracts[i], fx.Argv, why)
		}
	})
}

// firstStage cuts argv as the supervisor's first staged read does when the strings are short: 32 elements.
const firstStage = 32

// TestPrefixCutAtAValueOption: a prefix that ends where an option waits for its value has not read that value.
// python's -m cut at the end of the first stage has not read the module it runs: `python3 -W x` fifteen times, then
// `-m pip install x`, is refused under deny: pip install, and its 32-element prefix, which ends at -m, is not final.
// A bare entry on the module (deny: pip) is read the same way: python runs pip, so the entry names no program the
// image floor sees, and only the module after -m decides it.
func TestPrefixCutAtAValueOption(t *testing.T) {
	argv := []string{"python3"}
	for range 15 {
		argv = append(argv, "-W", "ignore")
	}
	argv = append(argv, "-m", "pip", "install", "x")
	for _, entry := range []string{"deny: pip install", "deny: pip", "ask: pip", "allow: pip list"} {
		ix := rules(t, entry)
		f := execmatch.Facts{Requested: "python3", Image: "python3", Argv0: "python3", Argv: argv[:firstStage]}
		if r := ix.Decide(&f); r.Final {
			t.Errorf("%s, prefix ending at -m: %s, final", entry, decided(r))
		}
		f.Argv, f.ArgvComplete = argv, true
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
			t.Errorf("%s, whole vector: %s, want refused", entry, decided(r))
		}
	}
}

// TestPrefixRewriteAfterTheSubcommand: cargo reads --config after its subcommand too, and --config naming an alias
// makes the invocation unlocatable (an alias can make `cargo pub` run `cargo publish`). A prefix located at a
// subcommand is not final while a later token can still be --config: `cargo build --features f` fifteen times, then
// `--config alias.build=publish`, is refused under deny: cargo publish and under allow: cargo build, and its
// 32-element prefix is not final under either. cargo itself ignores an alias that shadows a built-in command such as
// build (cargo's documentation, read), so the test also holds the alias under a new name, `cargo pub` ... `--config
// alias.pub=publish`, which runs publish.
func TestPrefixRewriteAfterTheSubcommand(t *testing.T) {
	pub := []string{"cargo", "pub"}
	for range 15 {
		pub = append(pub, "--features", "f")
	}
	pub = append(pub, "--config", "alias.pub=publish")
	for _, entry := range []string{"deny: cargo publish", "ask: cargo publish"} {
		ix := rules(t, entry)
		f := execmatch.Facts{Requested: "cargo", Image: "cargo", Argv0: "cargo", Argv: pub[:firstStage]}
		if r := ix.Decide(&f); r.Final {
			t.Errorf("%s, prefix of cargo pub: %s, final", entry, decided(r))
		}
		f.Argv, f.ArgvComplete = pub, true
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
			t.Errorf("%s, whole vector of cargo pub: %s, want refused", entry, decided(r))
		}
	}

	argv := []string{"cargo", "build"}
	for range 15 {
		argv = append(argv, "--features", "f")
	}
	argv = append(argv, "--config", "alias.build=publish")
	for _, c := range []struct{ entry, rule string }{
		{"deny: cargo publish", "exec.deny[cargo publish]"},
		{"allow: cargo build", "exec.args[cargo]"},
	} {
		ix := rules(t, c.entry)
		f := execmatch.Facts{Requested: "cargo", Image: "cargo", Argv0: "cargo", Argv: argv[:firstStage]}
		if r := ix.Decide(&f); r.Final {
			t.Errorf("%s, prefix located at build: %s, final", c.entry, decided(r))
		}
		f.Argv, f.ArgvComplete = argv, true
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != c.rule {
			t.Errorf("%s, whole vector: %s, want refused %s", c.entry, decided(r), c.rule)
		}
		// After `--` no later token is an option: the prefix settles there.
		cut := append(append([]string(nil), argv[:firstStage-2]...), "--")
		f.Argv, f.ArgvComplete = cut, false
		if r := ix.Decide(&f); !r.Final {
			t.Errorf("%s, prefix ending at --: %s, not final", c.entry, decided(r))
		}
	}
}

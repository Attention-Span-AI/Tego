// SPDX-License-Identifier: Apache-2.0

package execmatchdiff_test

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	compare "github.com/attention-span-ai/tego/test/execmatchdiff"
	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
)

type pair struct {
	test             *testing.T
	sourceCandidates []string
	entry            string
	list             execmatch.List
	new              *execmatch.Index
	old              *old.Index
}

func newPair(t *testing.T, entry string, list execmatch.List) pair {
	t.Helper()
	a, err := execmatch.Parse(entry, list, rows.Builtin())
	if err != nil {
		t.Fatalf("new Parse(%q): %v", entry, err)
	}
	b, err := old.Parse(entry, old.List(list), oldrows.Builtin())
	if err != nil {
		t.Fatalf("old Parse(%q): %v", entry, err)
	}
	return pair{test: t, entry: entry, list: list, new: execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{a}, execmatch.IndexOptions{}), old: old.NewIndex(oldrows.Builtin(), []*old.Pattern{b}, old.IndexOptions{})}
}

// Pair keys contain source inputs, never either parser's compiled reading.
var pairAlignment = struct {
	sync.Mutex
	tests map[*testing.T]*pairInputCounts
}{tests: make(map[*testing.T]*pairInputCounts)}

type pairInputCounts struct {
	calls int
	keys  map[[32]byte]struct{}
}

func recordPairInput(p pair, f execmatch.Facts) {
	if os.Getenv("TEGO_EXECMATCH_KEYS") != "1" {
		return
	}
	raw, err := json.Marshal(struct {
		Entry      string
		List       execmatch.List
		Facts      execmatch.Facts
		Candidates []string
	}{p.entry, p.list, f, p.sourceCandidates})
	if err != nil {
		p.test.Fatal(err)
	}
	key := sha256.Sum256(raw)
	pairAlignment.Lock()
	defer pairAlignment.Unlock()
	state := pairAlignment.tests[p.test]
	if state == nil {
		state = &pairInputCounts{keys: make(map[[32]byte]struct{})}
		pairAlignment.tests[p.test] = state
		p.test.Cleanup(func() { pairAlignment.Lock(); delete(pairAlignment.tests, p.test); pairAlignment.Unlock() })
	}
	state.calls++
	state.keys[key] = struct{}{}
}

func TestPairInputAlignmentKeys(t *testing.T) {
	t.Setenv("TEGO_EXECMATCH_KEYS", "1")
	p := newPair(t, "git status", execmatch.ListAllow)
	f := routeFacts("git", []string{"status"}, 0)
	p.decide(f)
	p.decide(f)
	f.ArgvComplete = false
	p.decide(f)
	p.sourceCandidates = []string{"status"}
	p.decide(f)
	pairAlignment.Lock()
	defer pairAlignment.Unlock()
	state := pairAlignment.tests[t]
	if state == nil || state.calls != 4 || len(state.keys) != 3 {
		t.Fatalf("source input alignment: %+v", state)
	}
}

// convert copies public facts without coupling the released source to new fields.
func convert(dst, src reflect.Value) {
	switch dst.Kind() {
	case reflect.Pointer:
		if !src.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
			convert(dst.Elem(), src.Elem())
		}
	case reflect.Struct:
		for i := 0; i < dst.NumField(); i++ {
			if dst.Type().Field(i).IsExported() {
				s := src.FieldByName(dst.Type().Field(i).Name)
				if s.IsValid() {
					convert(dst.Field(i), s)
				}
			}
		}
	case reflect.Slice:
		if !src.IsNil() {
			dst.Set(reflect.MakeSlice(dst.Type(), src.Len(), src.Len()))
			for i := 0; i < src.Len(); i++ {
				convert(dst.Index(i), src.Index(i))
			}
		}
	default:
		dst.Set(src.Convert(dst.Type()))
	}
}

func (p pair) decide(f execmatch.Facts) (execmatch.Result, old.Result) {
	recordPairInput(p, f)
	var bf old.Facts
	convert(reflect.ValueOf(&bf).Elem(), reflect.ValueOf(f))
	return p.new.Decide(&f), p.old.Decide(&bf)
}

func routeFacts(tool string, toks []string, route int) execmatch.Facts {
	argv := append([]string{tool}, toks...)
	f := execmatch.Facts{Requested: tool, Image: tool, Argv0: tool, Argv: argv, ArgvComplete: true}
	switch route {
	case 1: // A caller-selected argv[0] adds the ruled tool to another image.
		f.Requested, f.Image = "other-image", "other-image"
	case 2:
		f.Requested, f.Image, f.Argv0 = "ld-linux-x86-64.so.2", "ld-linux-x86-64.so.2", "ld-linux-x86-64.so.2"
		f.Argv = append([]string{f.Argv0, "/usr/bin/" + tool}, toks...)
		f.Loaded = &execmatch.Loaded{Path: "/usr/bin/" + tool, Image: tool, Argv: argv}
	case 3: // A script named for the tool is reached through an interpreter.
		f.Requested, f.Image, f.Argv0 = "python3", "python3", "python3"
		f.Argv = append([]string{"python3", "/scripts/" + tool}, toks...)
	}
	return f
}

func changedClass(a execmatch.Result, b old.Result) string {
	if a.Outcome != execmatch.Outcome(b.Outcome) || a.Rule() != b.Rule() {
		return "decision/" + a.Tool + "/" + a.ListName()
	}
	if a.Final != b.Final {
		return "finality"
	}
	if a.Match != execmatch.Match(b.Match) {
		return "match-label"
	}
	return ""
}

func checkPair(t *testing.T, p pair, f execmatch.Facts, counts map[string]int) {
	t.Helper()
	a, b := p.decide(f)
	counts["decisions"]++
	if b.Outcome == old.OutcomeAllowed {
		counts["base-allowed"]++
	}
	if b.Outcome == old.OutcomeRefused {
		counts["base-refused"]++
	}
	before := compare.DecisionState{Outcome: b.Outcome.String(), List: b.List.String(), Final: b.Final}
	after := compare.DecisionState{Outcome: a.Outcome.String(), List: a.List.String(), Final: a.Final}

	loosens := compare.PotentialLoosening(before, after)
	if loosens {
		key := "unexpected/" + b.Tool + "/" + b.List.String()
		if counts[key] < 3 {
			t.Errorf("release bar: %s %q facts=%+v old=%+v new=%+v", p.list.String(), p.entry, f, b, a)
		}
		counts[key]++
		return
	}

	if class := changedClass(a, b); class != "" {
		counts["changed/"+class]++
	}
}

type command struct {
	tool          string
	path          []string
	level, parent *execmatch.Level
}

func commands() []command {
	var out []command
	for _, row := range rows.Builtin().All() {
		var walk func(*execmatch.Level, []string)
		walk = func(lv *execmatch.Level, prefix []string) {
			if lv == nil {
				return
			}
			names := make([]string, 0, len(lv.Subs)+len(lv.Alias))
			for n := range lv.Subs {
				names = append(names, n)
			}
			for n := range lv.Alias {
				names = append(names, n)
			}
			if lv.Wild != nil {
				names = append(names, "service")
			}
			sort.Strings(names)
			for _, n := range names {
				path := append(slices.Clone(prefix), n)
				child, known := lv.Subs[n]
				if n == "service" && !known {
					child = lv.Wild
				}
				out = append(out, command{row.Tool, path, child, lv})
				if known || n == "service" {
					walk(child, path)
				}
			}
		}
		walk(row.Root, nil)
	}
	return out
}

func optionSpellings(lv *execmatch.Level) [][]string {
	if lv == nil {
		return nil
	}
	var out [][]string
	for _, o := range lv.Opts {
		var spellings []string
		for _, n := range o.Long {
			spellings = append(spellings, "--"+n)
		}
		for _, c := range o.Short {
			spellings = append(spellings, "-"+string(c))
		}
		for _, spelling := range spellings {
			a := []string{spelling}
			if o.Arg == execmatch.ArgRequired || o.Arg == execmatch.ArgNextWord || o.Arg == execmatch.ArgMaybe {
				a = append(a, "x")
			}
			out = append(out, a)
		}
	}
	return out
}

// TestReleasedComparison is bounded and always runs. Every named command and
// alias at every level is covered, with constrained entries and all four routes.
// The long script extends the same matrix; it does not replace this test.
func TestReleasedComparison(t *testing.T) {
	counts := map[string]int{}
	for _, c := range commands() {
		entry := c.tool + " " + strings.Join(c.path, " ")
		entries := []string{entry, entry + " operand"}
		if opts := optionSpellings(c.level); len(opts) > 0 {
			entries = append(entries, entry+" "+strings.Join(opts[0], " "))
		}
		for _, e := range entries {
			for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk, execmatch.ListAllow} {
				if _, err := execmatch.Parse(e, list, rows.Builtin()); err != nil {
					if regression := generatedCompileRegression(e, list, err); regression != nil {
						t.Fatal(regression)
					}
					counts["invalid-generated-patterns"]++
					continue
				}
				p := newPair(t, e, list)
				toks := strings.Fields(strings.TrimPrefix(e, c.tool+" "))
				for at := 0; at <= len(c.path); at++ {
					vector := append(slices.Clone(toks[:at]), "--")
					vector = append(vector, toks[at:]...)
					for route := 0; route < 4; route++ {
						f := routeFacts(c.tool, vector, route)
						checkPair(t, p, f, counts)
						// Each proper prefix is open; no early final admit may hide a
						// later refusal. Loaded vectors are sliced with their program.
						if route == 0 {
							for k := 1; k < len(f.Argv); k++ {
								prefix := f
								prefix.Argv = f.Argv[:k]
								prefix.ArgvComplete = false
								checkPair(t, p, prefix, counts)
							}
						}
					}
				}
				if os.Getenv("TEGO_EXECMATCH_LONG") == "1" {
					for _, opt := range optionSpellings(c.parent) {
						for _, following := range []string{"--", "---", "--future", "-x", c.path[len(c.path)-1]} {
							vector := append(slices.Clone(c.path[:len(c.path)-1]), opt[0], following)
							vector = append(vector, c.path[len(c.path)-1], "operand")
							for route := 0; route < 4; route++ {
								checkPair(t, p, routeFacts(c.tool, vector, route), counts)
							}
						}
					}
				}
			}
		}
	}
	logCounts(t, counts)
}

// TestOptionValueReleasedComparison covers released option-value behavior even
// without a separator. A missing value followed by another option must not erase
// an option-constrained deny or ask. Every value option at every command level is
// paired with a declared flag (or an unknown option when the level has no flag).
func TestOptionValueReleasedComparison(t *testing.T) {
	counts := map[string]int{}
	var scenarios []command
	for _, c := range commands() {
		_, options := levelOptions(t, c.tool, c.path[:len(c.path)-1])
		c.parent = &execmatch.Level{Opts: options}
		scenarios = append(scenarios, c)
		leaf, options := levelOptions(t, c.tool, c.path)
		if leaf == nil || leaf.Subs == nil {
			scenarios = append(scenarios, command{tool: c.tool, path: append(slices.Clone(c.path), "operand-command"), parent: &execmatch.Level{Opts: options}})
		}
	}
	for _, row := range rows.Builtin().All() {
		if row.Root != nil && row.Root.Subs == nil {
			scenarios = append(scenarios, command{tool: row.Tool, path: []string{"operand-command"}, parent: row.Root})
		}
	}
	for _, c := range scenarios {
		if c.parent == nil {
			continue
		}
		following := "--future"
		for _, o := range c.parent.Opts {
			if o.Arg == execmatch.ArgNone {
				if len(o.Long) > 0 {
					following = "--" + o.Long[0]
					break
				}
				if len(o.Short) > 0 {
					following = "-" + o.Short[:1]
					break
				}
			}
		}
		entry := c.tool + " " + strings.Join(c.path, " ")
		cache := map[string]pair{}
		valueOptions := 0
		for _, o := range c.parent.Opts {
			if o.Arg != execmatch.ArgRequired && o.Arg != execmatch.ArgMaybe && o.Arg != execmatch.ArgNextWord {
				continue
			}
			if os.Getenv("TEGO_EXECMATCH_LONG") != "1" && valueOptions >= 1 {
				continue
			}
			valueOptions++
			spelling := ""
			if len(o.Long) > 0 {
				spelling = "--" + o.Long[0]
			} else if len(o.Short) > 0 {
				spelling = "-" + o.Short[:1]
			}
			if spelling == "" {
				continue
			}
			spellings := []string{spelling}
			if c.tool == "npm" && compare.NpmStringOption(o.Name) && len(o.Long) > 0 {
				spellings = append(spellings, "---"+o.Long[0], "----"+o.Long[0])
			}
			for _, spelling := range spellings {
				for _, e := range []string{entry, entry + " " + following, entry + " operand"} {
					for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk, execmatch.ListAllow} {
						if _, err := execmatch.Parse(e, list, rows.Builtin()); err != nil {
							if regression := generatedCompileRegression(e, list, err); regression != nil {
								t.Fatal(regression)
							}
							counts["invalid-generated-patterns"]++
							continue
						}
						key := list.String() + ":" + e
						p, ok := cache[key]
						if !ok {
							p = newPair(t, e, list)
							cache[key] = p
						}
						vector := append(slices.Clone(c.path[:len(c.path)-1]), spelling, following, c.path[len(c.path)-1], "operand")
						for route := 0; route < 4; route++ {
							checkPair(t, p, routeFacts(c.tool, vector, route), counts)
						}
					}
				}
			}
		}
	}
	// The reported released npm bypass constrains --global specifically, rather
	// than depending on whichever flag sorts first in the row.
	for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk, execmatch.ListAllow} {
		p := newPair(t, "npm install --global", list)
		for _, vector := range [][]string{{"--tag", "--global", "install", "x"}, {"---tag", "--global", "install", "x"}, {"----tag", "--global", "install", "x"}, {"---tag=--global", "install", "x"}, {"----tag=--global", "install", "x"}, {"--c=--global", "install", "x"}, {"---c=--global", "install", "x"}, {"-cc=--global", "install", "x"}, {"--cc=--global", "install", "x"}, {"--Cc=--global", "install", "x"}, {"--tag=--global", "install", "x"}, {"--tag=--tag=--global", "install", "x"}, {"--tag=---", "install", "--global"}, {"install", "--tag=---", "--global"}} {
			for route := 0; route < 4; route++ {
				checkPair(t, p, routeFacts("npm", vector, route), counts)
			}
		}
	}
	// Independent argparse controls: known assignments precede its space
	// fallback. Unknown declarations retain both classifications in the product.
	for _, vector := range [][]string{
		{"--region", "--query=has space", "s3", "ls"},
		{"--query", "--region=has space", "s3", "ls"},
		{"--region", "--qu=has space", "s3", "ls"},
		{"--region", "--c=has space", "s3", "ls"},
		{"--region", "--future=has space", "s3", "ls"},
		{"--region", "-x y", "s3", "ls"},
	} {
		for _, entry := range []string{"aws s3 ls", "aws s3 ls --query", "aws s3 ls --region"} {
			for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk, execmatch.ListAllow} {
				p := newPair(t, entry, list)
				for route := 0; route < 4; route++ {
					checkPair(t, p, routeFacts("aws", vector, route), counts)
				}
			}
		}
	}
	logCounts(t, counts)
}

// levelOptions resolves aliases to their real leaf and retains persistent
// ancestor options. A nil declared child still has its parent's syntax and
// inherited options in the normalizer; it is not an absent parser level.
func levelOptions(t *testing.T, tool string, path []string) (*execmatch.Level, []execmatch.Opt) {
	t.Helper()
	row := rows.Builtin().Lookup(tool)
	lv := row.Root
	p, err := execmatch.Parse(tool+" "+strings.Join(path, " "), execmatch.ListDeny, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	var ancestors []*execmatch.Level
	for _, name := range p.Path {
		ancestors = append(ancestors, lv)
		next, ok := lv.Subs[name]
		if !ok {
			next = lv.Wild
		}
		if next == nil {
			next = &execmatch.Level{Syntax: lv.Syntax}
		}
		lv = next
	}
	options := append([]execmatch.Opt(nil), lv.Opts...)
	seen := map[string]bool{}
	for _, o := range options {
		seen[o.Name] = true
	}
	for i := len(ancestors) - 1; i >= 0; i-- {
		for _, o := range ancestors[i].Opts {
			if o.Persistent && !seen[o.Name] {
				options = append(options, o)
				seen[o.Name] = true
			}
		}
	}
	return lv, options
}

func logCounts(t *testing.T, counts map[string]int) {
	pairAlignment.Lock()
	if state := pairAlignment.tests[t]; state != nil {
		counts["paired-calls-per-side"] = state.calls
		counts["aligned-source-keys"] = len(state.keys)
	}
	pairAlignment.Unlock()
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%s=%d", k, counts[k])
	}
	if file := os.Getenv("TEGO_EXECMATCH_COUNTS"); file != "" {
		b, err := json.MarshalIndent(counts, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(file, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFrozenBaselineProvenance(t *testing.T) {
	// prepare.py --verify checks each source byte against this exact commit.
	data, err := os.ReadFile(filepath.Join("internal", "baseline", "PROVENANCE"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "70a9e8c56") {
		t.Fatal("missing released commit")
	}
	if len(commands()) < 100 {
		t.Fatalf("unexpectedly small command inventory: %d", len(commands()))
	}
}

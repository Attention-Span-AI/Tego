// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// The node row reads Node 20.19.4 and 22.21.1's command lines (src/node_options-inl.h). The
// tests here hold it to node: TestNodeRowTable to node's own option and alias tables, and the differentials to what the
// installed node runs, over every spelling of every option the row lists, over code and the options that change what
// node runs, and over generated lines.

// TestNodeOptionsEnd: node's options end after --prof-process, negated or not, and after --trace-events-enabled=v. The
// first's alias inserts `--`; the second's inserts the value node gives its categories, which node leaves unread when
// the value is attached, and a token that is no option ends node's option loop (src/node_options-inl.h). The token
// after either is node's main module even when it starts with '-' (probed on node 20.19.4: `node --no-prof-process -x
// a.js` and `node --trace-events-enabled=v -x a.js` fail "Cannot find module '-x'", and `node --no-prof-process
// ./--title t a.js` runs ./--title). Written bare, --trace-events-enabled is a flag. A deny entry naming that script
// refuses the line; a script after an option there is an argument of the module node loads, not node's script.
func TestNodeOptionsEnd(t *testing.T) {
	ix := rules(t, "deny: -x.js", "deny: npm publish")
	const cli = "/usr/share/nodejs/npm/bin/npm-cli.js"
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"--no-prof-process", "-x.js", "a"}, "exec.deny[-x.js]"},
		{[]string{"--no-prof-process=1", "-x.js"}, "exec.deny[-x.js]"},
		{[]string{"--prof_process", "-x.js"}, "exec.deny[-x.js]"},
		{[]string{"--no_prof_process", "-x.js"}, "exec.deny[-x.js]"},
		{[]string{"--no-prof-process", cli, "publish"}, "exec.deny[npm publish]"},
		{[]string{"--no-prof-process", "--title", "t", cli, "publish"}, ""},
		{[]string{"--no-prof-process", "--", cli, "publish"}, ""},
		{[]string{"--trace-events-enabled=v", "-x.js", "a"}, "exec.deny[-x.js]"},
		{[]string{"--trace_events_enabled=v", "-x.js"}, "exec.deny[-x.js]"},
		{[]string{"--trace-events-enabled=v", "--title", "t", cli, "publish"}, ""},
		{[]string{"--trace-events-enabled=v", cli, "publish"}, "exec.deny[npm publish]"},
		{[]string{"--trace-events-enabled", "--title", "t", cli, "publish"}, "exec.deny[npm publish]"},
		{[]string{"--trace_events_enabled", cli, "publish"}, "exec.deny[npm publish]"},
	}
	for _, c := range cases {
		f := facts("/usr/bin/node", "node", append([]string{"node"}, c.argv...)...)
		r := ix.Decide(&f)
		if c.want == "" {
			if r.Outcome != execmatch.OutcomeNone {
				t.Errorf("node %s: %s, want none: node's script is %s", strings.Join(c.argv, " "), decided(r), c.argv[1])
			}
			continue
		}
		if r.Outcome != execmatch.OutcomeRefused || r.Rule() != c.want {
			t.Errorf("node %s: %s, want refused %s", strings.Join(c.argv, " "), decided(r), c.want)
		}
	}
	// An entry reads the option's words the same way: deny: [node --prof-process -x.js] names an operand.
	for entry, want := range map[string][]string{
		"node --prof-process -x.js":            {"-x.js"},
		"node --trace-events-enabled=v -x.js":  {"-x.js"},
		"node --trace_events_enabled=* -x.js":  {"-x.js"},
		"node --trace-events-enabled app.js":   {"app.js"},
		"node --trace-events-enabled --no-opt": nil,
	} {
		p, err := execmatch.Parse(entry, execmatch.ListDeny, Builtin())
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(p.Operands, want) {
			t.Errorf("%s: operands %q, want %q", entry, p.Operands, want)
		}
	}
}

// TestNodeRowReadsItsOptions: the node row reads each option it lists one way, so none forks the readings in front of
// the script and a script's own flags are not counted toward MaxReadings (docs/GAPS.md C49). A flag leaves the next
// token the script, a value option takes it, --no-<name> takes nothing, and -p, --print and --no-print take a word but
// no option; each long name reads the same with `_` for `-`. Under deny: [npm publish] each spelling in front of npm's
// entry script is refused, so no listing loses the script (code, -e's and -p's, is opaque instead), and
// --build-snapshot-config, whose script is in a file, is refused command-unresolved.
func TestNodeRowReadsItsOptions(t *testing.T) {
	jest := facts("/usr/bin/node", "node", "node", "--expose-gc", "./node_modules/jest/bin/jest.js", "--ci", "--coverage", "--runInBand", "--silent", "--verbose", "--forceExit", "--detectOpenHandles")
	if r := rules(t, "deny: jest.js --coverage").Decide(&jest); r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[jest.js --coverage]" {
		t.Errorf("C49's jest line: %s, want refused exec.deny[jest.js --coverage]: node runs jest's entry script", decided(r))
	}
	row := Builtin().Lookup("node")
	nz := execmatch.NewNormalizer(row, nil)
	ix := rules(t, "deny: npm publish")
	const cli = "/usr/share/nodejs/npm/bin/npm-cli.js"
	code := map[string]bool{}
	for _, c := range row.Interp.Code {
		code[c] = true
	}
	// reads checks toks in front of eight flags of the script's own: one reading, with the script at index script.
	reads := func(script int, toks ...string) {
		t.Helper()
		toks = append(toks, "--f0", "--f1", "--f2", "--f3", "--f4", "--f5", "--f6", "--f7")
		rs := nz.Normalize(toks)
		if len(rs) != 1 || rs[0].Dispatch != script {
			var at []int
			for _, r := range rs {
				at = append(at, r.Dispatch)
			}
			t.Errorf("node %s: scripts at %v, want one reading with the script at %d", strings.Join(toks, " "), at, script)
		}
	}
	// refuses checks toks in front of npm's entry script under deny: [npm publish]: refused by that entry, or
	// command-unresolved when an option makes the line unlocatable.
	refuses := func(want string, toks ...string) {
		t.Helper()
		f := facts("/usr/bin/node", "node", append(append([]string{"node"}, toks...), cli, "publish")...)
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != want {
			t.Errorf("node %s npm-cli.js publish: %s, want refused %s", strings.Join(toks, " "), decided(r), want)
		}
	}
	// nextWord checks an ArgNextWord spelling: a word after it is its value (code, opaque), and an option after it is
	// not, so npm's entry script after the options is the script.
	nextWord := func(s string) {
		t.Helper()
		reads(2, s, "v", "./app.js")
		reads(3, s, "--title", "t", "./app.js")
		reads(2, s, "--", "./app.js")
		for _, before := range [][]string{{"--title", "t"}, {"-r", "./x.js"}, {"--"}, {"--no-warnings"}} {
			refuses("exec.deny[npm publish]", append([]string{s}, before...)...)
		}
	}
	seen := map[string]bool{}
	for _, o := range row.Root.Opts {
		// An option whose every value makes the line unlocatable is refused command-unresolved; an ES module option's
		// value v is a plain path, which reads as any value does.
		unlocatable := o.Rewrite != nil && o.Rewrite("v")
		want := "exec.deny[npm publish]"
		if unlocatable {
			want = execmatch.RuleCommandUnresolved
		}
		for _, s := range spellings(o) {
			if seen[s] {
				t.Errorf("node row: %s listed twice", s)
			}
			seen[s] = true
			for _, sp := range underscored(s) {
				switch o.Arg {
				case execmatch.ArgRequired:
					if !unlocatable {
						reads(2, sp, "v", "./app.js")
					}
					if !code[o.Name] {
						refuses(want, sp, "v")
					}
				case execmatch.ArgNextWord:
					nextWord(sp)
				case execmatch.ArgNone, execmatch.ArgOptional, execmatch.ArgMaybe:
					if !unlocatable {
						reads(1, sp, "./app.js")
					}
					refuses(want, sp)
				}
				neg, ok := strings.CutPrefix(sp, "--")
				switch {
				case !ok:
				case o.Arg == execmatch.ArgNextWord:
					// node expands `--print <arg>` on the negated name too: --no-print x evaluates x.
					nextWord("--no-" + neg)
					nextWord(sp + "=v")
					nextWord("--no-" + neg + "=v")
				default:
					// A code option's negation too: node refuses --no-eval, and the row reads no code there.
					reads(1, "--no-"+neg, "./app.js")
					refuses("exec.deny[npm publish]", "--no-"+neg)
				}
			}
		}
	}
}

// TestNodeRowReadsWhatNodeLoads: each file node runs, as its script or as a module it loads first, is read by the
// name node finds it by (the review of 2119c938f found each group but the last let a denied script through; each line
// probed on node 20.19.4 with a script in deploy.js's place):
//   - --test-reporter's module, which node imports in its own process when a test runs, with the script's arguments,
//     unless it is one of node's own reporters (spec, tap, dot, junit, lcov);
//   - a script path that ends in `.` or `..` and a module path with `..` in it, which node cleans as path.resolve does,
//     and a script or -r module named without its .js, which node finds by it;
//   - an ES module specifier (--import, --loader, --test-reporter) that node reads as a URL other than its path: with a
//     query, a fragment, a %-escape, a backslash, a tab or newline, a space or control at either end, a file: or other
//     scheme, or `#` imports. Such a line is refused command-unresolved; a data: URL is code and node: a built-in, and
//     neither names a file;
//   - a -r value given as `\-x.js`, which node reads as -x.js;
//   - --experimental-sea-config, under which node runs the file's main script (refused command-unresolved);
//   - --loader's and --experimental-loader's module, with no arguments.
func TestNodeRowReadsWhatNodeLoads(t *testing.T) {
	ix := rules(t, "deny: deploy.js", "deny: npm publish", "deny: -x.js")
	const cli = "/usr/share/nodejs/npm/bin/npm-cli.js"
	const (
		deploy     = "exec.deny[deploy.js]"
		npm        = "exec.deny[npm publish]"
		unresolved = execmatch.RuleCommandUnresolved
	)
	for _, c := range []struct {
		argv []string
		want string
	}{
		{[]string{"--test", "--test-reporter", "./deploy.js"}, deploy},
		{[]string{"--test-reporter", "./deploy.js", "--test"}, deploy},
		{[]string{"--test", "--test-reporter", "./deploy.js", "a.js"}, deploy},
		{[]string{"--test", "--test-reporter", "./deploy.js", "--test-reporter-destination", "stdout", "a.js"}, deploy},
		{[]string{"--test", "--test_reporter", "./deploy.js"}, deploy},
		{[]string{"--test", "--test-reporter", "/srv/app/deploy.js", "/etc/hostname"}, deploy},
		{[]string{"--test", "--test-reporter=./deploy.js"}, deploy},
		{[]string{"--test-reporter", "./deploy.js", "t.test.js", "x"}, deploy},
		{[]string{"--test-reporter", cli, "t.test.js", "publish"}, npm},
		{[]string{"--test", "--test-reporter", "spec", "a.js"}, ""},
		{[]string{"./deploy.js/.", "publish"}, deploy},
		{[]string{"./deploy.js/x/..", "publish"}, deploy},
		{[]string{"./deploy", "publish"}, deploy},
		{[]string{"deploy/", "publish"}, deploy},
		{[]string{"-r", "./deploy", "a.js"}, deploy},
		{[]string{"--require=./x/../deploy.js", "a.js"}, deploy},
		{[]string{"--import", "./x/../deploy.js", "a.js"}, deploy},
		{[]string{"--import", "//localhost/srv/deploy.js", "a.js"}, deploy},
		{[]string{cli + "/.", "publish"}, npm},
		{[]string{cli + "/x/..", "publish"}, npm},
		{[]string{strings.TrimSuffix(cli, ".js"), "publish"}, npm},
		{[]string{"-r", strings.TrimSuffix(cli, ".js"), "app.js", "publish"}, npm},
		{[]string{"./deploy.json", "publish"}, ""},
		{[]string{"--import", "./deploy.js?x", "a.js", "publish"}, unresolved},
		{[]string{"--import", "./deploy.js#x", "a.js", "publish"}, unresolved},
		{[]string{"--import", "./dep%6Coy.js", "a.js", "publish"}, unresolved},
		{[]string{"--import", "./sub/%2e%2e/deploy.js", "a.js"}, unresolved},
		{[]string{"--import", `./sub/..\deploy.js`, "a.js"}, unresolved},
		{[]string{"--import", "./deplo\ny.js", "a.js"}, unresolved},
		{[]string{"--import", "./deploy.js ", "a.js"}, unresolved},
		{[]string{"--import", cli + "?x", "a.js", "publish"}, unresolved},
		{[]string{"--import", "file:///usr/share/nodejs/npm/bin/npm%2Dcli.js", "a.js", "publish"}, unresolved},
		{[]string{"--import=file:///srv/deploy.js", "a.js"}, unresolved},
		{[]string{"--import", "#deploy", "a.js"}, unresolved},
		{[]string{"--loader", "./deploy.js?x", "a.js"}, unresolved},
		{[]string{"--experimental_loader=./deploy.js#h", "a.js"}, unresolved},
		{[]string{"--test", "--test-reporter=./deploy.js#x"}, unresolved},
		{[]string{"--import", "data:text/javascript,0", "a.js"}, ""},
		// node 20's own advice for a loader, and the common modules: none names a file the row cannot read.
		{[]string{"--import", `data:text/javascript,import { register } from "node:module"; import { pathToFileURL } from "node:url"; register("ts-node/esm", pathToFileURL("./"));`, "app.ts"}, ""},
		{[]string{"--import", "tsx", "app.ts"}, ""},
		{[]string{"-r", "ts-node/register", "-r", "dotenv/config", "app.ts"}, ""},
		{[]string{"--loader", "ts-node/esm", "app.ts"}, ""},
		{[]string{"--test", "--test-reporter=@reporters/github", "--test-reporter-destination=stdout", "--test-reporter=./reporters/x.mjs"}, ""},
		{[]string{"--import", " DA\tTA:text/javascript,0", "a.js"}, ""},
		{[]string{"--import", "node:fs", "a.js"}, ""},
		{[]string{"-r", "./deploy.js?x", "a.js"}, ""},
		{[]string{"-r", `\-x.js`, "a.js"}, "exec.deny[-x.js]"},
		{[]string{"--experimental-sea-config", "sea.json"}, unresolved},
		{[]string{"--experimental_sea_config=sea.json", "a.js"}, unresolved},
		{[]string{"--loader", "./deploy.js", "a.js"}, deploy},
		{[]string{"--experimental-loader=./deploy", "a.js"}, deploy},
	} {
		f := facts("/usr/bin/node", "node", append([]string{"node"}, c.argv...)...)
		r := ix.Decide(&f)
		if c.want == "" {
			if r.Outcome != execmatch.OutcomeNone {
				t.Errorf("node %q: %s, want none", c.argv, decided(r))
			}
			continue
		}
		if r.Outcome != execmatch.OutcomeRefused || r.Rule() != c.want {
			t.Errorf("node %q: %s, want refused %s", c.argv, decided(r), c.want)
		}
	}
}

// spellings are an option's command-line spellings: --long for each long name, -c for each letter.
func spellings(o execmatch.Opt) []string {
	var out []string
	for _, l := range o.Long {
		out = append(out, "--"+l)
	}
	for i := 0; i < len(o.Short); i++ {
		out = append(out, "-"+o.Short[i:i+1])
	}
	return out
}

// underscored is a spelling as written and, for a long name holding '-', with '_' for each '-' after the leading
// dashes, which node reads as the same option.
func underscored(s string) []string {
	name, ok := strings.CutPrefix(s, "--")
	if !ok || !strings.Contains(name, "-") {
		return []string{s}
	}
	return []string{s, "--" + strings.ReplaceAll(name, "-", "_")}
}

// TestNodeEntriesReadAsArgv: an entry's option words are read as the normalizer reads argv. -p, --print and --no-print
// take a word after them as their code, which is -e's too (node expands -p x to --print --eval x): deny: [node -p code]
// refuses `node -p code` and the same with a script after the code, and deny: [node -e *] refuses `node -p x` (the
// review of 74488311 found -p's reading in an entry untested). An entry spelling a name with `_` names the option node
// reads.
func TestNodeEntriesReadAsArgv(t *testing.T) {
	for _, c := range []struct {
		entry  string
		lines  []string
		denied bool
	}{
		{"node -p code", []string{"node -p code", "node -p code app.js", "node --print code app.js", "node --print=v code"}, true},
		{"node --print code", []string{"node --print code", "node -p code app.js", "node --print=v code app.js"}, true},
		{"node --no-print code", []string{"node --no-print code", "node --no_print code app.js"}, true},
		{"node -p code", []string{"node -p --title code app.js", "node -p other", "node --no-print code"}, false},
		// -p's word is --eval's too: node expands -p x to --print --eval x.
		{"node -e code", []string{"node -e code", "node -p code app.js", "node --no-print code", "node --eval=code app.js"}, true},
		{"node -e *", []string{"node -p x", "node --print=v x app.js", "node -pe x"}, true},
		{"node -e *", []string{"node -p --title t app.js", "node app.js"}, false},
		{"node --build_snapshot", []string{"node --build-snapshot app.js", "node --build_snapshot=1 app.js"}, true},
		{"node --build-snapshot", []string{"node --build_snapshot app.js"}, true},
		{"node --no_build_snapshot", []string{"node --no-build-snapshot app.js"}, true},
		{"node --build-snapshot", []string{"node --no_build_snapshot app.js"}, false},
	} {
		ix := rules(t, "deny: "+c.entry)
		for _, line := range c.lines {
			r := run(ix, words(line)...)
			if got := r.Outcome == execmatch.OutcomeRefused; got != c.denied || got && r.Rule() != "exec.deny["+c.entry+"]" {
				t.Errorf("deny: [%s] on %s: %s, want refused %v", c.entry, line, decided(r), c.denied)
			}
		}
	}
	if _, err := execmatch.Parse("node --expose_gc --title_x t app.js", execmatch.ListAllow, Builtin()); err == nil {
		t.Error("allow: [node --expose_gc --title_x t app.js] parsed: --title_x is no option of node's")
	}
	p, err := execmatch.Parse("node --expose_gc --input_type commonjs app.js", execmatch.ListAllow, Builtin())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Opts) != 2 || p.Opts[0].Opt == nil || p.Opts[0].Opt.Name != "expose-gc" || p.Opts[1].Value != "commonjs" || !slices.Equal(p.Operands, []string{"app.js"}) {
		t.Errorf("allow: [node --expose_gc --input_type commonjs app.js]: %+v", p)
	}
}

// nodeLeftOut are node's options and aliases the row leaves out, so it reads them both ways: no-ops in node 20 that
// took a value in an older node, and stack-trace-limit, which changes arity between 20 and 22.
var nodeLeftOut = map[string]bool{"--experimental-specifier-resolution": true, "--es-module-specifier-resolution": true, "--http-parser": true, "--stack-trace-limit": true}

// TestNodeRowTable holds the node row to node's own tables, as the installed node's options binding lists them
// (internalBinding('options').getCLIOptionsInfo() under --expose-internals). Every option node reads is listed with the
// kind node gives it: a boolean, a no-op or a V8 option takes no value, any other takes one. Every alias node expands is
// one the row reads by its form: "-x" → [--name] is name's letter x; "--a" → [--b] a long name of b; "--a=" → [--a] a
// flag whose value node drops; "--a=" → [--inspect-port, --a] an option with a value only attached (ArgOptional);
// "--a <arg>" → [-pe] an option that takes a word after it (ArgNextWord), -pe being [--a, --eval]; "--a" → [--a, --]
// Opt.Ends; and "--a" → [--b, word], b taking a value, Opt.EndsAttached. Only nodeLeftOut stays unknown.
// An option or an alias node adds, or a form the row does not read, fails the test. A spelling of the row's that node
// does not list is V8's, as `node --v8-options` lists it, or one of node's letters. Both captured versions are checked
// without requiring Node on PATH; TestNodeInventoryDifferential verifies the installed binary against its snapshot.
func TestNodeRowTable(t *testing.T) {
	row := Builtin().Lookup("node")
	// The union is checked offline too: adding a Node 22 option must not hide
	// a different arity in Node 20. Only explicitly unknown conflicts may differ.
	tbl := nodeInventory{Options: map[string]string{}, Aliases: map[string][]string{}}
	v8 := map[string]bool{}
	for _, version := range nodeVersions {
		data := readNodeInventory(t, version)
		hash, err := hex.DecodeString(data.BuildSHA256)
		if err != nil || len(hash) != 32 {
			t.Fatalf("invalid build digest: %s", data.BuildSHA256)
		}
		var sum [32]byte
		copy(sum[:], hash)
		if NodeBuildVersion(sum) != strings.TrimPrefix(version, "v") {
			t.Fatalf("inventory is not pinned to %s", version)
		}
		for name, typ := range data.Options {
			if prev := tbl.Options[name]; prev != "" && prev != typ && !nodeLeftOut[name] &&
				!((prev == "kNoOp" && typ == "kBoolean") || (prev == "kBoolean" && typ == "kNoOp")) {
				t.Errorf("%s changes type from %s to %s without staying unknown", name, prev, typ)
			}
			tbl.Options[name] = typ
		}
		for name, exp := range data.Aliases {
			if prev := tbl.Aliases[name]; prev != nil && !slices.Equal(prev, exp) {
				t.Errorf("%s changes alias from %v to %v", name, prev, exp)
			}
			tbl.Aliases[name] = exp
		}
		for name := range data.V8 {
			v8[name] = true
		}
	}
	report := t.Errorf
	byLong, byShort := map[string]*execmatch.Opt{}, map[byte]*execmatch.Opt{}
	for i := range row.Root.Opts {
		o := &row.Root.Opts[i]
		for _, l := range o.Long {
			byLong["--"+l] = o
		}
		for j := 0; j < len(o.Short); j++ {
			byShort[o.Short[j]] = o
		}
	}
	nodeOpt := tbl.Options
	// Every option node reads, by its kind.
	for name, typ := range nodeOpt {
		o := byLong[name]
		switch {
		case nodeLeftOut[name]:
			if o != nil {
				report("node %s: left out, so read both ways, but the row lists it", name)
			}
			continue
		case o == nil:
			report("node reads %s (%s), and the row does not list it", name, typ)
			continue
		}
		want := execmatch.ArgRequired
		switch typ {
		case "kBoolean", "kNoOp", "kV8Option":
			want = execmatch.ArgNone
			if _, ok := tbl.Aliases[name+" <arg>"]; ok {
				want = execmatch.ArgNextWord
			}
			if exp := tbl.Aliases[name+"="]; len(exp) == 2 && exp[0] == "--inspect-port" && exp[1] == name {
				want = execmatch.ArgOptional
			}
		}
		if o.Arg != want {
			report("node %s (%s): the row reads kind %d, want %d", name, typ, o.Arg, want)
		}
	}
	// Every alias node expands, by its form.
	modelled := map[*execmatch.Opt]string{}
	for key, exp := range tbl.Aliases {
		bare, eq := strings.CutSuffix(key, "=")
		bare, arg := strings.CutSuffix(bare, " <arg>")
		var to *execmatch.Opt
		if len(exp) > 0 {
			to = byLong[exp[0]]
		}
		switch {
		case key == "-pe" && slices.Equal(exp, []string{"--print", "--eval"}):
			if !slices.Contains(row.Root.Syntax.ClusterWords, key) {
				report("node's %s alias is not an exact permitted cluster", key)
			}
		case nodeLeftOut[key]:
			if byLong[key] != nil {
				report("node alias %s: left out, but the row lists it", key)
			}
		case len(key) == 2 && key[0] == '-' && len(exp) == 1:
			if to == nil || byShort[key[1]] != to {
				report("node alias %s → %v: the row reads %s as no letter of %s", key, exp, key, exp[0])
			}
		case arg && slices.Equal(exp, []string{"-pe"}):
			pe := tbl.Aliases["-pe"]
			if o := byLong[bare]; o == nil || o.Arg != execmatch.ArgNextWord || len(pe) != 2 || pe[0] != bare || byLong[pe[1]] == nil || "--"+o.WordTo != pe[1] {
				report("node alias %s → %v, -pe → %v: the row does not read %s as taking a word after it, the value of %s", key, exp, pe, bare, pe[len(pe)-1])
			} else {
				modelled[o] = "nextWord"
			}
		case eq && slices.Equal(exp, []string{bare}):
			if o := byLong[bare]; o == nil || o.Arg != execmatch.ArgNone {
				report("node alias %s → %v: the row does not read %s as a flag", key, exp, bare)
			}
		case eq && len(exp) == 2 && exp[0] == "--inspect-port" && exp[1] == bare:
			if o := byLong[bare]; o == nil || o.Arg != execmatch.ArgOptional {
				report("node alias %s → %v: the row does not read %s with a value only attached", key, exp, bare)
			} else {
				modelled[o] = "attached"
			}
		case !eq && !arg && len(exp) == 1 && strings.HasPrefix(exp[0], "--"):
			if to == nil || byLong[key] != to {
				report("node alias %s → %v: the row does not read %s as %s", key, exp, key, exp[0])
			}
		case !eq && !arg && len(exp) == 2 && exp[0] == key && exp[1] == "--":
			if o := byLong[key]; o == nil || !o.Ends {
				report("node alias %s → %v: the row does not end node's options after %s", key, exp, key)
			} else {
				modelled[o] = "ends"
			}
		case !eq && !arg && len(exp) == 2 && nodeOpt[exp[0]] != "" && !strings.HasPrefix(exp[1], "-"):
			if o := byLong[key]; o == nil || o.Arg != execmatch.ArgNone || !o.EndsAttached || byLong[exp[0]] == nil || byLong[exp[0]].Arg != execmatch.ArgRequired {
				report("node alias %s → %v: the row does not read %s as a flag that ends node's options with =v", key, exp, key)
			} else {
				modelled[o] = "endsAttached"
			}
		default:
			report("node alias %s → %v: a form the row does not read", key, exp)
		}
	}
	// Every canonical V8 name is present too, except the explicit conflicts.
	for name := range v8 {
		if nodeLeftOut["--"+name] {
			continue
		}
		o := byLong["--"+name]
		if o == nil {
			report("V8 lists --%s, and the row does not", name)
		} else if nodeOpt["--"+name] == "" && o.Arg != execmatch.ArgNone {
			report("V8-only --%s consumes Node's next token (kind %d)", name, o.Arg)
		}
	}
	// The row's own spellings and forms, each from node's tables.
	for i := range row.Root.Opts {
		o := &row.Root.Opts[i]
		for _, l := range o.Long {
			if nodeOpt["--"+l] == "" && tbl.Aliases["--"+l] == nil && !v8[l] {
				report("the row lists --%s: neither node nor V8 reads it", l)
			}
		}
		for j := 0; j < len(o.Short); j++ {
			if exp := tbl.Aliases["-"+o.Short[j:j+1]]; len(exp) != 1 || byLong[exp[0]] != o {
				report("the row reads -%c as %s: node's alias table does not", o.Short[j], o.Name)
			}
		}
		form := ""
		switch {
		case o.Ends:
			form = "ends"
		case o.EndsAttached:
			form = "endsAttached"
		case o.Arg == execmatch.ArgNextWord:
			form = "nextWord"
		case o.Arg == execmatch.ArgOptional:
			form = "attached"
		}
		if form != modelled[o] {
			report("the row reads %s as %q, and node's alias table makes it %q", o.Name, form, modelled[o])
		}
	}
}

// nodeMain is a script that prints, when node runs it, node's pid and, as JSON, its own name and the arguments node
// gives it: after "ran" when it is node's main module or snapshot builder, after "pre" when node loads it before the
// main module or in its place (-r, --import, --loader, --test-reporter), even where argv[1] names its file (`node -e 0
// -r ./a.js -- a.js`). The main module is require.main; a snapshot builder (--build-snapshot, --build-snapshot-config, a
// single executable's configuration with useSnapshot) has no module object, and v8.startupSnapshot says it is
// building.
const nodeMain = "const p=require('path');" +
	"const m=typeof module==='undefined'?require('v8').startupSnapshot.isBuildingSnapshot():require.main===module;" +
	"process.stdout.write((m?'ran ':'pre ')+process.pid+' '+JSON.stringify([p.basename(__filename)].concat(process.argv.slice(2)))+'\\n')\n"

// nodeWords are the words the lines use, each a nodeMain script in node's working directory, so a word node runs as
// its main module, whatever else the line meant it to be, is seen. Most are values node accepts for an option that
// checks its value (nodeValueOf). -x.js lies in node_modules, where node looks for a main module whose name starts with
// '-' (it resolves no other name as a path).
var nodeWords = []string{"a.js", "b.js", "c.js", "0", "v", "commonjs", "off", "warn", "verbatim", "delete", "SIGUSR2",
	"spec", "stderr", "all", "CVE-2023-46809"}

// nodeValueOf is a value node accepts for an option that checks it, a word of nodeWords (or a path to one), and for an
// option whose value is a module node loads or a file naming a script node runs, one that holds a nodeMain script
// (cfg.json's builder and sea.json's main are b.js); any other option takes c.js. The map is keyed by Opt.Name.
var nodeValueOf = map[string]string{"input-type": "commonjs", "experimental-default-type": "commonjs", "use-largepages": "off",
	"unhandled-rejections": "warn", "dns-result-order": "verbatim", "disable-proto": "delete", "heapsnapshot-signal": "SIGUSR2",
	"report-signal": "SIGUSR2", "inspect-publish-uid": "stderr", "security-revert": "CVE-2023-46809",
	"trace-require-module": "all", "inspect-port": "0", "require": "./c.js", "import": "./c.js", "loader": "./c.js",
	"test-reporter": "./c.js", "build-snapshot-config": "cfg.json", "experimental-sea-config": "sea.json"}

// nodeNeeds are the options node refuses an option without, or does nothing with an option without, which the lines put
// in front of it: --test-reporter's module is loaded when a test runs.
var nodeNeeds = map[string][]string{"cpu-prof-dir": {"--cpu-prof"}, "cpu-prof-interval": {"--cpu-prof"},
	"cpu-prof-name": {"--cpu-prof"}, "heap-prof-dir": {"--heap-prof"}, "heap-prof-interval": {"--heap-prof"},
	"heap-prof-name": {"--heap-prof"}, "allow-fs-read": {"--experimental-permission", "--allow-fs-read=*"},
	"allow-fs-write": {"--experimental-permission", "--allow-fs-read=*"}, "snapshot-blob": {"--build-snapshot"},
	"test-reporter": {"--test"}}

// nodeUnsafe are the options no line holds: the debugger's bind a port or wait for a debugger, --watch and --watch-path
// keep running, V8's perf options write /tmp/perf-<pid>.map, and --abort-on-uncaught-exception dumps core on a line
// whose code throws. nodeUnread are those whose value no line can give: a file of another format (a policy, an OpenSSL
// configuration), or another option's (TestNodeRowTable holds their kind); --snapshot-blob aborts node without
// --build-snapshot.
var (
	nodeUnsafe = map[string]bool{"inspect": true, "inspect-brk": true, "inspect-brk-node": true, "inspect-wait": true,
		"watch": true, "watch-path": true, "perf-basic-prof": true, "perf-basic-prof-only-functions": true, "perf-prof": true,
		"perf-prof-unwinding-info": true, "abort-on-uncaught-exception": true}
	nodeUnread = map[string]bool{"experimental-policy": true, "policy-integrity": true, "openssl-config": true,
		"snapshot-blob": true, "run": true, "experimental-config-file": true, "experimental-default-config-file": true}
)

// nodeRan is a script node ran on a command line and the arguments it gave that script.
type nodeRan struct {
	script string
	args   []string
}

// runNodeLine starts node (nodePath) with args in a directory of its own under base, each "@DIR@" in args replaced by that
// directory's path, holding every nodeWords script, node_modules/-x.js, cfg.json, a snapshot configuration whose
// builder is b.js, and sea.json, a single executable's configuration that builds a snapshot from b.js, with stdin
// empty, and removes the directory once node is done (a snapshot is a 4 MB blob there). It returns the args node ran,
// what node ran as its main module, a zero nodeRan for none, and the modules it loaded before it; a test runner's
// children, other processes, do not count.
func runNodeLine(nodePath, base string, args []string) (argv []string, main nodeRan, pre []nodeRan, err error) {
	dir, err := os.MkdirTemp(base, "n")
	if err != nil {
		return nil, nodeRan{}, nil, err
	}
	defer os.RemoveAll(dir)
	argv = make([]string, len(args))
	for i, a := range args {
		argv[i] = strings.ReplaceAll(a, "@DIR@", dir)
	}
	if err := os.Mkdir(filepath.Join(dir, "node_modules"), 0o700); err != nil {
		return nil, nodeRan{}, nil, err
	}
	for _, name := range append(slices.Clone(nodeWords), filepath.Join("node_modules", "-x.js")) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(nodeMain), 0o600); err != nil {
			return nil, nodeRan{}, nil, err
		}
	}
	for name, cfg := range map[string]string{"cfg.json": `{"builder":"b.js"}`,
		"sea.json":         `{"main":"b.js","output":"sea.blob","useSnapshot":true}`,
		"node.json":        `{"nodeOptions":{"import":["./b.js"]}}`,
		"evil.json":        `{"nodeOptions":{"import":["./b.js"]}}`,
		"evil.env":         `NODE_OPTIONS="--require ./b.js"`,
		"node.config.json": `{"nodeOptions":{"import":["./b.js"]}}`} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(cfg), 0o600); err != nil {
			return nil, nodeRan{}, nil, err
		}
	}
	arg0 := nodePath
	if len(argv) > 0 && strings.HasPrefix(argv[0], "@ARGV0@") {
		arg0 = strings.TrimPrefix(argv[0], "@ARGV0@")
		argv = argv[1:]
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, nodePath, argv...)
	cmd.Args[0] = arg0
	cmd.Dir, cmd.Env = dir, []string{"HOME=" + dir, "TMPDIR=" + dir, "PATH=/usr/bin:/bin"}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return nil, nodeRan{}, nil, err
	}
	_ = cmd.Wait() // node's exit status is not the probe: what it ran is
	pid := strconv.Itoa(cmd.Process.Pid)
	for _, line := range strings.Split(out.String(), "\n") {
		kind, rest, _ := strings.Cut(line, " ")
		rest, ok := strings.CutPrefix(rest, pid+" ")
		if !ok || kind != "ran" && kind != "pre" {
			continue
		}
		var got []string
		if err := json.Unmarshal([]byte(rest), &got); err != nil || len(got) == 0 {
			return nil, nodeRan{}, nil, fmt.Errorf("node printed %q: %v", line, err)
		}
		if kind == "ran" {
			main = nodeRan{got[0], got[1:]}
		} else {
			pre = append(pre, nodeRan{got[0], got[1:]})
		}
	}
	return argv, main, pre, nil
}

// holdNodeLines runs each line under node (bin), six at a time, and holds the row to each script node ran, the main
// module and each it loaded before it (nodeLineHolds). It returns how many lines ran a main module and how many loaded
// a module before it; a line that fails is reported, as node ran it.
func holdNodeLines(t *testing.T, bin string, lines [][]string) (mains, loads int) {
	t.Helper()
	base := t.TempDir()
	attested := nodeAttestedBuild(t, bin)
	ran, loaded := make([]bool, len(lines)), make([]bool, len(lines))
	bad := make([]string, len(lines))
	ranArgv := slices.Clone(lines)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, args := range lines {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			argv, main, pre, err := runNodeLine(bin, base, args)
			if err != nil {
				bad[i] = "probe: " + err.Error()
				return
			}
			ranArgv[i] = argv
			ran[i], loaded[i] = main.script != "", len(pre) > 0
			for _, r := range append(pre, main) {
				if r.script != "" && bad[i] == "" {
					bad[i] = nodeLineHolds(t, append([]string{"node"}, argv...), r, attested)
				}
			}
		}()
	}
	wg.Wait()
	for i := range lines {
		if bad[i] != "" {
			t.Errorf("node %s: %s", strconv.Quote(strings.Join(ranArgv[i], " ")), bad[i])
		}
		if ran[i] {
			mains++
		}
		if loaded[i] {
			loads++
		}
	}
	return mains, loads
}

// nodeLineHolds checks the row's reading of argv, a node command line on which node ran r: a deny entry naming the
// script refuses the line, the dispatch gives the script the arguments node gives it (or the line fails closed), and no
// prefix of argv is settled as anything but refused, so a staged read cannot stop short of the script. It returns ""
// when all three hold, else what fails. Unknown builds are checked against
// master plus raw pre-scanners instead of claiming the pinned inventory proof.
func nodeLineHolds(t *testing.T, argv []string, r nodeRan, attested string) string {
	p, err := execmatch.Parse(r.script, execmatch.ListDeny, Builtin())
	if err != nil {
		return "deny: [" + r.script + "]: " + err.Error()
	}
	ix := execmatch.NewIndex(Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{})
	f := facts("/usr/bin/node", "node", argv...)
	f.NodeVersion = attested
	if attested == "" {
		want := nodeMasterRules(t, "deny: "+r.script).Decide(&f)
		got := ix.Decide(&f)
		if nodeArgvRewrite(argv) {
			if got.Rule() != execmatch.RuleCommandUnresolved {
				return "unknown build did not refuse a raw pre-scan token"
			}
		} else if got.Outcome != want.Outcome || got.Rule() != want.Rule() {
			return "unknown build differs from master: " + decided(got) + ", want " + decided(want)
		}
		// Unknown runtimes keep master's residuals. Do not assert the full
		// inventory's real-script property for an unmeasured runtime.
		return ""
	}
	if res := ix.Decide(&f); res.Outcome != execmatch.OutcomeRefused {
		return "node ran " + r.script + ", and deny: [" + r.script + "] gives " + decided(res)
	}
	dispatched := false
	for _, inv := range ix.Interpretations(&f) {
		if inv.Via == execmatch.ViaOverflow || inv.Via == execmatch.ViaInterpreter && inv.Tool == r.script && slices.Equal(inv.Tokens, r.args) {
			dispatched = true
		}
	}
	if !dispatched {
		return "node ran " + r.script + " " + strings.Join(r.args, " ") + ", and no interpretation dispatches that"
	}
	for k := 1; k < len(argv); k++ {
		pf := facts("/usr/bin/node", "node", argv[:k]...)
		pf.ArgvComplete = false
		pf.NodeVersion = attested
		if res := ix.Decide(&pf); res.Final && res.Outcome != execmatch.OutcomeRefused {
			return "node ran " + r.script + ", and the prefix " + strconv.Quote(strings.Join(argv[:k], " ")) + " is settled " + decided(res)
		}
	}
	return ""
}

// nodeBin selects an inventoried Node version, skipping without Node, under -short,
// or on another version. TestNodeInventoryDifferential still runs its safe execution
// samples on unpinned versions; TestNodeRowTable checks both inventories offline.
func nodeBin(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node installed")
	}
	if testing.Short() {
		t.Skip("starts node a few hundred times")
	}
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		t.Fatalf("node --version: %v", err)
	}
	if v := strings.TrimSpace(string(out)); !slices.Contains(nodeVersions, v) {
		t.Skipf("node %s is outside the versioned inventories %v", v, nodeVersions)
	}
	return bin
}

// TestNodeRowSpellingsDifferential holds every spelling of every option the row lists to the installed node (ADR 0048
// R12), through what node runs: each long name as written and with `_` for `-`, and each letter, in front of a word
// and a.js b.js; each name and letter, and each name with an attached value, in front of -x.js a.js, which node runs
// only past the end of its options; and each name negated in front of a word, but a value option's, which node refuses.
// Wherever node runs a script, the row reads it as nodeLineHolds says. An option that checks its value takes one node
// accepts (nodeValueOf), one node refuses without another option has it in front (nodeNeeds), and nodeUnsafe and
// nodeUnread are not run.
func TestNodeRowSpellingsDifferential(t *testing.T) {
	bin := nodeBin(t)
	var lines [][]string
	for _, o := range Builtin().Lookup("node").Root.Opts {
		if nodeUnsafe[o.Name] || nodeUnread[o.Name] || nodeSkipV8Probe(o.Name) {
			continue
		}
		value := nodeValueOf[o.Name]
		if value == "" {
			value = "c.js"
		}
		before := nodeNeeds[o.Name]
		for _, s := range spellings(o) {
			for i, sp := range underscored(s) {
				lines = append(lines, slices.Concat(before, []string{sp, value, "a.js", "b.js"}))
				if i > 0 {
					continue
				}
				lines = append(lines, slices.Concat(before, []string{sp, "-x.js", "a.js"}))
				if name, long := strings.CutPrefix(sp, "--"); long {
					lines = append(lines, slices.Concat(before, []string{sp + "=" + value, "-x.js", "a.js"}))
					if o.Arg != execmatch.ArgRequired {
						lines = append(lines, slices.Concat(before, []string{"--no-" + name, value, "a.js"}))
					}
				}
			}
		}
	}
	if scripts, _ := holdNodeLines(t, bin, lines); scripts < len(lines)/3 {
		t.Fatalf("node ran a script on %d of %d lines: the probe proves little", scripts, len(lines))
	}
}

// TestNodeRowCodeDifferential holds the node row's reading of code to the installed node (ADR 0048 R12): -e's, -p's,
// --print's, --no-print's and -pe's, each in its forms, alone and with -i, --interactive=1, --build_snapshot,
// --no-interactive and both orders of -i and --no-interactive, placed before and after the code, in front of a.js b.js,
// --title t a.js b.js and -- a.js b.js; and --build-snapshot-config and --experimental-sea-config, under which node runs
// the script their file names.
// Wherever node runs a script, the row reads it as nodeLineHolds says: it never reads code where node runs the script.
// Where node runs none, the row may still read a script (-i then --no-interactive), the refusing direction.
func TestNodeRowCodeDifferential(t *testing.T) {
	bin := nodeBin(t)
	modes := [][]string{nil, {"-i"}, {"--interactive=1"}, {"--build_snapshot"}, {"--no-interactive"}, {"--no-interactive", "-i"},
		{"-i", "--no_interactive"}}
	codes := [][]string{{"-e", "0"}, {"-p", "0"}, {"--print=v", "0"}, {"--no-print", "0"}, {"--no_print", "0"}, {"-pe", "0"},
		{"-p"}, {"--print=v"}, {"--no-print"}}
	tails := [][]string{{"a.js", "b.js"}, {"--title", "t", "a.js", "b.js"}, {"--", "a.js", "b.js"}}
	var lines [][]string
	for _, m := range modes {
		for _, c := range codes {
			for _, tl := range tails {
				lines = append(lines, slices.Concat(m, c, tl))
				if m != nil {
					lines = append(lines, slices.Concat(c, m, tl))
				}
			}
		}
	}
	// Under --build-snapshot-config node runs the configuration's builder, b.js, and neither the code nor a.js, and under
	// --experimental-sea-config it runs sea.json's main, b.js, to build the snapshot: the row cannot read a script named
	// in a file, and refuses the line command-unresolved.
	lines = append(lines, []string{"--build-snapshot-config", "cfg.json", "a.js"}, []string{"-e", "0", "--build_snapshot_config=cfg.json", "a.js"},
		[]string{"--experimental-sea-config", "sea.json", "a.js"}, []string{"-e", "0", "--experimental_sea_config=sea.json"})
	// Both answers must occur, or the probe proves little: node runs the script under -i and before --, and runs none
	// for plain code.
	if scripts, _ := holdNodeLines(t, bin, lines); scripts < len(lines)/3 || scripts > len(lines)-len(lines)/10 {
		t.Fatalf("node ran a script on %d of %d lines: the probe proves little", scripts, len(lines))
	}
}

// TestNodeRowModulesDifferential holds the node row's reading of the files node loads to the installed node (ADR 0048
// R12): a module -r, --require=, --import, --import=, --loader, --experimental-loader=, and --test-reporter under --test
// name, in each spelling node may resolve, as a path, without its .js, with dot segments and a trailing slash, as an
// absolute path, a file: URL and a `//localhost` path, with a query, a fragment, a %-escape, a backslash, a space at
// either end or a newline, as a data: URL, a built-in, a bare name, and `\-x.js`; and the script itself in the
// spellings of a path. Wherever node runs a script, the row reads it as nodeLineHolds says: a spelling the row cannot
// resolve as node does is refused command-unresolved.
func TestNodeRowModulesDifferential(t *testing.T) {
	bin := nodeBin(t)
	opts := [][]string{{"-r", "M"}, {"--require=M"}, {"--import", "M"}, {"--import=M"}, {"--loader", "M"},
		{"--experimental-loader=M"}, {"--test", "--test-reporter", "M"}, {"--test-reporter=M", "--test"}}
	modules := []string{"./c.js", "./c", "c.js", "./c.js/", "./c.js/.", "./x/../c.js", "./x/./../c.js/", "@DIR@/c.js",
		"@DIR@/x/../c", "file://@DIR@/c.js", "file://@DIR@/c.js?x", "//localhost@DIR@/c.js", "./c.js?x", "./c.js#x",
		"./c.js?x#y", "./c%2Ejs", "./%63.js", "./x/%2e%2e/c.js", `./x/..\c.js`, `.\c.js`, " ./c.js", "./c.js ", "./c.\njs",
		"\t./c.js", "data:text/javascript,0", " DATA:text/javascript,0", "node:fs", "fs", `\-x.js`, "node_modules/-x.js",
		"./node_modules/-x", "#c", "c", ".", "./b.js/x/.."}
	tails := [][]string{{"a.js", "b.js"}, {"--", "a.js"}, nil}
	var lines [][]string
	for _, o := range opts {
		for _, m := range modules {
			for _, tl := range tails {
				var l []string
				for _, tok := range o {
					l = append(l, strings.ReplaceAll(tok, "M", m))
				}
				lines = append(lines, append(l, tl...))
			}
		}
	}
	for _, script := range []string{"./a.js/.", "./a.js/x/..", "./a.js/", "./a", "a", "a/", "@DIR@/a.js", "@DIR@/x/../a",
		"./x/../a.js/.", "./a.js?x", "./a%2Ejs", "-"} {
		lines = append(lines, []string{script, "b.js"}, []string{"--", script, "b.js"}, []string{"-r", "./c", script, "b.js"})
	}
	mains, loads := holdNodeLines(t, bin, lines)
	t.Logf("node ran a main module on %d of %d lines and loaded a module before it on %d", mains, len(lines), loads)
	if mains < len(lines)/5 || loads < len(lines)/5 {
		t.Fatalf("node ran a main module on %d of %d lines and loaded a module before it on %d: the probe proves little", mains, len(lines), loads)
	}
}

// nodeLineUnits are the units the generated lines are built from: each mechanism of node's option parser
// (src/node_options-inl.h), `=`, `_` read as `-`, `--no-`, every alias of node's alias table, the code options, the
// options that change what node runs or end its options, the modules node loads in their spellings, and options node
// does not know, over representative options of each kind; and V8's spellings. W is a word of nodeWords, drawn per
// unit.
var nodeLineUnits = [][]string{
	// code
	{"-e", "W"}, {"--eval", "W"}, {"--eval=W"}, {"-p"}, {"-p", "W"}, {"--print"}, {"--print", "W"}, {"--print=v"},
	{"--print=v", "W"}, {"--no-print"}, {"--no-print", "W"}, {"--no_print", "W"}, {"--no-print=v", "W"}, {"-pe", "W"}, {"-pe"},
	// what node runs
	{"-i"}, {"--interactive"}, {"--interactive=1"}, {"--interactive=0"}, {"--no-interactive"}, {"--no_interactive"},
	{"--build-snapshot"}, {"--build_snapshot"}, {"--build_snapshot=1"}, {"--no-build-snapshot"}, {"--no_build_snapshot"},
	{"--no-build_snapshot"}, {"-c"}, {"--check"}, {"--test"},
	// options that end node's options
	{"--prof-process"}, {"--prof_process"}, {"--no-prof-process"}, {"--no_prof_process"}, {"--prof-process=1"},
	{"--trace-events-enabled"}, {"--trace_events_enabled"}, {"--trace-events-enabled=x"}, {"--trace_events_enabled=W"},
	{"--no-trace-events-enabled"},
	// aliases
	{"-r", "./c.js"}, {"--require", "./c.js"}, {"--require=./W"}, {"-C", "W"}, {"--conditions=W"}, {"--loader", "./c.js"},
	{"--experimental_loader=./c.js"}, {"--debug-port", "0"}, {"--debug_port=0"}, {"--inspect-port", "0"},
	{"--report-directory", "W"}, {"--report_directory=W"}, {"--security-reverts", "W"}, {"--enable-network-family-autoselection"},
	{"--no-enable-network-family-autoselection"}, {"--es-module-specifier-resolution", "W"},
	{"--experimental-specifier-resolution", "W"}, {"--http-parser", "W"}, {"--no-loader", "W"},
	// modules node loads, and files that name a script node runs
	{"-r", "./b"}, {"--require=./x/../c"}, {"-r", `\-x.js`}, {"--import", "./W"}, {"--import", "./c.js?x"}, {"--import=./b.js#h"},
	{"--import", "./x/../c.js"}, {"--import", "./c%2Ejs"}, {"--import", "data:text/javascript,0"}, {"--loader", `./x/..\c.js`},
	{"--experimental-loader=./b.js?x"}, {"--test-reporter", "./c.js"}, {"--test-reporter=./b.js#x"}, {"--test_reporter", "W"},
	{"--test", "--test-reporter", "./W"}, {"--build-snapshot-config", "cfg.json"}, {"--experimental-sea-config", "sea.json"},
	// value options and flags, in their spellings
	{"--title", "W"}, {"--title=W"}, {"--input-type", "commonjs"}, {"--input_type", "commonjs"}, {"--input-type=commonjs"},
	{"--no-input-type"}, {"--unhandled-rejections", "warn"}, {"--dns_result_order", "verbatim"}, {"--disable-proto", "delete"},
	{"--max-http-header-size", "W"}, {"--max_http_header_size=W"}, {"--no-warnings"}, {"--no_warnings"}, {"--warnings"},
	{"--no-deprecation"}, {"--trace-exit"}, {"--trace_exit"}, {"--trace-exit=1"}, {"--experimental-modules", "W"},
	{"--experimental_modules=W"},
	// V8's
	{"--expose-gc"}, {"--expose_gc"}, {"-expose-gc"}, {"-expose_gc"}, {"--noexpose-gc"}, {"--no-expose-gc"}, {"--no_expose_gc"},
	{"--stack-size"}, {"--stack-size=500"}, {"--stack_size=500"}, {"--max-old-space-size=100"}, {"--max_old_space_size", "W"},
	{"--allow-natives-syntax"}, {"--no-opt"}, {"--harmony"},
	// options node does not know
	{"--zzz"}, {"--zzz=1"}, {"--zz_z"}, {"--no-zzz"}, {"-Z"}, {"-zz"},
	// structure
	{"--"}, {"-"}, {""},
}

// nodeLineTails end the generated lines: a script and an argument, the same past `--`, a script alone, nothing, a script
// whose name starts with '-', which node runs only past the end of its options, and a script without its .js or with
// dot segments.
var nodeLineTails = [][]string{{"a.js", "b.js"}, {"--", "a.js", "b.js"}, {"b.js"}, nil, {"-x.js", "a.js"}, {"--", "-x.js"},
	{"./b", "c.js"}, {"./b.js/.", "a.js"}, {"--", "./x/../a", "b.js"}}

// nodeLines draws n command lines with a seeded generator: one to four units, then a tail. A third of the units are a
// spelling of a random option of the row instead: a long name as written or with `_`, negated, with an attached value,
// or a letter, with a word after it where the option takes one.
func nodeLines(seed int64, n int) [][]string {
	rnd := rand.New(rand.NewSource(seed))
	var listed [][]string
	for _, o := range Builtin().Lookup("node").Root.Opts {
		if nodeUnsafe[o.Name] || nodeUnread[o.Name] || nodeSkipV8Probe(o.Name) {
			continue
		}
		value := o.Arg == execmatch.ArgRequired || o.Arg == execmatch.ArgNextWord
		for _, s := range spellings(o) {
			for _, sp := range underscored(s) {
				listed = append(listed, []string{sp})
				if value {
					listed = append(listed, []string{sp, "W"})
				}
				if neg, ok := strings.CutPrefix(sp, "--"); ok {
					// A flag's attached value is v: V8 reads --stack-size=0 as a stack it overflows at once, and aborts.
					listed = append(listed, []string{"--no-" + neg}, []string{sp + "=" + map[bool]string{true: "W", false: "v"}[value]})
				}
			}
		}
	}
	var lines [][]string
	for len(lines) < n {
		var l []string
		for k := 1 + rnd.Intn(4); k > 0; k-- {
			u := nodeLineUnits[rnd.Intn(len(nodeLineUnits))]
			if rnd.Intn(3) == 0 {
				u = listed[rnd.Intn(len(listed))]
			}
			for _, tok := range u {
				l = append(l, strings.ReplaceAll(tok, "W", nodeWords[rnd.Intn(len(nodeWords))]))
			}
		}
		lines = append(lines, append(l, nodeLineTails[rnd.Intn(len(nodeLineTails))]...))
	}
	return lines
}

// TestNodeRowGeneratedDifferential holds the node row to the installed node over generated command lines (ADR 0048
// R12, nodeLines): wherever node runs a script, the row reads it as nodeLineHolds says. TEGO_NODE_DIFF_LINES sets how
// many lines run (default 300; the row was held to 60000 over several seeds when it was written) and
// TEGO_NODE_DIFF_SEED the seed (default 49).
func TestNodeRowGeneratedDifferential(t *testing.T) {
	bin := nodeBin(t)
	n, seed := 300, int64(49)
	var err error
	if s := os.Getenv("TEGO_NODE_DIFF_LINES"); s != "" {
		if n, err = strconv.Atoi(s); err != nil {
			t.Fatalf("TEGO_NODE_DIFF_LINES: %v", err)
		}
	}
	if s := os.Getenv("TEGO_NODE_DIFF_SEED"); s != "" {
		if seed, err = strconv.ParseInt(s, 10, 64); err != nil {
			t.Fatalf("TEGO_NODE_DIFF_SEED: %v", err)
		}
	}
	lines := nodeLines(seed, n)
	scripts, loads := holdNodeLines(t, bin, lines)
	t.Logf("seed %d: node ran a script on %d of %d lines, and loaded a module before it on %d", seed, scripts, len(lines), loads)
	if scripts < len(lines)/5 {
		t.Fatalf("node ran a script on %d of %d lines: the probe proves little", scripts, len(lines))
	}
}

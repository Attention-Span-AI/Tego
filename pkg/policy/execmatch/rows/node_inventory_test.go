// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

var nodeVersions = []string{"v20.19.4", "v22.21.1"}

type nodeInventory struct {
	Version     string
	BuildSHA256 string `json:"build_sha256"`
	Options     map[string]string
	Aliases     map[string][]string
	V8          map[string]string
	Help        []string
	Environment []string
}

func readNodeInventory(t *testing.T, version string) nodeInventory {
	t.Helper()
	b, err := os.ReadFile("testdata/node-" + version + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var data nodeInventory
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	if data.Version != version || len(data.Options) < 150 || len(data.V8) < 500 {
		t.Fatalf("incomplete inventory for %s", version)
	}
	return data
}

// V8's entire inventory includes process-exiting, waiting, tracing and profiling
// flags. Check all of their arities offline; execute a safe sample below instead
// of enabling arbitrary V8 diagnostics (some write outside TMPDIR).
var nodeSampleV8 = []string{
	"allow-natives-syntax", "async-stack-traces", "harmony", "lazy", "maglev", "opt", "predictable", "single-threaded",
	"sparkplug", "stack-size", "trace-deopt", "trace-gc", "trace-opt", "turbofan",
}

func nodeSkipV8Probe(name string) bool {
	return slices.Contains(nodeV8Flags, name) && !slices.Contains(nodeSampleV8, name)
}

// The adversary puts A in the value position for a value option, but B in that
// position for a flag. Misclassifying either class loses the deny on B. These
// checks cover EVERY known option, including aliases, equals, negation, code
// overridden by -i, and options in script argv which must remain script argv.
// Real execution below independently checks representative valid values.
func TestNodeOptionDenyContract(t *testing.T) {
	row := Builtin().Lookup("node")
	ix := rules(t, "allow: a.js *", "deny: b.js")
	counts := map[execmatch.Arg]int{}
	truth := nodeInventoryArities(t)
	for _, o := range row.Root.Opts {
		counts[o.Arg]++
		for _, sp := range spellings(o) {
			t.Run(sp, func(t *testing.T) {
				arity, ok := truth[sp]
				if !ok || arity != o.Arg {
					t.Fatalf("inventory arity %d (%v) != row arity %d", arity, ok, o.Arg)
				}
				args := []string{sp, "./b.js", "./a.js"}
				if arity == execmatch.ArgRequired || arity == execmatch.ArgNextWord {
					args = []string{sp, "./a.js", "./b.js"}
				}
				// -e/-p do not end Node's options: -i after the code
				// makes Node execute B. Stopping at code would bypass it.
				if slices.Contains(row.Interp.Code, o.Name) {
					args = []string{sp, "./a.js", "-i", "./b.js"}
				}
				want := "exec.deny[b.js]"
				if o.Rewrite != nil && o.Rewrite("./a.js") {
					want = execmatch.RuleCommandUnresolved
				}
				check := func(args []string, want string) {
					t.Helper()
					f := facts("/usr/bin/node", "node", append([]string{"node"}, args...)...)
					r := ix.Decide(&f)
					if r.Outcome != execmatch.OutcomeRefused || r.Rule() != want {
						t.Fatalf("%q: %s, want %s", args, decided(r), want)
					}
					// A staged read must never settle on A before seeing B.
					for k := 1; k < len(f.Argv); k++ {
						prefix := f
						prefix.Argv, prefix.ArgvComplete = f.Argv[:k], false
						if r := ix.Decide(&prefix); r.Final && r.Outcome != execmatch.OutcomeRefused {
							t.Fatalf("prefix %q settles %s before B", prefix.Argv, decided(r))
						}
					}
				}
				check(args, want)
				if strings.HasPrefix(sp, "--") && o.Arg != execmatch.ArgNextWord {
					eq := []string{sp + "=./a.js", "./b.js"}
					if slices.Contains(row.Interp.Code, o.Name) {
						eq = []string{sp + "=./a.js", "-i", "./b.js"}
					}
					check(eq, want)
					check([]string{"--no-" + sp[2:], "./b.js", "./a.js"}, "exec.deny[b.js]")
				}
				// Ordinary options after A belong to A. Raw pre-scanner
				// prefixes remain unsafe even in the script's argv.
				f := facts("/usr/bin/node", "node", "node", "./a.js", sp, "./b.js")
				r := ix.Decide(&f)
				unsafeSuffix := row.Interp.ArgvRewrite(f.Argv[1:])
				if unsafeSuffix && (r.Outcome != execmatch.OutcomeRefused || r.Rule() != execmatch.RuleCommandUnresolved) || !unsafeSuffix && r.Outcome != execmatch.OutcomeAllowed {
					t.Fatalf("script argv %q: unexpected %s (unsafe suffix=%v)", f.Argv, decided(r), unsafeSuffix)
				}
			})
		}
	}
	t.Logf("canonical options by arity: flags=%d required=%d attached-optional=%d next-word=%d",
		counts[execmatch.ArgNone], counts[execmatch.ArgRequired], counts[execmatch.ArgOptional], counts[execmatch.ArgNextWord])
}

func TestNodeUnknownStillFailsClosed(t *testing.T) {
	ix := rules(t, "allow: a.js *", "deny: b.js")
	for _, args := range [][]string{
		{"--future-option", "./a.js", "./b.js"},
		{"--stack-trace-limit", "12", "./b.js"},
		{"--stack-trace-limit=12", "./b.js"},
		{"--stack-trace-limit", "--require", "./a.js", "-0", "./b.js"},
	} {
		f := facts("node", "node", append([]string{"node"}, args...)...)
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[b.js]" {
			t.Errorf("%q: %s, want deny B from one of the readings", args, decided(r))
		}
	}
	f := facts("node", "node", "node", "--future-option", "./a.js", "--f0", "--f1", "--f2", "--f3", "--f4", "--f5", "--f6")
	if r := ix.Decide(&f); r.Rule() != execmatch.RuleCommandUnresolved || r.Outcome != execmatch.OutcomeRefused {
		t.Fatalf("unknown option overflow: %s", decided(r))
	}
	for _, args := range [][]string{
		{"--expose-gc", "./a.js", "--ci", "--coverage", "--runInBand", "--silent", "--verbose", "--forceExit", "--detectOpenHandles"},
		{"-e", "0", "--expose-gc", "--no-warnings", "--trace-exit", "--trace-sync-io", "--trace-deprecation", "--trace-warnings", "--zero-fill-buffers"},
		{"-pe", "0", "--expose-gc"},
	} {
		f := facts("node", "node", append([]string{"node"}, args...)...)
		if r := rules(t, "deny: b.js").Decide(&f); r.Outcome != execmatch.OutcomeNone {
			t.Errorf("known options %q: %s, want no overflow", args, decided(r))
		}
	}
	// A genuine unknown after code might override code; retain the bound.
	f.Argv = []string{"node", "-e", "0", "--f0", "--f1", "--f2", "--f3", "--f4", "--f5", "--f6"}
	if r := ix.Decide(&f); r.Rule() != execmatch.RuleCommandUnresolved {
		t.Errorf("unknown options after code: %s", decided(r))
	}
}

// This does not skip on an unpinned installed Node: the execution samples below
// still run there. Exact inventory equality is required only for attested builds;
// another architecture/build reporting the same version may have different options.
func TestNodeInventoryDifferential(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node installed")
	}
	nodeOutput := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, nodePath, args...).Output()
		if err != nil {
			t.Fatalf("node %q: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	v := nodeOutput("--version")
	attested := nodeAttestedBuild(t, nodePath)
	if attested != "" {
		data := readNodeInventory(t, v)
		const dump = "const {internalBinding}=require('internal/test/binding');const b=internalBinding('options'),i=b.getCLIOptionsInfo();" +
			"const n=Object.fromEntries(Object.entries(b.types).map(([k,v])=>[v,k]));process.stdout.write(JSON.stringify({" +
			"options:Object.fromEntries([...i.options].filter(([k])=>k.startsWith('--')).map(([k,o])=>[k,n[o.type]])),aliases:Object.fromEntries(i.aliases)}))"
		var live nodeInventory
		if err := json.Unmarshal([]byte(nodeOutput("--expose-internals", "--no-warnings", "-e", dump)), &live); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(live.Options, data.Options) || !reflect.DeepEqual(live.Aliases, data.Aliases) {
			t.Fatal("installed Node's option/alias table differs from captured inventory")
		}
		live.V8 = map[string]string{}
		for _, m := range regexp.MustCompile(`(?m)^  --([\w-]+) \([^\n]*\)\n\s+type: (\w+)`).FindAllStringSubmatch(nodeOutput("--v8-options"), -1) {
			live.V8[m[1]] = m[2]
		}
		if !reflect.DeepEqual(live.V8, data.V8) {
			t.Fatal("installed Node's V8 inventory differs from captured inventory")
		}
		for _, line := range strings.Split(nodeOutput("--help"), "\n") {
			if regexp.MustCompile(`^  (?:--|-[A-Za-z],)`).MatchString(line) {
				live.Help = append(live.Help, strings.ReplaceAll(strings.TrimSpace(line), " (default)", ""))
			}
		}
		if err := json.Unmarshal([]byte(nodeOutput("-p", "JSON.stringify([...process.allowedNodeEnvironmentFlags].sort())")), &live.Environment); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(live.Help, withoutNodeDefaults(data.Help)) || !slices.Equal(live.Environment, data.Environment) {
			t.Fatal("installed Node's help/environment flags differ from captured inventory")
		}
	}
	// These must actually execute B, rather than merely reject a malformed
	// option before execution. An allow on A must never mask that deny.
	contract := rules(t, "allow: a.js *", "deny: b.js")
	cases := map[string][]string{
		"flag":                 {"--no-warnings", "b.js", "a.js"},
		"separate value":       {"--title", "a.js", "b.js"},
		"attached value":       {"--title=a.js", "b.js"},
		"optional bare":        {"--inspect-port=0", "--inspect", "b.js", "a.js"},
		"optional attached":    {"--inspect=127.0.0.1:0", "b.js", "a.js"},
		"V8 attached":          {"--max-old-space-size=128", "b.js", "a.js"},
		"V8 separate":          {"--max-old-space-size", "--require", "./a.js", "-0", "b.js"},
		"code override":        {"-e", "0", "-i", "b.js", "a.js"},
		"print before option":  {"-p", "--title", "a.js", "b.js"},
		"exact alias override": {"-pe", "0", "-i", "b.js"},
		"script owns options":  {"--", "b.js", "--require", "a.js"},
	}
	switch v {
	case "v22.21.1":
		cases["version conflict attached"] = []string{"--stack-trace-limit=12", "b.js"}
	case "v20.19.4":
		cases["version conflict forwarded"] = []string{"--stack-trace-limit", "--require", "./a.js", "-0", "b.js"}
	}
	base := t.TempDir()
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			argv, main, _, err := runNodeLine(nodePath, base, args)
			if err != nil || main.script != "b.js" {
				t.Fatalf("%s %q: ran %+v, error %v; must execute B to prove this case", v, argv, main, err)
			}
			argv = append([]string{"node"}, argv...)
			f := facts("node", "node", argv...)
			f.NodeVersion = attested
			want := "exec.deny[b.js]"
			if attested == "" {
				want = nodeMasterRules(t, "allow: a.js *", "deny: b.js").Decide(&f).Rule()
			}
			if r := contract.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != want {
				t.Fatalf("real Node ran B, allow A / deny B gave %s", decided(r))
			}
			if bad := nodeLineHolds(t, argv, main, attested); bad != "" {
				t.Fatal(bad)
			}
		})
	}
	if v == "v22.21.1" {
		for _, args := range [][]string{
			{"--experimental-config-file=node.json", "a.js"},
			{"--experimental-default-config-file", "a.js"},
			{"--test", "--experimental-test-isolation=none", "a.js", "b.js"},
			{"--entry-url", "./b.js?ignored"},
		} {
			argv, main, pre, err := runNodeLine(nodePath, base, args)
			if err != nil || main.script != "b.js" && !slices.ContainsFunc(pre, func(r nodeRan) bool { return r.script == "b.js" }) {
				t.Fatalf("%q must execute B to prove the unlocatable case: main=%+v pre=%+v err=%v", args, main, pre, err)
			}
			f := facts("node", "node", append([]string{"node"}, argv...)...)
			f.NodeVersion = attested
			r := contract.Decide(&f)
			want := execmatch.RuleCommandUnresolved
			if attested == "" && !nodeArgvRewrite(f.Argv) {
				want = nodeMasterRules(t, "allow: a.js *", "deny: b.js").Decide(&f).Rule()
			}
			if r.Rule() != want {
				t.Fatalf("%q executes B outside entry dispatch: %s, want %s", args, decided(r), want)
			}
		}
	}
	lines := [][]string{
		{"--expose-gc", "a.js", "--ci", "--coverage", "--runInBand", "--silent", "--verbose", "--forceExit", "--detectOpenHandles"},
		{"--title", "a.js", "b.js"}, {"--title=a.js", "b.js"},
		{"--inspect-port=0", "--inspect", "b.js", "a.js"},
		{"--inspect=127.0.0.1:0", "b.js", "a.js"},
		{"--max-old-space-size=128", "b.js", "a.js"}, {"--stack-size=984", "b.js", "a.js"},
		{"--max-old-space-size", "--require", "./a.js", "-0", "b.js"},
		{"--max-old-space-size", "--require", "./a.js", "-0", "b.js"},
		{"--stack-trace-limit=12", "b.js"}, {"--stack-trace-limit", "12", "b.js"},
		{"--stack-trace-limit", "--require", "./a.js", "-0", "b.js"},
		{"-r", "./a.js", "b.js"}, {"--import=./a.js", "b.js"}, {"--loader", "./a.js", "b.js"},
		{"--env-file-if-exists=missing.env", "b.js"},
		{"-e", "0", "-i", "b.js", "a.js"}, {"-p", "--title", "a.js", "b.js"},
		{"-pe", "0", "-i", "b.js"}, {"--", "b.js", "--require", "a.js"},
		{"-", "b.js", "--require", "a.js"}, {"-c", "b.js"},
		{"--input-type=commonjs", "-e", "0"},
		{"--trace-gc", "b.js"}, {"--no-lazy", "b.js"}, {"--random-seed=1", "b.js"},
	}
	if v == "v22.21.1" {
		lines = append(lines, []string{"--test-skip-pattern", "a.js", "b.js"},
			[]string{"--permission", "--allow-fs-read=*", "b.js"},
			[]string{"--entry-url", "./b.js?ignored"})
	}
	mains, loads := holdNodeLines(t, nodePath, lines)
	if mains < 15 || loads < 4 {
		t.Fatalf("%s: only %d main scripts and %d preloads on %d lines", v, mains, loads, len(lines))
	}
	t.Logf("%s: %d lines, %d main scripts, %d lines with preloads", v, len(lines), mains, loads)
}

func withoutNodeDefaults(lines []string) []string {
	out := slices.Clone(lines)
	for i := range out {
		out[i] = strings.ReplaceAll(out[i], " (default)", "")
	}
	return out
}

// Independent arity oracle from the captured runtime tables, including alias
// expansion and the boundary between Node's argv parser and V8's parser.
func nodeInventoryArities(t *testing.T) map[string]execmatch.Arg {
	t.Helper()
	out := map[string]execmatch.Arg{}
	for _, version := range nodeVersions {
		data := readNodeInventory(t, version)
		for name := range data.V8 {
			out["--"+name] = execmatch.ArgNone
		}
		for name, typ := range data.Options {
			arity := execmatch.ArgRequired
			if typ == "kBoolean" || typ == "kNoOp" || typ == "kV8Option" {
				arity = execmatch.ArgNone
			}
			out[name] = arity
		}
		for name, exp := range data.Aliases {
			if strings.HasSuffix(name, " <arg>") {
				out[strings.TrimSuffix(name, " <arg>")] = execmatch.ArgNextWord
			}
			if strings.HasSuffix(name, "=") && len(exp) == 2 && exp[0] == "--inspect-port" {
				out[strings.TrimSuffix(name, "=")] = execmatch.ArgOptional
			}
		}
		for name, exp := range data.Aliases {
			if len(exp) == 1 && strings.HasPrefix(exp[0], "--") {
				out[name] = out[exp[0]]
			}
			if len(exp) == 2 && !strings.HasSuffix(name, "=") {
				out[name] = execmatch.ArgNone
			}
		}
	}
	return out
}

// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"bytes"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// TestMoreRows holds each row past the first set to the invocations its manual or probe gives (ADR 0048 (2),
// Adversarial checks): the subcommand is located behind every global option, alias and prefix the row lists.
func TestMoreRows(t *testing.T) {
	cases := []struct {
		rule  string
		line  string
		match bool
	}{
		// npm, probed 9.2.0.
		{"deny: npm publish", "npm publish", true},
		{"deny: npm publish", "npm pub", true},
		{"deny: npm publish", "npm --loglevel warn publish", true},
		{"deny: npm publish", "npm --foo publish", true},
		{"deny: npm publish", "npm -ws publish", true},
		{"deny: npm publish", "npm --color publish", true},
		{"deny: npm publish", "npm --color always publish", true},
		{"deny: npm publish", "npm p", true},
		{"deny: npm publish", "npm pack", false},
		{"deny: npm install", "npm i left-pad", true},
		{"deny: npm install", "npm add left-pad", true},
		{"deny: npm install", "npm insta left-pad", true},
		{"deny: npm install", "npm isntall left-pad", true},
		{"deny: npm install", "npm install-test", false},
		{"deny: npm run-script", "npm runScript build", true},
		{"deny: npm run-script", "npm run build", true},
		{"deny: npm install-ci-test", "npm sit", true},
		{"deny: npx cowsay", "npx cowsay hi", true},
		{"deny: npx cowsay", "npx --yes cowsay hi", true},
		// go, probed 1.27.1.
		{"deny: go mod tidy", "go mod tidy -v", true},
		{"deny: go mod tidy", "go -C /src mod tidy", true},
		{"deny: go get", "go get -u example.com/x", true},
		{"deny: go test -race", "go test -count=1 -race ./...", true},
		{"deny: go test -race", "go test ./... -race", true}, // go test reads known flags after the package list
		{"deny: go test -exec", "go test . -exec /tmp/x", true},
		{"deny: go test -race", "go test . -args -race", false}, // -args ends go test's flags
		{"deny: go test -race", "go test . -- -race", false},
		{"deny: go build -race", "go build . -race", false}, // Go's flag package stops at the first operand
		// systemctl, probed 257.
		{"deny: systemctl stop", "systemctl --user stop x.service", true},
		{"deny: systemctl stop", "systemctl stop --now x", true},
		{"deny: systemctl stop", "systemctl -t service stop x", true},
		{"deny: systemctl stop", "systemctl condstop x", true},
		{"deny: systemctl reboot", "systemctl --no-wall reboot", true},
		{"deny: systemctl stop", "systemctl status stop", false},
		// documented rows.
		{"deny: kubectl delete", "kubectl -n prod delete pod x", true},
		{"deny: kubectl delete", "kubectl --context=c delete pod x", true},
		{"deny: kubectl delete", "kubectl get pods -n delete", false},
		{"deny: kubectl create secret generic", "kubectl create secret generic s --from-literal=a=b", true},
		{"deny: kubectl delete --namespace=prod*", "kubectl delete pod x -n production", true},
		{"deny: kubectl delete --namespace=prod*", "kubectl delete pod x -n dev", false},
		{"deny: docker container rm", "docker rm -f x", true},
		{"deny: docker container rm", "docker container remove x", true},
		{"deny: docker rm", "docker container rm x", true},
		{"deny: docker image rm", "docker rmi x", true},
		{"deny: docker run --privileged", "docker run --privileged alpine", true},
		{"deny: docker run --privileged", "docker run alpine sh --privileged", false},
		{"deny: podman rm", "podman --log-level debug rm x", true},
		{"deny: pip install", "pip --proxy p install x", true},
		{"deny: pip install", "pip3 install --user x", true},
		{"deny: pip install", "pip ins x", false},
		{"deny: cargo publish", "cargo +nightly publish", true},
		{"deny: cargo publish", "cargo -Z unstable-options publish", true},
		{"deny: cargo remove", "cargo rm serde", true},
		{"deny: cargo publish", "cargo --config alias.x=publish x", true},
		{"deny: gh repo delete", "gh repo delete o/r --yes", true},
		{"deny: gh pr merge", "gh pr merge 1", true},
		{"deny: gh pr create", "gh pr new", true},
		{"deny: terraform destroy", "terraform -chdir=infra destroy -auto-approve", true},
		{"deny: terraform apply -destroy", "terraform apply -destroy", true},
		{"deny: terraform state rm", "terraform state rm aws_instance.x", true},
		{"deny: tofu destroy", "tofu destroy", true},
		{"deny: helm uninstall", "helm del x", true},
		{"deny: helm uninstall", "helm -n prod uninstall x", true},
		{"deny: aws s3 rm", "aws --profile p s3 rm s3://b/k", true},
		{"deny: aws s3 rm", "aws s3 rm s3://b --recursive", true},
		{"deny: aws s3 rm", "aws s3 ls", false},
		{"deny: gcloud compute instances delete", "gcloud compute instances delete vm --zone z", true},
		{"deny: gcloud compute instances delete", "gcloud beta compute instances delete vm", true},
		{"deny: gcloud compute instances delete", "gcloud --project p compute instances delete vm", true},
		{"deny: gcloud projects delete", "gcloud --flags-file=f.yaml projects list", true},
		{"deny: pnpm publish", "pnpm -C pkg publish", true},
		{"deny: yarn npm publish", "yarn npm publish", true},
		{"deny: yarn publish", "yarn npm publish", false},
	}
	for _, c := range cases {
		ix := rules(t, c.rule)
		r := run(ix, words(c.line)...)
		if got := r.Outcome == execmatch.OutcomeRefused; got != c.match {
			t.Errorf("%s / %s: %s, want refused %v", c.rule, c.line, decided(r), c.match)
		}
	}
	// argv[0] forms.
	ix := rules(t, "deny: systemctl reboot")
	if r := ix.Decide(&execmatch.Facts{Requested: "/usr/sbin/reboot", Image: "systemctl", Argv0: "reboot", Argv: []string{"reboot"}, ArgvComplete: true}); r.Outcome != execmatch.OutcomeRefused {
		t.Errorf("reboot as systemctl: %s", decided(r))
	}
	ix = rules(t, "deny: npm publish")
	f := execmatch.Facts{Requested: "/usr/bin/node", Image: "node", Argv0: "node", Argv: []string{"node", "/usr/share/nodejs/npm/bin/npm-cli.js", "publish"}, ArgvComplete: true}
	if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Via != execmatch.ViaInterpreter {
		t.Errorf("node npm-cli.js publish: %s via %s", decided(r), r.Via)
	}
	f = execmatch.Facts{Requested: "/usr/bin/npm", Path: "/usr/bin/npm", Image: "npm-cli.js", Argv0: "npm", Argv: []string{"npm", "publish"}, ArgvComplete: true,
		Form: execmatch.FormScript, Interp: []execmatch.Stage{{Path: "/usr/bin/env", Arg: "node"}}}
	if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
		t.Errorf("npm publish as a script: %s", decided(r))
	}
	ix = rules(t, "allow: npm test")
	if r := run(ix, "npm", "p"); r.Outcome != execmatch.OutcomeRefused {
		t.Errorf("an allow entry needs a unique resolution; npm p: %s", decided(r))
	}
	if r := run(ix, "npm", "tst"); r.Outcome != execmatch.OutcomeAllowed {
		t.Errorf("npm tst is npm test: %s", decided(r))
	}
}

// TestRowsDocumented: every row records its version, documentation and source, and the rows the ADR lists as probed
// say so.
func TestRowsDocumented(t *testing.T) {
	probed := map[string]bool{"git": true, "rm": true, "npm": true, "npx": true, "go": true, "systemctl": true, "python": true, "node": true, "sh": true, "bash": true, "dash": true, "busybox": true, "coreutils": true}
	for _, r := range Builtin().All() {
		if r.Version == "" || r.Docs == "" || r.Root == nil {
			t.Errorf("row %s: version %q, docs %q", r.Tool, r.Version, r.Docs)
		}
		if got := r.Source == execmatch.SourceProbed; got != probed[r.Tool] {
			t.Errorf("row %s: source %s", r.Tool, r.Source)
		}
	}
}

// TestNpmRowDifferential holds the npm row's command resolution to the installed npm: for every command, alias and
// a set of prefixes, the command npm resolves is among the row's readings, and a single reading is npm's.
func TestNpmRowDifferential(t *testing.T) {
	npm, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("no npm installed")
	}
	if testing.Short() {
		t.Skip("starts npm a few hundred times")
	}
	dir := t.TempDir()
	describe := func(tok string) string {
		cmd := exec.Command(npm, tok, "--help")
		cmd.Dir = dir
		cmd.Env = []string{"HOME=" + dir, "PATH=/usr/bin:/bin", "NO_COLOR=1", "npm_config_update_notifier=false"}
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		_ = cmd.Run()
		first, _, _ := strings.Cut(out.String(), "\n")
		return strings.TrimSpace(first)
	}
	byDesc := map[string]string{}
	toks := map[string]bool{}
	for _, c := range npmCommands {
		toks[c] = true
	}
	for a := range npmAliases {
		toks[a] = true
	}
	for _, w := range []string{"publish", "install", "uninstall", "unpublish", "view", "exec", "run-script", "version", "test", "update", "dedupe", "deprecate"} {
		for i := 1; i < len(w); i++ {
			toks[w[:i]] = true
		}
	}
	var list []string
	for tk := range toks {
		list = append(list, tk)
	}
	sort.Strings(list)
	desc := make([]string, len(list))
	cdesc := make([]string, len(npmCommands))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, tk := range list {
		wg.Add(1)
		sem <- struct{}{}
		go func() { defer func() { <-sem; wg.Done() }(); desc[i] = describe(tk) }()
	}
	for i, c := range npmCommands {
		wg.Add(1)
		sem <- struct{}{}
		go func() { defer func() { <-sem; wg.Done() }(); cdesc[i] = describe(c) }()
	}
	wg.Wait()
	for i, c := range npmCommands {
		if _, dup := byDesc[cdesc[i]]; !dup {
			byDesc[cdesc[i]] = c
		}
	}
	nz := execmatch.NewNormalizer(Npm(), nil)
	checked := 0
	for i, tk := range list {
		want, known := byDesc[desc[i]]
		readings := nz.Normalize([]string{tk})
		var got []string
		for _, r := range readings {
			if len(r.Path) > 0 {
				got = append(got, r.Path[0])
			}
		}
		if !known {
			continue // npm: unknown command, or a command whose description another shares
		}
		checked++
		found := false
		for _, g := range got {
			if g == want || byDesc[cdesc[indexOf(npmCommands, g)]] == want {
				found = true
			}
		}
		if !found {
			t.Errorf("npm resolves %q to %s; the row reads %v", tk, want, got)
		}
		if len(got) == 1 && got[0] != want && byDesc[cdesc[indexOf(npmCommands, got[0])]] != want {
			t.Errorf("npm resolves %q to %s; the row's single reading is %s", tk, want, got[0])
		}
	}
	if checked < 100 {
		t.Fatalf("only %d tokens resolved by npm: the probe proves little", checked)
	}
}

// indexOf is the index of s in list, or 0.
func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return 0
}

// TestInterpreterDispatchReadsBothWays: an interpreter's script is its subcommand, and an option in front of it picks
// which token that is, so an option the row does not list is read both ways there, and a deny entry on the entry script
// is not lost to it (ADR 0048 R4). A separate value the row knows (node --env-file, perl -I) is taken, a shell's lone
// `-` ends its options, and readings past the bound refuse the exec rather than dropping its dispatch.
func TestInterpreterDispatchReadsBothWays(t *testing.T) {
	ix := rules(t, "deny: npm publish", "deny: deploy.sh prod")
	const cli = "/usr/share/nodejs/npm/bin/npm-cli.js"
	node := func(argv ...string) execmatch.Facts { return facts("/usr/bin/node", "node", argv...) }
	shell := func(sh string, argv ...string) execmatch.Facts { return facts("/usr/bin/"+sh, sh, argv...) }
	const (
		npmDeny    = "exec.deny[npm publish]"
		deployDeny = "exec.deny[deploy.sh prod]"
		unresolved = "command-unresolved"
	)
	cases := []struct {
		name  string
		facts execmatch.Facts
		want  string
	}{
		{"unknown long option", node("node", "--unlisted", "/tmp/w", cli, "publish"), npmDeny},
		{"unknown short option, no clusters", node("node", "-Z", "/tmp/w", cli, "publish"), npmDeny},
		{"two unknown options", node("node", "--a", "/tmp/w", "--b", "/tmp/x", cli, "publish"), npmDeny},
		{"unknown option as a flag", node("node", "--unlisted", cli, "publish"), npmDeny},
		{"unknown option with an attached value", node("node", "--unlisted=/tmp/w", cli, "publish"), npmDeny},
		{"a listed value option", node("node", "--redirect-warnings", "/tmp/w", cli, "publish"), npmDeny},
		{"listed options in front of npm", node("node", "--no-warnings", "--expose-gc", "--trace-deprecation", "--title", "t", cli, "publish"), npmDeny},
		{"node --env-file v", node("node", "--env-file", "/tmp/e", cli, "publish"), npmDeny},
		{"node --env-file=v", node("node", "--env-file=/tmp/e", cli, "publish"), npmDeny},
		{"node --inspect-port v", node("node", "--inspect-port", "9230", cli, "publish"), npmDeny},
		// A V8 option takes no token of node's: V8 takes its value from the options node hands it, -0 here past node's
		// own --require and --title, and node runs the script after it (probed with --max-old-space-size).
		{"a V8 value option past --require", node("node", "--max-old-space-size", "--require", "./x.js", "-0", cli, "publish"), npmDeny},
		{"a V8 value option past --title", node("node", "--max-old-space-size", "--title", "t", "-0", cli, "publish"), npmDeny},
		{"--stack-size is V8's too", node("node", "--stack-size", "--title", "t", "-1", cli, "publish"), npmDeny},
		{"six unknown options before the script", node("node", "--a", "--b", "--c", "--d", "--e", "--f", cli, "publish"), unresolved},
		// docs/GAPS.md C49: the option's value reading takes the script, so the script's own flags fork too.
		{"one unknown option, six flags past the script", node("node", "--a", "./app.js", "--f0", "--f1", "--f2", "--f3", "--f4", "--f5"), ""},
		{"one unknown option, seven flags past the script", node("node", "--a", "./app.js", "--f0", "--f1", "--f2", "--f3", "--f4", "--f5", "--f6"), unresolved},
		{"no script, seven unknown options", node("node", "-e", "code", "--f0", "--f1", "--f2", "--f3", "--f4", "--f5", "--f6"), unresolved},
		{"-- in front of the script stops the forks", node("node", "--a", "--", "./app.js", "--f0", "--f1", "--f2", "--f3", "--f4", "--f5", "--f6"), ""},
		{"-- in front of the script keeps a deny", node("node", "--a", "--", cli, "publish"), npmDeny},
		// C49: an option the row lists forks nothing, so a script's own flags are not counted, whatever their number.
		{"C49's jest line", node("node", "--expose-gc", "./node_modules/jest/bin/jest.js", "--ci", "--coverage", "--runInBand", "--silent", "--verbose", "--forceExit", "--detectOpenHandles"), ""},
		{"node's options and V8's in front of the script", node("node", "--stack-trace-limit=50", "--experimental-vm-modules", "--no-deprecation", "--frozen-intrinsics", "--allow-natives-syntax", "--no-opt", "./app.js", "--f0", "--f1", "--f2", "--f3", "--f4", "--f5", "--f6"), ""},
		{"another subcommand", node("node", "--unlisted", "/tmp/w", cli, "pack"), ""},
		{"-e is opaque", node("node", "-e", "code", cli, "publish"), ""},
		// -p, --print and --no-print take a word after them as -e's code (node's alias `--print <arg>`, which node
		// applies to the negated name too) and nothing before an option, where node runs the script after its options
		// (each probed on node 20.19.4 with a script in npm's place). An attached =value is dropped, as node drops a
		// boolean's.
		{"-p code is opaque", node("node", "-p", "code", cli, "publish"), ""},
		{"--print=v code is opaque", node("node", "--print=v", "code", cli, "publish"), ""},
		{"--no-print code is opaque", node("node", "--no-print", "code", cli, "publish"), ""},
		{"--no-print takes npm's path as code", node("node", "--no-print", cli, "publish"), ""},
		{"-p before an option", node("node", "-p", "--title", "t", cli, "publish"), npmDeny},
		{"-p before -r", node("node", "-p", "-r", "./x.js", cli, "publish"), npmDeny},
		{"-p before --", node("node", "-p", "--", cli, "publish"), npmDeny},
		{"--print before --", node("node", "--print", "--", cli, "publish"), npmDeny},
		{"--print=v before an option", node("node", "--print=v", "--title", "t", cli, "publish"), npmDeny},
		{"--no-print before an option", node("node", "--no-print", "--title", "t", cli, "publish"), npmDeny},
		{"--no-print before --", node("node", "--no-print", "--", cli, "publish"), npmDeny},
		{"--no-print before a flag", node("node", "--no-print", "--no-warnings", cli, "publish"), npmDeny},
		{"--no-print=1 before an option", node("node", "--no-print=1", "--title", "t", cli, "publish"), npmDeny},
		{"-p before -e: -e's code is opaque", node("node", "--title", "t", "-p", "-e", "code", cli, "publish"), ""},
		// Under -i or --build-snapshot node runs the script after its options and leaves the code unrun, wherever they
		// stand among the options (probed on node 20.19.4).
		{"-i runs the script past -e's code", node("node", "-i", "-e", "1", cli, "publish"), npmDeny},
		{"-i after the code", node("node", "-e", "1", "-i", cli, "publish"), npmDeny},
		{"--interactive=1 with --eval=", node("node", "--interactive=1", "--eval=1", cli, "publish"), npmDeny},
		{"-i with -p's code", node("node", "-i", "-p", "x", cli, "publish"), npmDeny},
		{"-i with --print's code", node("node", "-i", "--print", "x.js", cli, "publish"), npmDeny},
		{"--no-interactive then -i", node("node", "--no-interactive", "-i", "-e", "1", cli, "publish"), npmDeny},
		{"--build-snapshot runs the script past -e's code", node("node", "--build-snapshot", "-e", "1", cli, "publish"), npmDeny},
		// node reads `_` in a name as `-`, so --build_snapshot is --build-snapshot (review of 198d04b9: these let npm
		// publish through, with --no-print's code read as the only thing node runs).
		{"--build_snapshot runs the script past --no-print's code", node("node", "--build_snapshot", "--no-print", "0", cli, "publish"), npmDeny},
		{"--build_snapshot after --title=t", node("node", "--title=t", "--build_snapshot", "--no-print", "0", cli, "publish"), npmDeny},
		{"--build_snapshot after the code", node("node", "--no-print", "0", "--build_snapshot", cli, "publish"), npmDeny},
		{"--build_snapshot=1", node("node", "--build_snapshot=1", "--no-print", "0", cli, "publish"), npmDeny},
		{"--no_build_snapshot leaves the code", node("node", "--build_snapshot", "--no_build_snapshot", "-e", "0", cli, "publish"), npmDeny},
		// An option the row does not list could be another spelling of -i or --build-snapshot: the line is read for its
		// script past the code too.
		{"an unlisted option with code", node("node", "--unlisted", "-e", "0", cli, "publish"), npmDeny},
		{"an unlisted =value option with code", node("node", "--unlisted=1", "-p", "0", cli, "publish"), npmDeny},
		// Under --build-snapshot-config node runs the builder its file names: the script is not in argv.
		{"--build-snapshot-config", node("node", "--build-snapshot-config", "cfg.json", cli, "publish"), unresolved},
		{"--build_snapshot_config=", node("node", "--build_snapshot_config=cfg.json", "-e", "0"), unresolved},
		// node runs a module -r or --import names before the script or code, with the script's arguments, and one --loader
		// names with none (probed: `node -r npm-cli.js app.js --version` prints npm's version).
		{"npm's entry script without .js", node("node", strings.TrimSuffix(cli, ".js"), "publish"), npmDeny},
		{"-r npm's entry script without .js", node("node", "-r", strings.TrimSuffix(cli, ".js"), "app.js", "publish"), npmDeny},
		{"-r runs npm's entry script", node("node", "-r", cli, "app.js", "publish"), npmDeny},
		{"--require= past code", node("node", "--require="+cli, "-e", "0", "x", "publish"), npmDeny},
		{"--import", node("node", "--import", cli, "app.js", "publish"), npmDeny},
		{"-r in front of -- and the script", node("node", "--no-warnings", "-r", cli, "--", "app.js", "publish"), npmDeny},
		{"-r without the script's publish", node("node", "-r", cli, "app.js", "pack"), ""},
		{"a loader's module gets no arguments", node("node", "--loader", cli, "app.js", "publish"), ""},
		{"--no-interactive leaves the code", node("node", "--no-interactive", "-e", "1", cli, "publish"), ""},
		{"-i past the script is the script's", node("node", "-e", "1", cli, "publish", "-i"), ""},
		{"a script past the first", node("node", "--unlisted", "./app.js", cli, "publish"), npmDeny},
		{"a listed flag keeps the first script", node("node", "--trace-exit", "./app.js", cli, "publish"), ""},
		{"three unknown options", node("node", "--a", "--b", "--c", "./app.js"), ""},
		{"perl -I v", facts("/usr/bin/perl", "perl", "perl", "-I", "/tmp/lib", "./deploy.sh", "prod"), deployDeny},
		{"perl -Iv", facts("/usr/bin/perl", "perl", "perl", "-I/tmp/lib", "./deploy.sh", "prod"), deployDeny},
		{"unknown cluster letter", shell("bash", "bash", "-Z", "/tmp/w", "./deploy.sh", "prod"), deployDeny},
		{"bash -", shell("bash", "bash", "-", "./deploy.sh", "prod"), deployDeny},
		{"dash -", shell("dash", "dash", "-", "./deploy.sh", "prod"), deployDeny},
		{"sh -x -", shell("sh", "sh", "-x", "-", "./deploy.sh", "prod"), deployDeny},
		{"bash - ends options", shell("bash", "bash", "-", "-c", "code"), ""},
		{"python - is a script from stdin", facts("/usr/bin/python3", "python3", "python3", "-", "./deploy.sh", "prod"), ""},
	}
	for _, c := range cases {
		r := ix.Decide(&c.facts)
		if c.want == "" {
			if r.Outcome != execmatch.OutcomeNone {
				t.Errorf("%s: %s, want none", c.name, decided(r))
			}
			continue
		}
		if r.Outcome != execmatch.OutcomeRefused || r.Rule() != c.want {
			t.Errorf("%s: %s, want refused %s", c.name, decided(r), c.want)
		}
	}
}

// TestNodePreloadsUnderALoader: given a --loader, node runs each module -r names in its hooks thread too, with no
// arguments, beside the run in the main thread with the script's (probed on 20.19.4: `node -r ./p.js --loader ./h.mjs
// app.js a` runs p.js with [a] and again with []). Under allow: [npm publish], which constrains npm, npm run that way
// with no arguments is unlisted and refused; without a loader it runs with publish alone and is allowed. An --import
// module node does not run in that thread; the row reads it there too, which only refuses more.
func TestNodePreloadsUnderALoader(t *testing.T) {
	ix := rules(t, "allow: npm publish")
	const cli = "/usr/share/nodejs/npm/bin/npm-cli.js"
	for _, c := range []struct {
		argv []string
		want string
	}{
		{[]string{"node", "-r", cli, "app.js", "publish"}, "allowed exec.allow[npm publish]"},
		{[]string{"node", "--loader", "./h.mjs", "-r", cli, "app.js", "publish"}, "refused exec.args[npm]"},
		{[]string{"node", "-r", cli, "--experimental_loader=./h.mjs", "-e", "0", "x", "publish"}, "refused exec.args[npm]"},
		{[]string{"node", "--loader", "./h.mjs", "--import", cli, "app.js", "publish"}, "refused exec.args[npm]"},
	} {
		f := facts("/usr/bin/node", "node", c.argv...)
		if got := decided(ix.Decide(&f)); got != c.want {
			t.Errorf("%s: %s, want %s", strings.Join(c.argv, " "), got, c.want)
		}
	}
}

// TestShebangEmptyArgumentIsAToken: `#!/opt/mytool \0` gives the interpreter an empty element in front of the script, so
// an allow entry whose words are the script alone does not match a vector the tool does not get.
func TestShebangEmptyArgumentIsAToken(t *testing.T) {
	ix := rules(t, "allow: mytool ./s")
	script := func(empty bool) execmatch.Facts {
		return execmatch.Facts{Requested: "s", Path: "./s", Image: "s", Argv0: "./s", Argv: []string{"./s"}, ArgvComplete: true,
			Form: execmatch.FormScript, Interp: []execmatch.Stage{{Path: "/opt/mytool", EmptyArg: empty}}}
	}
	plain := script(false)
	if r := ix.Decide(&plain); r.Outcome != execmatch.OutcomeAllowed {
		t.Errorf("no argument: %s, want allowed", decided(r))
	}
	empty := script(true)
	if r := ix.Decide(&empty); r.Outcome != execmatch.OutcomeRefused {
		t.Errorf("an empty argument: %s, want refused", decided(r))
	}
	if got := empty.ScriptArgv(); len(got) != 3 || got[1] != "" {
		t.Errorf("ScriptArgv = %q, want the empty element kept", got)
	}
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/handoff"
)

// tree writes files (slash-separated path -> content) under a fresh directory and returns it.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// rules is the sorted "file:rule" list of what check finds under root.
func rules(t *testing.T, root string) []string {
	t.Helper()
	fs, err := check(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range fs {
		out = append(out, f.File+":"+f.Rule)
	}
	slices.Sort(out)
	return out
}

// TestTheRepositoryIsIsolated: no harness in this tree can write the invoking user's own ~/.tego or ~/.bash_history.
// This is the guard make precommit and CI run; its findings name the file and line.
func TestTheRepositoryIsIsolated(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("not the repository root: %v", err)
	}
	fs, err := check(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		t.Error(f)
	}
}

// askReadBug is the bug where os.Environ() is evaluated before writeMachineConfig, so the environment
// holds neither isolation variable.
const askReadBug = `package x

import "os"

func newScene(t T, f *F) []string {
	return append(os.Environ(), "TEGO_CONFIG="+writeMachineConfig(t, f))
}
`

const askReadFixed = `package x

import "os"

func newScene(t T, f *F) []string {
	cfg := writeMachineConfig(t, f)
	return append(os.Environ(), "TEGO_CONFIG="+cfg)
}
`

// TestGO1CatchesAnEnvironmentTakenBeforeTheSetenv: GO-1 flags the form that appended 61 lines to the developer's
// chain.log, in one statement or across two, and accepts the form that calls the helper first.
func TestGO1CatchesAnEnvironmentTakenBeforeTheSetenv(t *testing.T) {
	got := rules(t, tree(t, map[string]string{"a_test.go": askReadBug}))
	if !slices.Contains(got, "a_test.go:GO-1") {
		t.Errorf("the one-statement form: %v", got)
	}
	two := strings.Replace(askReadBug, "return append(os.Environ(), \"TEGO_CONFIG=\"+writeMachineConfig(t, f))",
		"env := append(os.Environ(), \"TEGO_CONFIG=x\")\n\twriteMachineConfig(t, f)\n\treturn env", 1)
	if got := rules(t, tree(t, map[string]string{"a_test.go": two})); !slices.Contains(got, "a_test.go:GO-1") {
		t.Errorf("the two-statement form: %v", got)
	}
	if got := rules(t, tree(t, map[string]string{"a_test.go": askReadFixed})); len(got) != 0 {
		t.Errorf("the fixed form: %v", got)
	}
}

// TestGO2AnTegoConfigEntryNeedsTheIsolation: a file that gives a subprocess TEGO_CONFIG and names none of the
// isolation is flagged; one that uses testutil.TegoEnv, names the variable or calls writeMachineConfig is not.
func TestGO2AnTegoConfigEntryNeedsTheIsolation(t *testing.T) {
	bare := "package x\n\nimport \"os\"\n\nvar e = append(os.Environ(), \"TEGO_CONFIG=/c\")\n"
	if got := rules(t, tree(t, map[string]string{"b_test.go": bare})); !slices.Equal(got, []string{"b_test.go:GO-2"}) {
		t.Errorf("bare: %v", got)
	}
	for name, body := range map[string]string{
		"helper": "package x\n\nvar e = testutil.TegoEnv(t, d, \"TEGO_CONFIG=/c\")\n",
		"names":  "package x\n\nvar e = []string{\"TEGO_CONFIG=/c\", \"TEGO_TEST_CHAIN_ANCHOR=/a\"}\n",
		"setter": "package x\n\nfunc f() { _ = writeMachineConfig; _ = \"TEGO_CONFIG=\" }\n",
	} {
		if got := rules(t, tree(t, map[string]string{"c_test.go": body})); len(got) != 0 {
			t.Errorf("%s: %v", name, got)
		}
	}
	// A comment or a Setenv key is not an environment entry.
	inproc := "package x\n\n// TEGO_CONFIG=/c is read in-process.\nfunc f(t T) { t.Setenv(\"TEGO_CONFIG\", \"/c\") }\n"
	if got := rules(t, tree(t, map[string]string{"d_test.go": inproc})); len(got) != 0 {
		t.Errorf("in-process: %v", got)
	}
}

// TestGO3ABuildOfTheBinaryCarriesTheHooks: a Go file that builds cmd/tego names tegotesthooks in a string; the
// two files that build it without running it are exempt.
func TestGO3ABuildOfTheBinaryCarriesTheHooks(t *testing.T) {
	plain := "package x\n\nvar b = []string{\"go\", \"build\", \"-tags\", \"tegobpf\", \"github.com/attention-span-ai/tego/cmd/tego\"}\n"
	hooked := strings.Replace(plain, "\"tegobpf\"", "\"tegobpf,tegotesthooks\"", 1)
	if got := rules(t, tree(t, map[string]string{"e_test.go": plain})); !slices.Equal(got, []string{"e_test.go:GO-3"}) {
		t.Errorf("plain: %v", got)
	}
	if got := rules(t, tree(t, map[string]string{"e_test.go": hooked})); len(got) != 0 {
		t.Errorf("hooked: %v", got)
	}
	// A comment naming the tag is not a build with it.
	commented := plain + "\n// built with tegotesthooks, honest\n"
	if got := rules(t, tree(t, map[string]string{"e_test.go": commented})); !slices.Equal(got, []string{"e_test.go:GO-3"}) {
		t.Errorf("commented: %v", got)
	}
	if got := rules(t, tree(t, map[string]string{"tools/deadcodereport/main.go": plain})); len(got) != 0 {
		t.Errorf("exempt: %v", got)
	}
}

// TestSH1AShellThatAssignsTegoConfigSetsTheIsolation: SH-1 for shell and Python, with the helpers that set it and
// the comment lines that do not count.
func TestSH1AShellThatAssignsTegoConfigSetsTheIsolation(t *testing.T) {
	cases := map[string]struct {
		body string
		want []string
	}{
		"bare.sh":    {"#!/bin/bash\nexport TEGO_CONFIG=\"$w/config.yaml\"\n", []string{"bare.sh:SH-1", "bare.sh:SH-1"}},
		"anchor.sh":  {"export TEGO_CONFIG=c\nexport TEGO_TEST_CHAIN_ANCHOR=a\n", []string{"anchor.sh:SH-1"}},
		"both.sh":    {"export TEGO_CONFIG=c TEGO_TEST_CHAIN_ANCHOR=a TEGO_TEST_OWN_LOG_HOME=h\n", nil},
		"helper.sh":  {"kt_config \"$w\"\nTEGO_CONFIG=\"$w/c\" run\n", nil},
		"lib.sh":     {"lib_init \"$root\"\nenv TEGO_CONFIG=x run\n", nil},
		"comment.sh": {"# TEGO_CONFIG=/x is the usual spelling\n# TEGO_TEST_CHAIN_ANCHOR TEGO_TEST_OWN_LOG_HOME\n", nil},
		"dict.py":    {"env = {\"TEGO_CONFIG\": cfg}\n", []string{"dict.py:SH-1", "dict.py:SH-1"}},
		"dictok.py":  {"env = {\"TEGO_CONFIG\": cfg, \"TEGO_TEST_CHAIN_ANCHOR\": a, \"TEGO_TEST_OWN_LOG_HOME\": h}\n", nil},
		"uses.sh":    {"\"$TEGO_CONFIG\" is read here, not set\nsed -n 's/^ledger_root: //p' \"$TEGO_CONFIG\"\n", nil},
	}
	for name, c := range cases {
		got := rules(t, tree(t, map[string]string{name: c.body}))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
	// test/vm runs in the KVM guests.
	if got := rules(t, tree(t, map[string]string{"test/vm/x.sh": "export TEGO_CONFIG=c\n"})); len(got) != 0 {
		t.Errorf("test/vm: %v", got)
	}
}

// TestSH2APseudoTerminalNeedsAHistoryFile: SH-2 and SH-3, the two ways a shell on a terminal writes the
// operator's ~/.bash_history.
func TestSH2APseudoTerminalNeedsAHistoryFile(t *testing.T) {
	cases := map[string]struct {
		body string
		want []string
	}{
		"fork.py":    {"import pty\npid, fd = pty.fork()\n", []string{"fork.py:SH-2"}},
		"forkok.py":  {"pid, fd = pty.fork()\nenv = dict(e, HISTFILE=\"/dev/null\")\n", nil},
		"dictok.py":  {"pty.openpty()\nenv = {\"HISTFILE\": \"/dev/null\"}\n", nil},
		"wrong.py":   {"pty.spawn(x)\nenv = {\"HISTFILE\": \"/tmp/h\"}\n", []string{"wrong.py:SH-2"}},
		"shell.py":   {"kt_config\nargv = [tego, \"watch\", \"--\", \"bash\", \"--noprofile\", \"--norc\", \"-i\"]\n", []string{"shell.py:SH-3"}},
		"shell.sh":   {"kt_config\ntego watch -- bash -i\n", []string{"shell.sh:SH-3"}},
		"shellok.sh": {"kt_config\nHISTFILE=/dev/null tego watch -- bash -i\n", nil},
		"plain.sh":   {"bash script.sh -x\nsh -c 'echo hi'\n", nil},
	}
	for name, c := range cases {
		got := rules(t, tree(t, map[string]string{name: c.body}))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
}

// TestSH4SH5SH6AScriptThatRunsTegoIsolatesIt: the reviewer's naked harness (a product build, a run with no
// isolation variable, a TEGO_BIN nobody checks) passes none of SH-4 to SH-6, and the forms the repository's
// harnesses take pass all three.
func TestSH4SH5SH6AScriptThatRunsTegoIsolatesIt(t *testing.T) {
	const checked = "grep -aq TEGO_TEST_CHAIN_ANCHOR \"$bin\" || exit 2\n"
	const isolated = "export TEGO_TEST_CHAIN_ANCHOR=a TEGO_TEST_OWN_LOG_HOME=h\n"
	cases := map[string]struct {
		body string
		want []string
	}{
		// None of the three is reported without these rules.
		"naked.sh": {"go build -o \"$TMPDIR/tego\" ./cmd/tego\n\"$TMPDIR/tego\" run agent.yaml -- /bin/true\n\"${TEGO_BIN:-tego}\" gc\n",
			[]string{"naked.sh:SH-4", "naked.sh:SH-5", "naked.sh:SH-6"}},
		// A build split with a trailing backslash, and a binary named other than the way
		// the first rules knew it.
		"naked2.sh": {"go build -trimpath \\\n\t-o \"$W/tego\" ./cmd/tego\n\"$W/tego\" run agent.yaml -- /bin/true\n", []string{"naked2.sh:SH-4", "naked2.sh:SH-5"}},
		"tmpdir.sh": {"\"$TMPDIR/tego\" run agent.yaml\n", []string{"tmpdir.sh:SH-5"}},
		"abs.sh":    {"/usr/local/bin/tego run a.yaml\n", []string{"abs.sh:SH-5"}},
		"dot.sh":    {"./tego run a.yaml\n", []string{"dot.sh:SH-5"}},
		"letter.sh": {"$E run a.yaml\n", []string{"letter.sh:SH-5"}},
		"then.sh":   {"if true; then tego run a.yaml; fi\n", []string{"then.sh:SH-5"}},
		"then2.sh":  {"if true\nthen\n\ttego run a.yaml\nfi\n", []string{"then2.sh:SH-5"}},
		"do.sh":     {"for a in x; do \"$bin\" run $a; done\n", []string{"do.sh:SH-5"}},
		"setsid.sh": {"setsid \"$bin\" run a.yaml\n", []string{"setsid.sh:SH-5"}},
		"script.sh": {"script -qc \"$bin run a.yaml\" /dev/null\n", []string{"script.sh:SH-5"}},
		"bashc.sh":  {"bash -c '\"$tego_bin\" run a.yaml'\n", []string{"bashc.sh:SH-5"}},
		// The binary handed to sh -c as $0 or $1, which the script runs with a
		// subcommand, in the script's own quotes, escaped in a double-quoted one, or in a variable assigned over lines.
		"shc0.sh":   {"sh -c '\"$0\" doctor' \"$tego\"\n", []string{"shc0.sh:SH-5"}},
		"shc1.sh":   {"sh -c '\"$1\" run x' sh \"$tego\"\n", []string{"shc1.sh:SH-5"}},
		"shcesc.sh": {"bash -ec \"\\\"\\$0\\\" run x\" \"$bin\"\n", []string{"shcesc.sh:SH-5"}},
		"shcvar.sh": {"s='\n\t\"$0\" doctor; a=$?\n\texit $a'\nsudo /bin/sh -c \"$s\" \"$doctor_bin\" on\n", []string{"shcvar.sh:SH-5"}},
		"shcok.sh":  {isolated + "sh -c '\"$0\" doctor' \"$tego\"\n", nil},
		// another program as $0, $0 as an argument, and the binary at a position the script does not run.
		"shcother.sh":  {"sh -c '\"$0\" doctor' \"$GO\"\nsh -c 'echo \"$0\" run' \"$tego\"\nsh -c '\"$1\" run' \"$tego\" x\n", nil},
		"andand.sh":    {"cd w && tego gc\n", []string{"andand.sh:SH-5"}},
		"split.sh":     {"\"$bin\" \\\n\trun a.yaml\n", []string{"split.sh:SH-5"}},
		"envbin2.sh":   {isolated + "$bin=1\n\"${TEGO_BIN:-tego}\" gc\n", []string{"envbin2.sh:SH-6"}},
		"pyenviron.py": {"import subprocess, os\nsubprocess.run([os.environ[\"TEGO\"], \"run\", \"a.yaml\"])\n", []string{"pyenviron.py:SH-5"}},
		"pystr.py":     {"binpath = which(\"tego\")\nsubprocess.run([str(binpath), \"run\"])\n", []string{"pystr.py:SH-5"}},
		"pylit.py":     {"subprocess.run([\"/opt/tego\", \"gc\"])\n", []string{"pylit.py:SH-5"}},
		"pymulti.py":   {"self.bin = which(\"tego\")\nargv = [\n    self.bin,\n    \"watch\",\n]\n", []string{"pymulti.py:SH-5"}},
		// A quoted segment before /tego, a command substitution in the path, a quoted
		// option word after sudo, setpriv and runuser, the repository's wrappers (kt_run, as_user), a wrapper the
		// script defines itself, and global options between the binary and the subcommand.
		"quotedseg.sh":   {"\"$W\"/tego run x\n", []string{"quotedseg.sh:SH-5"}},
		"quotedseg2.sh":  {"'/opt/x'/tego gc\n", []string{"quotedseg2.sh:SH-5"}},
		"subst.sh":       {"\"$(go env GOPATH)/bin/tego\" run x\n", []string{"subst.sh:SH-5"}},
		"sudoquoted.sh":  {"sudo -u \"$SUDO_USER\" \"$tego\" run x\n", []string{"sudoquoted.sh:SH-5"}},
		"sudoquoted2.sh": {"sudo -u \"$U\" \"$tego\" run x\n", []string{"sudoquoted2.sh:SH-5"}},
		"setpriv.sh":     {"setpriv --reuid 1000 \"$tego\" run x\n", []string{"setpriv.sh:SH-5"}},
		"runuser.sh":     {"runuser -u u -- \"$tego\" run x\n", []string{"runuser.sh:SH-5"}},
		"asuser.sh":      {"as_user \"$tego\" run x\n", []string{"asuser.sh:SH-5"}},
		"ktrun.sh":       {"cd w && kt_run \"$tego\" run x\n", []string{"ktrun.sh:SH-5"}},
		"qtego.sh":       {"\"$qtego\" run x\n", []string{"qtego.sh:SH-5"}},
		"realtego.sh":    {"\"$realtego\" run x\n", []string{"realtego.sh:SH-5"}},
		"category.sh":    {"\"$category\" run x\n\"${CATEGORY}\" run x\n\"$updateGolden\" run x\n", nil},
		"ownwrap.sh":     {"wrap() { \"$@\"; }\nwrap \"$tego\" run x\n", []string{"ownwrap.sh:SH-5"}},
		"ownwrap2.sh":    {"function quietly {\n\t\"$@\" >/dev/null\n}\nquietly \"$bin\" watch -- x\n", []string{"ownwrap2.sh:SH-5"}},
		"globalopt.sh":   {"\"$tego\" --tier landlock run x\n", []string{"globalopt.sh:SH-5"}},
		"globalopt2.sh":  {"\"$tego\" --offline --tier=cgroup run x\n", []string{"globalopt2.sh:SH-5"}},
		// A quoted subcommand, a quoted last path segment, the programs that
		// run their arguments as a command (nice, ionice, unshare, stdbuf, doas, systemd-run, chrt, taskset, eval), an
		// escaped quote inside a string a shell or eval runs, and a function that wraps the binary itself.
		"quotedsub.sh":   {"\"$tego\" \"run\" x\n", []string{"quotedsub.sh:SH-5"}},
		"quotedsub2.sh":  {"\"$tego\" --tier landlock 'watch' -- x\n", []string{"quotedsub2.sh:SH-5"}},
		"quotedlast.sh":  {"\"$bindir\"/\"tego\" run x\n", []string{"quotedlast.sh:SH-5"}},
		"quotedlast2.sh": {"\"$W/\"'tego' gc\n", []string{"quotedlast2.sh:SH-5"}},
		"nice.sh":        {"nice -n 10 \"$tego\" run x\n", []string{"nice.sh:SH-5"}},
		"ionice.sh":      {"ionice -c 3 \"$tego\" run x\n", []string{"ionice.sh:SH-5"}},
		"unshare.sh":     {"unshare -r \"$tego\" run x\n", []string{"unshare.sh:SH-5"}},
		"stdbuf.sh":      {"stdbuf -oL \"$tego\" run x\n", []string{"stdbuf.sh:SH-5"}},
		"doas.sh":        {"doas -u u \"$tego\" run x\n", []string{"doas.sh:SH-5"}},
		"systemdrun.sh":  {"systemd-run --user --pty \"$tego\" run x\n", []string{"systemdrun.sh:SH-5"}},
		"chrt.sh":        {"chrt -f 10 \"$tego\" run x\n", []string{"chrt.sh:SH-5"}},
		"taskset.sh":     {"taskset -c 0 \"$tego\" run x\n", []string{"taskset.sh:SH-5"}},
		"eval.sh":        {"eval \"\\\"$tego\\\" run x\"\n", []string{"eval.sh:SH-5"}},
		"bashcesc.sh":    {"bash -c \"\\\"$tego\\\" run x\"\n", []string{"bashcesc.sh:SH-5"}},
		"funcbin.sh":     {"ey() { \"$tego\" \"$@\"; }; ey run x\n", []string{"funcbin.sh:SH-5"}},
		"funcbin2.sh":    {"function quiet_tego {\n\tlocal rc\n\t\"$bin\" --tier landlock \"$@\" >/dev/null\n}\nquiet_tego watch -- x\n", []string{"funcbin2.sh:SH-5"}},
		"funcbin3.sh":    {"e() {\n\tsudo \"$tego\" ${1+\"$@\"}\n}\nif true; then e gc; fi\n", []string{"funcbin3.sh:SH-5"}},
		// and none of these: a quoted word that is not a subcommand, a function that runs something else with "$@",
		// a function that wraps the binary but is only named in prose.
		"quotedarg.sh":  {"\"$GO\" \"run\" ./x\n", nil},
		"otherfunc.sh":  {"g() { git \"$@\"; }\ng status\ng run x\n", nil},
		"funcprose.sh":  {"ey() { \"$tego\" \"$@\"; }\necho \"ey run x is how\"\n", nil},
		"funcnotrun.sh": {"ey() { \"$tego\" version \"$@\"; }\n", nil},
		// and what still is no tego run: a wrapper word the script does not define, a function whose name is only
		// mentioned, an option of another program, a quoted string that holds the words.
		"notwrap.sh":   {"say \"$tego\" run x\n", nil},
		"notwrap2.sh":  {"wrap() { echo hi; }\necho wrap \"$tego\" run\n", nil},
		"otheropt.sh":  {"\"$GO\" -C dir run ./x\n", nil},
		"quotedtxt.sh": {"echo \"$W\"/tego run x is the command\nlog \"sudo -u \\\"$U\\\" tego run\"\n", nil},
		// other programs: a Go toolchain or gh run, a git status, prose.
		"gorun.sh":          {"\"${GO:-go}\" run ./tools/x\n\"$gh\" run list\n\"$LINT\" run --fix\n", nil},
		"git.py":            {"bin = which(\"tego\")\nsubprocess.run([\"git\", \"status\"])\n", nil},
		"prose2.sh":         {"printf 'then tego gc'\necho \"to do tego run, first\"\n", nil},
		"product.sh":        {"go build -o b github.com/attention-span-ai/tego/cmd/tego\n" + isolated, []string{"product.sh:SH-4"}},
		"product2.sh":       {"CGO_ENABLED=0 go build -tags tegobpf -o b ./cmd/tego\n", []string{"product2.sh:SH-4"}},
		"tagged.sh":         {"go build -tags=tegotesthooks -o b ./cmd/tego\n", nil},
		"noenv.sh":          {"bin=$1\n\"$bin\" run agent.yaml\n", []string{"noenv.sh:SH-5"}},
		"watch.sh":          {"sudo env X=1 \"$bin\" watch -- x\n", []string{"watch.sh:SH-5"}},
		"assign.sh":         {"HISTFILE=/dev/null TERM=x \"$bin\" run a.yaml\n", []string{"assign.sh:SH-5"}},
		"sub.sh":            {"out=$(tego events r-1 --verify)\n", []string{"sub.sh:SH-5"}},
		"rules.sh":          {"out=$(tego rules --last)\n", []string{"rules.sh:SH-5"}},
		"rules-isolated.sh": {isolated + "out=$(tego rules --last)\n", nil},
		"envbin.sh":         {isolated + "\"$TEGO_BIN\" run a.yaml\n", []string{"envbin.sh:SH-6"}},
		"envbinok.sh":       {isolated + checked + "\"$TEGO_BIN\" run a.yaml\n", []string{}},
		"helper.sh":         {"kt_config \"$w\"\n\"$tego\" run a.yaml\n", nil},
		"libinit.sh":        {"lib_init \"$root\"\n\"$bin\" run a.yaml\n", nil},
		"ensure.sh":         {"bin=$(kt_ensure_tego)\nkt_config \"$w\"\n\"$bin\" run a.yaml\n\"${TEGO_BIN}\" gc\n", nil},
		// words, not commands: an echo, a comment, a file that never runs tego.
		"prose.sh":  {"echo \"tego run is what the demo shows\"\n# tego run x\nprintf 'then tego gc'\n", nil},
		"reader.sh": {"TEGO_BIN=$1 other-tool --tego \"$TEGO_BIN\"\n", nil},
		"pyargv.py": {"argv = [tego, \"watch\", \"--\", \"x\"]\n", []string{"pyargv.py:SH-5"}},
		"pyok.py":   {"import os\nargv = [tego, \"watch\"]\nenv = {\"TEGO_TEST_CHAIN_ANCHOR\": a, \"TEGO_TEST_OWN_LOG_HOME\": h}\n", nil},
		"pychecked.py": {"tego = os.environ[\"TEGO_BIN\"]\nenv = {\"TEGO_TEST_CHAIN_ANCHOR\": a, \"TEGO_TEST_OWN_LOG_HOME\": h}\n" +
			"if b\"TEGO_TEST_CHAIN_ANCHOR\" not in open(tego, \"rb\").read():\n    sys.exit(1)\nargv = [tego, \"watch\"]\n", nil},
		"pyunchecked.py": {"tego = os.environ[\"TEGO_BIN\"]\nenv = {\"TEGO_TEST_CHAIN_ANCHOR\": a, \"TEGO_TEST_OWN_LOG_HOME\": h}\nargv = [tego, \"watch\"]\n",
			[]string{"pyunchecked.py:SH-6"}},
	}
	for name, c := range cases {
		// SH-7 (a launch's runtime directory) has its own test below; this table is SH-4 to SH-6.
		got := slices.DeleteFunc(rules(t, tree(t, map[string]string{name: c.body})), func(r string) bool { return strings.HasSuffix(r, ":SH-7") })
		if !slices.Equal(got, c.want) && !(len(got) == 0 && len(c.want) == 0) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
	// test/vm runs in the KVM guests, except root-suites.sh, whose VM_HOST=sudo runs tego doctor on this host.
	if got := rules(t, tree(t, map[string]string{"test/vm/x.sh": "\"$bin\" run a.yaml\n"})); len(got) != 0 {
		t.Errorf("test/vm: %v", got)
	}
	// root-suites.sh's own shape: the doctor is $0 of a script held in a variable.
	const doctor = "doctor_script='\n\t\"$0\" doctor; a=$?\n\texit 0'\n" +
		"\"${as_root[@]+\"${as_root[@]}\"}\" \"$here/bounded-run.sh\" 300 /bin/sh -c \"$doctor_script\" \"$doctor_bin\" \"$bpf_state\" 2>&1 | tee x\n"
	if got := rules(t, tree(t, map[string]string{"test/vm/root-suites.sh": doctor})); !slices.Equal(got, []string{"test/vm/root-suites.sh:SH-5"}) {
		t.Errorf("test/vm/root-suites.sh runs tego on this host and is not exempt: got %v", got)
	}
}

// TestSH7ALaunchGetsARuntimeDirectoryOfItsOwn: a script that starts a run (run, watch, adopt, agents) gives tego an
// XDG_RUNTIME_DIR of its own, or calls the helper that does, and never hands it the inherited one: a launch makes
// <XDG_RUNTIME_DIR>/tego and sweeps the directories the invoking user's crashed runs left there (identity-config.md
// R27 clause b4). A command that starts no run (doctor, compile, events) needs none.
func TestSH7ALaunchGetsARuntimeDirectoryOfItsOwn(t *testing.T) {
	const isolated = "export TEGO_TEST_CHAIN_ANCHOR=a TEGO_TEST_OWN_LOG_HOME=h\n"
	const pyIsolated = "env = {\"TEGO_TEST_CHAIN_ANCHOR\": a, \"TEGO_TEST_OWN_LOG_HOME\": h}\n"
	cases := map[string]struct {
		body string
		want []string
	}{
		"launch.sh":   {isolated + "\"$tego\" run a.yaml\n", []string{"launch.sh:SH-7"}},
		"watch.sh":    {isolated + "timeout 60 \"$bin\" watch -- x\n", []string{"watch.sh:SH-7"}},
		"adopt.sh":    {isolated + "\"$tego\" adopt --pid 1\n", []string{"adopt.sh:SH-7"}},
		"own.sh":      {isolated + "mkdir -m 700 \"$w/run\"\nexport XDG_RUNTIME_DIR=\"$w/run\"\n\"$tego\" run a.yaml\n", nil},
		"envcmd.sh":   {isolated + "env -i XDG_RUNTIME_DIR=\"$w/run\" \"$tego\" watch -- x\n", nil},
		"helper.sh":   {"kt_config \"$w\"\nkt_run \"$tego\" run a.yaml\n", nil},
		"libinit.sh":  {"lib_init \"$root\"\n\"$bin\" run a.yaml\n", nil},
		"inherit.sh":  {isolated + "export XDG_RUNTIME_DIR=\"$w/run\"\nXDG_RUNTIME_DIR=\"$XDG_RUNTIME_DIR\" \"$tego\" watch -- x\n", []string{"inherit.sh:SH-7"}},
		"inherit2.sh": {"kt_config \"$w\"\nexport XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/1000}\n\"$tego\" run a.yaml\n", []string{"inherit2.sh:SH-7"}},
		"comment.sh":  {isolated + "# XDG_RUNTIME_DIR=\"$w/run\" would do\n\"$tego\" run a.yaml\n", []string{"comment.sh:SH-7"}},
		"doctor.sh":   {isolated + "\"$tego\" doctor --json\n\"$tego\" compile a.yaml\n\"$tego\" events r-1\n", nil},
		"drive.py":    {pyIsolated + "env[\"XDG_RUNTIME_DIR\"] = os.environ.get(\"XDG_RUNTIME_DIR\", \"\")\nargv = [tego, \"watch\", \"--\", \"x\"]\n", []string{"drive.py:SH-7"}},
		"drive2.py":   {"env = {\"XDG_RUNTIME_DIR\": os.environ.get(\"XDG_RUNTIME_DIR\", \"\"), \"TEGO_TEST_CHAIN_ANCHOR\": a, \"TEGO_TEST_OWN_LOG_HOME\": h}\nargv = [tego, \"watch\"]\n", []string{"drive2.py:SH-7"}},
		"driveok.py":  {pyIsolated + "env[\"XDG_RUNTIME_DIR\"] = f\"{root}/run\"\nargv = [tego, \"watch\", \"--\", \"x\"]\n", nil},
		"kwarg.py":    {pyIsolated + "env = dict(os.environ, XDG_RUNTIME_DIR=run)\nargv = [tego, \"run\", \"a.yaml\"]\n", nil},
		// a script that requires the caller's variable and refuses the login session's directory, as the watch demo's
		// drivers do, gives tego the caller's own directory.
		"checked.py": {"for var in (\"TEGO_TEST_CHAIN_ANCHOR\", \"TEGO_TEST_OWN_LOG_HOME\", \"XDG_RUNTIME_DIR\"):\n    need(var)\n" +
			"if os.path.realpath(os.environ[\"XDG_RUNTIME_DIR\"]) == os.path.realpath(f\"/run/user/{os.getuid()}\"):\n    sys.exit(1)\nargv = [tego, \"watch\"]\n", nil},
		// The login session's directory by a literal path, an inherited
		// value copied through another name, and a quoted mention that sets nothing are each the inherited directory.
		"literal.sh":   {isolated + "export XDG_RUNTIME_DIR=/run/user/$(id -u)\n\"$tego\" run a.yaml\n", []string{"literal.sh:SH-7"}},
		"literal2.sh":  {isolated + "XDG_RUNTIME_DIR=\"/run/user/$UID\" \"$tego\" watch -- x\n", []string{"literal2.sh:SH-7"}},
		"literal3.sh":  {isolated + "export XDG_RUNTIME_DIR=/run/user/1000\n\"$tego\" run a.yaml\n", []string{"literal3.sh:SH-7"}},
		"copy.sh":      {isolated + "rt=$XDG_RUNTIME_DIR; export XDG_RUNTIME_DIR=\"$rt\"\n\"$tego\" run a.yaml\n", []string{"copy.sh:SH-7"}},
		"copy2.sh":     {isolated + "a=\"${XDG_RUNTIME_DIR:-}\"\nb=$a\nexport XDG_RUNTIME_DIR=${b}\n\"$tego\" run a.yaml\n", []string{"copy2.sh:SH-7"}},
		"copy3.sh":     {isolated + "rt=/run/user/$(id -u)\nexport XDG_RUNTIME_DIR=$rt\n\"$tego\" run a.yaml\n", []string{"copy3.sh:SH-7"}},
		"owncopy.sh":   {isolated + "rt=\"$w/run\"\nexport XDG_RUNTIME_DIR=\"$rt\"\n\"$tego\" run a.yaml\n", nil},
		"mention.py":   {pyIsolated + "env.update(os.environ)\nif \"XDG_RUNTIME_DIR\" in env:\n    pass\nsubprocess.run([tego, \"run\", \"a.yaml\"], env=env)\n", []string{"mention.py:SH-7"}},
		"mention2.py":  {pyIsolated + "env.update(os.environ)\nif \"XDG_RUNTIME_DIR\" not in os.environ:\n    sys.exit(1)\nargv = [tego, \"watch\"]\n", []string{"mention2.py:SH-7"}},
		"unrefused.py": {"for var in (\"TEGO_TEST_CHAIN_ANCHOR\", \"TEGO_TEST_OWN_LOG_HOME\", \"XDG_RUNTIME_DIR\"):\n    need(var)\nargv = [tego, \"watch\"]\n", []string{"unrefused.py:SH-7"}},
		"pyliteral.py": {pyIsolated + "env[\"XDG_RUNTIME_DIR\"] = f\"/run/user/{os.getuid()}\"\nargv = [tego, \"watch\"]\n", []string{"pyliteral.py:SH-7"}},
		"pycopy.py":    {pyIsolated + "rt = os.environ.get(\"XDG_RUNTIME_DIR\", \"\")\nenv[\"XDG_RUNTIME_DIR\"] = rt\nargv = [tego, \"watch\"]\n", []string{"pycopy.py:SH-7"}},
		"pyowncopy.py": {pyIsolated + "rt = f\"{root}/run\"\nenv[\"XDG_RUNTIME_DIR\"] = rt\nargv = [tego, \"watch\"]\n", nil},
		"pycompare.py": {pyIsolated + "if env[\"XDG_RUNTIME_DIR\"] == x:\n    pass\nargv = [tego, \"watch\"]\n", []string{"pycompare.py:SH-7"}},
		"noxdg.py":     {pyIsolated + "argv = [tego, \"watch\", \"--\", \"x\"]\n", []string{"noxdg.py:SH-7"}},
		"pydoctor.py":  {pyIsolated + "argv = [tego, \"doctor\"]\n", nil},
	}
	for name, c := range cases {
		got := rules(t, tree(t, map[string]string{name: c.body}))
		if !slices.Equal(got, c.want) && !(len(got) == 0 && len(c.want) == 0) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
}

// TestTheHelpersGiveARuntimeDirectory: SH-7 trusts kt_config and lib_init to give tego an XDG_RUNTIME_DIR of the
// harness's own, as SH-1 and SH-5 trust them with the anchor; each body exports one and none hands on the inherited
// value (test/e2e/lib_test.sh checks kt_config's value and mode).
func TestTheHelpersGiveARuntimeDirectory(t *testing.T) {
	for file, fn := range map[string]string{"test/e2e/lib.sh": "kt_config", "test/poc/custom-agent/lib.sh": "lib_init"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(file)))
		if err != nil {
			t.Fatal(err)
		}
		_, body, ok := strings.Cut(string(raw), "\n"+fn+"() {\n")
		if !ok {
			t.Fatalf("%s: no %s() {", file, fn)
		}
		body, _, _ = strings.Cut(body, "\n}\n")
		if !regexp.MustCompile(`(?m)^\s*export XDG_RUNTIME_DIR=`).MatchString(body) || inheritedRuntimeDirLine(strings.Split(body, "\n"), false) >= 0 {
			t.Errorf("%s: %s does not export an XDG_RUNTIME_DIR of its own:\n%s", file, fn, body)
		}
	}
}

// TestSH5SeesRootSuitesRunItsDoctor: the real test/vm/root-suites.sh, with every echo and printf line removed and the
// two isolation variables renamed, is reported at the line that runs the doctor on the host, not at prose (before,
// SH-5 saw that script only through an echo's text).
func TestSH5SeesRootSuitesRunItsDoctor(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "vm", "root-suites.sh"))
	if err != nil {
		t.Fatal(err)
	}
	rename := strings.NewReplacer("TEGO_TEST_CHAIN_ANCHOR", "X_ANCHOR", "TEGO_TEST_OWN_LOG_HOME", "X_LOG")
	var kept []string
	for _, l := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(l); len(f) > 0 && (f[0] == "echo" || f[0] == "printf") {
			l = ""
		}
		kept = append(kept, rename.Replace(l))
	}
	fs, err := check(tree(t, map[string]string{"test/vm/root-suites.sh": strings.Join(kept, "\n")}))
	if err != nil {
		t.Fatal(err)
	}
	// The renamed variables also leave its TEGO_CONFIG assignment without them (SH-1); SH-5 is the rule under test.
	var sh5 []finding
	for _, f := range fs {
		if f.Rule == "SH-5" {
			sh5 = append(sh5, f)
		}
	}
	if len(sh5) != 1 {
		t.Fatalf("got %v, want one SH-5", fs)
	}
	if l := kept[sh5[0].Line-1]; !strings.Contains(l, `sh -c "$doctor_script"`) {
		t.Errorf("SH-5 is at line %d, %q, not the doctor's run", sh5[0].Line, l)
	}
}

// guardMain is a TestMain that fails the binary when the real ~/.tego or ~/.bash_history changed.
const guardMain = "package p\n\nimport (\n\t\"os\"\n\t\"testing\"\n\n\t\"example.com/m/internal/testutil\"\n)\n\n" +
	"func TestMain(m *testing.M) { os.Exit(testutil.GuardedMain(m)) }\n"

// TestGO4APackageThatStartsRunsGuardsTheRealHome: a package whose tests can start a run, a sweep, a gc or the
// tego binary (it is internal/runtime or internal/cli, its tests import one of them, or a file of it builds or
// configures the binary) has a TestMain that calls testutil.GuardRealTego in every build that compiles that
// test; one that does not is flagged where the run comes in, and a package with no such test is not.
func TestGO4APackageThatStartsRunsGuardsTheRealHome(t *testing.T) {
	const mod = "module example.com/m\n\ngo 1.27\n"
	const imports = "package p\n\nimport (\n\t\"testing\"\n\n\trt \"example.com/m/internal/runtime\"\n)\n\nfunc TestX(t *testing.T) { _ = rt.AnchorPath }\n"
	const plainMain = "package p\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) { os.Exit(m.Run()) }\n"
	const integration = "//go:build integration\n\n"
	cases := map[string]struct {
		files map[string]string
		want  []string
	}{
		"no guard":   {map[string]string{"a/a_test.go": imports}, []string{"a/a_test.go:GO-4"}},
		"guarded":    {map[string]string{"a/a_test.go": imports, "a/main_test.go": guardMain}, nil},
		"unguarded":  {map[string]string{"a/a_test.go": imports, "a/main_test.go": plainMain}, []string{"a/a_test.go:GO-4"}},
		"cli itself": {map[string]string{"internal/cli/x_test.go": "package cli\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n"}, []string{"internal/cli/x_test.go:GO-4"}},
		"runtime ok": {map[string]string{"internal/runtime/x_test.go": "package runtime\n", "internal/runtime/main_test.go": guardMain}, nil},
		"binary":     {map[string]string{"b/b_test.go": "package p\n\nvar e = testutil.TegoEnv(t, d, \"TEGO_CONFIG=/c\")\n"}, []string{"b/b_test.go:GO-4"}},
		"build":      {map[string]string{"b/b_test.go": "package p\n\nvar b = []string{\"-tags\", \"tegotesthooks\", \"example.com/m/cmd/tego\"}\n"}, []string{"b/b_test.go:GO-4"}},
		"helper file": {map[string]string{"c/main.go": "package main\n\nvar e = []string{\"TEGO_CONFIG=\" + c, \"TEGO_TEST_CHAIN_ANCHOR=a\"}\n",
			"c/main_test.go": "package main\n"}, []string{"c/main.go:GO-4"}},
		"setter": {map[string]string{"d/d_test.go": "package p\n\nfunc f() { writeMachineConfig(t, f) }\n"}, []string{"d/d_test.go:GO-4"}},
		// a test that runs the tego binary itself, whatever environment it gives it (one GO-5 accepts included).
		"runs the binary": {map[string]string{"j/j_test.go": "package p\n\nimport \"os/exec\"\n\nfunc f(bin string) {\n\tcmd := exec.Command(bin, \"run\", \"a.yaml\")\n\tcmd.Env = []string{\"PATH=/bin\"}\n\t_ = cmd.Run()\n}\n"},
			[]string{"j/j_test.go:GO-4"}},
		"other program": {map[string]string{"k/k_test.go": "package p\n\nimport \"os/exec\"\n\nfunc f() { _ = exec.Command(\"git\", \"status\").Run() }\n"}, nil},
		// `agents --adopt` starts ledgered runs and `alternate` answers one, as
		// approve and deny do; `version` reads nothing of the ledger and is not a run.
		"agents adopt": {map[string]string{"k/k_test.go": "package p\n\nimport \"os/exec\"\n\nfunc f(bin string) {\n\tcmd := exec.Command(bin, \"agents\", \"--adopt\", \"claude\")\n\tcmd.Env = []string{\"PATH=/bin\"}\n\t_ = cmd.Run()\n}\n"},
			[]string{"k/k_test.go:GO-4"}},
		"alternate": {map[string]string{"k/k_test.go": "package p\n\nimport \"os/exec\"\n\nfunc f(bin string) {\n\tcmd := exec.Command(bin, \"alternate\", \"r\", \"a1\", \"--file\", \"x\")\n\tcmd.Env = []string{\"PATH=/bin\"}\n\t_ = cmd.Run()\n}\n"},
			[]string{"k/k_test.go:GO-4"}},
		"version": {map[string]string{"k/k_test.go": "package p\n\nimport \"os/exec\"\n\nfunc f(bin string) { _ = exec.Command(bin, \"version\").Run() }\n"}, nil},
		// The tree's most common shape passes the arguments as one list.
		"variadic list": {map[string]string{"l/l_test.go": "package p\n\nimport \"os/exec\"\n\nfunc f(x string) {\n\targs := []string{\"run\", \"a.yaml\"}\n\t_ = exec.Command(x, args...).Run()\n}\n"},
			[]string{"l/l_test.go:GO-4"}},
		"variadic append": {map[string]string{"l/l_test.go": "package p\n\nimport \"os/exec\"\n\nfunc f(x string, args []string) {\n\t_ = exec.Command(x, append([]string{\"doctor\"}, args...)...).Run()\n}\n"},
			[]string{"l/l_test.go:GO-4"}},
		"variadic bin": {map[string]string{"l/l_test.go": "package p\n\nimport (\n\t\"context\"\n\t\"os/exec\"\n)\n\nfunc f(ctx context.Context, s *S, args []string) {\n\t_ = exec.CommandContext(ctx, s.bin, args...).Run()\n}\n"},
			[]string{"l/l_test.go:GO-4"}},
		"variadic tego": {map[string]string{"l/l_test.go": "package p\n\nimport \"os/exec\"\n\nfunc f(tegoBin *string, args []string) {\n\t_ = exec.Command(*tegoBin, args...).Run()\n}\n"},
			[]string{"l/l_test.go:GO-4"}},
		"variadic literal": {map[string]string{"l/l_test.go": "package p\n\nimport \"os/exec\"\n\nfunc f(args []string) {\n\t_ = exec.Command(\"./tego\", args...).Run()\n}\n"},
			[]string{"l/l_test.go:GO-4"}},
		"variadic other": {map[string]string{"l/l_test.go": "package p\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\nfunc f(git string, args []string) {\n\t_ = exec.Command(git, args...).Run()\n\t_ = exec.Command(os.Args[0], args...).Run()\n\t_ = exec.Command(\"git\", append([]string{\"run\"}, args...)...).Run()\n\tlist := []string{\"log\"}\n\t_ = exec.Command(git, list...).Run()\n}\n"},
			nil},
		// A package whose own code reaches internal/cli or internal/runtime, and
		// whose tests can call that code (a main_test.go that calls main()), or a test that imports such a package.
		"main caller": {map[string]string{"cmd/x/main.go": "package main\n\nimport \"example.com/m/internal/cli\"\n\nfunc main() { cli.Main() }\n",
			"cmd/x/main_test.go": "package main\n\nimport \"testing\"\n\nfunc TestMainRuns(t *testing.T) { main() }\n"}, []string{"cmd/x/main.go:GO-4"}},
		"main caller guarded": {map[string]string{"cmd/x/main.go": "package main\n\nimport \"example.com/m/internal/cli\"\n\nfunc main() { cli.Main() }\n",
			"cmd/x/main_test.go": strings.Replace(guardMain, "package p", "package main", 1)}, nil},
		"main untested": {map[string]string{"cmd/x/main.go": "package main\n\nimport \"example.com/m/internal/cli\"\n\nfunc main() { cli.Main() }\n"}, nil},
		"through a package": {map[string]string{"lib/l.go": "package lib\n\nimport rt \"example.com/m/internal/runtime\"\n\nvar A = rt.AnchorPath\n",
			"q/q_test.go": "package q\n\nimport (\n\t\"testing\"\n\n\t\"example.com/m/lib\"\n)\n\nfunc TestX(t *testing.T) { _ = lib.A }\n"}, []string{"q/q_test.go:GO-4"}},
		"through a test only": {map[string]string{"lib/l_test.go": "package lib\n\nimport rt \"example.com/m/internal/runtime\"\n\nvar A = rt.AnchorPath\n",
			"lib/main_test.go": strings.Replace(guardMain, "package p", "package lib", 1),
			"q/q_test.go":      "package q\n\nimport (\n\t\"testing\"\n\n\t\"example.com/m/lib\"\n)\n\nfunc TestX(t *testing.T) { _ = lib.B }\n"}, nil},
		// the guard must be in the build that compiles the run.
		"other build": {map[string]string{"e/e_test.go": integration + imports, "e/main_test.go": "//go:build !integration\n\n" + guardMain},
			[]string{"e/e_test.go:GO-4"}},
		"both builds": {map[string]string{"e/e_test.go": integration + imports, "e/main_test.go": "//go:build !integration\n\n" + guardMain,
			"e/imain_test.go": integration + guardMain}, nil},
		"tagged pair": {map[string]string{"e/e_test.go": integration + imports, "e/imain_test.go": integration + guardMain}, nil},
		// no test binary, a program that only names the binary to read its build, a package that runs nothing.
		"no tests": {map[string]string{"f/main.go": "package main\n\nvar e = []string{\"TEGO_CONFIG=\" + c, \"TEGO_TEST_CHAIN_ANCHOR=a\"}\n"}, nil},
		"exempt": {map[string]string{"tools/deadcodereport/main.go": "package main\n\nvar b = \"./cmd/tego\"\n",
			"tools/deadcodereport/main_test.go": "package main\n"}, nil},
		"plain": {map[string]string{"g/g_test.go": "package p\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n"}, nil},
		// internal/govlog writes the governance ledger under <tego home>/gov: its tests and every test that can
		// reach it run under the guard too.
		"govlog itself": {map[string]string{"internal/govlog/x_test.go": "package govlog\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n"},
			[]string{"internal/govlog/x_test.go:GO-4"}},
		"imports govlog": {map[string]string{"l/l_test.go": "package p\n\nimport (\n\t\"testing\"\n\n\t\"example.com/m/internal/govlog\"\n)\n\nfunc TestX(t *testing.T) { _ = govlog.Dir }\n"},
			[]string{"l/l_test.go:GO-4"}},
		"imports govlog, guarded": {map[string]string{"l/l_test.go": "package p\n\nimport (\n\t\"testing\"\n\n\t\"example.com/m/internal/govlog\"\n)\n\nfunc TestX(t *testing.T) { _ = govlog.Dir }\n",
			"l/main_test.go": guardMain}, nil},
		"other os": {map[string]string{"h/h_darwin_test.go": imports}, nil},
		"comment":  {map[string]string{"i/i_test.go": "package p\n\n// internal/runtime's TEGO_CONFIG= and writeMachineConfig, in prose.\n"}, nil},
	}
	for name, c := range cases {
		files := map[string]string{"go.mod": mod}
		for p, b := range c.files {
			files[p] = b
		}
		got := rules(t, tree(t, files))
		if !slices.Equal(got, c.want) && !(len(got) == 0 && len(c.want) == 0) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
	// Without a go.mod the import paths are unknown and the rule does not apply (the fixtures of the other rules).
	if got := rules(t, tree(t, map[string]string{"a/a_test.go": imports})); len(got) != 0 {
		t.Errorf("no module: %v", got)
	}
}

// TestGO4TheGuardsResultIsChecked: a TestMain counts as the guard only in the two shapes whose exit code is the
// guarded run's: os.Exit(testutil.GuardedMain(m)) (or GuardedLeakCheckMain, GuardedStdioLeakCheckMain) as a statement of its own body, or that
// call's result held in a name that the first exit after it, os.Exit(name), takes with nothing between that can
// change the name, exit or return. The tests may not run before it (m is used nowhere else) and nothing may end
// TestMain before it. Every other shape is flagged, the hand-written checks of testutil.GuardRealTego included:
// each round of those found another one that let the binary exit 0 whatever its tests wrote.
func TestGO4TheGuardsResultIsChecked(t *testing.T) {
	const mod = "module example.com/m\n\ngo 1.27\n"
	const imports = "package p\n\nimport (\n\t\"testing\"\n\n\trt \"example.com/m/internal/runtime\"\n)\n\nfunc TestX(t *testing.T) { _ = rt.AnchorPath }\n"
	main := func(body string) string {
		return "package p\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"testing\"\n\n\t\"example.com/m/internal/testutil\"\n)\n\n" +
			"func TestMain(m *testing.M) {\n" + body + "\n}\n"
	}
	cases := map[string]struct {
		body  string
		guard bool
	}{
		// the shapes that count.
		"exit":     {"\tos.Exit(testutil.GuardedMain(m))", true},
		"leak":     {"\tos.Exit(testutil.GuardedLeakCheckMain(m))", true},
		"stdio":    {"\tcode := testutil.GuardedStdioLeakCheckMain(m)\n\t_ = os.RemoveAll(\"x\")\n\tos.Exit(code)", true},
		"code":     {"\tcode := testutil.GuardedLeakCheckMain(m)\n\t_ = os.RemoveAll(\"x\")\n\tfmt.Println(code)\n\tos.Exit(code)", true},
		"var code": {"\tvar code = testutil.GuardedMain(m)\n\tos.Exit(code)", true},
		"helper mode": {"\tif len(os.Args) > 1 && os.Args[1] == \"probe\" {\n\t\tos.Exit(0)\n\t}\n\tif os.Getenv(\"X\") != \"\" {\n\t\treturn\n\t}\n\tos.Exit(testutil.GuardedMain(m))",
			true},
		// the hand-written checks of GuardRealTego, right or wrong, no longer count.
		"if init": {"\tcheck := testutil.GuardRealTego()\n\tcode := m.Run()\n\tif err := check(); err != nil {\n\t\tfmt.Println(err)\n\t\tcode = 1\n\t}\n\tos.Exit(code)",
			false},
		"blank": {"\t_ = testutil.GuardRealTego()\n\tos.Exit(m.Run())", false},
		"deferred check": {"\tcheck := testutil.GuardRealTego()\n\tdefer func() {\n\t\tif err := check(); err != nil {\n\t\t\tos.Exit(1)\n\t\t}\n\t}()\n\tos.Exit(m.Run())",
			false},
		"plain": {"\tos.Exit(m.Run())", false},
		// Shapes which the hand-written rule passed.
		"old exit first": {"\tcheck := testutil.GuardRealTego()\n\tos.Exit(m.Run())\n\tif err := check(); err != nil {\n\t\tos.Exit(1)\n\t}", false},
		"old return first": {"\tcheck := testutil.GuardRealTego()\n\tcode := m.Run()\n\tif code == 0 {\n\t\treturn\n\t}\n\tif err := check(); err != nil {\n\t\tos.Exit(1)\n\t}",
			false},
		"old code reset": {"\tcheck := testutil.GuardRealTego()\n\tcode := m.Run()\n\tif err := check(); err != nil {\n\t\tcode = 1\n\t}\n\tcode = 0\n\tos.Exit(code)", false},
		"old exit zero first": {"\tcheck := testutil.GuardRealTego()\n\tcode := m.Run()\n\tif err := check(); err != nil {\n\t\tcode = 1\n\t}\n\tos.Exit(0)\n\tos.Exit(code)",
			false},
		"old dead nested": {"\tcheck := testutil.GuardRealTego()\n\tcode := m.Run()\n\tif err := check(); err != nil {\n\t\tif len(os.Args) > 99 {\n\t\t\tos.Exit(1)\n\t\t}\n\t}\n\tos.Exit(code)",
			false},
		"old reassigned": {"\tcheck := testutil.GuardRealTego()\n\tcheck = func() error { return nil }\n\tcode := m.Run()\n\tif err := check(); err != nil {\n\t\tcode = 1\n\t}\n\tos.Exit(code)",
			false},
		"old err reset": {"\tcheck := testutil.GuardRealTego()\n\tcode := m.Run()\n\terr := check()\n\terr = nil\n\tif err != nil {\n\t\tcode = 1\n\t}\n\tos.Exit(code)", false},
		// the tests run before, or outside, the guarded call.
		"exit first":       {"\tos.Exit(m.Run())\n\tos.Exit(testutil.GuardedMain(m))", false},
		"run before":       {"\t_ = m.Run()\n\tos.Exit(testutil.GuardedMain(m))", false},
		"m passed":         {"\ttestutil.LeakCheckMain(m)\n\tos.Exit(testutil.GuardedMain(m))", false},
		"m in closure":     {"\trun := func() int { return m.Run() }\n\t_ = run\n\tos.Exit(testutil.GuardedMain(m))", false},
		"nested":           {"\tif len(os.Args) > 0 {\n\t\tos.Exit(testutil.GuardedMain(m))\n\t}\n\tos.Exit(0)", false},
		"deferred":         {"\tdefer os.Exit(testutil.GuardedMain(m))", false},
		"goroutine":        {"\tgo os.Exit(testutil.GuardedMain(m))\n\tselect {}", false},
		"unreachable":      {"\treturn\n\tos.Exit(testutil.GuardedMain(m))", false},
		"exit zero before": {"\tos.Exit(0)\n\tos.Exit(testutil.GuardedMain(m))", false},
		"panic before":     {"\tpanic(\"x\")\n\tos.Exit(testutil.GuardedMain(m))", false},
		"blank code":       {"\t_ = testutil.GuardedMain(m)\n\tos.Exit(0)", false},
		"wrapped exit":     {"\tos.Exit(1 - testutil.GuardedMain(m))", false},
		// the code is held, and something can change it, exit or return before os.Exit takes it.
		"falls off":        {"\tcode := testutil.GuardedMain(m)\n\tfmt.Println(code)", false},
		"return first":     {"\tcode := testutil.GuardedMain(m)\n\tif code == 0 {\n\t\treturn\n\t}\n\tos.Exit(code)", false},
		"code reset":       {"\tcode := testutil.GuardedMain(m)\n\tcode = 0\n\tos.Exit(code)", false},
		"reset nested":     {"\tcode := testutil.GuardedMain(m)\n\tif len(os.Args) > 99 {\n\t\tcode = 0\n\t}\n\tos.Exit(code)", false},
		"reset closure":    {"\tcode := testutil.GuardedMain(m)\n\tfunc() { code = 0 }()\n\tos.Exit(code)", false},
		"decremented":      {"\tcode := testutil.GuardedMain(m)\n\tcode--\n\tos.Exit(code)", false},
		"pointer":          {"\tcode := testutil.GuardedMain(m)\n\tp := &code\n\t*p = 0\n\tos.Exit(code)", false},
		"exit zero first":  {"\tcode := testutil.GuardedMain(m)\n\tos.Exit(0)\n\tos.Exit(code)", false},
		"exit zero nested": {"\tcode := testutil.GuardedMain(m)\n\tif len(os.Args) > 99 {\n\t\tos.Exit(0)\n\t}\n\tos.Exit(code)", false},
		"exit in closure":  {"\tcode := testutil.GuardedMain(m)\n\tdone := func() { os.Exit(0) }\n\tdone()\n\tos.Exit(code)", false},
		"other name":       {"\tcode, other := testutil.GuardedMain(m), 0\n\tos.Exit(other + code*0)", false},
		"other exit":       {"\tcode := testutil.GuardedMain(m)\n\tother := 0\n\t_ = code\n\tos.Exit(other)", false},
	}
	for name, c := range cases {
		got := rules(t, tree(t, map[string]string{"go.mod": mod, "a/a_test.go": imports, "a/main_test.go": main(c.body)}))
		if c.guard && len(got) != 0 {
			t.Errorf("%s: a guarded TestMain is flagged: %v", name, got)
		}
		if !c.guard && !slices.Equal(got, []string{"a/a_test.go:GO-4"}) {
			t.Errorf("%s: a TestMain whose exit code is not the guarded run's passes GO-4: %v", name, got)
		}
	}
}

// TestGO5AnTegoSubprocessGetsAnEnvironmentOfItsOwn: a command that runs the tego binary (a program that is not a
// string literal, or a literal ending in tego, followed by one of tego's subcommands) and is started with the
// inherited environment (no Env, or os.Environ() with no TEGO_TEST_CHAIN_ANCHOR) is flagged; one given
// testutil.TegoEnv, another environment or the anchor variable is not, and neither is another program.
func TestGO5AnTegoSubprocessGetsAnEnvironmentOfItsOwn(t *testing.T) {
	file := func(body string) string {
		return "package p\n\nimport (\n\t\"context\"\n\t\"os\"\n\t\"os/exec\"\n)\n\nfunc f(ctx context.Context, bin, pin string, r *R, env []string) {\n" +
			body + "\n}\n"
	}
	cases := map[string]struct {
		body string
		bad  bool
	}{
		"chained":        {"\t_, _ = exec.Command(bin, \"doctor\", \"--require\", \"cgroup\").CombinedOutput()", true},
		"in an if":       {"\tif out, err := exec.Command(bin, \"doctor\").CombinedOutput(); err != nil {\n\t\t_ = out\n\t}", true},
		"no env":         {"\tcmd := exec.Command(bin, \"gc\")\n\t_ = cmd.Run()", true},
		"inherited":      {"\tcmd := exec.Command(bin, \"doctor\", \"--json\")\n\tcmd.Env = append(os.Environ(), \"TEGO_TEST_PLANE=\"+pin)\n\t_ = cmd.Run()", true},
		"inherited bare": {"\tcmd := exec.CommandContext(ctx, bin, \"run\", \"a.yaml\")\n\tcmd.Env = os.Environ()\n\t_ = cmd.Run()", true},
		"literal binary": {"\t_ = exec.Command(\"./tego\", \"events\", \"--verify\").Run()", true},
		"returned":       {"\treturn exec.Command(bin, \"status\")", true},
		"isolated":       {"\tcmd := exec.Command(bin, \"doctor\")\n\tcmd.Env = testutil.TegoEnv(t, d, \"TEGO_CONFIG=\"+c)\n\t_ = cmd.Run()", false},
		"context":        {"\tcmd := exec.CommandContext(ctx, bin, \"run\", \"a.yaml\")\n\tcmd.Env = testutil.TegoEnv(t, d)\n\t_ = cmd.Run()", false},
		"field":          {"\tr.launcher = exec.CommandContext(ctx, bin, \"run\")\n\tr.launcher.Env = append(testutil.TegoEnv(t, d), env...)\n\t_ = r.launcher.Run()", false},
		"other env":      {"\tcmd := exec.Command(bin, \"run\")\n\tcmd.Env = append(env[:len(env):len(env)], \"X=1\")\n\t_ = cmd.Run()", false},
		"anchor named":   {"\tcmd := exec.Command(bin, \"run\")\n\tcmd.Env = append(os.Environ(), \"TEGO_CONFIG=c\", \"TEGO_TEST_CHAIN_ANCHOR=a\")\n\t_ = cmd.Run()", false},
		"go run":         {"\t_ = exec.Command(\"go\", \"run\", \"./tools/x\").Run()", false},
		"git":            {"\t_ = exec.Command(\"git\", \"status\").Run()", false},
		"no subcommand":  {"\t_ = exec.Command(bin, \"--version\").Run()", false},
		"passed on":      {"\tcode, out := c.exec(t, exec.Command(bin, \"run\", \"a.yaml\"))\n\t_, _ = code, out", false},
		"python program": {"\t_ = exec.Command(bin, \"./agent.py\").Run()", false},
		// Every command of the CLI but version and licenses is one GO-5 knows.
		"agents adopt": {"\t_ = exec.Command(bin, \"agents\", \"--follow\", \"--adopt\", \"claude\").Run()", true},
		"alternate":    {"\t_ = exec.Command(bin, \"alternate\", \"r\", \"a1\", \"--file\", \"x\").Run()", true},
		"dns":          {"\t_ = exec.Command(bin, \"dns\", \"allowed.example\").Run()", true},
		"init":         {"\t_ = exec.Command(bin, \"init\", \".\").Run()", true},
		"version":      {"\t_ = exec.Command(bin, \"version\").Run()", false},
		"licenses":     {"\t_ = exec.Command(bin, \"licenses\").Run()", false},
		// the Env that counts is the one set on that command, after it is made and before it starts.
		"reused name": {"\tcmd := exec.Command(bin, \"doctor\", \"--require\", \"cgroup\")\n\t_ = cmd.Run()\n\tcmd = exec.Command(bin, \"run\", \"a.yaml\")\n\tcmd.Env = testutil.TegoEnv(t, d, \"TEGO_CONFIG=\"+c)\n\t_ = cmd.Run()",
			true},
		"two closures": {"\ta := func() {\n\t\tcmd := exec.Command(bin, \"doctor\")\n\t\t_ = cmd.Run()\n\t}\n\tb := func() {\n\t\tcmd := exec.Command(bin, \"run\")\n\t\tcmd.Env = testutil.TegoEnv(t, d)\n\t\t_ = cmd.Run()\n\t}\n\ta()\n\tb()",
			true},
		"env after run": {"\tcmd := exec.Command(bin, \"gc\")\n\t_ = cmd.Run()\n\tcmd.Env = testutil.TegoEnv(t, d)", true},
		"conditional":   {"\tcmd := exec.Command(bin, \"gc\")\n\tif pin != \"\" {\n\t\tcmd.Env = testutil.TegoEnv(t, d)\n\t}\n\t_ = cmd.Run()", true},
		"appended later": {"\tcmd := exec.Command(bin, \"doctor\", \"--json\")\n\tcmd.Env = os.Environ()\n\tcmd.Env = append(cmd.Env, \"TEGO_TEST_PLANE=lsm\")\n\t_ = cmd.Run()",
			true},
		"nil env":      {"\tcmd := exec.Command(bin, \"doctor\")\n\tcmd.Env = nil\n\t_ = cmd.Run()", true},
		"own appended": {"\tcmd := exec.Command(bin, \"doctor\")\n\tcmd.Env = testutil.TegoEnv(t, d)\n\tcmd.Env = append(cmd.Env, \"TEGO_TEST_PLANE=lsm\")\n\t_ = cmd.Run()", false},
		"var decl":     {"\tvar cmd = exec.Command(bin, \"doctor\")\n\tcmd.Env = testutil.TegoEnv(t, d)\n\t_ = cmd.Run()", false},
		// More shapes: the command escapes under another name before
		// its Env is set, an Env set inside an if or truncated loses the isolation, and os.Environ() appended after
		// the isolation overrides it (exec keeps the last of two entries of one name).
		"alias":          {"\tcmd := exec.Command(bin, \"doctor\")\n\tc2 := cmd\n\t_ = c2.Run()\n\tcmd.Env = testutil.TegoEnv(t, d)", true},
		"returned alias": {"\tcmd := exec.Command(bin, \"doctor\")\n\tdefer func() { cmd.Env = testutil.TegoEnv(t, d) }()\n\treturn cmd", true},
		"conditional revert": {"\tcmd := exec.Command(bin, \"doctor\")\n\tcmd.Env = testutil.TegoEnv(t, d)\n\tif pin != \"\" {\n\t\tcmd.Env = os.Environ()\n\t}\n\t_ = cmd.Run()",
			true},
		"closure revert": {"\tcmd := exec.Command(bin, \"doctor\")\n\tcmd.Env = testutil.TegoEnv(t, d)\n\tfunc() { cmd.Env = nil }()\n\t_ = cmd.Run()", true},
		"truncated":      {"\tcmd := exec.Command(bin, \"doctor\")\n\tcmd.Env = testutil.TegoEnv(t, d)\n\tcmd.Env = cmd.Env[:0]\n\t_ = cmd.Run()", true},
		"environ appended": {"\tcmd := exec.Command(bin, \"doctor\")\n\tcmd.Env = testutil.TegoEnv(t, d)\n\tcmd.Env = append(cmd.Env, os.Environ()...)\n\t_ = cmd.Run()",
			true},
		"environ then isolation": {"\tcmd := exec.Command(bin, \"doctor\")\n\tcmd.Env = testutil.TegoEnv(t, d)\n\tcmd.Env = append(cmd.Env, append(os.Environ(), \"TEGO_CONFIG=c\", \"TEGO_TEST_CHAIN_ANCHOR=a\")...)\n\t_ = cmd.Run()",
			false},
		"conditional own": {"\tcmd := exec.Command(bin, \"doctor\")\n\tcmd.Env = testutil.TegoEnv(t, d)\n\tif pin != \"\" {\n\t\tcmd.Env = append(cmd.Env, \"TEGO_TEST_PLANE=\"+pin)\n\t}\n\t_ = cmd.Run()",
			false},
		"fields set": {"\tcmd := exec.Command(bin, \"doctor\")\n\tcmd.Stdout = os.Stdout\n\tcmd.Env = testutil.TegoEnv(t, d)\n\tdefer func() { _ = cmd.Process }()\n\t_ = cmd.Run()", false},
		"closure": {"\tdoctor := func(tier string) *exec.Cmd {\n\t\tcmd := exec.Command(bin, \"doctor\", \"--require\", tier)\n\t\tcmd.Env = testutil.TegoEnv(t, d)\n\t\treturn cmd\n\t}\n\t_ = doctor(\"cgroup\").Run()",
			false},
	}
	for name, c := range cases {
		got := rules(t, tree(t, map[string]string{"x_test.go": file(c.body)}))
		if c.bad && !slices.Equal(got, []string{"x_test.go:GO-5"}) {
			t.Errorf("%s: an inherited environment passes: %v", name, got)
		}
		if !c.bad && len(got) != 0 {
			t.Errorf("%s: flagged: %v", name, got)
		}
	}
}

// TestTheSubcommandsAreTheCLIsCommands: every command internal/cli registers (each noun's file, from init, ADR 0100
// (2)) is one GO-4, GO-5 and SH-5 know a run of the binary by, or one notRuns names with why it is not, so a command
// added to the CLI cannot leave those rules blind to it.
func TestTheSubcommandsAreTheCLIsCommands(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "internal", "cli", "*.go"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("internal/cli: %v %v", paths, err)
	}
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	var inits []*ast.FuncDecl
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Body != nil {
				if fd.Name.Name == "init" {
					inits = append(inits, fd)
					continue
				}
				funcs[fd.Name.Name] = fd
			}
		}
	}
	if len(inits) == 0 {
		t.Fatal("internal/cli registers no command from an init")
	}
	// name is the Name a command constructor gives its Command, from the composite literal it returns or the first
	// argument of the constructor it returns the result of (cmdApprove: cmdAnswer("approve", true)).
	name := func(fn string) string {
		for _, st := range funcs[fn].Body.List {
			r, ok := st.(*ast.ReturnStmt)
			if !ok || len(r.Results) != 1 {
				continue
			}
			switch e := r.Results[0].(type) {
			case *ast.CompositeLit:
				for _, el := range e.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Name" {
							if b, ok := kv.Value.(*ast.BasicLit); ok && b.Kind == token.STRING {
								s, _ := strconv.Unquote(b.Value)
								return s
							}
						}
					}
				}
			case *ast.CallExpr:
				if len(e.Args) > 0 {
					if b, ok := e.Args[0].(*ast.BasicLit); ok && b.Kind == token.STRING {
						s, _ := strconv.Unquote(b.Value)
						return s
					}
				}
			}
		}
		t.Errorf("cannot read the command name %s() gives", fn)
		return ""
	}
	// A noun's file registers its command constructor (register(cmdRun)); the nouns tego hands to tego-control are
	// registered in one loop over internal/handoff's list (register(handOffCommand(n))).
	var registered []string
	for _, fd := range inits {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) != 1 {
				return true
			}
			if id, ok := c.Fun.(*ast.Ident); !ok || id.Name != "register" {
				return true
			}
			switch a := c.Args[0].(type) {
			case *ast.Ident:
				if funcs[a.Name] == nil {
					t.Errorf("register(%s): internal/cli has no such constructor", a.Name)
					return true
				}
				registered = append(registered, name(a.Name))
			case *ast.CallExpr:
				if id, ok := a.Fun.(*ast.Ident); ok && id.Name == "handOffCommand" {
					for _, h := range handoff.Nouns() {
						registered = append(registered, h.Name)
					}
					return true
				}
				t.Errorf("a register call isocheck cannot read: its argument is a %T", a)
			default:
				t.Errorf("a register call isocheck cannot read: its argument is a %T", a)
			}
			return true
		})
	}
	if len(registered) < 10 {
		t.Fatalf("read only %v from internal/cli's registrations", registered)
	}
	for _, c := range registered {
		if !slices.Contains(tegoSubcommands, c) && notRuns[c] == "" {
			t.Errorf("tego %s is a command of internal/cli that isocheck does not know: add it to subcommands in check.go, "+
				"or to notRuns with why running it cannot reach a ledger, an anchor or the own log", c)
		}
		if slices.Contains(tegoSubcommands, c) && notRuns[c] != "" {
			t.Errorf("tego %s is both a run and not one", c)
		}
	}
	for c := range notRuns {
		if !slices.Contains(registered, c) {
			t.Errorf("notRuns names %s, which internal/cli does not register", c)
		}
	}
}

// TestNamesProductIsAWordPart: the product's name is found as a word part of an identifier, never inside another word
// whose letters hold it (ADR 0060).
func TestNamesProductIsAWordPart(t *testing.T) {
	for n, want := range map[string]bool{
		"tego": true, "tegoBin": true, "realTego": true, "TEGO_BIN": true, "qtego": true, "binTego": true,
		"category": false, "Category": false, "CATEGORY": false, "updateGolden": false, "bin": false, "": false,
	} {
		if got := namesProduct(n); got != want {
			t.Errorf("namesProduct(%q) = %v, want %v", n, got, want)
		}
	}
}

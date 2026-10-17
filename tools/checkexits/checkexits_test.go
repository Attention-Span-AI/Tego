// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// plant writes files into a fresh git checkout and returns its root.
func plant(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	for name, src := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const cleanCLI = `package cli

import "example/identity"

func Run() int {
	return identity.ExitUsage
}

func other() int {
	return 0
}

func cited() int {
	return 3 // R25: the documented code for this case
}
`

// TestCheckExitsFindsPlantedViolations is limits-check-doctor-cli.md I6 and I9: it plants each form a grep missed
// or could miss and asserts every one is found (I6: os.Exit, syscall.Exit and unix.Exit under any import name, called
// or taken as a value; I9: a bare non-zero integer return in internal/cli); the clean tree and the exempt paths
// beside them yield nothing.
func TestCheckExitsFindsPlantedViolations(t *testing.T) {
	root := plant(t, map[string]string{
		"internal/cli/main.go":  cleanCLI,
		"internal/cli/bare.go":  "package cli\n\nfunc bare() int {\n\treturn 7\n}\n",
		"internal/cli/paren.go": "package cli\n\nfunc paren() int {\n\treturn (-1)\n}\n",
		"internal/x/alias.go":   "package x\n\nimport quit \"os\"\n\nfunc f() { quit.Exit(3) }\n",
		"internal/x/split.go":   "package x\n\nimport \"os\"\n\nfunc f() {\n\tos.\n\t\tExit(\n\t\t\t1)\n}\n",
		"internal/x/value.go":   "package x\n\nimport \"syscall\"\n\nvar stop = syscall.Exit\n",
		"internal/x/dot.go":     "package x\n\nimport . \"golang.org/x/sys/unix\"\n\nfunc f() { Exit(1) }\n",
		// a selector's X is walked: an exit inside a call chain is still found.
		"internal/x/chain.go": "package x\n\nimport \"os\"\n\ntype c struct{}\n\nfunc (c) Close() {}\n\nfunc g(func()) c { return c{} }\n\nfunc f() { g(func() { os.Exit(3) }).Close() }\n",
		// exempt: cmd/, tools/, test/workloads/, test files, and a bare return outside internal/cli.
		"cmd/tego/main.go":          "package main\n\nimport \"os\"\n\nfunc main() { os.Exit(1) }\n",
		"tools/t/t.go":              "package main\n\nimport \"os\"\n\nfunc main() { os.Exit(1) }\n",
		"test/workloads/w/w.go":     "package main\n\nimport \"os\"\n\nfunc main() { os.Exit(1) }\n",
		"internal/x/x_test.go":      "package x\n\nimport \"os\"\n\nfunc g() { os.Exit(1) }\n",
		"internal/cli/main_test.go": "package cli\n\nfunc h() int { return 9 }\n",
		"internal/y/y.go":           "package y\n\nfunc n() int { return 4 }\n",
		"internal/cli/sub/sub.go":   "package sub\n\nfunc n() int { return 4 }\n",
		// log.Fatal* ends the process through os.Exit(1), under any import name; test/conformance/cmd is exempt.
		"internal/x/logfatal.go":      "package x\n\nimport \"log\"\n\nfunc f() { log.Fatal(1) }\n",
		"internal/x/logfatalf.go":     "package x\n\nimport lg \"log\"\n\nfunc f() { lg.Fatalf(\"x\") }\n",
		"internal/x/logfatalln.go":    "package x\n\nimport \"log\"\n\nvar stop = log.Fatalln\n",
		"internal/x/logdot.go":        "package x\n\nimport . \"log\"\n\nfunc f() { Fatal(1) }\n",
		"internal/x/logok.go":         "package x\n\nimport \"log\"\n\nfunc f() { log.Printf(\"x\") }\n",
		"test/conformance/cmd/a/a.go": "package main\n\nimport \"log\"\n\nfunc main() { log.Fatal(1) }\n",
		// the guest helpers under test/vm/cmd (permlistener, a third-party listener) are programs of their own.
		"test/vm/cmd/h/h.go": "package main\n\nimport \"os\"\n\nfunc main() { os.Exit(2) }\n",
		// the stand-in Claude Code (test/e2e/reason-claude/fakeclaude) is a program of its own, not tego.
		"test/e2e/reason-claude/fakeclaude/main.go": "package main\n\nimport \"os\"\n\nfunc main() { os.Exit(3) }\n",
		// a *log.Logger's Fatal* methods and the flag package's ExitOnError paths end the process too.
		"internal/x/lognew.go":     "package x\n\nimport (\n\t\"log\"\n\t\"os\"\n)\n\nvar l = log.New(os.Stderr, \"\", 0)\n",
		"internal/x/logdefault.go": "package x\n\nimport \"log\"\n\nvar l = log.Default\n",
		"internal/x/logmethod.go":  "package x\n\nimport \"log\"\n\nfunc f(l *log.Logger) { l.Fatalf(\"x\") }\n",
		"internal/x/flagparse.go":  "package x\n\nimport \"flag\"\n\nfunc f() { flag.Parse() }\n",
		"internal/x/flagexit.go":   "package x\n\nimport fl \"flag\"\n\nvar s = fl.NewFlagSet(\"x\", fl.ExitOnError)\n",
		"internal/x/flagok.go":     "package x\n\nimport \"flag\"\n\nvar s = flag.NewFlagSet(\"x\", flag.ContinueOnError)\n",
		"internal/x/fatalnolog.go": "package x\n\ntype T struct{}\n\nfunc (T) Fatal(string) {}\n\nfunc f(t T) { t.Fatal(\"x\") }\n",
		"internal/x/otherexit.go":  "package x\n\ntype T struct{}\n\nfunc (T) Exit(int) {}\n\nfunc f(t T) { t.Exit(1) }\n",
	})
	findings, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Rule+" "+f.Pos] = true
	}
	want := []string{
		"I9 internal/cli/bare.go:4",
		"I9 internal/cli/paren.go:4",
		"I6 internal/x/alias.go:5",
		"I6 internal/x/split.go:6",
		"I6 internal/x/value.go:5",
		"I6 internal/x/dot.go:5",
		"I6 internal/x/chain.go:11",
		"I6 internal/x/logfatal.go:5",
		"I6 internal/x/logfatalf.go:5",
		"I6 internal/x/logfatalln.go:5",
		"I6 internal/x/logdot.go:5",
		"I6 internal/x/lognew.go:8",
		"I6 internal/x/logdefault.go:5",
		"I6 internal/x/logmethod.go:5",
		"I6 internal/x/flagparse.go:5",
		"I6 internal/x/flagexit.go:5",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing finding %s; got %v", w, findings)
		}
	}
	if len(findings) != len(want) {
		t.Errorf("got %d findings, want %d: %v", len(findings), len(want), findings)
	}
}

// TestCheckExitsRefusesAnEmptyList: a file list that holds nothing under internal/cli is a failure, not a
// pass: the grep this replaces passed on git 2.51 because its pathspec listed no file.
func TestCheckExitsRefusesAnEmptyList(t *testing.T) {
	root := plant(t, map[string]string{"internal/x/x.go": "package x\n"})
	if _, err := Check(root); err == nil || !strings.Contains(err.Error(), "internal/cli") {
		t.Errorf("Check = %v, want an error naming internal/cli", err)
	}
}

// TestCheckExitsScriptFailsOnAViolation runs scripts/check-exits.sh, the entry precommit and CI call, over a
// planted checkout and asserts it fails and names the violation.
func TestCheckExitsScriptFailsOnAViolation(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go run")
	}
	_, self, _, _ := runtime.Caller(0)
	script := filepath.Join(filepath.Dir(self), "..", "..", "scripts", "check-exits.sh")
	root := plant(t, map[string]string{
		"internal/cli/main.go": cleanCLI,
		"internal/cli/bare.go": "package cli\n\nfunc bare() int {\n\treturn 7\n}\n",
	})
	out, err := exec.Command(script, root).CombinedOutput()
	if err == nil {
		t.Fatalf("check-exits.sh passed a bare return 7 in internal/cli:\n%s", out)
	}
	if !strings.Contains(string(out), "internal/cli/bare.go:4") {
		t.Errorf("check-exits.sh did not name the violation:\n%s", out)
	}
	clean := plant(t, map[string]string{"internal/cli/main.go": cleanCLI})
	if out, err := exec.Command(script, clean).CombinedOutput(); err != nil {
		t.Errorf("check-exits.sh failed a clean checkout: %v\n%s", err, out)
	}
}

// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/cli"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// codexRowsTable is a `compile --test` table of the decisions the Codex contract is for: the task's own directory
// is written without anyone asked, and a write under held/ is granted by no fs.write entry. `compile --test` does not
// model fs.ask (it never supplies a person's answer), so the row for held/ reads `refused`, with no ordinary allow
// beneath it, which is the condition for the ask to fire; with an allow there it would read `allow` and the ask would
// be dead.
const codexRowsTable = `version: 0
tests:
  - name: a write in the work directory is allowed
    action: fs.write
    path: work/out.txt
    expect: allow
  - name: a write under held/ is covered by no fs.write entry, so only the ask can decide it
    action: fs.write
    path: held/x.txt
    expect: refused
    rule: unmatched
  - name: a write beside the work directory is refused
    action: fs.write
    path: elsewhere/x.txt
    expect: refused
`

// runCodexRows places codex.yaml (with rewrite applied), writes codexRowsTable beside it and returns the exit code
// and the text `tego compile --test` printed.
func runCodexRows(t *testing.T, rewrite ...string) (int, string) {
	t.Helper()
	path := place(t, "codex.yaml", rewrite...)
	if err := os.MkdirAll("held", 0o755); err != nil {
		t.Fatal(err)
	}
	table := filepath.Join(filepath.Dir(path), "codex-rows.yaml")
	if err := os.WriteFile(table, []byte(codexRowsTable), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := cli.Main([]string{"tego", "compile", path, "--offline", "--test", table}, &out, &errb)
	return code, out.String() + errb.String()
}

// codexAskLine is the example's approval scope exactly as the file spells it.
const codexAskLine = `ask: ["./held/"]`

// TestCodexExampleAsksForHeld pins that the example's `fs.ask` is not dead: an ordinary write grant decides before an
// ask does (spec/policy/SEMANTICS.md §6), so held/ must lie outside every fs.write entry. The first pass is the
// example itself; the second is a mutant with the grant widened to "./", where the write is allowed and nobody asked.
// The rows cannot show the other half, that an fs.ask entry for held/ exists at all (`compile --test` does not model
// fs.ask, and the compiled table does not list it), so two checks stand in: the file still spells the scope as
// codexAskLine, and the compiler does read that line as an fs.ask scope (a glob in its place is refused with the
// fs.ask diagnostic, which a file with no entry never produces).
func TestCodexExampleAsksForHeld(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgDir, "codex.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte("\n  "+codexAskLine+"\n")) {
		t.Fatalf("codex.yaml no longer holds %s under fs: a copy without the approval gate lets Codex write held/ unasked, or never reaches it", codexAskLine)
	}
	path := place(t, "codex.yaml", codexAskLine, `ask: ["./held/*"]`)
	var globOut, globErr bytes.Buffer
	if code := cli.Main([]string{"tego", "compile", path, "--offline"}, &globOut, &globErr); code == identity.ExitOK || !strings.Contains(globErr.String(), "fs.ask requires literal") {
		t.Errorf("a glob in fs.ask was not refused as an fs.ask scope, so the compiler does not read the example's ask line (exit %d):\n%s", code, globOut.String()+globErr.String())
	}
	if code, out := runCodexRows(t); code != identity.ExitOK {
		t.Errorf("the example's rule table is not what its comments say (exit %d):\n%s", code, out)
	}
	code, out := runCodexRows(t, `- "./work/"`, `- "./"`)
	if code == identity.ExitOK || !strings.Contains(out, "a write under held/ is covered by no fs.write entry, so only the ask can decide it") {
		t.Errorf("a grant of ./ leaves held/ inside fs.write and the ask never fires, yet the table passed (exit %d):\n%s", code, out)
	}
}

// TestCodexExample pins what lets examples/agents/codex.yaml, the full-screen Codex behind tego's forwarder
// (docs/OPERATIONS.md, "Interactive Codex under a boundary"; test/poc/interactive-codex), run under a contract with
// its model calls recorded:
//   - capture through the forwarder: Codex ignores OPENAI_BASE_URL, so the run's own CODEX_HOME carries the route, and
//     a static musl binary has no TLS library for a uprobe;
//   - `--no-daemon`: Codex's shared background server would otherwise run its commands outside the run;
//   - no `/proc/self/exe` in exec.allow, which compiles to tego's own executable;
//   - no write or ask entry over tego's runtime parent, $XDG_RUNTIME_DIR/tego: the run grants its private
//     CODEX_HOME there itself (R10a), and ~/.codex is not denied as a whole, because Codex's own installation lives in it;
//   - a direct connect to the model host refused in every tier (R38).
func TestCodexExample(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgDir, "codex.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte(`command: ["codex", "--no-daemon"]`)) {
		t.Error("the command is not `codex --no-daemon`: the shared background server would run Codex's commands outside the run")
	}
	c := compile(t, "codex.yaml")
	if c.Capture != "forwarder" {
		t.Errorf("capture %q, want forwarder: Codex ignores OPENAI_BASE_URL and has no TLS library for a uprobe", c.Capture)
	}
	if c.EnvSet["CODEX_HOME"] == "" {
		t.Errorf("env.set %v lacks CODEX_HOME: the launcher copies the config.toml from the directory it names", c.EnvSet)
	}
	for _, e := range c.Exec {
		if e.Raw == "/proc/self/exe" {
			t.Error("exec.allow lists /proc/self/exe, which compiles to tego's own executable")
		}
	}
	// No write entry reaches tego's runtime parent: the run grants its own CODEX_HOME there by itself, and an entry
	// over or inside <runtime>/tego is a contradiction (agent-contract.md R10a). place moves /run/user/<uid>/ into the
	// stand-in machine's runtime directory, which machine names in XDG_RUNTIME_DIR, so compile has already refused such
	// an entry; this reads the compiled table too, in case that check stops running here. The table compile --json
	// prints holds the write entries and the deny sets, not the fs.ask scopes, so an ask entry is covered by compile's
	// refusal alone, which TestCodexRuntimeParentGrantIsRefused holds for an ask entry too.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := filepath.EvalSymlinks(runtimeDir(cwd))
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(rt, "tego")
	for _, f := range c.FS {
		p := filepath.Clean(f.Path)
		if f.Kind == "write" && (p == parent || strings.HasPrefix(p, parent+"/") || strings.HasPrefix(parent, p+"/")) {
			t.Errorf("fs.%s %s reaches tego's runtime parent %s, where every run keeps its private directory; the run grants its own CODEX_HOME", f.Kind, f.Path, parent)
		}
	}
	for _, f := range c.FS {
		if f.Kind == "deny_read" && strings.HasSuffix(strings.TrimRight(f.Path, "/"), "/.codex") {
			t.Errorf("fs.deny_read %s denies all of ~/.codex, which holds Codex's own installation", f.Path)
		}
	}
	requireConnectRefused(t, "codex.yaml", "api.openai.com:443")
}

// TestCodexRealKeyContractsSayHowTheyDiffer pins the prose around test/poc/interactive-codex/codex-real-forwarder.yaml
// to what that contract is. Against the contract the POC ran offline (codex-interactive-offline.yaml)
// it drops the fs.ask for held/, widens the write grant to ./ and adds git, ls and mkdir, so it is not that contract
// "with the one change a real key needs": its header and the POC README's "With a real key" must say what it drops
// and send a reader who wants the held/ approval gate to examples/agents/codex.yaml, which keeps it; the changelog
// must not call it the same boundary; and codex.yaml is modelled on it, not its twin. The first checks are the
// differences themselves: when the contracts change, this test asks for the prose to be read again.
func TestCodexRealKeyContractsSayHowTheyDiffer(t *testing.T) {
	read := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(pkgDir, "..", "..", rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	poc := "test/poc/interactive-codex/"
	offline, realFwd := read(poc+"codex-interactive-offline.yaml"), read(poc+"codex-real-forwarder.yaml")
	if !strings.Contains(offline, "\n  "+codexAskLine+"\n") || strings.Contains(realFwd, codexAskLine) ||
		!strings.Contains(realFwd, "\n    - \"./\"\n") || !strings.Contains(realFwd, `allow: ["bash", "git", "cat", "ls", "mkdir"]`) {
		t.Fatalf("the differences between %s's offline and real-key contracts are no longer the ones this test pins "+
			"(no fs.ask for held/, a write grant of ./, git, ls and mkdir added): read the prose it checks again and update both", poc)
	}
	// header is the comment block the contract starts with.
	var header strings.Builder
	for _, l := range strings.Split(realFwd, "\n") {
		if !strings.HasPrefix(l, "#") {
			break
		}
		header.WriteString(l + "\n")
	}
	readme := read(poc + "README.md")
	section := readme
	if i := strings.Index(section, "\n## With a real key"); i >= 0 {
		section = section[i+1:]
		if j := strings.Index(section, "\n## "); j >= 0 {
			section = section[:j]
		}
	} else {
		t.Fatalf("%sREADME.md has no section \"With a real key\"", poc)
	}
	flat := func(s string) string { return strings.Join(strings.Fields(strings.ReplaceAll(s, "#", " ")), " ") }
	for _, d := range []struct{ name, text string }{{"codex-real-forwarder.yaml's header", header.String()}, {"README.md's \"With a real key\"", section}} {
		text := flat(d.text)
		if strings.Contains(text, "one change") {
			t.Errorf("%s still calls codex-real-forwarder.yaml the offline contract with one change", d.name)
		}
		for _, want := range []string{"held/", "examples/agents/codex.yaml"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not name %s: a reader of it expects the held/ approval gate the offline run showed", d.name, want)
			}
		}
	}
	if strings.Contains(flat(readme), "The same boundary for a real") {
		t.Errorf("%sREADME.md's file table still calls the real-key contracts the same boundary", poc)
	}
	if strings.Contains(flat(read("docs/CHANGELOG.md")), "codex-real-direct.yaml`: the same boundary for a real OpenAI") {
		t.Error("docs/CHANGELOG.md still calls the real-key contracts the same boundary as the offline one")
	}
	for _, f := range []string{"examples/agents/codex.yaml", "examples/README.md", "examples/agents/README.md"} {
		if strings.Contains(read(f), "twin") {
			t.Errorf("%s calls a Codex contract another's twin; they differ by more than the model's address", f)
		}
	}
}

// TestCodexRuntimeParentGrantIsRefused is the other half of TestCodexExample's runtime-parent check (agent-contract.md
// R10a): a copy of the example that grants tego's runtime parent, as the example did before the
// run granted its own CODEX_HOME, is refused by compile on the stand-in machine as on a real one, so the examples here
// are compiled with that check running. The grants are spelt as the example used to (/run/user/1000/...), which place
// moves into the stand-in runtime directory: the parent itself, a run's directory inside it, and the base above it,
// each as a write entry and as an fs.ask scope (compile --json lists no ask scope, so TestCodexExample's table check
// cannot see one).
func TestCodexRuntimeParentGrantIsRefused(t *testing.T) {
	for _, grant := range []string{`"/run/user/1000/tego/"`, `"/run/user/1000/tego/some-run/"`, `"/run/user/1000/"`} {
		for _, kind := range []string{"write", "ask"} {
			t.Run(kind+" "+grant, func(t *testing.T) {
				rewrite := []string{`    - "./work/"` + "\n", `    - "./work/"` + "\n    - " + grant + "\n"}
				if kind == "ask" {
					rewrite = []string{codexAskLine, `ask: ["./held/", ` + grant + `]`}
				}
				refusedOverRuntimeParent(t, "codex.yaml", "fs."+kind+" "+grant, rewrite...)
			})
		}
	}
}

// refusedOverRuntimeParent places name with rewrite on the stand-in machine, with tego's runtime parent and a run's
// directory in it made, as on a machine with tego runs, and wants compile to refuse it as a contradiction over that
// parent (R10a).
func refusedOverRuntimeParent(t *testing.T, name, what string, rewrite ...string) {
	t.Helper()
	path := place(t, name, rewrite...)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runtimeDir(cwd), "tego", "some-run"), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := cli.Main([]string{"tego", "compile", path, "--offline"}, &out, &errb)
	if code == identity.ExitOK || !strings.Contains(errb.String(), "tego's runtime directory") || !strings.Contains(errb.String(), "[contradiction]") {
		t.Errorf("%s over tego's runtime parent was not refused as a contradiction (exit %d):\n%s", what, code, out.String()+errb.String())
	}
}

// TestCodexPOCRealKeyContractsCompile compiles the interactive-Codex POC's two real-key contracts on the stand-in
// machine, with its runtime directory in XDG_RUNTIME_DIR, so that compile's R10a check runs on them: the forwarder
// variant granted $XDG_RUNTIME_DIR/tego/ for the run's CODEX_HOME before the run granted that itself, and a copy that
// still did is refused by `tego compile`. The offline contract is a template, and is compiled
// filled in as run.sh fills it, with run.sh's XDG_RUNTIME_DIR ($ROOT/xdg-tego) the stand-in machine's runtime
// directory, so any entry that reaches the runtime parent is refused whatever its spelling ("@ROOT@/" covers it as
// "@ROOT@/xdg-tego/tego/" does: the text check caught only the second).
func TestCodexPOCRealKeyContractsCompile(t *testing.T) {
	poc := filepath.Join("..", "..", "test", "poc", "interactive-codex")
	for _, name := range []string{"codex-real-forwarder.yaml", "codex-real-direct.yaml"} {
		t.Run(name, func(t *testing.T) {
			compile(t, filepath.Join(poc, name))
		})
	}
	offline := filepath.Join(poc, "codex-interactive-offline.yaml")
	t.Run("codex-interactive-offline.yaml", func(t *testing.T) {
		compile(t, offline, fillOffline()...)
	})
	// The check runs on the filled template: a copy that grants the runtime parent, or the root above it, is refused.
	// A replacement is not scanned again, so the added entry is spelt as fillOffline fills $ROOT and the runtime dir.
	for _, grant := range []struct{ template, filled string }{
		{`"@ROOT@/xdg-tego/tego/"`, `"@WORK@/../xdg/tego/"`},
		{`"@ROOT@/"`, `"@WORK@/../"`},
	} {
		t.Run("refused "+grant.template, func(t *testing.T) {
			refusedOverRuntimeParent(t, offline, "fs.write "+grant.template,
				fillOffline(`    - "@ROOT@/tmp/"`+"\n", `    - "@WORK@/../tmp/"`+"\n    - "+grant.filled+"\n")...)
		})
	}
}

// fillOffline is place's rewrite for the offline template, after the extra pairs first: run.sh's names filled in on
// the stand-in machine, $ROOT the directory above the work directory, whose xdg/ is the machine's runtime directory
// (machine, runtimeDir), where run.sh's is $ROOT/xdg-tego. The model port is any; the deny_read line is left out (the
// machine's ~/.codex files are not in the template's form); CODEX_HOME names a directory under $ROOT.
func fillOffline(extra ...string) []string {
	return append(extra,
		"@ROOT@/xdg-tego", "@WORK@/../xdg",
		"@ROOT@", "@WORK@/..",
		"@STUB_PORT@", "8000",
		"@DENY_READ@", "",
		"@PASS_EXTRA@", "",
	)
}

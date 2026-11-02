// SPDX-License-Identifier: Apache-2.0

//go:build integration

// Package demo holds the test that keeps the demo kit honest: it runs demo.sh's acts 1 to 3 (and, in
// features_test.go, the feature scenes) against a real tego and asserts what README.md tells the presenter to say. The binary is built with
// -tags tegotesthooks, so its chain anchor and own log stay in the test's directory, and the test runs
// under a machine config of its own: nothing here reads or writes the invoking user's ~/.tego. The
// agents are fake: the "secret" is a planted file and the "internet" is sink.py on 127.0.0.1.
//
// Run: go test -tags integration ./examples/demo/   (needs python3, curl and Landlock)
package demo

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestMain(m *testing.M) { os.Exit(testutil.GuardedMain(m)) }

// kit is one isolated demo: its own tego binary, machine config, ledger, stage and sink port.
type kit struct {
	t      *testing.T
	base   string
	bin    string
	stage  string
	ledger string
	env    []string
}

func newKit(t *testing.T) *kit {
	t.Helper()
	for _, tool := range []string{"python3", "curl", "sh"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	base := t.TempDir()
	// the machine config's directory must not be group-writable
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "bin", "tego")
	build := exec.Command("go", "build", "-tags", "tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build tego: %v\n%s", err, out)
	}
	for _, d := range []string{"home", "ledger"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Outside tego-own/, which TegoEnv keeps as tego's own directory and the agent is denied: the reason
	// file (TEGO_REASON) lives under XDG_RUNTIME_DIR and the agent has to be able to read it.
	xdg := filepath.Join(base, "xdg")
	if err := os.MkdirAll(xdg, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "machine.yaml")
	ledger := filepath.Join(base, "ledger")
	if err := os.WriteFile(cfg, []byte("version: 0\nledger_root: "+ledger+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	stage := filepath.Join(base, "stage")
	env := testutil.TegoEnv(t, base,
		"HOME="+filepath.Join(base, "home"),
		"XDG_RUNTIME_DIR="+xdg,
		"TEGO_CONFIG="+cfg,
		"TEGO="+bin,
		"PATH="+filepath.Dir(bin)+":/usr/local/bin:/usr/bin:/bin",
		"DEMO_STAGE="+stage,
		"DEMO_PORT="+strconv.Itoa(port),
		"LANG=C.UTF-8", "TERM=dumb",
	)
	k := &kit{t: t, base: base, bin: bin, stage: stage, ledger: ledger, env: env}
	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = env
	testutil.RequireTier(t, doctor, "landlock")
	t.Cleanup(func() { _, _ = k.demo("reset") })
	return k
}

// demo runs `demo.sh <args>` and returns its combined output.
func (k *kit) demo(args ...string) (string, error) {
	k.t.Helper()
	cmd := exec.Command("sh", append([]string{"demo.sh"}, args...)...)
	cmd.Env = k.env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (k *kit) mustDemo(args ...string) string {
	k.t.Helper()
	out, err := k.demo(args...)
	if err != nil {
		k.t.Fatalf("demo.sh %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (k *kit) sinkLog() string {
	b, _ := os.ReadFile(filepath.Join(k.stage, "sink.log"))
	return string(b)
}

func readLedgerEvents(t *testing.T, ledger string) string {
	t.Helper()
	runs, err := os.ReadDir(ledger)
	if err != nil || len(runs) == 0 {
		t.Fatalf("no run in the ledger %s: %v", ledger, err)
	}
	b, err := os.ReadFile(filepath.Join(ledger, runs[len(runs)-1].Name(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustContain(t *testing.T, what, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("%s: missing %q in:\n%s", what, w, out)
		}
	}
}

// TestActsOneToThree is the demo's spine: harm without Tego, the same agent refused under Tego, and the
// reason and the tamper-evident record.
func TestActsOneToThree(t *testing.T) {
	k := newKit(t)
	mustContain(t, "setup", k.mustDemo("setup"), "loopback sink")

	// Act 1: without Tego the fake secret reaches the sink and the machine is changed.
	out := k.mustDemo("without")
	mustContain(t, "without", out,
		"read "+filepath.Join(k.stage, "secrets", ".env"), "sent ", "appended to the shell profile",
		"wrote .git/hooks/pre-commit", "deleted notes.txt", "ran whoami",
		"1 request(s) arrived", "shell profile: TAMPERED", "git hook: PLANTED", "notes.txt: DELETED")
	if !strings.Contains(k.sinkLog(), "reached the sink") {
		t.Errorf("Act 1: the sink received nothing:\n%s", k.sinkLog())
	}

	// Act 2: the same agent under Tego. The sink hears nothing, the machine is untouched, the ledger
	// holds a refusal per step.
	out = k.mustDemo("with")
	mustContain(t, "with", out,
		"could not read the secrets file (refused)", "could not reach", "write to the shell profile refused",
		"git-hook write refused", "notes.txt still here (delete refused)", "exec refused",
		"0 request(s) arrived", "shell profile: untouched", "git hook: none", "notes.txt: still there")
	if strings.Contains(k.sinkLog(), "reached the sink") {
		t.Errorf("Act 2: the sink received a request under Tego:\n%s", k.sinkLog())
	}
	events := readLedgerEvents(t, k.ledger)
	for _, reason := range []string{"read-denied", "net-not-allowed", "write-outside-contract", "delete-outside-contract", "exec-not-allowed"} {
		if !strings.Contains(events, `"reason":"`+reason+`"`) {
			t.Errorf("Act 2: the ledger holds no refusal %q", reason)
		}
	}

	// The run id Act 3 reads back is the one the agent printed about its own run, not the last row of
	// `tego status --all`.
	mustContain(t, "run id", out, "run id: r-")
	if b, err := os.ReadFile(filepath.Join(k.stage, "last-run")); err != nil || !strings.Contains(out, "run id: "+strings.TrimSpace(string(b))) {
		t.Errorf("stage/last-run %q is not the run id the agent printed: %v", b, err)
	}

	// The reason the agent was given names the rule (step 7 of the agent reads $TEGO_REASON).
	mustContain(t, "reason file", out,
		"Tego refused open", "rule fs.deny_read[../secrets/]", "Tego refused exec", "that program is not allowed")

	// Act 3: the last refusal, the verified chain, and a copy with one word changed that does not verify.
	out = k.mustDemo("why")
	mustContain(t, "why", out, "exec-not-allowed", ": verified ", "head ", "(exit 1: the edit is detected)", "ledger-corrupt")
}

// shimPython3 puts a version manager's kind of python3 first on the kit's PATH: a #! script that runs the real one, as
// pyenv's and asdf's shims do. It returns the shim's folder.
func (k *kit) shimPython3() string {
	k.t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		k.t.Skip("python3 is not installed")
	}
	shim := filepath.Join(k.base, "shims")
	if err := os.MkdirAll(shim, 0o755); err != nil {
		k.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shim, "python3"), []byte("#!/usr/bin/env sh\nexec '"+py+"' \"$@\"\n"), 0o755); err != nil {
		k.t.Fatal(err)
	}
	k.env = append(k.env, "PATH="+shim+":"+filepath.Dir(k.bin)+":/usr/local/bin:/usr/bin:/bin")
	return shim
}

// TestActTwoGrantsThePython3ItRuns: where python3 on PATH is a version manager's #! shim (pyenv, asdf), the guarded
// contract granted the shim by that name, and tego refused to start Act 2's run: the shim's own interpreter,
// /usr/bin/env, is on no list ("script interpreter is not granted"). demo.sh now writes the file python3 runs as into
// the contract and hands it to the agent as PYTHON3, so the act runs as it does without a shim: every step refused, the
// sentences of step 7, and no refusal of the interpreter itself.
func TestActTwoGrantsThePython3ItRuns(t *testing.T) {
	k := newKit(t)
	shim := k.shimPython3()
	k.mustDemo("setup")
	out := k.mustDemo("with")
	if strings.Contains(out, "script interpreter is not granted") {
		t.Fatalf("tego refused to start Act 2 under a python3 shim:\n%s", out)
	}
	mustContain(t, "with, python3 a shim", out,
		"could not read the secrets file (refused)", "exec refused", "run id: r-",
		"Tego refused open", "rule fs.deny_read[../secrets/]", "Tego refused exec", "that program is not allowed",
		"0 request(s) arrived", "shell profile: untouched")
	b, err := os.ReadFile(filepath.Join(k.stage, "project", "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if contract := string(b); strings.Contains(contract, `"python3"`) || strings.Contains(contract, shim) || !strings.Contains(contract, `"PYTHON3"`) {
		t.Errorf("the planted contract does not name python3 by the file it runs as, or does not pass it on:\n%s", contract)
	}
	for _, ln := range strings.Split(readLedgerEvents(t, k.ledger), "\n") {
		if strings.Contains(ln, `"reason":"exec-not-allowed"`) && !strings.Contains(ln, "/usr/bin/whoami") {
			t.Errorf("Act 2 refused an exec other than whoami's: %s", ln)
		}
	}
}

// TestActTwoGrantsAPython3ReachedThroughASpace: a venv under a folder whose name holds a space names its python3 there
// (sys.executable), and an exec.allow entry with a space reads as a command: the planted contracts stopped compiling.
// demo.sh passes over a spelling with a space for the file it links to, so Act 2 runs as it does without one.
func TestActTwoGrantsAPython3ReachedThroughASpace(t *testing.T) {
	k := newKit(t)
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	real, err := filepath.EvalSymlinks(py)
	if err != nil {
		t.Fatal(err)
	}
	venv := filepath.Join(k.base, "My Projects", "bin")
	if err := os.MkdirAll(venv, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(venv, "python3")); err != nil {
		t.Fatal(err)
	}
	k.env = append(k.env, "PATH="+venv+":"+filepath.Dir(k.bin)+":/usr/local/bin:/usr/bin:/bin")
	k.mustDemo("setup")
	out := k.mustDemo("with")
	mustContain(t, "with, python3 behind a space", out, "could not read the secrets file (refused)", "run id: r-",
		"Tego refused exec", "shell profile: untouched")
	b, err := os.ReadFile(filepath.Join(k.stage, "project", "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if contract := string(b); strings.Contains(contract, "My Projects") {
		t.Errorf("the planted contract names python3 by a spelling with a space:\n%s", contract)
	}
}

// TestTamperStepTakesTheRecordFromTego: Act 3's copy of the record comes from tego, which reads the ledger wherever
// the machine config puts it. demo.sh used to read ledger_root out of the config with sed, which took a value in quotes
// or one followed by a comment as part of the path, so the tamper step was skipped; this kit's config writes it so.
func TestTamperStepTakesTheRecordFromTego(t *testing.T) {
	k := newKit(t)
	cfg := filepath.Join(k.base, "machine.yaml")
	if err := os.WriteFile(cfg, []byte("version: 0\nledger_root: \""+k.ledger+"\"   # this kit's own\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k.mustDemo("setup")
	k.mustDemo("with")
	out := k.mustDemo("why")
	mustContain(t, "why", out, ": verified ", "(exit 1: the edit is detected)", "ledger-corrupt")
	// The copy is the record itself: `tego events --json` gives back events.jsonl byte for byte, so the one change
	// --verify can find in the copy is the word sed changed.
	b, err := os.ReadFile(filepath.Join(k.stage, "last-run"))
	if err != nil {
		t.Fatal(err)
	}
	run := strings.TrimSpace(string(b))
	cmd := exec.Command(k.bin, "events", run, "--json")
	cmd.Env = k.env
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("tego events %s --json: %v", run, err)
	}
	want, err := os.ReadFile(filepath.Join(k.ledger, run, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("tego events %s --json is not the run's events.jsonl byte for byte:\n%s\nwant\n%s", run, got, want)
	}
}

// TestNetworkScene holds the network scene to its three outcomes, and to a ledger line for each refusal:
// the unnamed port and the backdoor listener (net.listen: [] makes the bind a recorded refusal).
func TestNetworkScene(t *testing.T) {
	k := newKit(t)
	k.mustDemo("setup")
	out := k.mustDemo("network")
	mustContain(t, "network", out, "[agent] ALLOWED connect", "[agent] REFUSED connect", "[agent] REFUSED listen on 127.0.0.1:4444")
	// The ledger tables hold the allowed connection and the refusals, once each, and no exec row of net-agent.sh.
	mustContain(t, "network tables", out, "The connection the contract allows", "The refusals (each carries its rule)")
	if i := strings.Index(out, "The connection the contract allows"); i >= 0 && strings.Contains(out[i:], "net-agent.sh") {
		t.Errorf("the network scene's ledger tables show an exec row:\n%s", out[i:])
	}
	events := readLedgerEvents(t, k.ledger)
	for _, want := range []string{`"op":"bind","target":"127.0.0.1:4444"`, `"reason":"net-not-allowed"`} {
		if !strings.Contains(events, want) {
			t.Errorf("network: the ledger holds no %s", want)
		}
	}
}

// TestContractsCompile holds every contract of the kit to `tego compile` with no error. The real-agent
// contracts need their binary on PATH to compile (the command names it), so they are skipped without.
func TestContractsCompile(t *testing.T) {
	k := newKit(t)
	k.mustDemo("setup")
	proj := filepath.Join(k.stage, "project")
	xdg := ""
	for _, kv := range k.env {
		if v, ok := strings.CutPrefix(kv, "XDG_RUNTIME_DIR="); ok {
			xdg = v
		}
	}
	codexHost := ""
	if p, err := exec.LookPath("codex"); err == nil {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			codexHost = filepath.Dir(real)
		}
	}
	fillers := strings.NewReplacer("@@STAGE@@", k.stage, "@@XDG@@", xdg, "@@CODEXHOST@@", codexHost)
	for _, tc := range []struct{ file, bin string }{
		{"guarded.yaml", ""}, {"always-on.yaml", ""}, {"claude-code.yaml", "claude"}, {"codex.yaml", "codex"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			if tc.bin != "" {
				if _, err := exec.LookPath(tc.bin); err != nil {
					t.Skipf("%s is not installed", tc.bin)
				}
			}
			src, err := os.ReadFile(filepath.Join("contracts", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(k.base, "compile-"+strings.TrimSuffix(tc.file, ".yaml"))
			if err := os.MkdirAll(filepath.Join(dir, "work"), 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(k.base, "c-"+tc.file)
			if err := os.WriteFile(path, []byte(fillers.Replace(string(src))), 0o644); err != nil {
				t.Fatal(err)
			}
			cwd := dir
			if tc.file == "guarded.yaml" || tc.file == "always-on.yaml" {
				cwd = proj // "../secrets/" is relative to the project
			}
			// the tool's PATH for the command lookup includes the real claude / codex
			env := append(append([]string{}, k.env...), "PATH="+os.Getenv("PATH"))
			cmd := exec.Command(k.bin, "compile", path)
			cmd.Dir, cmd.Env = cwd, env
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("tego compile %s: %v\n%s", tc.file, err, out)
			}
			for _, ln := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(ln, "error") {
					t.Errorf("tego compile %s: %s", tc.file, ln)
				}
			}
		})
	}
}

// TestCodexContractFilled: demo.sh codex writes a contract Codex can run commands under. Codex runs every command
// in a pseudo-terminal and through its own helper, codex-code-mode-host, which sits next to the real codex binary
// (the PATH entry is usually a symlink to it), so the written contract names both: /dev/ptmx and /dev/pts/
// writable, and the helper's real path in exec.allow. A fake codex stands in; the run itself may fail, the contract
// is what is checked.
func TestCodexContractFilled(t *testing.T) {
	k := newKit(t)
	k.mustDemo("setup")
	real := filepath.Join(k.base, "codex-install", "bin")
	link := filepath.Join(k.base, "codex-path")
	for _, d := range []string{real, link} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(real, "codex"), []byte("#!/bin/sh\necho fake codex \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(real, "codex"), filepath.Join(link, "codex")); err != nil {
		t.Fatal(err)
	}
	realDir, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "demo.sh", "codex", "--version")
	cmd.Env = append(append([]string{}, k.env...), "PATH="+link+":"+filepath.Dir(k.bin)+":/usr/local/bin:/usr/bin:/bin")
	_, _ = cmd.CombinedOutput()
	b, err := os.ReadFile(filepath.Join(k.stage, "codex.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "@@CODEXHOST@@") {
		t.Errorf("codex.yaml still holds @@CODEXHOST@@:\n%s", got)
	}
	mustContain(t, "codex.yaml", got, `"/dev/ptmx"`, `"/dev/pts/"`, `"`+realDir+`/codex-code-mode-host"`,
		`"touch"`, `"grep"`, `"sed"`, `"head"`, `"tail"`, `"find"`, `"wc"`, `"tr"`, `"sort"`)
}

// TestResetLeavesTheDefaultUnitAlone: a reset on a stage of its own (DEMO_STAGE, as every test and isolated run has)
// stops the unit named from that stage and never tego-demo-agent, which may be a user's own always-on demo.
func TestResetLeavesTheDefaultUnitAlone(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "systemctl.log")
	stub := filepath.Join(dir, "bin")
	if err := os.MkdirAll(stub, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho \"$*\" >>'" + log + "'\n"
	if err := os.WriteFile(filepath.Join(stub, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(extra ...string) string {
		_ = os.Remove(log)
		cmd := exec.Command("sh", "demo.sh", "reset")
		cmd.Env = append([]string{"PATH=" + stub + ":/usr/local/bin:/usr/bin:/bin", "HOME=" + dir,
			"DEMO_STAGE=" + filepath.Join(dir, "stage")}, extra...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("demo.sh reset: %v\n%s", err, out)
		}
		b, _ := os.ReadFile(log)
		return string(b)
	}
	got := run()
	if !strings.Contains(got, "stop tego-demo-agent-") || strings.Contains(got, "stop tego-demo-agent\n") {
		t.Errorf("reset on its own stage called systemctl %q: want a stop of tego-demo-agent-<n> only", got)
	}
	if got := run("TEGO_DEMO_UNIT=mine"); !strings.Contains(got, "stop mine\n") {
		t.Errorf("reset with TEGO_DEMO_UNIT=mine called systemctl %q: want a stop of mine", got)
	}
}

// TestAlwaysOnTakesTheUnitTemplatesKeys: the always-on act's transient unit ends a run the way the shipped template
// (examples/systemd/tego-agent@.service) does, so the dashboard's Stop or `tego stop` leaves it stopped rather
// than restarted, `./demo.sh always-on stop` leaves it inactive rather than failed, and a crash or the hour's wall
// limit still restarts it.
func TestAlwaysOnTakesTheUnitTemplatesKeys(t *testing.T) {
	tmpl, err := os.ReadFile(filepath.Join("..", "systemd", "tego-agent@.service"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile("demo.sh")
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, line := range strings.Split(string(tmpl), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
			keys[k] = v
		}
	}
	for _, k := range []string{"Restart", "SuccessExitStatus", "RestartPreventExitStatus", "KillMode", "TimeoutStopSec"} {
		v, ok := keys[k]
		if !ok {
			t.Fatalf("the template sets no %s", k)
		}
		if p := k + "=" + v; !strings.Contains(string(script), "-p "+p+" ") && !strings.Contains(string(script), "-p '"+p+"'") {
			t.Errorf("demo.sh's always-on unit does not set %s as the template does", p)
		}
	}
}

// stubBin writes executable scripts named after the programs they stand in for into a new directory and returns it.
func stubBin(t *testing.T, scripts map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestAlwaysOnPrintsOneOptionALine: the always-on act prints the systemd-run command it runs one option to a line, not
// as one line of some 700 characters, and the values it passes on stay one word each: they went into the evaluated text
// unquoted, so a PATH entry with a space reached systemd-run as two words and a HOME with a quote broke the command.
// The PATH is a presenter's, some dozen tool folders: printed as its value it was one line of hundreds of characters,
// so the variables the unit takes from the caller are printed by name, and still reach systemd-run whole, the
// caller's XDG_RUNTIME_DIR included (not the user manager's, which the command line sets for systemd-run itself).
func TestAlwaysOnPrintsOneOptionALine(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "systemd-run.args")
	stub, home, stage := filepath.Join(dir, "stub bin"), filepath.Join(dir, "it's home"), filepath.Join(dir, "stage")
	for _, d := range []string{stub, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"tego":        "echo tego\n",
		"systemd-run": "for a in \"$@\"; do printf '%s\\n' \"$a\"; done >'" + log + "'\n",
		"systemctl":   "exit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(stub, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	entries := []string{stub}
	for i := range 12 {
		entries = append(entries, filepath.Join(dir, "tools", "a-version-manager", "installs", "tool-"+strconv.Itoa(i), "bin"))
	}
	path := strings.Join(append(entries, "/usr/local/bin", "/usr/bin", "/bin"), ":")
	xdg, cfg := filepath.Join(dir, "xdg"), filepath.Join(dir, "machine.yaml")
	env := []string{"PATH=" + path, "HOME=" + home, "XDG_RUNTIME_DIR=" + xdg, "TEGO_CONFIG=" + cfg, "DEMO_STAGE=" + stage, "DEMO_PORT=" + freePort(t)}
	demo := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("sh", append([]string{"demo.sh"}, args...)...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("demo.sh %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	t.Cleanup(func() { demo("reset") })
	out := demo("always-on")

	b, _ := os.ReadFile(log)
	args := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	for _, want := range []string{"--setenv=PATH=" + path, "--setenv=HOME=" + home, "--setenv=XDG_RUNTIME_DIR=" + xdg,
		"--setenv=TEGO_CONFIG=" + cfg, "--working-directory=" + filepath.Join(stage, "always-on", "project"),
		"RestartPreventExitStatus=143 125"} {
		if !slices.Contains(args, want) {
			t.Errorf("systemd-run got no argument %q:\n%s", want, strings.Join(args, "\n"))
		}
	}
	if n := len(args); n < 3 || !slices.Equal(args[n-3:], []string{filepath.Join(stub, "tego"), "run", "always-on.yaml"}) {
		t.Errorf("systemd-run's command is not tego run always-on.yaml:\n%s", strings.Join(args, "\n"))
	}

	// What the presenter sees, with the test's own folder as a short word, as a stage would be on a demo machine.
	shown := strings.ReplaceAll(out, dir, "$T")
	i, j := strings.Index(shown, "$ XDG_RUNTIME_DIR="), strings.Index(shown, "watch it:")
	if i < 0 || j < i {
		t.Fatalf("no systemd-run command printed:\n%s", out)
	}
	for _, ln := range strings.Split(shown[i:j], "\n") {
		if strings.Count(ln, "--setenv=") > 1 {
			t.Errorf("one printed line holds more than one --setenv: %s", ln)
		}
	}
	for _, ln := range strings.Split(shown, "\n") {
		if len(ln) > 200 {
			t.Errorf("a printed line is %d characters long: %s", len(ln), ln)
		}
	}
	mustContain(t, "the printed command", shown[i:j], `--setenv=PATH="$PATH"`, `--setenv=XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR"`)
}

// freePort is a TCP port on 127.0.0.1 that was free a moment ago, for a sink of the test's own.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// TestStageThatCannotBeQuotedIsRefused: show() evaluates each command it prints with the stage's paths between single
// quotes, and the claude, codex and reason-hook acts put the stage into contracts through sed, between double quotes.
// A stage path holding ' " \ | & or a line break broke the command ("Unterminated quoted string") or the contract, so
// it is refused before anything is made; a space is quoted like any other character, and the act runs.
func TestStageThatCannotBeQuotedIsRefused(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	dir := t.TempDir()
	stub := stubBin(t, map[string]string{"tego": "exit 0\n"})
	port := freePort(t)
	demo := func(stage string, args ...string) (string, error) {
		cmd := exec.Command("sh", append([]string{"demo.sh"}, args...)...)
		cmd.Env = []string{"PATH=" + stub + ":/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "DEMO_STAGE=" + stage, "DEMO_PORT=" + port}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, name := range []string{"it's", `say "hi"`, `back\slash`, "a|b", "a&b", "line\nbreak"} {
		stage := filepath.Join(dir, name, "stage")
		// A stage that is not refused starts a sink there, which a reset of that stage would not stop: stop it here.
		t.Cleanup(func() {
			if b, err := os.ReadFile(filepath.Join(stage, "sink.pid")); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
					_ = syscall.Kill(pid, syscall.SIGTERM)
				}
			}
		})
		out, err := demo(stage, "without")
		if err == nil || !strings.Contains(out, "the stage holds one of") || !strings.Contains(out, stage+" (set DEMO_STAGE to a path without them)") {
			t.Errorf("DEMO_STAGE=%q: want the stage refused, named whole, got %v:\n%s", stage, err, out)
		}
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			t.Errorf("DEMO_STAGE=%q: the refused stage was made", stage)
		}
	}
	stage := filepath.Join(dir, "my stage")
	t.Cleanup(func() { _, _ = demo(stage, "reset") })
	out, err := demo(stage, "without")
	if err != nil {
		t.Fatalf("DEMO_STAGE=%q: demo.sh without: %v\n%s", stage, err, out)
	}
	mustContain(t, "a stage with a space", out, "deleted notes.txt", "shell profile: TAMPERED", "notes.txt: DELETED")
}

// copyKit copies the demo kit (the scripts, agents, contracts and scenes, not a stage of its own) to dst.
func copyKit(t *testing.T, dst string) {
	t.Helper()
	for _, d := range []string{"agents", "contracts", "scenes"} {
		if err := os.CopyFS(filepath.Join(dst, d), os.DirFS(d)); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"demo.sh", "sink.py", "sockd.py", "modelsaw.py", "README.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, f), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// TestKitFolderIsHeldOnlyToTheQuote: the kit's own folder and tego's path reach show()'s evaluated text between single
// quotes only, and are otherwise quoted arguments, so a ' or a line break is all that is refused in them. demo.sh
// refused a " \ | or & there too, as it must in the stage, which goes into contracts: a checkout under a folder named
// R&D ran no act at all, even with DEMO_STAGE elsewhere. Without DEMO_STAGE the stage is in that folder, and is refused
// with what to do.
func TestKitFolderIsHeldOnlyToTheQuote(t *testing.T) {
	for _, tool := range []string{"python3", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	// demo runs `demo.sh <sub>` of the kit in kit, with bin first on PATH and env added.
	demo := func(kit, bin, sub string, env ...string) (string, error) {
		cmd := exec.Command("sh", "demo.sh", sub)
		cmd.Dir = kit
		cmd.Env = append([]string{"PATH=" + bin + ":/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "DEMO_PORT=" + freePort(t)}, env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// kitIn copies the kit to <parent>/demo and a stand-in tego to <parent>/bin, and returns both folders.
	kitIn := func(parent string) (string, string) {
		kit, bin := filepath.Join(parent, "demo"), filepath.Join(parent, "bin")
		copyKit(t, kit)
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "tego"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return kit, bin
	}
	for i, name := range []string{"R&D", `say "hi"`, `back\slash`, "a|b"} {
		kit, bin := kitIn(filepath.Join(dir, name))
		stage := filepath.Join(dir, "stage-"+strconv.Itoa(i))
		out, err := demo(kit, bin, "without", "DEMO_STAGE="+stage)
		if _, rerr := demo(kit, bin, "reset", "DEMO_STAGE="+stage); rerr != nil { // stops the act's sink
			t.Errorf("demo.sh reset of %s: %v", stage, rerr)
		}
		if err != nil {
			t.Errorf("a kit under %q, DEMO_STAGE elsewhere: demo.sh without: %v\n%s", name, err, out)
		} else {
			mustContain(t, "a kit under "+name, out, "deleted notes.txt", "notes.txt: DELETED")
		}
		own := filepath.Join(kit, "stage")
		out, err = demo(kit, bin, "without")
		if err == nil || !strings.Contains(out, "the stage holds one of") || !strings.Contains(out, own+" (set DEMO_STAGE to a path without them)") {
			t.Errorf("a kit under %q with its own stage: want that stage refused, saying to set DEMO_STAGE, got %v:\n%s", name, err, out)
		}
		if _, err := os.Lstat(own); err == nil {
			t.Errorf("a kit under %q: the refused stage was made", name)
		}
	}
	// A ' does break show()'s quoting, in the kit's folder as in tego's path: refused before the act plants anything.
	kit, bin := kitIn(filepath.Join(dir, "it's"))
	stage := filepath.Join(dir, "stage-quote")
	if out, err := demo(kit, bin, "without", "DEMO_STAGE="+stage); err == nil || !strings.Contains(out, "the demo kit's folder holds a ' or a line break") {
		t.Errorf("a kit under a folder holding a ': want it refused, got %v:\n%s", err, out)
	}
	if _, err := os.Lstat(stage); err == nil {
		t.Errorf("a kit under a folder holding a ': the stage was made")
	}
	plainKit, _ := kitIn(filepath.Join(dir, "plain"))
	if out, err := demo(plainKit, bin, "without", "DEMO_STAGE="+stage); err == nil || !strings.Contains(out, "tego's path holds a ' or a line break") {
		t.Errorf("a tego under a folder holding a ': want it refused, got %v:\n%s", err, out)
	}
	if _, err := os.Lstat(filepath.Join(stage, "project")); err == nil {
		t.Errorf("a refused tego: the act planted the stage's project")
	}
}

// TestRealAgentsGetTheirArgumentsWhole: the words after `./demo.sh claude` or `./demo.sh codex` reach the agent as
// typed. show() evaluates the command it prints, and the words went in unquoted: a quote ended the command with a
// syntax error, and a space or a ~ split or expanded a prompt.
func TestRealAgentsGetTheirArgumentsWhole(t *testing.T) {
	prompt := "what's in ~/.ssh, and why?"
	for agent, want := range map[string][]string{
		"claude": {"claude", "-p", prompt},
		"codex":  {"codex", "--no-daemon", "-p", prompt},
	} {
		t.Run(agent, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "run.args")
			stub := stubBin(t, map[string]string{
				"tego": "[ \"$1\" = run ] || exit 0\nfor a in \"$@\"; do echo \"$a\"; done >'" + log + "'\n",
				agent:  "exit 0\n",
			})
			cmd := exec.Command("sh", "demo.sh", agent, "-p", prompt)
			cmd.Env = []string{"PATH=" + stub + ":/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "DEMO_STAGE=" + filepath.Join(dir, "stage")}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("demo.sh %s -p %q: %v\n%s", agent, prompt, err, out)
			}
			b, _ := os.ReadFile(log)
			args := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
			if i := slices.Index(args, "--"); i < 0 || !slices.Equal(args[i+1:], want) {
				t.Errorf("tego got %q, want %q after --", args, want)
			}
		})
	}
}

// TestTiersSaysWhenATierDidNotRun: the tiers scene pipes each run through tee and grep, so the pipeline's status was
// grep's and "tier 2 did not run" never showed: a sudo that refused was followed by "What is left on the machine",
// untouched since nothing ran, as if tier 2 had held. With stand-ins for tego and sudo, a sudo that refuses gets the
// message and no damage report, and one that runs the command gets the damage report and no message.
func TestTiersSaysWhenATierDidNotRun(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	for name, sudo := range map[string]string{
		"refused": "echo 'sudo: a password is required' >&2\nexit 1\n",
		"ran":     "shift\nexec \"$@\"\n", // drops --preserve-env=...
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			stub := stubBin(t, map[string]string{"tego": "[ \"$1\" = run ] || exit 0\necho '[agent] done'\n", "sudo": sudo})
			env := []string{"PATH=" + stub + ":/usr/local/bin:/usr/bin:/bin", "HOME=" + dir,
				"DEMO_STAGE=" + filepath.Join(dir, "stage"), "DEMO_PORT=" + freePort(t)}
			demo := func(args ...string) (string, error) {
				cmd := exec.Command("sh", append([]string{"demo.sh"}, args...)...)
				cmd.Env = env
				out, err := cmd.CombinedOutput()
				return string(out), err
			}
			t.Cleanup(func() { _, _ = demo("reset") })
			out, err := demo("tiers")
			if err != nil {
				t.Fatalf("demo.sh tiers: %v\n%s", err, out)
			}
			i, j := strings.Index(out, "== Tier 2"), strings.Index(out, "== Tier 3")
			if i < 0 || j < i {
				t.Fatalf("demo.sh tiers printed no tier 2 or tier 3 heading:\n%s", out)
			}
			tier2 := out[i:j]
			if name == "refused" {
				mustContain(t, "tier 2", tier2, "sudo: a password is required", "(tier 2 did not run: exit 1, see the message above)")
				if strings.Contains(tier2, "What is left on the machine") {
					t.Errorf("a tier 2 that did not run was followed by a damage report:\n%s", tier2)
				}
			} else {
				mustContain(t, "tier 2", tier2, "[agent] done", "What is left on the machine")
				if strings.Contains(tier2, "did not run") {
					t.Errorf("a tier 2 that ran was said not to:\n%s", tier2)
				}
			}
			if strings.Contains(out, "(tier 1 did not run") {
				t.Errorf("a tier 1 that ran was said not to:\n%s", out)
			}
		})
	}
}

// TestActTwoSaysWhenItsRunFailed: Act 2 piped `tego run` through tee and grep, so the act's status was grep's. A tego
// that refused to start the run was followed by "What is left on the machine", untouched since nothing ran, and by the
// refusals of the newest earlier run of the contract, as if this run had made them. With a stand-in tego whose run
// fails at start, the act now stops at tego's own status and says so, and leaves no stage/last-run, so Act 3 does not
// take the earlier run for this one either.
func TestActTwoSaysWhenItsRunFailed(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	dir := t.TempDir()
	stub := stubBin(t, map[string]string{"tego": `case "$1" in
run) echo 'tego run: runtime: prepare landlock: the test refuses this run [run]' >&2; exit 125 ;;
status) printf 'RUN AGENT\nr-earlier demo-guarded\n' ;;
events) echo "the refusals of $2" ;;
esac
`})
	stage := filepath.Join(dir, "stage")
	demo := func(args ...string) (string, error) {
		cmd := exec.Command("sh", append([]string{"demo.sh"}, args...)...)
		cmd.Env = []string{"PATH=" + stub + ":/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "DEMO_STAGE=" + stage, "DEMO_PORT=" + freePort(t)}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	t.Cleanup(func() { _, _ = demo("reset") })
	// An earlier Act 2 left its run for Act 3.
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "last-run"), []byte("r-earlier\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := demo("with")
	if err == nil {
		t.Errorf("demo.sh with exited 0 when its run failed:\n%s", out)
	}
	mustContain(t, "with, its run refused", out, "the test refuses this run", "the run failed (tego run exited 125): see its message above")
	for _, bad := range []string{"What is left on the machine", "the refusals of r-earlier", "Every refusal"} {
		if strings.Contains(out, bad) {
			t.Errorf("Act 2 whose run failed went on to %q:\n%s", bad, out)
		}
	}
	if _, err := os.Stat(filepath.Join(stage, "last-run")); err == nil {
		t.Errorf("Act 2 whose run failed left stage/last-run, which Act 3 would take for its run")
	}
	if out, err := demo("why"); err == nil || !strings.Contains(out, "no run yet") {
		t.Errorf("Act 3 after an Act 2 whose run failed: want no run, got %v:\n%s", err, out)
	}
}

// TestRogueReadsTheReasonFileByItsKeys: step 7 of the rogue agent prints each refusal's sentence from the reason file's
// keys. It took them with grep, tr and tail from the file's bytes, not its JSON: a & in a sentence, which Go's JSON
// writes as the escape of U+0026, came out as "u0026", and the escapes Tego puts in a quoted target were lost; and it
// slept a fixed second for the file to catch up. The agent runs here on its own, outside Tego, against files tego's own
// encoder writes: every step but the one a subtest breaks succeeds, so the agent waits only for the refusal it met.
func TestRogueReadsTheReasonFileByItsKeys(t *testing.T) {
	for _, tool := range []string{"python3", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	if _, err := os.Stat("/usr/bin/whoami"); err != nil {
		t.Skip("no /usr/bin/whoami: step 6 would fail, and the agent would wait for an exec refusal")
	}
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer sink.Close()
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	read := reason.Refusal{Seq: 4, TS: at, PID: 7, Payload: record.RefusedPayload{Op: "open",
		Target: `/stage/R&D "plans"/.env`, Reason: record.ReasonReadDenied, Rule: "fs.deny_read[../secrets/]"}}
	exe := reason.Refusal{Seq: 9, TS: at, PID: 8, Payload: record.RefusedPayload{Op: "exec", Target: "/usr/bin/whoami",
		Reason: record.ReasonExecNotAllowed, Rule: "unmatched"}}
	profile := reason.Refusal{Seq: 12, TS: at, PID: 9, Payload: record.RefusedPayload{Op: "open",
		Target: "/stage/home/.bashrc", Reason: record.ReasonWriteOutsideContract, Rule: "unmatched"}}
	lookup := reason.Refusal{Seq: 14, TS: at, PID: 10, Payload: record.RefusedPayload{Op: "net",
		Target: "unix:/var/run/nscd/socket", Reason: record.ReasonNetNotAllowed, Rule: "unmatched"}}
	sentences := func(rs ...reason.Refusal) string {
		var b strings.Builder
		for _, r := range rs {
			b.WriteString(reason.Text(r.Payload.Reason, r.Payload.Op, r.Payload.Target, r.Payload.Rule) + "\n")
		}
		return b.String()
	}
	// agent runs rogue.sh in a fake world of its own with TEGO_REASON at <dir>/r-test/last-refusal.json, which holds
	// first, and returns what step 7 printed after its run id line and how long that took. When then is set, the
	// file is rewritten to hold it 200 ms after that line is out.
	agent := func(t *testing.T, first, then []reason.Refusal, profileIsADir bool) (string, time.Duration) {
		t.Helper()
		dir := t.TempDir()
		secrets, home, project := filepath.Join(dir, "secrets"), filepath.Join(dir, "home"), filepath.Join(dir, "project")
		runDir := filepath.Join(dir, "r-test")
		for _, d := range []string{secrets, home, filepath.Join(project, ".git", "hooks"), runDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for p, s := range map[string]string{filepath.Join(secrets, ".env"): "fake\n", filepath.Join(project, "notes.txt"): "notes\n"} {
			if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if profileIsADir { // the shell profile cannot be appended to: step 3 fails, as under Tego
			if err := os.Mkdir(filepath.Join(home, ".bashrc"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		file := filepath.Join(runDir, reason.FileName)
		writeReasonFile(t, file, first)
		rewritten := make(chan struct{})
		cmd := exec.Command("sh", filepath.Join("agents", "rogue.sh"))
		cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + home, "SECRETS=" + secrets, "SINK=" + sink.URL,
			"HOMEISH=" + home, "PROJECT=" + project, "TEGO_REASON=" + file}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var all, step7 strings.Builder
		seen := false
		var started, ended time.Time
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			ln := sc.Text()
			all.WriteString(ln + "\n")
			switch {
			case seen && ln == "[agent] done":
				ended = time.Now()
			case seen:
				step7.WriteString(ln + "\n")
			case strings.HasPrefix(ln, "[agent]    run id: "):
				seen, started = true, time.Now()
				if ln != "[agent]    run id: r-test" {
					t.Errorf("step 7 printed %q, want the reason file's folder as the run id", ln)
				}
				if then != nil {
					go func() {
						defer close(rewritten)
						time.Sleep(200 * time.Millisecond)
						writeReasonFile(t, file, then)
					}()
				}
			}
		}
		err = cmd.Wait()
		if then != nil && seen {
			<-rewritten
		}
		if err != nil || !seen || ended.IsZero() {
			t.Fatalf("rogue.sh: %v, step 7 reached: %v\n%s", err, seen, all.String())
		}
		return step7.String(), ended.Sub(started)
	}

	t.Run("every sentence, decoded", func(t *testing.T) {
		if got, _ := agent(t, []reason.Refusal{read, exe}, nil, false); got != sentences(read, exe) {
			t.Errorf("step 7 printed\n%s\nwant\n%s", got, sentences(read, exe))
		}
	})
	t.Run("it waits for the refusal it met", func(t *testing.T) {
		// The agent met a refused write to its shell profile, which the file it first reads does not hold yet: it
		// reads the file again until it does, as Tego's file trails its ledger by a moment.
		got, _ := agent(t, []reason.Refusal{read, exe}, []reason.Refusal{read, exe, profile}, true)
		if want := sentences(read, exe, profile); got != want {
			t.Errorf("step 7 printed\n%s\nwant\n%s", got, want)
		}
	})
	t.Run("a later refusal does not hold it up", func(t *testing.T) {
		// The refused write it met is listed, and a refusal it never saw comes after it, as whoami's name lookup does
		// under rules that allow no socket: the agent stops reading at once, not at its 3 s limit.
		got, took := agent(t, []reason.Refusal{read, exe, profile, lookup}, nil, true)
		if want := sentences(read, exe, profile, lookup); got != want {
			t.Errorf("step 7 printed\n%s\nwant\n%s", got, want)
		}
		if took > 2*time.Second {
			t.Errorf("step 7 took %v: it waited for the file's latest refusal to be the one it met", took)
		}
	})
}

// writeReasonFile writes the reason file of recent at path as tego writes it: whole, through a rename.
func writeReasonFile(t *testing.T, path string, recent []reason.Refusal) {
	b, err := reason.Encode("r-test", uint64(len(recent)), recent)
	if err != nil {
		t.Error(err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Error(err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Error(err)
	}
}

// TestDashboardPassesItsArguments: with port 8484 busy the presenter needs `demo.sh dashboard --addr ...`.
func TestDashboardPassesItsArguments(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "args.log")
	stub := stubBin(t, map[string]string{"tego-control": "for a in \"$@\"; do echo \"$a\"; done >'" + log + "'\n"})
	cmd := exec.Command("sh", "demo.sh", "dashboard", "--addr", "127.0.0.1:18585")
	cmd.Env = []string{"PATH=" + stub + ":/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "DEMO_STAGE=" + filepath.Join(dir, "stage")}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("demo.sh dashboard: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(log)
	if got := strings.Join(strings.Fields(string(b)), " "); got != "serve --open --addr 127.0.0.1:18585" {
		t.Errorf("tego-control got %q, want serve --open --addr 127.0.0.1:18585", got)
	}
}

// TestAlwaysOnHasItsOwnFolders: the always-on service works in stage/always-on/, so the other acts'
// plant(), which clears project/, never pulls the running service's folders from under it.
func TestAlwaysOnHasItsOwnFolders(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	stub := stubBin(t, map[string]string{
		"tego":        "echo tego\n",
		"systemd-run": "echo \"$*\" >>'" + log + "'\n",
		"systemctl":   "exit 0\n",
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	stage := filepath.Join(dir, "stage")
	env := []string{"PATH=" + stub + ":/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "DEMO_STAGE=" + stage, "DEMO_PORT=" + strconv.Itoa(port)}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("sh", append([]string{"demo.sh"}, args...)...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("demo.sh %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	t.Cleanup(func() { run("reset") })
	run("always-on")
	b, _ := os.ReadFile(log)
	own := filepath.Join(stage, "always-on")
	for _, want := range []string{"--working-directory=" + filepath.Join(own, "project"), "--setenv=SECRETS=" + filepath.Join(own, "secrets")} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the always-on unit was started without %q:\n%s", want, b)
		}
	}
	if _, err := os.Stat(filepath.Join(stage, "project")); err == nil {
		t.Errorf("always-on planted stage/project, which the other acts clear")
	}
	if _, err := os.Stat(filepath.Join(own, "project", "watcher.sh")); err != nil {
		t.Errorf("the watcher is not in the service's own project: %v", err)
	}
}

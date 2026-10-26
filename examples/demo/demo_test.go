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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
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

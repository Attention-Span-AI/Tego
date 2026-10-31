// SPDX-License-Identifier: Apache-2.0

//go:build integration

package supplychain

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestProofShowsTheAttackRowsWhole: in a real take the enforced run's refusals start with Codex's own
// connections, so proof printed the first twelve refusals cut at 200 characters and the key's path fell off the
// screen. Here the enforced run makes 30 unrelated refused connects before the poisoned import: proof still shows
// the key, the token and the send to the right attacker, each line whole, and says how many refusals there were in
// all. After backup has cleared the attacker logs, proof says why they are empty.
func TestProofShowsTheAttackRowsWhole(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")
	noise := freePort(t) // nothing listens there, and the contract allows only the API
	initPy := filepath.Join(w.stage, "with", "proj", "tests", "__init__.py")
	extra := fmt.Sprintf(`
import socket as _s
for _i in range(30):
    _c = _s.socket()
    try:
        _c.settimeout(0.5)
        _c.connect(("127.0.0.1", %d))
    except OSError:
        pass
    finally:
        _c.close()
`, noise)
	b := readFile(t, initPy)
	if err := os.WriteFile(initPy, []byte(b+extra), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := w.demoEnv([]string{"DEMO_BACKUP_KEEP_LOGS=0"}, "backup"); code != 0 {
		t.Fatalf("backup: exit %d\n%s", code, out)
	}
	out := w.mustDemo("proof")
	right := strconv.Itoa(w.right)
	mustContain(t, "proof", out,
		"(empty: nothing reached it since the last reset or backup)",
		"fs.deny_read[<stage>/with/home/.ssh/]", "open <stage>/with/home/.ssh/id_rsa\n",
		"open <stage>/with/home/.config/telemetry/token\n",
		"net 127.0.0.1:"+right+"\n",
		"refusals in all (the rest are not the attack: Codex's own connections and any command the take refused; see the dashboard Logs)",
		"open <stage>/without/home/.ssh/id_rsa\n",
		"<stage> is "+w.stage)
	if strings.Contains(out, "127.0.0.1:"+strconv.Itoa(noise)) {
		t.Errorf("proof shows the unrelated connects:\n%s", out)
	}
	if strings.Contains(out, "left received, right did not") {
		t.Errorf("proof claims the left attacker received something though its log is empty:\n%s", out)
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "SEQ ") || strings.Contains(line, "refusals in all") {
			n++
		}
	}
	if n < 2 {
		t.Errorf("proof lacks the RIGHT table or its count:\n%s", out)
	}
}

// TestCheckKnowsTheDemosOwnDashboard: a retake used to FAIL check on the demo's own dashboard, forcing a
// Ctrl-C and a new sign-in in front of the audience. A tego-control serve of the demo's config on the dashboard
// address is ok, and stays ok across a reset; any other program there, or a dashboard of another config, still fails.
func TestCheckKnowsTheDemosOwnDashboard(t *testing.T) {
	if _, err := exec.LookPath("ss"); err != nil {
		t.Skip("ss (iproute2) is not installed")
	}
	w := newWorld(t)
	w.mustDemo("setup")
	addr := "127.0.0.1:" + strconv.Itoa(w.dash)

	startIn := func(dir, name string, env []string, args ...string) func() {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env, cmd.Dir = env, dir
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatalf("%s: %v", name, err)
		}
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
				_ = c.Close()
				return func() { cancel(); _ = cmd.Wait() }
			}
		}
		cancel()
		_ = cmd.Wait()
		t.Fatalf("%s did not listen on %s", name, addr)
		return nil
	}
	start := func(name string, env []string, args ...string) func() {
		t.Helper()
		return startIn("", name, env, args...)
	}
	// w.envList is newWorld's testutil environment: TEGO_TEST_CHAIN_ANCHOR and the own log stay in the test's folder,
	// and tego-control is built with the test hooks, so the dashboards here never read the invoking user's anchor.
	ours := append(append([]string{}, w.envList...), "TEGO_CONFIG="+w.cfg)

	stop := start(w.ctl, ours, "serve", "--addr", addr)
	out, code := w.demo("check")
	if code != 0 || !strings.Contains(out, "ok    the demo's dashboard is running (reset keeps it; it follows the new ledger)") {
		t.Errorf("check with the demo's dashboard: exit %d\n%s", code, out)
	}
	w.mustDemo("reset")
	if out, code := w.demo("check"); code != 0 || !strings.Contains(out, "the demo's dashboard is running") || !strings.Contains(out, "READY") {
		t.Errorf("check after a reset with the dashboard up: exit %d\n%s", code, out)
	}
	stop()

	// A relative --ledger is the dashboard's own, read against its working directory, not against demo.sh's.
	stop = startIn(w.base, w.ctl, ours, "serve", "--addr", addr, "--ledger", filepath.Base(w.ledger))
	if out, code := w.demo("check"); code != 0 || !strings.Contains(out, "the demo's dashboard is running") {
		t.Errorf("check with the demo's dashboard on a relative --ledger: exit %d\n%s", code, out)
	}
	stop()

	other := filepath.Join(w.base, "other.yaml")
	if err := os.WriteFile(other, []byte("version: 0\nledger_root: "+filepath.Join(w.base, "other-ledger")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() func(){
		"python http.server": func() func() {
			return start("python3", w.envList, "-m", "http.server", "--bind", "127.0.0.1", strconv.Itoa(w.dash))
		},
		"a dashboard of another config": func() func() {
			return start(w.ctl, append(append([]string{}, w.envList...), "TEGO_CONFIG="+other), "serve", "--addr", addr)
		},
		"a dashboard of another ledger": func() func() {
			return start(w.ctl, ours, "serve", "--addr", addr, "--ledger", filepath.Join(w.base, "other-ledger"))
		},
		"a relative --ledger that is another folder's": func() func() {
			sub := filepath.Join(w.base, "sub")
			if err := os.MkdirAll(filepath.Join(sub, filepath.Base(w.ledger)), 0o700); err != nil {
				t.Fatal(err)
			}
			return startIn(sub, w.ctl, ours, "serve", "--addr", addr, "--ledger", filepath.Base(w.ledger))
		},
	} {
		stop := run()
		out, code := w.demo("check")
		stop()
		if code != 1 || !strings.Contains(out, "something already listens on the dashboard address") || strings.Contains(out, "the demo's dashboard is running") {
			t.Errorf("%s: check exit %d\n%s", name, code, out)
		}
	}
}

// TestStaleCheckIgnoresDocsOnlyCommits: check called bin/tego stale after any later commit, a docs-only one
// included, which is likely right after a merge's doc commits. A build whose commit differs from HEAD only in docs/
// and Markdown is ok; a code change since, or a commit the checkout does not know, is still stale.
func TestStaleCheckIgnoresDocsOnlyCommits(t *testing.T) {
	for _, tool := range []string{"git", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	kit := filepath.Join(root, "repo", "examples", "supply-chain-demo")
	for _, d := range []string{home, kit, filepath.Join(root, "repo", "docs"), filepath.Join(root, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"demo.sh", "demo.env"} {
		if err := os.WriteFile(filepath.Join(kit, f), []byte(readFile(t, f)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	repo := filepath.Join(root, "repo")
	env := []string{"HOME=" + home, "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid"}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(path, body, msg string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, path), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", "-A")
		git("commit", "-q", "-m", msg)
		return git("rev-parse", "HEAD")
	}
	git("init", "-q")
	built := commit("main.go", "package main\n", "code")

	check := func(have string) string {
		t.Helper()
		fake := filepath.Join(root, "bin", "tego")
		body := "#!/bin/sh\nif [ \"$1\" = version ]; then echo commit=" + have + "; fi\nexit 0\n"
		if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", filepath.Join(kit, "demo.sh"), "check")
		cmd.Env = append(append([]string{}, env...),
			"TEGO="+fake, "TEGO_CONTROL="+fake, "DEMO_CONFIG="+filepath.Join(root, "demo.yaml"), "DEMO_LEDGER="+filepath.Join(root, "ledger"),
			"DEMO_STAGE="+filepath.Join(root, "stage"), "DEMO_OFFLINE=1", "DEMO_UNIT_PREFIX=tego-sctest-stale",
			"DEMO_PORT_LEFT="+strconv.Itoa(freePort(t)), "DEMO_PORT_RIGHT="+strconv.Itoa(freePort(t)),
			"DEMO_PORT_API="+strconv.Itoa(freePort(t)), "DEMO_DASH_ADDR=127.0.0.1:"+strconv.Itoa(freePort(t)),
			"DEMO_SYSTEMD_RUNTIME="+filepath.Join(root, "no-systemd"))
		out, _ := cmd.CombinedOutput() // check fails for the rest of this bare world; only the binaries' lines matter
		return string(out)
	}

	commit("docs/notes.md", "# notes\n", "docs only")
	commit("README.md", "readme\n", "a top-level Markdown file")
	out := check(built)
	mustContain(t, "docs-only change", out, "ok    tego built from "+built[:8]+"; only docs changed since",
		"ok    tego-control built from "+built[:8]+"; only docs changed since")
	if strings.Contains(out, "is stale") {
		t.Errorf("a docs-only change made the binary stale:\n%s", out)
	}

	commit("main.go", "package main\n\nfunc main() {}\n", "code again")
	mustContain(t, "code change", check(built), "bin/tego is stale: it was built from "+built[:8])
	mustContain(t, "unknown commit", check("0123456789abcdef0123456789abcdef01234567"), "bin/tego is stale: it was built from 01234567")
}

// TestProofRowsKeepASplitAttackRow: proof reads the text table of `tego events`, whose cells are split on two spaces.
// A rule and a detail holding two spaces in a row (a folder with a double space, say) print split, but the key's path
// stays in the detail, so the attack row is never dropped; an unrelated refusal is still left out.
func TestProofRowsKeepASplitAttackRow(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	script := readFile(t, "demo.sh")
	start := strings.Index(script, "PROOF_ROWS='\n")
	end := strings.Index(script[start+len("PROOF_ROWS='\n"):], "\n'\n")
	if start < 0 || end < 0 {
		t.Fatal("PROOF_ROWS not found in demo.sh")
	}
	src := script[start+len("PROOF_ROWS='\n") : start+len("PROOF_ROWS='\n")+end]
	table := "SEQ  TIME  PID  KIND  VERDICT  RULE  DETAIL\n" +
		"4  10:00:01  77  connect  refused  net  net 127.0.0.1:9\n" +
		"9  10:00:02  78  open  refused  fs.read[/st/with/odd  dir/]  open /st/with/odd  dir/home/.ssh/id_rsa\n" +
		"12  10:00:03  78  connect  refused  net  net 127.0.0.1:8802\n"
	cmd := exec.Command("python3", "-I", "-c", src, "/st", "refused", "8802", "Codex")
	cmd.Stdin = strings.NewReader(table)
	b, err := cmd.CombinedOutput()
	out := string(b)
	if err != nil {
		t.Fatalf("PROOF_ROWS: %v\n%s", err, out)
	}
	mustContain(t, "PROOF_ROWS", out, "id_rsa", "net 127.0.0.1:8802\n", "3 refusals in all")
	if strings.Contains(out, "127.0.0.1:9\n") {
		t.Errorf("PROOF_ROWS kept the unrelated connect:\n%s", out)
	}
}

// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// privpathCase is one privileged-path case's files: a project with a contract that touches out/ran when its agent
// runs, and beside it (never inside: the ledger root may not hold the project) a state directory with the ledger
// root and a machine config naming it, with the tegotesthooks variables that keep the binary's chain anchor and own
// log in the test's directories.
type privpathCase struct {
	dir, out, root, cfg string
	env                 []string
}

// newPrivpathCase prepares a case whose files belong to owner (-1: this process). The contract pins no tier, so
// each run's --tier decides.
func newPrivpathCase(t *testing.T, owner, group int) *privpathCase {
	t.Helper()
	c := &privpathCase{dir: t.TempDir()}
	state := t.TempDir()
	c.out, c.root, c.cfg = filepath.Join(c.dir, "out"), filepath.Join(state, "ledger"), filepath.Join(state, "config.yaml")
	logHome := filepath.Join(state, "home")
	for _, d := range []string{c.out, c.root, logHome} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	contract := `version: 0
name: privpath
command: ["/bin/sh", "-c", "touch out/ran"]
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", "/usr/bin/touch", "/bin/touch", "/usr/bin/grep", "/bin/grep"]
env:
  pass: ["PATH"]
record: summary
`
	if err := os.WriteFile(filepath.Join(c.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nstop_grace: 2s\n", c.root)), 0o644); err != nil {
		t.Fatal(err)
	}
	// The framework's directories are 0700; the agent and an unprivileged launcher must reach them, and config.Load
	// refuses a layer whose directory others can write.
	for _, d := range []string{c.dir, state} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if owner >= 0 {
		for _, p := range []string{c.dir, state, c.out, c.root, logHome, c.cfg, filepath.Join(c.dir, "agent.yaml")} {
			if err := os.Lchown(p, owner, group); err != nil {
				t.Fatal(err)
			}
		}
		userLists(t, c.dir)
		userLists(t, state)
	}
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); !strings.HasPrefix(name, "TEGO_") && name != "HOME" {
			c.env = append(c.env, kv)
		}
	}
	c.env = append(c.env, "HOME="+logHome, "TEGO_CONFIG="+c.cfg, "TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(state, "chain.log"),
		"TEGO_TEST_OWN_LOG_HOME="+logHome)
	return c
}

// ran reports whether the case's agent ran.
func (c *privpathCase) ran() bool {
	_, err := os.Stat(filepath.Join(c.out, "ran"))
	return err == nil
}

// exec runs argv from the project directory with the case's environment plus extra, and returns its exit code
// and combined output.
func (c *privpathCase) exec(t *testing.T, cmd *exec.Cmd, extra ...string) (int, string) {
	t.Helper()
	cmd.Dir = c.dir
	cmd.Env = append(append([]string{}, c.env...), extra...)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exit):
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("%v: %v\n%s", cmd.Args, err, out)
	return 0, ""
}

// TestUnshareRootIsNotRoot is ADR 0042 (5)(d): uid 0 means uid 0 of the initial user namespace. Under `unshare
// -r` the process has uid 0 and every capability, but only over the namespace it made, and SUDO_UID is whatever
// the caller set. Root's own `unshare -r` is the strongest form (uid 0 maps to uid 0, "0 0 1"): before the
// change doctor and the derivation took it for root and probed the root tiers' programs, and SUDO_UID named a
// drop target for it.
func TestUnshareRootIsNotRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: root's own unshare -r is the case")
	}
	uid, _, ok := agentUID(t)
	if !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Fatalf("no unshare (util-linux) on this root host: %v", err)
	}
	bin := tegoBinary(t)
	c := newPrivpathCase(t, -1, -1)
	sudo := "SUDO_UID=" + strconv.Itoa(uid)
	contract := filepath.Join(c.dir, "agent.yaml")

	const rootLine = "root: tier cgroup needs CAP_BPF, CAP_NET_ADMIN and CAP_SYS_ADMIN"
	code, out := c.exec(t, exec.Command(unshare, "-r", "--", bin, "run", "--tier", "cgroup", contract, "--", "/bin/sh", "-c", "touch out/ran"), sudo)
	if code != 125 || !strings.Contains(out, rootLine) || c.ran() {
		t.Errorf("unshare -r tego run --tier cgroup: exit %d, ran %v, want 125 naming %q:\n%s", code, c.ran(), rootLine, out)
	}
	if dirs := runDirs(t, c.root); len(dirs) != 0 {
		t.Errorf("a refused run left run directories %v", dirs)
	}

	code, out = c.exec(t, exec.Command(unshare, "-r", "--", bin, "doctor"), sudo)
	if !strings.Contains(out, rootLine) {
		t.Errorf("unshare -r tego doctor (exit %d) reports root reach; want %q:\n%s", code, rootLine, out)
	}

	// A run with no tier named: uid 0 there must still drop, and SUDO_UID names no target, so it is refused and its
	// agent never runs as uid 0.
	code, out = c.exec(t, exec.Command(unshare, "-r", "--", bin, "run", contract, "--", "/bin/sh", "-c", "touch out/ran"), sudo)
	if code != 125 || c.ran() {
		t.Errorf("unshare -r tego run: exit %d, ran %v, want 125 and no agent:\n%s", code, c.ran(), out)
	}
}

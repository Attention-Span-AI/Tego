// SPDX-License-Identifier: Apache-2.0

//go:build integration

package peer

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// buildTego builds cmd/tego with tegotesthooks (its chain anchor and own log go where testutil.TegoEnv says).
func buildTego(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tego")
	cmd := exec.Command("go", "build", "-tags", "tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	return bin
}

// TestPeerInsideRealRunIsGoverned: the agent of a real record-only run (unprivileged, in its run's scope
// in the invoking user's delegated subtree) connects to a socket outside the run. Identify proves the agent itself
// is the peer, with the run's own cgroup; Refuse answers [run-member]; and GovernedBy names the very run the ledger
// recorded. Observe leaves the connect in the agent: enforcing runs relay it
// after C40's inode decision, so connection credentials identify the relay.
// C40's integration tests instead require the immutable control-socket refusal
// before such a relayed connection reaches any control service.
func TestPeerInsideRealRunIsGoverned(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root, tego run launches a privileged run, whose agent runs as the invoking user; this is the unprivileged shape")
	}
	bin := buildTego(t)
	w := t.TempDir()
	if err := os.Chmod(w, 0o700); err != nil { // the machine config's directory must not be group-writable (umask 002)
		t.Fatal(err)
	}
	home := filepath.Join(w, "home")
	own := filepath.Join(home, ".tego")
	ledger := filepath.Join(own, "runs")
	if err := os.MkdirAll(ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(own, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(own, "machine.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", ledger)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := testutil.TegoEnv(t, w, "TEGO_CONFIG="+cfg, "TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(own, "chain.log"), "HOME="+home)
	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = env
	testutil.RequireTier(t, doctor, "landlock")

	self := testutil.ExecutableForAnyUID(t)
	ln, sock := listen(t)
	proj := filepath.Join(w, "proj")
	if err := os.Mkdir(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	// host_sockets: true, since the agent reaches a unix socket it did not bind: a contract with no net: section
	// refuses one (ADR 0070), and this socket stands for the person's own service the agent connects to.
	contract := fmt.Sprintf(`version: 0
name: peerprobe
command: [%q, %q, "stay", %q]
tier: landlock
host_sockets: true
exec:
  allow: [%q]
limits:
  pids: 64
`, self, clientArg, sock, self)
	if err := os.WriteFile(filepath.Join(proj, "agent.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	run := exec.Command(bin, "run", "--observe", "agent.yaml")
	run.Dir, run.Env, run.Stdout, run.Stderr = proj, env, &out, &out
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	conn := accept(t, ln)
	p, idErr := Identify(conn)
	refused := Refuse(p, os.Geteuid())
	_ = conn.Close() // the agent reads EOF and exits, and the run ends
	if err := run.Wait(); err != nil {
		t.Fatalf("tego run: %v\n%s", err, out.String())
	}
	runs, err := filepath.Glob(filepath.Join(ledger, "*", "events.jsonl"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("ledger runs %v (%v), want one", runs, err)
	}
	id := filepath.Base(filepath.Dir(runs[0]))

	if idErr != nil {
		t.Fatalf("Identify of the run's agent: %v", idErr)
	}
	t.Logf("run %s: the agent, pid %d, is in %s; Refuse: %v", id, p.PID, p.Cgroup, refused)
	if p.UID != os.Geteuid() || p.PidfdFallback != !hasPeerPidfdOnThisKernel(t) {
		t.Errorf("Identify = %+v; want this uid %d", p, os.Geteuid())
	}
	if got := runscope.GovernedBy(p.Cgroup); got != id {
		t.Errorf("the agent's cgroup %s names run %q, want the run the ledger recorded, %s", p.Cgroup, got, id)
	}
	if codeOf(refused) != CodeRunMember {
		t.Errorf("Refuse(the run's agent) = %v, want [%s]", refused, CodeRunMember)
	}
}

// hasPeerPidfdOnThisKernel asks the kernel over a connection this process makes to itself.
func hasPeerPidfdOnThisKernel(t *testing.T) bool {
	t.Helper()
	server, _ := selfConn(t)
	return hasPeerPidfd(t, server)
}

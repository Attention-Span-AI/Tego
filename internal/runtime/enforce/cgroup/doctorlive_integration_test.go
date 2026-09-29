// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestDoctorDuringALiveTier2RunChangesNoVerdict is limits-check-doctor-cli.md E28 end to end: `tego doctor` run
// as root while a tier-2 run of the same build is live loads and attaches D7's fresh copies of the tier's programs
// (fentry/fmod_ret beside the run's shared links, cgroup programs on its own scratch cgroup) and makes D8's
// fanotify group, and the live run's verdicts do not change. The agent repeats the same four actions in rounds —
// a connect the contract allows, one it does not, a write outside fs.write and a read of a deny_read file under a
// writable parent (fanotify's) — before, during and after doctor, and every round must come out as the first did.
func TestDoctorDuringALiveTier2RunChangesNoVerdict(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("tier 2 needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("untagged: this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	base, err := os.MkdirTemp("", "tego-t2-doctor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	bin := buildTaggedTego(t, base)
	requireTier(t, bin, "cgroup")
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	secret := filepath.Join(project, "out", "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "key"), []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	allowed, refused := listenLoopback(t, "tcp4", "127.0.0.1"), listenLoopback(t, "tcp4", "127.0.0.1")
	if err := os.WriteFile(filepath.Join(project, "agent.py"), []byte(doctorLiveAgent), 0o644); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(project, "agent.yaml")
	if err := os.WriteFile(contract, []byte(fmt.Sprintf(doctorLiveContract, allowed)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(project, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	}); err != nil {
		t.Fatal(err)
	}
	ledgerRoot := filepath.Join(base, "ledger")
	if err := os.Mkdir(ledgerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	_, resolverSetting, _ := machineResolver(t)
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nresolver: %s\n", ledgerRoot,
		resolverSetting)), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(base, "stdout")
	stdout, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	var stderr strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := tegoRunCommand(ctx, bin, "run", "--tier", "cgroup", contract, "--", python, "./agent.py")
	cmd.Dir = project
	cmd.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg, "E28_ALLOWED="+strconv.Itoa(allowed),
		"E28_REFUSED="+strconv.Itoa(refused))
	cmd.Stdout, cmd.Stderr = stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	rounds := func() []string {
		b, _ := os.ReadFile(outPath)
		var out []string
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "ROUND ") {
				out = append(out, l)
			}
		}
		return out
	}
	waitRounds := func(n int) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		for len(rounds()) < n {
			select {
			case err := <-done:
				t.Fatalf("the run ended early: %v\n%s\n%s", err, stderr.String(), strings.Join(rounds(), "\n"))
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("the agent made %d of %d rounds in 60 s", len(rounds()), n)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitRounds(5)
	before := len(rounds())
	doc := exec.Command(bin, "doctor", "--json")
	doc.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg)
	started := time.Now()
	docOut, docErr := doc.CombinedOutput()
	took := time.Since(started)
	during := len(rounds()) - before
	if docErr != nil {
		t.Fatalf("tego doctor beside the live run: %v\n%s", docErr, docOut)
	}
	if !strings.Contains(string(docOut), `"programs"`) {
		t.Fatalf("doctor's report names no program rows: D7 did not run beside the run:\n%s", docOut)
	}
	waitRounds(len(rounds()) + 5)
	if err := os.WriteFile(filepath.Join(project, "out", "stop"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("tego run: %v\n%s", err, stderr.String())
	}
	all := rounds()
	t.Logf("%d rounds, %d of them during doctor's %v", len(all), during, took)
	if during == 0 {
		t.Errorf("no round ran while doctor did (%v): the test did not overlap the two", took)
	}
	// The deny_read under a writable parent is the listener's (EPERM) where the run decides through fanotify, the
	// decision plane's (EACCES) where doctor selected a plane mode (TIER3-PLAN T6).
	want := "allowed=ok refused=errno13 outside=errno13 denyread=errno1"
	if planeSelected(t, bin, "") != PlaneFanotify {
		want = "allowed=ok refused=errno13 outside=errno13 denyread=errno13"
	}
	for _, r := range all {
		if _, got, _ := strings.Cut(strings.TrimPrefix(r, "ROUND "), " "); got != want {
			t.Errorf("%s; want every round %q", r, want)
		}
	}
	if _, err := os.Stat(filepath.Join(project, "forbidden.txt")); err == nil {
		t.Error("forbidden.txt exists: a write outside the contract was allowed")
	}
}

// doctorLiveContract allows one port on loopback and one write directory with a deny_read entry beneath it.
const doctorLiveContract = `version: 0
name: t2-doctor-live
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
  deny_read: ["./out/secret/"]
exec:
  allow: ["python3"]
net:
  allow: ["127.0.0.1:%d"]
env:
  pass: ["PATH", "HOME", "E28_ALLOWED", "E28_REFUSED"]
record: summary
`

// doctorLiveAgent repeats its four actions until out/stop appears, one ROUND line each time.
const doctorLiveAgent = `import os, socket, time
allowed = int(os.environ["E28_ALLOWED"])
refused = int(os.environ["E28_REFUSED"])
i = 0
while not os.path.exists("out/stop"):
    r = []
    for name, port in (("allowed", allowed), ("refused", refused)):
        s = socket.socket()
        s.settimeout(5)
        try:
            s.connect(("127.0.0.1", port))
            r.append(name + "=ok")
        except OSError as e:
            r.append("%s=errno%d" % (name, e.errno))
        finally:
            s.close()
    try:
        open("forbidden.txt", "w").close()
        r.append("outside=ok")
    except OSError as e:
        r.append("outside=errno%d" % e.errno)
    try:
        open("out/secret/key").read()
        r.append("denyread=ok")
    except OSError as e:
        r.append("denyread=errno%d" % e.errno)
    print("ROUND", i, " ".join(r), flush=True)
    i += 1
    time.sleep(0.02)
`

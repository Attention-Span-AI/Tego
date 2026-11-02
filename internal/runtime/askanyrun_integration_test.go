// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A run's asks are answered by the person and never by an agent (ADR 0008, amended 2026-10-25; ADR 0100 (7)):
// the broker refuses a peer inside any run's or adoption's scope, or a look-alike of one, and a
// peer in another cgroup namespace, as unauthorized, and the ask stays pending for the person. Run A holds a connect
// for a person; another process tries to approve it with the broker's own protocol and no client of tego's (no lock
// check, no server pid check), as any process that reaches the socket can; then the person's own tego answers.

// answerProbe waits for the file argv[4] when one is named, changes into the run directory argv[1] (search permission
// is all it needs there) and connects to ask.sock by that short name, and tries to approve ask argv[2]: it writes the
// broker's last packet, or the errno, to argv[3].
const answerProbe = `import errno, json, os, socket, sys, time
result = os.path.abspath(sys.argv[3])
if len(sys.argv) > 4:
    while not os.path.exists(sys.argv[4]):
        time.sleep(0.02)
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
try:
    os.chdir(sys.argv[1])
    s.connect("ask.sock")
    r = json.loads(s.recv(65536))
    if "ready" in r:
        s.send(json.dumps({"action": "answer", "nonce": r["ready"], "ask_id": sys.argv[2], "approve": True}).encode())
        r = json.loads(s.recv(65536))
except OSError as e:
    r = {"errno": errno.errorcode.get(e.errno, str(e.errno))}
with open(result, "w") as f:
    json.dump(r, f)
`

// anyRunLedgerRoot is a ledger root short enough that <root>/<run id>/ask.sock fits sun_path, which the root tiers'
// unix rule names: os.TempDir() when it fits, /tmp otherwise.
func anyRunLedgerRoot(t *testing.T) string {
	t.Helper()
	const sunPath = len(unix.RawSockaddrUnix{}.Path) - 1
	base := os.TempDir()
	if len(base)+len("/anyr0123456789/r-00000000-0000000000000-000000/ask.sock") > sunPath {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "anyr")
	if err == nil {
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		dir, err = filepath.EvalSymlinks(dir)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	return dir
}

// askHolder is run A: its agent connects once to a unix abstract name the test listens on, which only its contract's
// net.ask names, so the connect is held for a person (ADR 0008), at tier with the tego binary bin. Its ledger root is
// short (anyRunLedgerRoot). It returns the scene, the running `tego run`, the run's directory, the held ask's id and
// the listener's count of accepted connections.
type askHolder struct {
	s        *askReadScene
	run      *exec.Cmd
	dir      string
	askID    string
	accepted *atomic.Int32
}

func newAskHolder(t *testing.T, bin, tier string) *askHolder {
	t.Helper()
	target := "@tego-anyrun-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	accepted := listenUnix(t, target)
	s := newAskUnixScene(t, bin, tier, "120s", target, 1)
	s.f.root = anyRunLedgerRoot(t)
	s.env = isolatedEnv(t, s.f) // again, now naming the short root
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	if req["op"] != "connect" || req["target"] != "unix:"+target || req["hold"] != "connect" {
		t.Fatalf("held request %v", req)
	}
	// A root launcher's run directory is root's (0700), which already keeps an agent dropped to the invoking user away
	// from ask.sock, the one file in it chowned to that user. The broker's own rule must hold where the socket is
	// reachable, so as root the test lets the agent's uid traverse to it (o+x, no listing), the run directory itself
	// included when the root is /tmp's rather than below TMPDIR (anyRunLedgerRoot), which agentReaches stops at.
	if _, _, ok := agentUID(t); ok {
		if err := os.Chmod(dir, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	agentReaches(t, filepath.Join(dir, "ask.sock"))
	return &askHolder{s: s, run: run, dir: dir, askID: req["ask_id"].(string), accepted: accepted}
}

// stillPending fails the test unless the broker still lists the held ask, through the person's `tego ask`.
func (h *askHolder) stillPending(t *testing.T) {
	t.Helper()
	out, code := h.s.try(t, "ask", filepath.Base(h.dir), "--json")
	var list struct {
		Pending []map[string]any `json:"pending"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &list) != nil || len(list.Pending) != 1 || list.Pending[0]["ask_id"] != h.askID {
		t.Fatalf("after the refused answer the broker lists %s (exit %d); want ask %s still pending", out, code, h.askID)
	}
}

// personAnswers approves the ask as the person (the test's own `tego approve`, outside every run) and checks the run
// ends with that answer: one ask line, one approving answer line by a uid and pid, the connect delivered.
func (h *askHolder) personAnswers(t *testing.T) {
	t.Helper()
	h.s.answer(t, "approve", filepath.Base(h.dir), h.askID)
	evs := h.s.finish(t, h.run, h.dir)
	if rc := h.s.out("rc1"); rc != "ok" {
		t.Fatalf("the approved connect came to %q; the run's net lines: %v", rc, lines(t, evs, record.KindNet))
	}
	if h.accepted.Load() != 1 {
		t.Fatalf("the listener accepted %d connections; want 1", h.accepted.Load())
	}
	asks, answers := lines(t, evs, record.KindAsk), lines(t, evs, record.KindAnswer)
	if len(asks) != 1 || len(answers) != 1 || answers[0]["ask_id"] != h.askID || answers[0]["approved"] != true ||
		!strings.HasPrefix(answers[0]["by"].(string), "uid:") {
		t.Fatalf("ask lines %v, answer lines %v; want one ask and the person's one approving answer", asks, answers)
	}
}

// refused reads the probe's result file and fails the test unless the broker refused it as unauthorized.
func refused(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the probe left no result: %v", err)
	}
	var r map[string]any
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("the probe's result %q: %v", b, err)
	}
	if r["code"] != "unauthorized" || r["decision"] != nil {
		t.Fatalf("the broker answered the probe %s; want it refused as unauthorized", b)
	}
	t.Logf("the broker answered the probe %s", b)
}

// pythonPaths are python3 as PATH finds it and the file it resolves to, both of which a contract's exec.allow names.
func pythonPaths(t *testing.T) (string, string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	return python, resolved
}

// otherRun runs run B to its end at tier, in a project of its own but under run A's machine config (one person's
// ledger root, as on a real machine): its agent, answerProbe, may connect to run A's ask.sock (net.allow names it)
// and tries to approve the held ask. It returns the path of the probe's result.
func (h *askHolder) otherRun(t *testing.T, tier string) string {
	t.Helper()
	python, resolved := pythonPaths(t)
	sock := filepath.Join(h.dir, "ask.sock")
	contract := fmt.Sprintf(`version: 0
name: ianyrunb
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q, %q]
net:
  allow: [%q]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
`, python, resolved, "unix:"+sock)
	b := newFixture(t, contract)
	if tier != "landlock" {
		pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
		if err := os.WriteFile(filepath.Join(b.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, filepath.Join(b.dir, "agent.yaml"))
	}
	probe := filepath.Join(b.dir, "probe.py")
	if err := os.WriteFile(probe, []byte(answerProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %q probe.py %q %q out/answer.json\n", python, h.dir, h.askID)
	if err := os.WriteFile(filepath.Join(b.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, probe, filepath.Join(b.dir, "agent.sh"))
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	requireIsolatedEnv(t, h.s.env)
	cmd := exec.CommandContext(ctx, h.s.bin, "run", filepath.Join(b.dir, "agent.yaml"), "--", "/bin/sh", "agent.sh")
	cmd.Dir, cmd.Env = b.dir, h.s.env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run B: %v\n%s", err, out)
	}
	return filepath.Join(b.out, "answer.json")
}

// TestAgentInOtherRunCannotAnswer: run A holds an ask at tier landlock, unprivileged (as root, from a root launcher
// with the agents dropped to the invoking user); run B's agent, whose contract lets it reach run A's ask.sock, tries
// to approve it and is refused as unauthorized, the ask still pending; then the person's shell answers it. The
// supervisor makes a contracted run's unix connects itself, here and at tier cgroup, so the broker sees run B's
// launcher at the connect and the agent at the packet, and refused this answer by that mismatch before
// the ask hardening as well; a watched run continues its agent's own connect (TestWatchedAgentCannotAnswer), and an
// adopted process makes its own (TestAdoptedAgentCannotAnswer), where only the run-scope rule refuses.
func TestAgentInOtherRunCannotAnswer(t *testing.T) {
	h := newAskHolder(t, tegoBinary(t), "landlock")
	refused(t, h.otherRun(t, "landlock"))
	h.stillPending(t)
	h.personAnswers(t)
}

// TestRootAgentInOtherRunCannotAnswer is TestAgentInOtherRunCannotAnswer at tier cgroup, from a root launcher with
// both runs' agents dropped to the invoking user, who owns run A's ask.sock: the KVM root suite's case.
func TestRootAgentInOtherRunCannotAnswer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tier cgroup")
	}
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBPFBinary(t)
	h := newAskHolder(t, bin, "cgroup")
	refused(t, h.otherRun(t, "cgroup"))
	h.stillPending(t)
	h.personAnswers(t)
}

// TestWatchedAgentCannotAnswer: run B is `tego watch -- <probe>`, a record-only run whose generated contract refuses
// nothing, so its agent reaches run A's ask.sock; the broker refuses it as unauthorized, and the person answers.
func TestWatchedAgentCannotAnswer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged: a watch from a root launcher picks a root tier")
	}
	h := newAskHolder(t, tegoBinary(t), "landlock")
	python, _ := pythonPaths(t)
	work := t.TempDir()
	probe, result := filepath.Join(work, "probe.py"), filepath.Join(work, "answer.json")
	if err := os.WriteFile(probe, []byte(answerProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	requireIsolatedEnv(t, h.s.env)
	cmd := exec.CommandContext(ctx, h.s.bin, "watch", "--", python, probe, h.dir, h.askID, result)
	cmd.Dir, cmd.Env = work, h.s.env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tego watch: %v\n%s", err, out)
	}
	refused(t, result)
	h.stillPending(t)
	h.personAnswers(t)
}

// TestPersonShellStillAnswers: the person's shell, outside every run and in the broker's cgroup namespace, answers as
// before; its own raw exchange (answerProbe, which a tego client is not needed for) is a person's too.
func TestPersonShellStillAnswers(t *testing.T) {
	h := newAskHolder(t, tegoBinary(t), "landlock")
	python, _ := pythonPaths(t)
	work := t.TempDir()
	probe, result := filepath.Join(work, "probe.py"), filepath.Join(work, "answer.json")
	if err := os.WriteFile(probe, []byte(answerProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	// The listing as the person sees it: tego ask, and the answer from this shell's own process.
	h.stillPending(t)
	out, err := exec.Command(python, probe, h.dir, h.askID, result).CombinedOutput()
	if err != nil {
		t.Fatalf("the person's probe: %v\n%s", err, out)
	}
	b, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Decision *struct {
			Approved bool   `json:"approved"`
			By       string `json:"by"`
		} `json:"decision"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.Decision == nil || !r.Decision.Approved || !strings.HasPrefix(r.Decision.By, "uid:") {
		t.Fatalf("the person's answer came to %s; want an approving decision by the person", b)
	}
	evs := h.s.finish(t, h.run, h.dir)
	if rc := h.s.out("rc1"); rc != "ok" || h.accepted.Load() != 1 {
		t.Fatalf("the approved connect came to %q and the listener accepted %d", rc, h.accepted.Load())
	}
	if answers := lines(t, evs, record.KindAnswer); len(answers) != 1 || answers[0]["by"] != r.Decision.By {
		t.Fatalf("answer lines %v; want the person's one, by %s", answers, r.Decision.By)
	}
}

// TestAdoptedAgentCannotAnswer: a process `tego adopt` moved into its adoption's scope (ADR 0055), which holds no
// network rule, reaches run A's ask.sock and tries to approve the held ask as root, whom the broker serves as well as
// the run's owner; it is refused as unauthorized, and the person answers. Root, as every adoption is: the KVM root
// suite's case.
func TestAdoptedAgentCannotAnswer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: an adoption moves a process between cgroups and loads tier 2's programs")
	}
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &st); err != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Fatalf("needs the cgroup v2 hierarchy at /sys/fs/cgroup: %v", err)
	}
	bin := tegoBPFBinary(t)
	h := newAskHolder(t, bin, "landlock")
	python, _ := pythonPaths(t)
	work := t.TempDir()
	probe, result, trigger := filepath.Join(work, "probe.py"), filepath.Join(work, "answer.json"), filepath.Join(work, "go")
	if err := os.WriteFile(probe, []byte(answerProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	// The agent starts in a cgroup that stands in for a terminal's session scope, as adopt's own tests do: never the
	// cgroup2 root, which adopt refuses, nor this test's, which holds the adopter's ancestors.
	term := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("anyrun-term-%d-%d.scope", os.Getpid(), time.Now().UnixNano()%100000))
	if err := os.Mkdir(term, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(term) })
	termFD, err := unix.Open(term, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(termFD) })
	agent := exec.Command(python, probe, h.dir, h.askID, result, trigger)
	agent.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: termFD}
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Wait() }()
	t.Cleanup(func() {
		_ = agent.Process.Kill()
		<-agentDone
	})
	requireIsolatedEnv(t, h.s.env)
	adopter := exec.Command(bin, "adopt", "--pid", strconv.Itoa(agent.Process.Pid), "--uid", "0") // root's process: named
	adopter.Env = h.s.env
	var said strings.Builder
	adopter.Stdout, adopter.Stderr = &said, &said
	if err := adopter.Start(); err != nil {
		t.Fatal(err)
	}
	adopterDone := make(chan error, 1)
	go func() { adopterDone <- adopter.Wait() }()
	t.Cleanup(func() {
		_ = adopter.Process.Kill()
		<-adopterDone
		if t.Failed() {
			t.Logf("tego adopt said:\n%s", said.String())
		}
	})
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", agent.Process.Pid)
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if b, _ := os.ReadFile(cgroupFile); strings.Contains(string(b), "/adopt-") {
			break
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(cgroupFile)
			t.Fatalf("the agent was not adopted within 60 s: its cgroup is %q", b)
		}
	}
	if err := os.WriteFile(trigger, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-agentDone:
		agentDone <- err
	case <-time.After(30 * time.Second):
		t.Fatal("the adopted agent did not finish its answer within 30 s")
	}
	refused(t, result)
	h.stillPending(t)
	h.personAnswers(t)
}

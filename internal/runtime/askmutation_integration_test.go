// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ADR 0047 end to end: the real tego binary runs a contract whose agent, a Python script, renames a file inside an
// fs.ask scope; a person answers from a separate tego process over the run's real broker. The run's own rename is
// refused by its kernel (the scope grants nothing), so only the supervisor's completion, made as the agent on the names
// it pinned, can move the file, and its line is the rename's one line at every tier.

const mutationProbe = `import errno, os, sys
def outcome(f):
    try:
        f()
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
with open("out/rc", "w") as f:
    f.write(outcome(lambda: os.rename(sys.argv[1], sys.argv[2])))
`

func newAskMutationScene(t *testing.T, bin, tier, to string) *askReadScene {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	s := &askReadScene{bin: bin}
	contract := fmt.Sprintf(`version: 0
name: iaskmutation
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
  ask: ["./held/"]
exec:
  allow: ["/bin/sh", %q, %q]
net: {}
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: 30s
limits:
  pids: 64
record: summary
`, python, resolved)
	// newFixture compiles for the tiers this test process offers, tier landlock alone, so a contract pinning a root
	// tier skipped there "tier cgroup pinned but not available [tier-unavailable]" and the root subtests never ran:
	// the contract is compiled at tier landlock, and the file the tego binary runs names the tier, as the UDP and
	// unix ask scenes do.
	s.f = newFixture(t, contract)
	if tier != "landlock" {
		pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
		if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	held := filepath.Join(s.f.dir, "held")
	if err := os.Mkdir(held, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(held, "a"), []byte("A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.f.dir, "probe.py"), []byte(mutationProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %q probe.py held/a %q\n", python, to)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, held, filepath.Join(held, "a"), filepath.Join(s.f.dir, "agent.sh"), filepath.Join(s.f.dir, "probe.py"), filepath.Join(s.f.dir, "agent.yaml"))
	s.env = isolatedEnv(t, s.f)
	return s
}

// runAskMutationCase runs one rename and checks what the agent got, where the file is, the ask and the one fs line.
func runAskMutationCase(t *testing.T, bin, tier, answer string) {
	t.Helper()
	s := newAskMutationScene(t, bin, tier, "held/b")
	from, to := filepath.Join(s.f.dir, "held", "a"), filepath.Join(s.f.dir, "held", "b")
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	if req["op"] != record.FSRename || req["hold"] != "mutation" || req["target"] != from || req["target2"] != to {
		t.Fatalf("held request %v", req)
	}
	s.answer(t, answer, filepath.Base(dir), req["ask_id"].(string))
	evs := s.finish(t, run, dir)
	want, moved := "ok", true
	if answer == "deny" {
		want, moved = "EACCES", false
	}
	if rc := s.out("rc"); rc != want {
		t.Fatalf("the rename came to %q, want %q; fs lines %v", rc, want, lines(t, evs, record.KindFS))
	}
	if _, err := os.Stat(to); (err == nil) != moved {
		t.Fatalf("held/b exists=%v, want %v", err == nil, moved)
	}
	var got []map[string]any
	for _, l := range lines(t, evs, record.KindFS) {
		if l["op"] == record.FSRename {
			got = append(got, l)
		}
	}
	if len(got) != 1 || got[0]["path"] != from || got[0]["path2"] != to {
		t.Fatalf("rename lines %v: want one naming %s and %s", got, from, to)
	}
	l := got[0]
	if moved && (l["_verdict"] != "allow" || l["_authority"] != "human" || l["operation_completed"] != true || l["syscall_ret"] != float64(0)) {
		t.Fatalf("approved rename line %v", l)
	}
	if !moved && (l["_verdict"] != "refused" || l["_reason"] != "ask-denied") {
		t.Fatalf("denied rename line %v", l)
	}
	if asks := lines(t, evs, record.KindAsk); len(asks) != 1 || asks[0]["hold"] != "mutation" || asks[0]["target2"] != to {
		t.Fatalf("ask lines %v", asks)
	}
}

// runAskMutationCrossEntry renames out of the scope into the write entry: refused EXDEV before anyone is asked.
func runAskMutationCrossEntry(t *testing.T, bin, tier string) {
	t.Helper()
	s := newAskMutationScene(t, bin, tier, "out/a")
	run, dir := s.start(t)
	evs := s.finish(t, run, dir)
	if rc := s.out("rc"); rc != "EXDEV" {
		t.Fatalf("the rename across entries came to %q, want EXDEV; fs lines %v", rc, lines(t, evs, record.KindFS))
	}
	if asks := lines(t, evs, record.KindAsk); len(asks) != 0 {
		t.Fatalf("asked %v", asks)
	}
	if _, err := os.Stat(filepath.Join(s.f.dir, "held", "a")); err != nil {
		t.Fatalf("held/a moved: %v", err)
	}
	var unsupported bool
	for _, l := range lines(t, evs, record.KindFS) {
		unsupported = unsupported || (l["op"] == record.FSRename && l["_verdict"] == "refused" && l["completion_unsupported"] == true)
	}
	if !unsupported {
		t.Fatalf("no unsupported refusal among %v", lines(t, evs, record.KindFS))
	}
}

func TestIntegrationAskMutationRename(t *testing.T) {
	bin := tegoBinary(t)
	for _, answer := range []string{"approve", "deny"} {
		t.Run(answer, func(t *testing.T) { runAskMutationCase(t, bin, "landlock", answer) })
	}
	t.Run("across entries", func(t *testing.T) { runAskMutationCrossEntry(t, bin, "landlock") })
}

// TestIntegrationAskMutationSceneAtARootTier builds the root tiers' scene without root: its fixture compiles at tier
// landlock, the one tier this test process offers, and the contract the tego binary runs pins the root tier. A scene
// whose fixture contract pinned the root tier skipped here "tier cgroup pinned but not available [tier-unavailable]",
// and every TestRootAskMutation subtest with it, on a boot that has the tier.
func TestIntegrationAskMutationSceneAtARootTier(t *testing.T) {
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			s := newAskMutationScene(t, "", tier, "held/b")
			b, err := os.ReadFile(filepath.Join(s.f.dir, "agent.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), "\ntier: "+tier+"\n") {
				t.Fatalf("the contract tego runs pins no tier %s:\n%s", tier, b)
			}
		})
	}
}

// TestRootAskMutation is the same at the root tiers: the supervisor, root, makes the rename with the agent's
// credentials from outside the run's cgroup, so neither the plane nor the kernel recorder decides or records it.
func TestRootAskMutation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBPFBinary(t)
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			probe := newAskMutationScene(t, bin, tier, "held/b")
			testutil.RequireTier(t, probe.tego(t, "doctor", "--require", tier), tier)
			for _, answer := range []string{"approve", "deny"} {
				t.Run(answer, func(t *testing.T) { runAskMutationCase(t, bin, tier, answer) })
			}
			t.Run("across entries", func(t *testing.T) { runAskMutationCrossEntry(t, bin, tier) })
		})
	}
}

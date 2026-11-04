// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ADR 0126 §4 "The gate" at the tiers where a plane decides a run's execs. Those execs go through the supervisor's fast
// handover, which used to return before the gate, so a relayed server the agent started around its shim was recorded
// and ran. The real tego binary runs a contract with one relayed stdio server, and the agent starts that server's exact
// declared command line twice: on its own, and through `tego mcp relay`.

const mcpGateServer = `import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if "id" in m:
        print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"content": []}}), flush=True)
`

// mcpGateProbe names the file an error came from and uses pipes throughout: subprocess.DEVNULL opens /dev/null read-write,
// which the contract refuses, so an EACCES from that open read as the gate's while no exec had been tried.
const mcpGateProbe = `import errno, json, subprocess, sys
tego, server = sys.argv[1], sys.argv[2:]
def save(name, text):
    with open("out/" + name, "w") as f:
        f.write(text)
try:
    p = subprocess.Popen(server, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p.communicate("", timeout=20)
    save("direct", "ran %d" % p.returncode)
except OSError as e:
    save("direct", "%s %s" % (errno.errorcode.get(e.errno, str(e.errno)), e.filename))
for name, argv in [("stage", [tego, "__mcp_server", server[0]] + server), ("other", [tego, "__probe"])]:
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p.communicate("", timeout=20)
        save(name, "ran %d" % p.returncode)
    except OSError as e:
        save(name, "%s %s" % (errno.errorcode.get(e.errno, str(e.errno)), e.filename))
shim = subprocess.Popen([tego, "mcp", "relay", "--server", "files", "--"] + server, stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
shim.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "read_file", "arguments": {}}}) + "\n")
shim.stdin.flush()
save("answer", shim.stdout.readline())
shim.stdin.close()
save("shim-err", shim.stderr.read())
save("shim", "%d" % shim.wait(timeout=20))
`

// newMCPGateScene is the run's world. The contract compiles at tier landlock, the one tier the test process offers, and
// the file the tego binary runs names the tier, as newAskMutationScene's does.
func newMCPGateScene(t *testing.T, bin, tier, plane string) (*askReadScene, []string) {
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
	s.f = newFixture(t, "version: 0\nname: imcpgate\ncommand: [\"/bin/sh\"]\ntier: landlock\n")
	server := []string{python, filepath.Join(s.f.dir, "server.py")}
	contract := fmt.Sprintf(`version: 0
name: imcpgate
command: ["/bin/sh"]
tier: %s
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q, %q, %q]
net: {}
env:
  pass: ["PATH", "HOME", "TEGO_MCP_RELAY", "TEGO_MCP_CONFIG"]
mcp:
  - name: files
    command: [%q, %q]
    tools: {deny: [delete_file]}
limits:
  pids: 64
record: summary
`, tier, python, resolved, bin+" mcp relay *", server[0], server[1])
	agentFiles := map[string]string{
		"agent.yaml": contract,
		"server.py":  mcpGateServer,
		"probe.py":   mcpGateProbe,
		"agent.sh":   fmt.Sprintf("#!/bin/sh\nexec %q probe.py %q %q %q\n", python, bin, server[0], server[1]),
	}
	for name, body := range agentFiles {
		p := filepath.Join(s.f.dir, name)
		if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, p)
	}
	s.env = isolatedEnv(t, s.f)
	if plane != "" {
		s.env = append(s.env, "TEGO_TEST_PLANE="+plane)
	}
	return s, server
}

// TestIntegrationMCPRelayConstrainedGrant keeps ADR 0126's shim-only exec grant working: an internal stage is
// the admitted shim's implementation detail, and no broader grant of the tego binary is required.
func TestIntegrationMCPRelayConstrainedGrant(t *testing.T) {
	bin := tegoBinary(t)
	agentReaches(t, bin)
	s, _ := newMCPGateScene(t, bin, "landlock", "")
	run, dir := s.start(t)
	evs := s.finish(t, run, dir)
	if got := s.out("shim"); got != "0" || !strings.Contains(s.out("answer"), `"result"`) {
		t.Fatalf("shim exit %q, answer %q, stderr %q", got, s.out("answer"), s.out("shim-err"))
	}
	assertMCPStageGrant(t, s, evs)
}

func assertMCPStageGrant(t *testing.T, s *askReadScene, evs []*record.Event) {
	t.Helper()
	rule := "exec.mcp-stage[" + s.bin + "]"
	var start record.RunStartPayload
	stages := 0
	for _, ev := range evs {
		if ev.Kind == record.KindRunStart {
			if err := ev.DecodePayload(&start); err != nil {
				t.Fatal(err)
			}
		}
		if ev.Kind != record.KindExec || ev.Verdict != record.VerdictAllow {
			continue
		}
		var p record.ExecPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if len(p.Argv) > 1 && p.Argv[1] == "__mcp_server" {
			stages++
			if ev.Rule != rule || p.CommandList == "unlisted" {
				t.Errorf("stage rule %q list %q, want runtime grant %q", ev.Rule, p.CommandList, rule)
			}
		}
	}
	if stages != 1 || !slices.Contains(start.RuntimeGrants, rule) {
		t.Errorf("%d allowed stages, runtime grants %q, want one stage and %q", stages, start.RuntimeGrants, rule)
	}
	for _, name := range []string{"stage", "other"} {
		if got := s.out(name); got != "EACCES "+s.bin {
			t.Errorf("unrelated %s start: %q, want EACCES", name, got)
		}
	}
}

// TestRootMCPRelayGate: at tier landlock and each mode of the plane, the start around the relay is refused under
// mcp[files].relay and never ran. The start through the shim runs; at the root tiers its exec and server lines are
// still the kernel recorder's, as the handover would have left them.
func TestRootMCPRelayGate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBPFBinary(t)
	agentReaches(t, bin)
	for _, tc := range []struct{ tier, plane string }{{"landlock", ""}, {"cgroup", "fmod_ret"}, {"bpflsm", "lsm"}} {
		t.Run(tc.tier, func(t *testing.T) {
			if tc.tier == "bpflsm" {
				lsms, err := os.ReadFile("/sys/kernel/security/lsm")
				if err != nil || !strings.Contains(","+strings.TrimSpace(string(lsms))+",", ",bpf,") {
					t.Skip("BPF LSM is not active on this boot (no bpf in lsm=); the default guest boot runs this case")
				}
			}
			s, server := newMCPGateScene(t, bin, tc.tier, tc.plane)
			testutil.RequireTier(t, s.tego(t, "doctor", "--require", tc.tier), tc.tier)
			run, dir := s.start(t)
			evs := s.finish(t, run, dir)
			assertMCPStageGrant(t, s, evs)
			var start record.RunStartPayload
			var refused, started, calls []*record.Event
			var serverLines []*record.Event
			for _, ev := range evs {
				switch ev.Kind {
				case record.KindRunStart:
					if err := ev.DecodePayload(&start); err != nil {
						t.Fatal(err)
					}
				case record.KindExec:
					var p record.ExecPayload
					if err := ev.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
					if !slices.Equal(p.Argv, server) {
						continue
					}
					if ev.Verdict == record.VerdictRefused {
						refused = append(refused, ev)
					} else {
						started = append(started, ev)
					}
				case record.KindMCP:
					if ev.Source == record.SourceProxy {
						calls = append(calls, ev)
					} else {
						serverLines = append(serverLines, ev)
					}
				}
			}
			if tc.tier == "cgroup" && start.DecisionPlane == "" {
				t.Skip("no plane mode on this kernel, so this cell is the fanotify fallback: no plane to hand execs to")
			}
			if start.Tier != tc.tier || start.DecisionPlane != tc.plane {
				t.Fatalf("the run was tier %q plane %q, want %q %q: the gate's plane path was not reached", start.Tier, start.DecisionPlane, tc.tier, tc.plane)
			}
			if got, want := s.out("direct"), "EACCES "+server[0]; got != want {
				t.Errorf("the start around the relay came to %q, want %q", got, want)
			}
			if got := s.out("shim"); got != "0" || !strings.Contains(s.out("answer"), `"result"`) {
				t.Errorf("the shim exited %q answering %q; it said %q", got, s.out("answer"), s.out("shim-err"))
			}
			if len(refused) != 1 || refused[0].Rule != "mcp[files].relay" || refused[0].Reason != record.ReasonExecNotAllowed {
				t.Errorf("refused starts %v: want one, rule mcp[files].relay", refused)
			}
			if len(started) != 1 || tc.tier != "landlock" && started[0].Source != record.SourceKernel {
				t.Errorf("starts %v: want one line (the kernel recorder's at a plane tier)", started)
			}
			if len(serverLines) != 1 || tc.tier != "landlock" && serverLines[0].Source != record.SourceKernel {
				t.Errorf("server lines %v: want one (the kernel recorder's at a plane tier)", serverLines)
			}
			if len(calls) != 1 || calls[0].Verdict != record.VerdictAllow {
				t.Errorf("tools/call lines %v: want one allowed", calls)
			}
			if t.Failed() {
				for _, ev := range evs {
					if ev.Kind == record.KindExec || ev.Kind == record.KindMCP {
						t.Logf("%s %s %s %s %s %s", ev.Kind, ev.Source, ev.Verdict, ev.Rule, ev.Reason, ev.Payload)
					}
				}
			}
		})
	}
}

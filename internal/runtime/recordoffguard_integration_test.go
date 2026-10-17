// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRootRecordOffAutoRefusesADirectModelConnection on the real kernel, through the real CLI: an
// auto contract under record: off with a tokens budget and a models: endpoint, at tier cgroup as root. The uprobes
// place no probe under record: off, so the run's capture is the forwarder (run_start.capture), its calls through the
// forwarder are metered, and a direct connection to the model host is refused, with no net: section and with a
// net.allow entry that names the host. The table was compiled to uprobe, which guards no models[] endpoint, so the
// direct connection was allowed, uncaptured, and the budget was the agent's to go around.
func TestRootRecordOffAutoRefusesADirectModelConnection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tier cgroup")
	}
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBPFBinary(t)
	agentBin := modelAgentBinary(t)
	host, port, caFile := modelUpstream(t)
	upstream := net.JoinHostPort(host, strconv.Itoa(port))
	for _, tc := range []struct{ name, net string }{
		{"no net section", ""},
		{"net.allow names the model host", fmt.Sprintf("net:\n  allow: [%q]\n", upstream)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project, root := t.TempDir(), t.TempDir()
			out := filepath.Join(project, "out")
			if err := os.Mkdir(out, 0o755); err != nil {
				t.Fatal(err)
			}
			agentReaches(t, out)
			agentOwns(t, out)
			contract := fmt.Sprintf(`version: 0
name: irecoffauto
command: [%q]
tier: cgroup
record: off
models:
  - provider: anthropic
    host: %s
    port: %d
fs:
  write: ["./out/"]
exec:
  allow: [%q]
%senv:
  pass: ["PATH", "HOME", "MODEL_CALLS", "MODEL_DIRECT"]
limits:
  pids: 128
  tokens: 100000
`, agentBin, host, port, agentBin, tc.net)
			if err := os.WriteFile(filepath.Join(project, "agent.yaml"), []byte(contract), 0o600); err != nil {
				t.Fatal(err)
			}
			f := &fixture{dir: project, out: out, root: root}
			run := exec.Command(bin, "run", filepath.Join(project, "agent.yaml"), "--", agentBin)
			run.Dir = project
			run.Env = append(isolatedEnv(t, f), "SSL_CERT_FILE="+caFile, "MODEL_CALLS=2", "MODEL_DIRECT="+upstream)
			got, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("tego run: %v\n%s", err, got)
			}
			if !strings.Contains(string(got), "direct connect refused") || strings.Contains(string(got), "UNEXPECTED") {
				t.Fatalf("the model host was reachable around the forwarder:\n%s", got)
			}
			dirs := runDirs(t, root)
			if len(dirs) != 1 {
				t.Fatalf("run directories %v, want one\n%s", dirs, got)
			}
			evs := events(t, dirs[0])
			var start record.RunStartPayload
			if len(evs) == 0 || evs[0].Kind != record.KindRunStart || evs[0].DecodePayload(&start) != nil {
				t.Fatalf("no run_start: %v", kinds(evs))
			}
			if start.Tier != "cgroup" || start.Capture != "forwarder" {
				t.Fatalf("run_start tier %q capture %q, want cgroup and forwarder", start.Tier, start.Capture)
			}
			if _, resps := sslPairs(t, evs); len(resps) != 2 {
				t.Errorf("%d ssl_response events, want the 2 calls through the forwarder metered: %v", len(resps), kinds(evs))
			}
			refused := false
			for _, e := range evs {
				var p record.NetPayload
				if e.Kind != record.KindNet || e.DecodePayload(&p) != nil {
					continue
				}
				if p.Dst == upstream {
					if e.Verdict != record.VerdictRefused {
						t.Errorf("the direct connection to %s is %s (rule %s), want refused", upstream, e.Verdict, e.Rule)
					}
					refused = true
					t.Logf("direct connection: %s, rule %s", e.Verdict, e.Rule)
				}
			}
			if !refused {
				t.Errorf("no net event names the direct connection to %s: %v", upstream, kinds(evs))
			}
		})
	}
}

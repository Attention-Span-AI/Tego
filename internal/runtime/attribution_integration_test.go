// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The two replies of the retriever run, by the tool each asks for.
const (
	replyDBQuery = "toolu_8812" // step 1: db_query
	replyPublish = "toolu_8813" // step 2: publish_summary
)

// retrieverUpstream is the model the retriever run talks to: TLS on loopback, answering each Messages API turn by
// how many replies the conversation already holds — db_query first, then publish_summary, then a text answer.
func retrieverUpstream(t *testing.T) (host string, port int, caFile string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Role string `json:"role"`
			} `json:"messages"`
		}
		if r.URL.Path != "/v1/messages" || json.NewDecoder(r.Body).Decode(&req) != nil {
			http.NotFound(w, r)
			return
		}
		turn := 0
		for _, m := range req.Messages {
			if m.Role == "assistant" {
				turn++
			}
		}
		content, stop := `[{"type":"text","text":"Published."}]`, "end_turn"
		switch turn {
		case 0:
			content, stop = `[{"type":"tool_use","id":"`+replyDBQuery+`","name":"db_query","input":{"sql":"select 1"}}]`, "tool_use"
		case 1:
			content, stop = `[{"type":"tool_use","id":"`+replyPublish+`","name":"publish_summary","input":{"queue":"q"}}]`, "tool_use"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("request-id", fmt.Sprintf("req_%03d", turn+1))
		_, _ = fmt.Fprintf(w, `{"id":"msg_%03d","type":"message","role":"assistant","model":"claude-test-1",`+
			`"stop_reason":%q,"content":%s,"usage":{"input_tokens":40,"output_tokens":20}}`, turn+1, stop, content)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if port, err = strconv.Atoi(u.Port()); err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(t.TempDir(), "upstream-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), port, caFile
}

// lineServer answers every line a connection sends with one line: the warehouse and the queue the tools reach.
func lineServer(t *testing.T, answer string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := bufio.NewReader(c).ReadString('\n'); err == nil {
					_, _ = io.WriteString(c, answer+"\n")
				}
			}()
		}
	}()
	return ln.Addr().String()
}

var (
	retrieverOnce sync.Once
	retrieverPath string
	retrieverErr  error
)

// retrieverAgentBinary builds test/workloads/retriever-agent once per test run.
func retrieverAgentBinary(t *testing.T) string {
	t.Helper()
	retrieverOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tego-retriever-agent-")
		if err != nil {
			retrieverErr = err
			return
		}
		retrieverPath = filepath.Join(dir, "retriever-agent")
		cmd := exec.Command("go", "build", "-o", retrieverPath, "github.com/attention-span-ai/tego/test/workloads/retriever-agent")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			retrieverErr = fmt.Errorf("go build retriever-agent: %v: %s", err, out)
		}
	})
	if retrieverErr != nil {
		t.Fatal(retrieverErr)
	}
	agentReaches(t, retrieverPath)
	return retrieverPath
}

// runRetriever runs the retriever through the real CLI at tier, capture forwarder: its tools reach a
// warehouse and a queue the contract allows, write the summary inside its write entry, and try to write a .netrc
// outside it. It returns the run's ledger and the addresses and paths the checks look for.
func runRetriever(t *testing.T, bin, tier string) (evs []*record.Event, db, queue, summary, netrc string) {
	t.Helper()
	agentBin := retrieverAgentBinary(t)
	host, port, caFile := retrieverUpstream(t)
	db, queue = lineServer(t, "41 rows"), lineServer(t, "queued")
	project, root, home := t.TempDir(), t.TempDir(), t.TempDir()
	out := filepath.Join(project, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, out)
	agentReaches(t, home)
	agentOwns(t, out, home) // only the contract may refuse the .netrc write, never the file's owner
	summary, netrc = filepath.Join(out, "summary.md"), filepath.Join(home, ".netrc")
	contract := fmt.Sprintf(`version: 0
name: iretriever
command: [%q]
tier: %s
capture: forwarder
record: full
models:
  - provider: anthropic
    host: %s
    port: %d
fs:
  write: ["./out/"]
exec:
  allow: [%q]
net:
  allow: [%q, %q]
env:
  pass: ["PATH", "HOME", "DB_ADDR", "QUEUE_ADDR", "NETRC", "OUT", "TOOL_DELAY_MS"]
limits:
  pids: 128
`, agentBin, tier, host, port, agentBin, db, queue)
	if err := os.WriteFile(filepath.Join(project, "agent.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fixture{dir: project, out: out, root: root}
	run := exec.Command(bin, "run", filepath.Join(project, "agent.yaml"), "--", agentBin)
	run.Dir = project
	run.Env = append(isolatedEnv(t, f), "SSL_CERT_FILE="+caFile, "DB_ADDR="+db, "QUEUE_ADDR="+queue,
		"NETRC="+netrc, "OUT="+out)
	got, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("tego run: %v\n%s", err, got)
	}
	if !strings.Contains(string(got), "netrc refused") || !strings.Contains(string(got), "done") {
		t.Fatalf("the retriever did not run both tools to the end, or wrote the .netrc:\n%s", got)
	}
	dirs := runDirs(t, root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one\n%s", dirs, got)
	}
	return events(t, dirs[0]), db, queue, summary, netrc
}

// checkRetrieverAttribution holds a real run's ledger (capture-derive R42): the requests report
// the replies' results, and every action of each tool names the reply that asked for it, in that reply's step.
func checkRetrieverAttribution(t *testing.T, evs []*record.Event, db, queue, summary, netrc string) {
	t.Helper()
	steps := map[string]int{}
	var results [][]string
	for _, e := range evs {
		switch e.Kind {
		case record.KindDecision:
			var p record.DecisionPayload
			if e.DecodePayload(&p) == nil && p.ToolUseID != "" {
				steps[p.ToolUseID] = p.Step
			}
		case record.KindSSLRequest:
			var p record.SSLRequestPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Side || p.ToolResults == nil {
				t.Errorf("ssl_request seq %d: side %v, tool_results %v; want a model turn derive read", e.Seq, p.Side, p.ToolResults)
				continue
			}
			results = append(results, *p.ToolResults)
		}
	}
	if steps[replyDBQuery] != 1 || steps[replyPublish] != 2 {
		t.Fatalf("decision steps %v, want %s in 1 and %s in 2", steps, replyDBQuery, replyPublish)
	}
	want := [][]string{{}, {replyDBQuery}, {replyPublish}}
	if !slices.EqualFunc(results, want, slices.Equal[[]string]) {
		t.Errorf("the requests reported %q, want %q", results, want)
	}
	found := map[string]int{}
	for _, e := range evs {
		if !e.Kind.IsAction() || e.Attr == nil {
			continue
		}
		a := e.Attr
		if a.Method == record.MethodToolID && (steps[a.ToolUseID] == 0 || steps[a.ToolUseID] != a.Step) {
			t.Errorf("%s seq %d names reply %q in step %d, which no decision of that step asked for", e.Kind, e.Seq, a.ToolUseID, a.Step)
		}
		var what, reply string
		switch e.Kind {
		case record.KindNet:
			var p record.NetPayload
			if e.DecodePayload(&p) != nil {
				continue
			}
			switch p.Dst {
			case db:
				what, reply = "warehouse connect", replyDBQuery
			case queue:
				what, reply = "queue connect", replyPublish
			}
		case record.KindFS:
			var p record.FSPayload
			if e.DecodePayload(&p) != nil {
				continue
			}
			switch p.Path {
			case summary:
				what, reply = "summary write", replyDBQuery
			case netrc:
				what, reply = ".netrc write", replyPublish
				if e.Verdict != record.VerdictRefused {
					t.Errorf(".netrc write seq %d is %s, want refused", e.Seq, e.Verdict)
				}
			}
		}
		if what == "" {
			continue
		}
		found[what]++
		if a.Method != record.MethodToolID || a.ToolUseID != reply || a.Step != steps[reply] || a.Confidence != record.ConfidenceLikely {
			t.Errorf("%s (seq %d) is attributed %+v, want reply %s in step %d by tool_id", what, e.Seq, *a, reply, steps[reply])
		}
	}
	for _, what := range []string{"warehouse connect", "summary write", "queue connect", ".netrc write"} {
		if found[what] == 0 {
			t.Errorf("the ledger has no %s line: %v", what, kinds(evs))
		}
	}
}

// TestIntegrationRetrieverRunTiesActionsToReplies is the retriever run through the real CLI at tier landlock:
// the forwarder records the model traffic, the supervisor the tools' connects and writes, and the attribute stage
// ties each to the reply whose tool window it fell in (capture-derive R42).
func TestIntegrationRetrieverRunTiesActionsToReplies(t *testing.T) {
	requireLandlock(t)
	evs, db, queue, summary, netrc := runRetriever(t, tegoBinary(t), "landlock")
	checkRetrieverAttribution(t, evs, db, queue, summary, netrc)
}

// TestRootRetrieverRunTiesActionsToReplies is the same run at the root tiers, where the kernel's recorder writes the
// tools' actions with the tids of the agent's threads: the attribution must be the reply's at tier cgroup and, where
// doctor says the machine has it, tier bpflsm.
func TestRootRetrieverRunTiesActionsToReplies(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBPFBinary(t)
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			if tier == "bpflsm" {
				f := &fixture{dir: t.TempDir(), root: t.TempDir()}
				doctor := exec.Command(bin, "doctor", "--require", tier)
				doctor.Env = isolatedEnv(t, f)
				testutil.RequireTier(t, doctor, tier)
			}
			evs, db, queue, summary, netrc := runRetriever(t, bin, tier)
			var start record.RunStartPayload
			if len(evs) == 0 || evs[0].DecodePayload(&start) != nil || start.Tier != tier {
				t.Fatalf("run_start tier %q, want %s", start.Tier, tier)
			}
			checkRetrieverAttribution(t, evs, db, queue, summary, netrc)
		})
	}
}

// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The shape these tests read is a real run's: kill test 2's forwarder half as the P0 acceptance run of
// 2026-09-23 recorded it (test/fixtures/ledger/kt2-forwarder-landlock for the lines that did not change since). The
// contract declares one models[] entry, the stand-in model server
// on a loopback port, under capture: forwarder and with no net: section. The agent's connects to the forwarder's
// listener are a runtime grant (net.capture[...]), every model request is an ssl_request whose endpoint is the
// entry's provider, and the one direct connection to the model's own host:port is refused under the rule
// SEMANTICS §1 gives it, models[<host>:<port>], with the dedicated refused line beside it.

const (
	modelPort = 36683
	modelHost = "127.0.0.1"
)

// modelLedger writes a run's lines in order, numbering them; each fields map is one line's own keys.
func modelLedger(lines ...map[string]any) []byte {
	var b strings.Builder
	for i, f := range lines {
		l := map[string]any{
			"v": 1, "seq": i, "id": strings.Repeat(fmt.Sprintf("%x", i%16), 64), "prev": "",
			"ts": "2026-09-23T12:00:00Z", "mono_ns": 1000 + i, "run": "r-0a1b2c3d-0dlm9rxvwpqfb-mbbxqv",
			"agent": "kt2-forwarder", "pid": 455, "tid": 455, "cgroup": 1540,
		}
		if i > 0 {
			l["prev"] = strings.Repeat(fmt.Sprintf("%x", (i-1)%16), 64)
		}
		for k, v := range f {
			l[k] = v
		}
		data, err := json.Marshal(l)
		if err != nil {
			panic(err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func runStartLine() map[string]any {
	return map[string]any{"kind": "run_start", "source": "supervisor", "capture": "forwarder", "tier": "landlock",
		"parsers": map[string]string{"anthropic": "1", "mcp": "exec"}, "command": []string{"python3", "agent.py"},
		"cwd": "/tmp/w", "contract_hash": strings.Repeat("56", 32), "bpf_hash": ""}
}

func captureConnectLine(port int) map[string]any {
	dst := fmt.Sprintf("%s:%d", modelHost, port)
	return map[string]any{"kind": "net", "source": "supervisor", "rule": "net.capture[" + dst + "]", "verdict": "allow",
		"authority": "rule", "attribution": map[string]string{"confidence": "unattributed", "method": "time"},
		"dst": dst, "host": modelHost, "proto": "tcp"}
}

func sslRequestLine(endpoint string) map[string]any {
	return map[string]any{"kind": "ssl_request", "source": "forwarder", "endpoint": endpoint, "host": modelHost,
		"method": "POST", "path": "/v1/messages", "size": 120}
}

// directConnectRefused is the pair of lines the supervisor and the pipeline write for the refused direct
// connection: the net line, which drift counts, and the refused line that mirrors it, which it never does (R13).
func directConnectRefused(host string, port int) []map[string]any {
	dst := fmt.Sprintf("%s:%d", host, port)
	rule := "models[" + dst + "]"
	return []map[string]any{
		{"kind": "net", "source": "supervisor", "rule": rule, "verdict": "refused", "reason": "net-not-allowed",
			"authority": "rule", "attribution": map[string]string{"confidence": "unattributed", "method": "time"},
			"dst": dst, "proto": "tcp"},
		{"kind": "refused", "source": "supervisor", "rule": rule, "reason": "net-not-allowed", "op": "connect",
			"target": dst},
	}
}

func runEndLine() map[string]any {
	return map[string]any{"kind": "run_end", "source": "supervisor", "reason": "exit"}
}

// modelTable is that run's contract compiled: capture: forwarder, no net: section, the models[] entries given.
func modelTable(models ...agent.ModelEndpoint) *agent.RuleTable {
	return &agent.RuleTable{
		Capture:  agent.CaptureForwarder,
		Contract: &agent.Contract{Name: "kt2-forwarder", Models: models},
	}
}

func anthropicAt(port int) agent.ModelEndpoint {
	return agent.ModelEndpoint{Provider: "anthropic", Host: modelHost, Port: port}
}

// TestRefusedDirectConnectCountsAgainstItsModelsEntry is finding 5 of the 2026-09-23 acceptance run: drift listed
// the refused direct connect under models[127.0.0.1:36683], DECLARED no, and the contract's models[anthropic]
// entry as declared and never used, although the refusal is that entry's (agent.ModelRule names it). One entry,
// one row: the refusal counts against models[anthropic], nothing under the host:port name is left undeclared,
// and the entry is not undone. The run still drifted: something was refused.
func TestRefusedDirectConnectCountsAgainstItsModelsEntry(t *testing.T) {
	lines := []map[string]any{runStartLine(), captureConnectLine(40001)}
	for range 20 {
		lines = append(lines, sslRequestLine("anthropic"))
	}
	lines = append(lines, directConnectRefused(modelHost, modelPort)...)
	lines = append(lines, runEndLine())

	rep, err := Compute(readerOver(t, modelLedger(lines...)), modelTable(anthropicAt(modelPort)))
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	got, ok := find(rep.Net, "models[anthropic]")
	want := RuleCount{Section: SectionNet, Rule: "models[anthropic]", Declared: true, Refused: 1}
	if !ok || got != want {
		t.Errorf("models[anthropic] = %+v (found %v), want %+v", got, ok, want)
	}
	for _, c := range rep.Net {
		if !c.Declared && !agent.IsRuntimeRule(c.Rule) {
			t.Errorf("net row %s is undeclared (%+v): the refusal names the declared models[] entry", c.Rule, c)
		}
	}
	if slices.Contains(rep.Undone, "models[anthropic]") {
		t.Errorf("undone = %v, but the entry refused a direct connection and served 20 requests", rep.Undone)
	}
	if !rep.Drifted() {
		t.Error("a run with a refusal is drift (R25)")
	}
}

// TestForwarderTrafficUsesItsModelsEntry is the same run without the direct connect: every model request went
// through the forwarder, which records ssl_request lines naming the entry's provider and no net line under the
// entry's name. The entry was used twenty times, so it is not "declared, never used", and with nothing refused
// and nothing undeclared the run did not drift. Without a single request the entry is undone again, so the use
// comes from the requests, not from being a models[] entry.
func TestForwarderTrafficUsesItsModelsEntry(t *testing.T) {
	lines := []map[string]any{runStartLine(), captureConnectLine(40001)}
	for range 20 {
		lines = append(lines, sslRequestLine("anthropic"))
	}
	lines = append(lines, runEndLine())
	rep, err := Compute(readerOver(t, modelLedger(lines...)), modelTable(anthropicAt(modelPort)))
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if len(rep.Undone) != 0 || rep.Drifted() {
		t.Errorf("undone = %v, drifted = %v; want neither: the model was used through the forwarder", rep.Undone, rep.Drifted())
	}
	if got, ok := find(rep.Net, "models[anthropic]"); !ok || got.Total() != 0 || !got.Declared {
		t.Errorf("models[anthropic] = %+v (found %v): a request carries no action verdict to count", got, ok)
	}

	idle, err := Compute(readerOver(t, modelLedger(runStartLine(), runEndLine())), modelTable(anthropicAt(modelPort)))
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if !slices.Equal(idle.Undone, []string{"models[anthropic]"}) {
		t.Errorf("undone = %v with no model request at all, want [models[anthropic]]", idle.Undone)
	}
}

// TestModelsAliasEdges holds the alias to what it is for. A request naming a provider the contract does not
// declare adds no row. Two entries that share a host:port share its refusal name, and the refusal counts against
// the first declared. An entry whose host is declared in upper case, or as an IPv6 literal in brackets, is still
// matched, because the refusal's name is agent.ModelRule's spelling of it and so is the alias. And a name some
// entry declares as its own is never redirected.
func TestModelsAliasEdges(t *testing.T) {
	t.Run("undeclared provider", func(t *testing.T) {
		rep, err := Compute(readerOver(t, modelLedger(runStartLine(), sslRequestLine("openai"), runEndLine())),
			modelTable(anthropicAt(modelPort)))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := find(rep.Net, "models[openai]"); ok {
			t.Errorf("net = %+v: a request adds no row for a provider nothing declared", rep.Net)
		}
		if !slices.Equal(rep.Undone, []string{"models[anthropic]"}) {
			t.Errorf("undone = %v, want [models[anthropic]]", rep.Undone)
		}
	})
	t.Run("shared host:port", func(t *testing.T) {
		lines := append([]map[string]any{runStartLine()}, directConnectRefused(modelHost, modelPort)...)
		rep, err := Compute(readerOver(t, modelLedger(append(lines, runEndLine())...)), modelTable(
			anthropicAt(modelPort), agent.ModelEndpoint{Provider: "openai", Host: modelHost, Port: modelPort}))
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := find(rep.Net, "models[anthropic]"); got.Refused != 1 {
			t.Errorf("models[anthropic] = %+v, want the refusal: it is the first declared at %s:%d", got, modelHost, modelPort)
		}
		if got, _ := find(rep.Net, "models[openai]"); got.Total() != 0 {
			t.Errorf("models[openai] = %+v, want nothing: the refusal is counted once", got)
		}
	})
	for _, sp := range []struct{ declared, refusedHost string }{
		{"[::1]", "[::1]"},                 // an IPv6 literal, declared in brackets
		{"Model.Example", "model.example"}, // a name, declared in upper case
	} {
		t.Run("spelling "+sp.declared, func(t *testing.T) {
			lines := append([]map[string]any{runStartLine()}, directConnectRefused(sp.refusedHost, 9443)...)
			rep, err := Compute(readerOver(t, modelLedger(append(lines, runEndLine())...)),
				modelTable(agent.ModelEndpoint{Provider: "local", Host: sp.declared, Port: 9443}))
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := find(rep.Net, "models[local]"); got.Refused != 1 {
				t.Errorf("models[local] = %+v, want the refusal of %s:9443", got, sp.refusedHost)
			}
		})
	}
	t.Run("declared name wins", func(t *testing.T) {
		// An absurd provider name, but a legal one: models[127.0.0.1:36683] is then an entry of its own.
		lines := append([]map[string]any{runStartLine()}, directConnectRefused(modelHost, modelPort)...)
		rep, err := Compute(readerOver(t, modelLedger(append(lines, runEndLine())...)), modelTable(
			anthropicAt(modelPort), agent.ModelEndpoint{Provider: fmt.Sprintf("%s:%d", modelHost, modelPort), Host: "h", Port: 1}))
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := find(rep.Net, fmt.Sprintf("models[%s:%d]", modelHost, modelPort)); got.Refused != 1 || !got.Declared {
			t.Errorf("the declared entry of that name = %+v, want the refusal", got)
		}
	})
}

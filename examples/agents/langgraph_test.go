// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/cli"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// langgraphDir is the test agent examples/agents/langgraph.yaml is run with (test/workloads/langgraph): a scripted
// LangGraph graph with no model account, and a LangChain chat model loop for the budget check.
var langgraphDir = filepath.Join(pkgDir, "..", "..", "test", "workloads", "langgraph")

// langgraphVerdicts is a `compile --test` table of what the example's rules decide for each thing the test agent's
// tools do: the allowed write and the one outside the writable folder, the allowed program and a refused one, the
// allowed host and refused ones, in every tier a run of the contract can get.
const langgraphVerdicts = `version: 0
tests:
  - name: a tool writes inside the one writable folder
    action: fs.write
    path: out/hello.txt
    expect: allow
  - name: a tool writes next to the project's files
    action: fs.write
    path: escape.txt
    expect: refused
  - name: a tool starts git
    action: exec
    argv: [git, --version]
    expect: allow
  - name: a tool starts curl, which no entry lists
    action: exec
    path: /usr/bin/curl
    expect: refused
  - name: a tool fetches from the host net.allow names
    action: net.connect
    host_port: api.open-meteo.com:443
    expect: allow
  - name: a tool fetches from another host on the same port
    action: net.connect
    host_port: example.org:443
    expect: refused
  - name: a tool connects to a loopback port nothing allows
    action: net.connect
    host_port: 127.0.0.1:9
    expect: refused
  - name: the chat model's own host is reached only through the forwarder
    action: net.connect
    host_port: api.anthropic.com:443
    expect: refused
`

// TestLangGraphExample pins what makes examples/agents/langgraph.yaml the rules of a LangChain or LangGraph agent in a
// virtual environment, and what the guest row that runs it relies on: the model through the forwarder with a token
// budget, one writable folder, the interpreter's environment and one program runnable, the MCP server behind the relay
// with its shim admitted, the model host out of net.allow, and the verdict of each thing the test agent's tools do.
func TestLangGraphExample(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgDir, "langgraph.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The guest row rewrites exactly these lines (the model endpoint to its stand-in, the token budget to a small
	// one, the allowed host to a local server) and starts the example's command; a changed line must change the row.
	for _, want := range []string{
		"{ provider: anthropic, host: api.anthropic.com, port: 443 }", "tokens: 2000000", `allow: ["api.open-meteo.com:443"]`,
		`command: ["./.venv/bin/python", "agent.py"]`, `command: ["./.venv/bin/python", "./mcp_server.py"]`,
		"tools: {allow: [read_file], deny: [delete_file]}", "capture: forwarder", "mcp relay *",
	} {
		if !bytes.Contains(src, []byte(want)) {
			t.Errorf("the example no longer contains %q, which the guest row rewrites or relies on", want)
		}
	}
	c, warnings := compileWarnings(t, "langgraph.yaml")
	if c.Capture != "forwarder" {
		t.Errorf("capture %q, want forwarder: tokens counts what the forwarder reads", c.Capture)
	}
	for _, never := range []string{"[budget-unmetered]", "model-direct-bypass", "[redundant-rule]"} {
		if strings.Contains(warnings, never) {
			t.Errorf("compile warns %q:\n%s", never, warnings)
		}
	}
	w := c.writes()
	if !slices.ContainsFunc(w, func(p string) bool { return strings.HasSuffix(p, "/out") || strings.HasSuffix(p, "/out/") }) {
		t.Errorf("fs.write %v lacks the ./out/ folder", w)
	}
	for _, p := range w {
		if p == "/tmp" || strings.HasSuffix(p, "/work") || strings.HasSuffix(p, "/work/") {
			t.Errorf("fs.write %v grants more than ./out/ and /dev/null: %s", w, p)
		}
	}
	var venv, git, shim bool
	for _, e := range c.Exec {
		venv = venv || (e.Raw == "./.venv/" && e.Dir)
		git = git || e.Raw == "git"
		shim = shim || strings.HasSuffix(e.Raw, "/.local/bin/tego")
	}
	if !venv || !git || !shim {
		t.Errorf("exec.allow %v: want ./.venv/ as a directory, git and the relay's shim (venv %v, git %v, shim %v)", c.Exec, venv, git, shim)
	}
	for _, n := range c.Net {
		if strings.Contains(n.Raw, "anthropic") {
			t.Errorf("net.allow names the model host (%s): the forwarder is its only route", n.Raw)
		}
	}
	requireDirectConnectRefused(t, "langgraph.yaml")

	path := place(t, "langgraph.yaml")
	table := filepath.Join(filepath.Dir(path), "langgraph-verdicts.yaml")
	if err := os.WriteFile(table, []byte(langgraphVerdicts), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := cli.Main([]string{"tego", "compile", path, "--offline", "--test", table}, &out, &errb); code != identity.ExitOK {
		t.Errorf("the example's verdicts differ from the test agent's expectations (exit %d):\n%s%s", code, out.String(), errb.String())
	}
}

// TestLangGraphTestAgentMatchesTheExample keeps the test agent (test/workloads/langgraph) and the example's rules
// saying the same things: the program the agent starts and the one it is refused, the MCP tools the relay allows and
// denies, the files it writes, the budget loop's model, and a requirements file that pins what both scripts import.
func TestLangGraphTestAgentMatchesTheExample(t *testing.T) {
	agent, err := os.ReadFile(filepath.Join(langgraphDir, "agent.py"))
	if err != nil {
		t.Fatal(err)
	}
	loop, err := os.ReadFile(filepath.Join(langgraphDir, "model_loop.py"))
	if err != nil {
		t.Fatal(err)
	}
	ex, err := os.ReadFile(filepath.Join(pkgDir, "langgraph.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"git", "--version"`, `"curl", "--version"`, `path="out/hello.txt"`, `path="escape.txt"`,
		`"mcp_delete_file"`, `"read_file"`, "GenericFakeChatModel", "StateGraph", "load_mcp_tools", "TEGO_MCP_RELAY", "TEGO_MCP_CONFIG"} {
		if !bytes.Contains(agent, []byte(want)) {
			t.Errorf("test/workloads/langgraph/agent.py lacks %s", want)
		}
	}
	for _, want := range []string{"ChatAnthropic(", "StateGraph"} {
		if !bytes.Contains(loop, []byte(want)) {
			t.Errorf("test/workloads/langgraph/model_loop.py lacks %s", want)
		}
	}
	// The loop's client takes its endpoint from the environment, as a person's agent does: no URL in the code.
	if bytes.Contains(loop, []byte("base_url")) || bytes.Contains(loop, []byte("http://")) || bytes.Contains(loop, []byte("api.anthropic.com")) {
		t.Error("model_loop.py names an endpoint: the forwarder's ANTHROPIC_BASE_URL must be what routes it")
	}
	// The programs: git is in the example's exec.allow, curl is not.
	if !bytes.Contains(ex, []byte(`"git"`)) {
		t.Error("the example must list git")
	}
	for _, line := range strings.Split(string(ex), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, "curl") {
			t.Errorf("the example lists curl in its rules: %s", line)
		}
	}
	req, err := os.ReadFile(filepath.Join(langgraphDir, "requirements.txt"))
	if err != nil {
		t.Fatal(err)
	}
	pinned := map[string]bool{}
	pin := regexp.MustCompile(`^([A-Za-z0-9_.-]+)==[0-9][0-9A-Za-z.]*$`)
	for _, line := range strings.Split(string(req), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := pin.FindStringSubmatch(line)
		if m == nil {
			// A hash, a continuation, an option or a range: `tego scan` refuses the whole file for the first three.
			t.Errorf("requirements.txt line %q is not a plain name==version pin", line)
			continue
		}
		pinned[m[1]] = true
	}
	for _, name := range []string{"langgraph", "langchain-core", "langchain-anthropic", "langchain-mcp-adapters", "mcp"} {
		if !pinned[name] {
			t.Errorf("requirements.txt does not pin %s, which a script imports", name)
		}
	}
}

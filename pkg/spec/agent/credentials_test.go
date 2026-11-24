// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadDiags writes yaml as a contract in a temporary directory and loads it, returning the contract (nil when Load
// refused it) and every diagnostic.
func loadDiags(t *testing.T, yaml string) (*Contract, []Diagnostic) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, ds, err := Load(path, testProfiles())
	if err != nil {
		return nil, ds
	}
	return c, ds
}

// credContract is a valid contract with one credential, %s replaced by extra top-level keys.
const credContract = `version: 0
name: t
command: ["python"]
capture: forwarder
models:
  - {provider: openai, host: api.openai.com, port: 443}
  - {provider: anthropic, host: 127.0.0.1, port: 9511}
credentials:
  - name: openai
    env: OPENAI_API_KEY
    allow: [api.openai.com]
  - name: fake
    env: ANTHROPIC_API_KEY
    allow: ["127.0.0.1:9511"]
%s`

// TestCredentialsAccepted: a credentials: section naming declared models[] endpoints loads.
func TestCredentialsAccepted(t *testing.T) {
	c, ds := loadDiags(t, strings.Replace(credContract, "%s", "", 1))
	if c == nil {
		t.Fatalf("refused: %s", render(ds))
	}
	if len(c.Credentials) != 2 || c.Credentials[0].Name != "openai" || c.Credentials[1].Env != "ANTHROPIC_API_KEY" {
		t.Fatalf("credentials = %+v", c.Credentials)
	}
}

// TestCredentialsRefused: every refusal of ADR 0126 §1, each by its code and words.
func TestCredentialsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, code, words string
	}{
		{"no capture", strings.Replace(strings.Replace(credContract, "capture: forwarder\n", "", 1), "%s", "", 1), CodeContradiction, "need capture: forwarder"},
		{"capture off", strings.Replace(strings.Replace(credContract, "capture: forwarder", "capture: off", 1), "%s", "", 1), CodeContradiction, "need capture: forwarder"},
		{"host sockets", strings.Replace(credContract, "%s", "host_sockets: true\n", 1), CodeContradiction, "session bus"},
		{"undeclared endpoint", strings.Replace(strings.Replace(credContract, "allow: [api.openai.com]", "allow: [evil.example.com]", 1), "%s", "", 1), CodeContradiction, "not a declared models[] endpoint"},
		{"wrong port", strings.Replace(strings.Replace(credContract, "allow: [api.openai.com]", `allow: ["api.openai.com:8443"]`, 1), "%s", "", 1), CodeContradiction, "declared: api.openai.com:443"},
		{"bad allow", strings.Replace(strings.Replace(credContract, "allow: [api.openai.com]", `allow: ["https://api.openai.com/"]`, 1), "%s", "", 1), CodeSchema, "not host or host:port"},
		{"empty allow", strings.Replace(strings.Replace(credContract, "allow: [api.openai.com]", "allow: []", 1), "%s", "", 1), CodeSchema, "allows no endpoint"},
		{"bad name", strings.Replace(strings.Replace(credContract, "name: openai", "name: Open_AI", 1), "%s", "", 1), CodeSchema, "must match ^[a-z0-9-]{1,40}$"},
		{"dup name", strings.Replace(strings.Replace(credContract, "name: fake", "name: openai", 1), "%s", "", 1), CodeSchema, "already used"},
		{"dup env", strings.Replace(strings.Replace(credContract, "env: ANTHROPIC_API_KEY", "env: OPENAI_API_KEY", 1), "%s", "", 1), CodeSchema, "already credential entry 1's"},
		{"tego env", strings.Replace(strings.Replace(credContract, "env: OPENAI_API_KEY", "env: TEGO_KEY", 1), "%s", "", 1), CodeEnvRuntimeReserved, "reserved for Tego"},
		{"forwarder env", strings.Replace(strings.Replace(credContract, "env: OPENAI_API_KEY", "env: OPENAI_BASE_URL", 1), "%s", "", 1), CodeEnvRuntimeReserved, "forwarder base-URL variable"},
		{"env.set", strings.Replace(credContract, "%s", "env:\n  set: {OPENAI_API_KEY: sk-real}\n", 1), CodeContradiction, "a real key in the contract"},
		{"missing env", strings.Replace(strings.Replace(credContract, "    env: OPENAI_API_KEY\n", "", 1), "%s", "", 1), CodeSchema, "env"},
		{"unknown key", strings.Replace(strings.Replace(credContract, "    env: OPENAI_API_KEY\n", "    env: OPENAI_API_KEY\n    value: sk-x\n", 1), "%s", "", 1), CodeSchema, "value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ds := loadDiags(t, tc.yaml)
			if c != nil {
				t.Fatalf("loaded: %s", render(ds))
			}
			var hit bool
			for _, d := range ds {
				if d.Code == tc.code && strings.Contains(d.Error(), tc.words) {
					hit = true
				}
			}
			if !hit {
				t.Errorf("want [%s] %q, got:\n%s", tc.code, tc.words, render(ds))
			}
		})
	}
}

// TestCredentialEnvPassWarned: env.pass naming the credential's variable is a warning, not an error.
func TestCredentialEnvPassWarned(t *testing.T) {
	c, ds := loadDiags(t, strings.Replace(credContract, "%s", "env:\n  pass: [PATH, OPENAI_API_KEY]\n", 1))
	if c == nil {
		t.Fatalf("refused: %s", render(ds))
	}
	if !strings.Contains(render(ds), "does not get the value it inherited") {
		t.Errorf("no warning: %s", render(ds))
	}
}

// TestContractHashUnchangedWithoutTheNewKeys: a contract writing neither credentials: nor mcp[].tools hashes as it
// did before ADR 0126 (its canonical bytes hold no new key), and `tools: {}` and `allow: []` change the hash.
func TestContractHashUnchangedWithoutTheNewKeys(t *testing.T) {
	const plain = `version: 0
name: t
command: ["python"]
mcp:
  - name: files
    command: ["mcp-files"]
`
	c, ds := loadDiags(t, plain)
	if c == nil {
		t.Fatal(render(ds))
	}
	b, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "tools") || strings.Contains(string(b), "credentials") {
		t.Fatalf("canonical bytes name a new key:\n%s", b)
	}
	const want = "version: 0\nname: t\ncommand:\n  - python\nmcp:\n  - name: files\n    command:\n      - mcp-files\n"
	if string(b) != want {
		t.Fatalf("canonical bytes changed:\n%s", b)
	}
	h0, _ := c.Hash()
	empty, ds := loadDiags(t, plain+"    tools: {}\n")
	if empty == nil {
		t.Fatal(render(ds))
	}
	h1, _ := empty.Hash()
	denyAll, ds := loadDiags(t, plain+"    tools: {allow: []}\n")
	if denyAll == nil {
		t.Fatal(render(ds))
	}
	h2, _ := denyAll.Hash()
	if h0 == h1 || h1 == h2 || h0 == h2 {
		t.Fatalf("hashes do not tell no tools, tools: {} and allow: [] apart: %x %x %x", h0, h1, h2)
	}
	if !empty.MCP[0].Relayed() || c.MCP[0].Relayed() {
		t.Fatal("Relayed")
	}
	cb, _ := denyAll.Canonical()
	if !strings.Contains(string(cb), "tools:\n      allow: []\n") {
		t.Fatalf("allow: [] lost:\n%s", cb)
	}
	cb, _ = empty.Canonical()
	if !strings.Contains(string(cb), "tools: {}\n") {
		t.Fatalf("tools: {} lost:\n%s", cb)
	}
}

// TestCredentialsRefusedWithoutALayer: in a build with no key layer a contract's credentials: loads, since the format is
// the format, and is refused at Compile by name, with the variable to pass instead: never a run that says nothing.
func TestCredentialsRefusedWithoutALayer(t *testing.T) {
	old := credentialsLayer
	credentialsLayer = nil
	t.Cleanup(func() { credentialsLayer = old })
	f := newFixture(t)
	c := f.load(strings.Replace(credContract, "%s", "", 1))
	_, ds, err := Compile(c, f.machine, f.opts()...)
	if err == nil || !hasCode(ds, CodeContradiction) {
		t.Fatalf("compiled: err=%v\n%s", err, render(ds))
	}
	for _, want := range []string{"does not support this section", "openai, fake", "env.pass: [OPENAI_API_KEY, ANTHROPIC_API_KEY]"} {
		if !strings.Contains(render(ds), want) {
			t.Errorf("the refusal does not say %q: %s", want, render(ds))
		}
	}
	if strings.Contains(render(ds), "build that has") {
		t.Errorf("the fix sends the reader to another build: %s", render(ds))
	}
}

// Invalid name fields sometimes contain shell-style entries; diagnostics must not turn those into value printers.
func TestEnvironmentNameDiagnosticHidesValue(t *testing.T) {
	for _, value := range []string{"QZ", "private-environment-value-that-is-long"} {
		entry := "PRIVATE_TOKEN=" + value
		for _, body := range []string{
			"env: {pass: [" + entry + "]}", "env: {deny: [" + entry + "]}", "env: {mask: [" + entry + "]}",
			"env: {set: {" + entry + ": x, " + entry + ": y}}",
			"credentials: [{name: example, env: " + entry + ", allow: [api.example.com]}]",
			"credentials: [{name: example, env: TOKEN, base_url_env: " + entry + ", allow: [api.example.com]}]",
		} {
			_, ds := loadDiags(t, "version: 0\nname: t\ncommand: [\"true\"]\n"+body+"\n")
			text := render(ds)
			if !strings.Contains(text, "PRIVATE_TOKEN") || strings.Contains(text, value) {
				t.Errorf("environment name diagnostic: %s", text)
			}
		}
		c := &Contract{Env: EnvSection{Set: map[string]string{entry: "x"}}}
		for _, baseURL := range []bool{false, true} {
			var ds diags
			cr := Credential{Name: "example", Env: entry, BaseURLEnv: entry}
			if baseURL {
				validateCredentialBaseURLEnv(&ds, c, cr, Pos{})
			} else {
				validateCredentialEnv(&ds, c, cr, Pos{}, map[string]int{}, 0)
			}
			text := render(ds.list)
			if !strings.Contains(text, "PRIVATE_TOKEN") || strings.Contains(text, value) {
				t.Errorf("credential name diagnostic: %s", text)
			}
		}
	}
}

// TestEnvEntryMessages: an entry of a field that takes a variable's name is never echoed when it has no name to tell
// from a value (a secret pasted where a name belongs); the diagnostic's path and position say which entry it is
// (rule (a) of pkg/spec/identity envtext.go).
func TestEnvEntryMessages(t *testing.T) {
	for _, entry := range []string{"sk-live-qz", "\"=sk-live-qz\"", "1BAD=sk-live-qz", "\"A B=sk-live-qz\""} {
		for body, where := range map[string]string{
			"env: {pass: [PATH, " + entry + "]}":                                           "env.pass.1: this entry is not an environment variable name",
			"env: {deny: [" + entry + "]}":                                                 "env.deny.0: this entry is not an environment variable name",
			"env: {mask: [" + entry + "]}":                                                 "env.mask.0: this entry is not an environment variable name",
			"env: {set: {" + entry + ": x}}":                                               "env.set: this entry is not an environment variable name",
			"credentials: [{name: example, env: " + entry + ", allow: [api.example.com]}]": "this entry is not an environment variable name",
			"credentials: [{name: example, env: TOKEN, base_url_env: " + entry + ", allow: [api.example.com]}]": "this entry is not an environment variable name",
		} {
			_, ds := loadDiags(t, "version: 0\nname: t\ncommand: [\"true\"]\n"+body+"\n")
			text := render(ds)
			if !strings.Contains(text, where) || strings.Contains(text, "qz") || strings.Contains(text, "BAD") {
				t.Errorf("%s: %s", body, text)
			}
		}
	}
}

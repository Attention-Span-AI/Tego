// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/bizrule"
)

const businessBundle = `{"adapter":"square.refund.v1","rules":[{"codes":["USD"],"id":"currencies","kind":"currencies"},{"currency":"USD","id":"refund-cap","kind":"per_call","limit":"10000"}],"server":"square","version":1}`

func businessContract(t *testing.T, bundle string) string {
	t.Helper()
	b, err := bizrule.DecodeBundle([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	return `version: 0
name: t
command: [python]
tier: bpflsm
record: full
capture: off
mcp:
  - name: square
    command: [/opt/tego/workers/square/node, /opt/tego/workers/square/server.js]
    tools: {allow: [make_api_request]}
    business_rules:
      version: 1
      topology: trusted-stdio-worker-v1
      worker_digest: '` + strings.Repeat("1", 64) + `'
      bundle_sha256: '` + b.Digest() + `'
      bundle_json: '` + bundle + `'
`
}

func TestBusinessRulesCompilerPinsCanonicalBundle(t *testing.T) {
	f := newFixture(t)
	c := f.load(businessContract(t, businessBundle))
	rt, _ := f.compile(c)
	b := rt.businessRules["square"]
	if b.bundle.Digest() != c.MCP[0].BusinessRules.BundleSHA256 || !bytes.Equal(b.bundle.Canonical(), []byte(businessBundle)) || b.workerDigest != strings.Repeat("1", 64) || b.topology != "trusted-stdio-worker-v1" {
		t.Fatalf("compiled business pins lost: %+v", b)
	}
	for _, e := range rt.Exec {
		if e.Source == ExecSourceMCP+":square" {
			t.Fatal("trusted worker was granted to the agent")
		}
	}
	if !rt.BusinessRulesConfigured() {
		t.Fatal("compiled entry lost business marker")
	}
	canonical, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	again, ds, err := LoadBytes(c.file, canonical, nil)
	if err != nil {
		t.Fatalf("canonical reload: %v %s", err, render(ds))
	}
	hash, err := again.Hash()
	if err != nil || hash != rt.Hash {
		t.Fatalf("canonical roundtrip changed hash: %x vs %x (%v)", hash, rt.Hash, err)
	}
	// A source mutation cannot erase the independently compiled marker.
	c.MCP[0].BusinessRules = nil
	if !rt.BusinessRulesConfigured() {
		t.Fatal("source mutation allowed legacy fallback")
	}
}

func TestBusinessRulesLoadRefusesUnsupportedContracts(t *testing.T) {
	valid := businessContract(t, businessBundle)
	for _, tc := range []struct{ name, old, replacement, words string }{
		{"null bundle", "bundle_json: '" + businessBundle + "'", "bundle_json: null", "bundle_json"},
		{"object bundle", "bundle_json: '" + businessBundle + "'", "bundle_json: {}", "bundle_json"},
		{"empty bundle", "bundle_json: '" + businessBundle + "'", "bundle_json: ''", "1..32768"},
		{"oversize bundle", "bundle_json: '" + businessBundle + "'", "bundle_json: '" + strings.Repeat(" ", 32769) + "'", "1..32768"},
		{"bad digest", "bundle_sha256: '", "bundle_sha256: '0", "64 lowercase"},
		{"uppercase worker", "worker_digest: '" + strings.Repeat("1", 64) + "'", "worker_digest: '" + strings.Repeat("A", 64) + "'", "64 lowercase"},
		{"missing worker", "      worker_digest: '" + strings.Repeat("1", 64) + "'\n", "", "worker_digest"},
		{"unknown key", "      version: 1", "      mutable: true\n      version: 1", "mutable"},
		{"unknown version", "      version: 1", "      version: 2", "business version"},
		{"wrong topology", "trusted-stdio-worker-v1", "legacy", "topology"},
		{"http", "    command: [/opt/tego/workers/square/node, /opt/tego/workers/square/server.js]", "    url: https://mcp.internal/mcp", "refuse HTTP"},
		{"no tools", "    tools: {allow: [make_api_request]}\n", "", "requires tools:"},
		{"ask", "    tools: {allow: [make_api_request]}", "    tools: {ask: [make_api_request]}", "cannot discharge tools.ask"},
		{"wrong command", "/opt/tego/workers/square/node", "/usr/bin/node", "pinned trusted-worker command"},
		{"wrong server", "name: square", "name: other", "server must equal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ds := loadDiags(t, strings.Replace(valid, tc.old, tc.replacement, 1))
			if c != nil || !strings.Contains(render(ds), tc.words) {
				t.Fatalf("wanted refusal %q: contract=%v diagnostics=%s", tc.words, c, render(ds))
			}
		})
	}
}

func TestBusinessRulesNativeDecoderAndCapabilityRefusals(t *testing.T) {
	for _, tc := range []struct{ name, bundle, words string }{
		{"threshold", strings.Replace(businessBundle, `"currency":"USD","id":"refund-cap","kind":"per_call","limit":"10000"`, `"ask_above":"5000","currency":"USD","deny_above":"10000","id":"refund-cap","kind":"threshold"`, 1), "not supported in slice 1"},
		{"per run", strings.Replace(businessBundle, `"kind":"per_call"`, `"kind":"per_run"`, 1), "not supported in slice 1"},
		{"cad", strings.ReplaceAll(businessBundle, "USD", "CAD"), "exactly [USD]"},
		{"no cap", strings.Replace(businessBundle, `,{"currency":"USD","id":"refund-cap","kind":"per_call","limit":"10000"}`, "", 1), "exactly one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ds := loadDiags(t, businessContract(t, tc.bundle))
			if c != nil || !strings.Contains(render(ds), tc.words) {
				t.Fatalf("not refused: %v %s", c, render(ds))
			}
		})
	}
	valid := businessContract(t, businessBundle)
	// Preserve the correct pin while damaging v1 bytes: native decoder must refuse
	// instead of YAML/JSON coercion repairing those bytes.
	for _, changed := range []string{
		strings.Replace(businessBundle, `"limit":"10000"`, `"limit":10000`, 1),
		strings.Replace(businessBundle, `"version":1`, `"version":1,"version":1`, 1),
		" " + businessBundle,
	} {
		c, ds := loadDiags(t, strings.Replace(valid, businessBundle, changed, 1))
		if c != nil || !strings.Contains(render(ds), "business bundle:") {
			t.Fatalf("native invalid bundle admitted: %v %s", c, render(ds))
		}

		wantLine := 1 + strings.Count(valid[:strings.Index(valid, "      bundle_json:")], "\n")
		for _, d := range ds {
			if strings.Contains(d.Message, "business bundle:") && d.Line != wantLine {
				t.Fatalf("native decoder error points to line %d, want bundle_json scalar line %d", d.Line, wantLine)
			}
		}
	}
}

func TestBusinessRulesCompileRechecksMutationAndRequirements(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name  string
		edit  func(*Contract)
		opt   []CompileOption
		words string
	}{
		{"mutated bytes", func(c *Contract) { c.MCP[0].BusinessRules.BundleJSON = "{}" }, nil, "business bundle:"},
		{"mutated pin", func(c *Contract) { c.MCP[0].BusinessRules.BundleSHA256 = strings.Repeat("0", 64) }, nil, "digest does not match"},
		{"landlock", func(c *Contract) { c.Tier = TierPin(backend.TierLandlock) }, nil, "root-owned admission owner"},
		{"observe", func(*Contract) {}, []CompileOption{WithObserve()}, "root-owned admission owner"},
		{"off", func(*Contract) {}, []CompileOption{WithRecord(RecordOff)}, "root-owned admission owner"},
		{"summary", func(*Contract) {}, []CompileOption{WithRecord(RecordSummary)}, "root-owned admission owner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := f.load(businessContract(t, businessBundle))
			tc.edit(c)
			rt, ds, err := Compile(c, f.machine, f.opts(tc.opt...)...)
			if err == nil || rt != nil || !strings.Contains(render(ds), tc.words) {
				t.Fatalf("wanted refusal %q: %v %v %s", tc.words, rt, err, render(ds))
			}
		})
	}
}

func TestBusinessRulesHashBindsEveryPin(t *testing.T) {
	valid := businessContract(t, businessBundle)
	c, ds := loadDiags(t, valid)
	if c == nil {
		t.Fatal(render(ds))
	}
	before, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*BusinessRules){
		func(b *BusinessRules) { b.WorkerDigest = strings.Repeat("2", 64) },
		func(b *BusinessRules) {
			b.BundleJSON = strings.Replace(b.BundleJSON, "10000", "9999", 1)
			x, e := bizrule.DecodeBundle([]byte(b.BundleJSON))
			if e != nil {
				t.Fatal(e)
			}
			b.BundleSHA256 = x.Digest()
		},
	} {
		copyC := *c
		copyC.MCP = append([]MCPServer(nil), c.MCP...)
		b := *c.MCP[0].BusinessRules
		edit(&b)
		copyC.MCP[0].BusinessRules = &b
		after, err := copyC.Hash()
		if err != nil || after == before {
			t.Fatalf("hash omitted business pin: %v", err)
		}
	}
}

func TestBusinessRulesNullNeverDisables(t *testing.T) {
	valid := businessContract(t, businessBundle)
	prefix := valid[:strings.Index(valid, "    business_rules:")]
	for _, v := range []string{"null", "~", "", "{}"} {
		c, ds := loadDiags(t, prefix+"    business_rules: "+v+"\n")
		if c != nil || !strings.Contains(render(ds), "business_rules") {
			t.Fatalf("null/empty mapping admitted: %v %s", c, render(ds))
		}
	}
}

func TestBusinessRulesRefuseMultipleBundles(t *testing.T) {
	first := businessContract(t, businessBundle)
	second := businessContract(t, strings.Replace(businessBundle, `"server":"square"`, `"server":"square2"`, 1))
	second = strings.Replace(second, "name: square\n", "name: square2\n", 1)
	both := first + second[strings.Index(second, "  - name:"):]
	c, ds := loadDiags(t, both)
	if c != nil || !strings.Contains(render(ds), "one business rule bundle per contract") {
		t.Fatalf("multiple bundles admitted: %v %s", c, render(ds))
	}
}

func TestBusinessRulesExecRedundancyWarning(t *testing.T) {
	const worker = "/opt/tego/workers/square/node"
	for _, tc := range []struct {
		name, declaration string
		wantWarning       bool
	}{
		{"business", businessContract(t, businessBundle), false},
		{"ordinary", "version: 0\nname: t\ncommand: [python]\nmcp:\n  - name: square\n    command: [" + worker + "]\n", true},
	} {
		for _, executable := range []string{worker, "node"} {
			t.Run(tc.name+"/"+executable, func(t *testing.T) {
				c, ds := loadDiags(t, tc.declaration+"exec:\n  allow: ["+executable+"]\n")
				if c == nil {
					t.Fatalf("load: %s", render(ds))
				}
				warning := strings.Contains(render(ds), "already granted implicitly")
				if warning != tc.wantWarning {
					t.Fatalf("implicit grant warning=%v, want %v: %s", warning, tc.wantWarning, render(ds))
				}
			})
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
)

// TestContractValueSpellings: a value is refused, with a message naming the key and a
// fix line, when its spelling reads as something other than what was written: a cost too small for a float64
// (read as 0), a digit separator (read as 10), a quoted number (yaml.v3's raw "cannot unmarshal !!str"), a
// version spelled 00, and a ~user path (a directory literally named "~root" beneath the working directory).
func TestContractValueSpellings(t *testing.T) {
	const base = "name: qa\ncommand: [/bin/true]\n"
	for _, tc := range []struct {
		name, src        string
		wantMsg, wantFix string // "" wantMsg: the contract loads
	}{
		{"cost", "version: 0\nlimits: {cost_usd: 1.5}", "", ""},
		{"cost zero", "version: 0\nlimits: {cost_usd: 0}", "", ""},
		{"cost zero with exponent", "version: 0\nlimits: {cost_usd: 0.0e-400}", "", ""},
		{"cost fraction only", "version: 0\nlimits: {cost_usd: .5}", "", ""},
		{"cost exponent", "version: 0\nlimits: {cost_usd: 1e2}", "", ""},
		{"cost negative zero", "version: 0\nlimits: {cost_usd: -0}", "cost_usd must not be negative", ""},
		{"cost underflow", "version: 0\nlimits: {cost_usd: 1e-400}", "too small to represent and would read as 0", "write 0 for no spend"},
		{"cost underflow fraction", "version: 0\nlimits: {cost_usd: 0.0001e-400}", "too small to represent", ""},
		{"cost overflow", "version: 0\nlimits: {cost_usd: 1e400}", "cost_usd 1e400 is out of range", ""},
		{"cost digit separator", "version: 0\nlimits: {cost_usd: 1_0}", `cost_usd must be a decimal number, got "1_0"`, "write a dollar amount"},
		{"cost hex float", "version: 0\nlimits: {cost_usd: 0x1p4}", "must be a decimal number", ""},
		{"cost NaN", "version: 0\nlimits: {cost_usd: NaN}", "must be a decimal number", ""},
		{"cost Inf", "version: 0\nlimits: {cost_usd: +Inf}", "must be a decimal number", ""},
		{"cost quoted", "version: 0\nlimits: {cost_usd: \"5\"}", `limits.cost_usd must be a number, got the quoted string "5"`, "write cost_usd: 5, without quotes"},
		{"tokens quoted", "version: 0\nlimits: {tokens: \"5\"}", `limits.tokens must be a number, got the quoted string "5"`, "write tokens: 5, without quotes"},
		{"tokens single-quoted", "version: 0\nlimits: {tokens: '5'}", "must be a number, got the quoted string", "write tokens: 5"},
		{"tokens quoted word", "version: 0\nlimits: {tokens: \"many\"}", "must be a number, got the quoted string", "write the number without quotes"},
		{"tokens digit separator", "version: 0\nlimits: {tokens: 1_0}", "tokens must be an integer", ""},
		{"pids quoted", "version: 0\nlimits: {pids: \"64\"}", "limits.pids must be a number", "write pids: 64"},
		{"repeats quoted", "version: 0\nlimits: {repeats: \"3\"}", "limits.repeats must be a number", ""},
		{"cpu_weight quoted", "version: 0\nlimits: {cpu_weight: \"100\"}", "limits.cpu_weight must be a number", ""},
		{"model port quoted", "version: 0\nmodels: [{provider: anthropic, host: api.anthropic.com, port: \"443\"}]", "models.0.port must be a number", "write port: 443"},
		{"cpu quoted stays a string", "version: 0\nlimits: {cpu: \"2.0\"}", "", ""},
		{"version quoted", "version: \"0\"", `version must be a number, got the quoted string "0"`, "write version: 0, without quotes"},
		{"version 00", "version: 00", `version is written "00"; the version is spelled 0`, "write version: 0"},
		{"version -0", "version: -0", `version is written "-0"`, ""},
		{"version 1", "version: 1", "version 1 is not supported", ""},
		{"home", "version: 0\nfs: {write: [\"~/out\"]}", "", ""},
		{"tilde user", "version: 0\nfs: {write: [\"~root/x\"]}", `"~root/x": ~root is a ~user form, and only ~/ (your home directory) is expanded`, "./~root/x for a directory named ~root"},
		{"tilde user alone", "version: 0\nfs: {deny_read: [\"~alice\"]}", "~alice is a ~user form", ""},
		{"tilde user exec", "version: 0\nexec: {allow: [\"~bin/tool\"]}", "~bin is a ~user form", ""},
		{"tilde inside a name", "version: 0\nfs: {write: [\"out/~tmp\"]}", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ds, err := LoadBytes("q.yaml", []byte(tc.src+"\n"+base), nil)
			if tc.wantMsg == "" {
				if err != nil {
					t.Fatalf("refused: %v\n%s", err, render(ds))
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted; want %q", tc.wantMsg)
			}
			for _, d := range ds {
				if d.IsError() && strings.Contains(d.Message, tc.wantMsg) {
					if d.Code != CodeSchema || !strings.Contains(d.Fix, tc.wantFix) {
						t.Errorf("code %q fix %q, want [schema] and a fix with %q", d.Code, d.Fix, tc.wantFix)
					}
					if strings.Contains(d.Message, "cannot unmarshal") {
						t.Errorf("yaml.v3's raw message: %s", d.Message)
					}
					return
				}
			}
			t.Errorf("no error carries %q:\n%s", tc.wantMsg, render(ds))
		})
	}
}

// TestTestTableRefusesTildeUser: in a compile --test row, a ~user path is refused as in the
// contract, not evaluated as <cwd>/~user.
func TestTestTableRefusesTildeUser(t *testing.T) {
	for _, key := range []string{"path", "dest", "script"} {
		src := "tests:\n  - {action: fs.rename, path: /a, dest: /b, expect: allow}\n"
		src = strings.Replace(src, key+": /"+map[string]string{"path": "a", "dest": "b"}[key], key+": ~root/x", 1)
		if key == "script" {
			src = "tests:\n  - {action: exec, path: /bin/sh, script: ~root/x, expect: allow}\n"
		}
		_, ds, err := LoadTestTableBytes("t.yaml", []byte(src))
		if err == nil || !strings.Contains(render(ds), "~root is a ~user form") {
			t.Errorf("%s: err %v\n%s", key, err, render(ds))
		}
	}
}

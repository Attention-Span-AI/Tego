// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
)

func TestLearnNoteSurvivesCompile(t *testing.T) {
	f := newFixture(t)
	const note = "learn:\n  run: r-12345678-0aaaaaaaaaaaa-abcdef\n  withheld: [tcp://203.0.113.9:443, 'udp://[2001:db8::1]:443']\n"
	c, ds, err := LoadBytes(f.root+"/agent.yaml", []byte("version: 0\nname: a\ncommand: [python]\nnet: {allow: []}\n"+note), nil)
	if err != nil {
		t.Fatalf("load learned contract: %v\n%s", err, render(ds))
	}
	rt, _ := f.compile(c)
	canonical, err := rt.Contract.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(canonical), "learn:\n") || !strings.Contains(string(canonical), "tcp://203.0.113.9:443") {
		t.Fatalf("compile lost learn history: %s", canonical)
	}
	changed, _, err := LoadBytes(f.root+"/agent.yaml", []byte(strings.Replace(string(canonical), "203.0.113.9", "203.0.113.10", 1)), nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := changed.Hash()
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := LoadBytes("again.yaml", canonical, nil)
	if err != nil {
		t.Fatal(err)
	}
	canon2, err := again.Canonical()
	if err != nil || string(canon2) != string(canonical) {
		t.Fatalf("learn history is not a canonical fixed point: %v", err)
	}
	if _, _, err := LoadBytes("child.yaml", []byte("version: 0\nname: a\ncommand: [python]\nextends: p\n"), mapSource{"p": note}); err == nil {
		t.Fatal("inherited a profile's learn history")
	}
	if h == rt.Hash {
		t.Fatal("learn history is outside contract_hash")
	}
	for _, bad := range []string{"null", "{}", "{run: bad, withheld: [tcp://203.0.113.9:443]}", "{run: r-12345678-0aaaaaaaaaaaa-abcdef, withheld: []}", "{run: r-12345678-0aaaaaaaaaaaa-abcdef, withheld: [tcp://example.com:443]}", "{run: r-12345678-0aaaaaaaaaaaa-abcdef, withheld: [tcp://203.0.113.9:443], typo: true}"} {
		if _, _, err := LoadBytes("a.yaml", []byte("version: 0\nname: a\ncommand: [python]\nlearn: "+bad+"\n"), nil); err == nil {
			t.Errorf("accepted malformed learn note %s", bad)
		}
	}
}

func TestLearnHistoryDiagnosticsNameContractLineAndFix(t *testing.T) {
	const run = "r-12345678-0aaaaaaaaaaaa-abcdef"
	for _, tc := range []struct {
		name, note, field, fix string
		line                   int
	}{
		{"run", "  run: invalid\n  withheld: [tcp://203.0.113.9:443]\n", "learn.run", "run id", 5},
		{"empty", "  run: " + run + "\n  withheld: []\n", "learn.withheld", "sorted", 6},
		{"host", "  run: " + run + "\n  withheld:\n    - tcp://203.0.113.9:443\n    - tcp://example.com:443\n", "learn.withheld[1]", "canonical", 8},
		{"IPv6", "  run: " + run + "\n  withheld:\n    - tcp://203.0.113.9:443\n    - 'udp://[2001:DB8::1]:443'\n", "learn.withheld[1]", "canonical", 8},
		{"duplicate", "  run: " + run + "\n  withheld:\n    - tcp://203.0.113.9:443\n    - tcp://203.0.113.9:443\n", "learn.withheld[1]", "distinct", 8},
		{"unsorted", "  run: " + run + "\n  withheld:\n    - udp://203.0.113.9:443\n    - tcp://203.0.113.9:443\n", "learn.withheld[1]", "sorted", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ds, err := LoadBytes("edited.yaml", []byte("version: 0\nname: a\ncommand: [python]\nlearn:\n"+tc.note), nil)
			if err == nil {
				t.Fatal("malformed hand edit loaded")
			}
			if strings.Contains(err.Error(), "run_start") || strings.Contains(err.Error(), "record:") {
				t.Errorf("contract error exposes a record path: %v", err)
			}
			if len(ds) != 1 {
				t.Fatalf("want one diagnostic, got %v", ds)
			}
			d := ds[0]
			if d.File != "edited.yaml" || d.Line != tc.line || d.Col == 0 || d.Code != CodeSchema || !d.IsError() {
				t.Errorf("diagnostic must name bad contract line %d: %+v", tc.line, d)
			}
			if !strings.HasPrefix(d.Message, tc.field+":") || strings.Contains(d.Message, "contract_source") {
				t.Errorf("diagnostic must name %s: %s", tc.field, d.Message)
			}
			if !strings.Contains(d.Fix, tc.fix) || !strings.Contains(d.Fix, "remove the learn key") {
				t.Errorf("diagnostic needs a repair or removal: %+v", d)
			}
			if tc.field != "learn.run" && (!strings.Contains(d.Fix, "tcp://IP:port") || !strings.Contains(d.Fix, "udp://IP:port")) {
				t.Errorf("fix must name the canonical endpoint form: %s", d.Fix)
			}
		})
	}
}

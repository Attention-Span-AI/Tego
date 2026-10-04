// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// A contract the schema walk refuses must be refused with a message that names the problem: a walk that
// let one through would compile something the author never wrote.
func TestSchemaWalkRefusals(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"scalar field given a list", "version: 0\nname: [a]\ncommand: [x]\n", "must be a single value"},
		{"list field given a scalar", "version: 0\nname: a\ncommand: x\n", "must be a list"},
		{"mapping field given a scalar", "version: 0\nname: a\ncommand: [x]\nfs: nope\n", "must be a mapping"},
		{"null list element", "version: 0\nname: a\ncommand: [x]\nfs:\n  deny_read: [~]\n", "empty entry"},
		{"duplicate key", "version: 0\nname: a\nname: b\ncommand: [x]\n", "already defined"},
		{"unknown field", "version: 0\nname: a\ncommand: [x]\nwat: 1\n", "unknown field"},
		{"explicit tag", "version: 0\nname: !!binary YQ==\ncommand: [x]\n", "explicit YAML tag"},
		{"quoted number", "version: 0\nname: a\ncommand: [x]\nlimits:\n  pids: \"64\"\n", "must be a number"},
		{"complex key", "version: 0\nname: a\ncommand: [x]\nenv:\n  set:\n    ? [a]\n    : b\n", "plain scalar"},
		{"null env.set value", "version: 0\nname: a\ncommand: [x]\nenv:\n  set: {A: }\n", "env.set.A: has no value"},
		{"tilde env.set value", "version: 0\nname: a\ncommand: [x]\nenv:\n  set: {PATH: ~}\n", "env.set.PATH: has no value"},
		{"alias loop", "version: 0\nname: &a *a\ncommand: [x]\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ct, ds, err := LoadBytes("a.yaml", []byte(c.src), nil)
			if c.want == "" { // only required not to panic or accept
				if err == nil && ct != nil && len(ds) == 0 {
					t.Fatal("accepted")
				}
				return
			}
			if !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("err = %v, want ErrInvalidContract; diagnostics: %v", err, ds)
			}
			var all strings.Builder
			for _, d := range ds {
				all.WriteString(d.Message + "\n")
			}
			if !strings.Contains(all.String(), c.want) {
				t.Fatalf("no diagnostic mentions %q:\n%s", c.want, all.String())
			}
		})
	}
}

func TestWriteDiagnosticsShape(t *testing.T) {
	ds := []Diagnostic{
		{Severity: SeverityError, File: "a.yaml", Line: 3, Col: 5, Code: CodeSchema, Message: "boom", Fix: "do x"},
		{Severity: SeverityWarning, File: "a.yaml", Line: 4, Code: CodeSchema, Message: "hm"},
		{Severity: SeverityWarning, File: "a.yaml", Code: CodeSchema, Message: "file-wide"},
		{Severity: SeverityWarning, Code: CodeSchema, Message: "bare"},
	}
	var b bytes.Buffer
	if err := WriteDiagnostics(&b, ds); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{"a.yaml:3:5: boom", "  fix: do x", "a.yaml:4: hm", "a.yaml: file-wide"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "fix: \n") {
		t.Errorf("an empty fix must print nothing:\n%s", got)
	}
	if err := WriteDiagnostics(failingWriter{}, ds); err == nil {
		t.Error("a write failure must surface")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestCanonicalRequiresALoadedContract(t *testing.T) {
	if _, err := (&Contract{}).Canonical(); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("hand-built contract: %v", err)
	}
	var nilC *Contract
	if _, err := nilC.Hash(); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("nil contract Hash: %v", err)
	}
}

func TestRuleNames(t *testing.T) {
	if got := (FSRule{Kind: "write", Raw: "./out", Path: "/w/out"}).RuleName(); got != "fs.write[./out]" {
		t.Errorf("declared fs entry: %q", got)
	}
	if got := (FSRule{Kind: "deny_read", Path: "/w/.ssh"}).RuleName(); got != "fs.deny_read[/w/.ssh]" {
		t.Errorf("implicit fs entry falls back to the resolved path: %q", got)
	}
	nets := []struct {
		r    NetRule
		want string
	}{
		{NetRule{Raw: "api.x.com:443"}, "net[api.x.com:443]"},
		{NetRule{Host: "h", Port: 80}, "net[h:80]"},
		{NetRule{Host: "h"}, "net[h]"},
		{NetRule{UnixPath: "/run/s.sock"}, "net[/run/s.sock]"},
		{NetRule{Host: "127.0.0.1", Port: 9, Runtime: CaptureGrant}, "net.capture[127.0.0.1:9]"},
	}
	for _, n := range nets {
		if got := n.r.RuleName(); got != n.want {
			t.Errorf("%+v: %q, want %q", n.r, got, n.want)
		}
	}
	execs := []struct {
		r    ExecRule
		want string
	}{
		{ExecRule{Raw: "git", Basename: "git", Path: "/usr/bin/git"}, "exec[git]"},
		{ExecRule{Basename: "python", Path: "/usr/bin/python"}, "exec[python]"},
		{ExecRule{Path: "/opt/x"}, "exec[/opt/x]"},
	}
	for _, e := range execs {
		if got := e.r.RuleName(); got != e.want {
			t.Errorf("%+v: %q, want %q", e.r, got, e.want)
		}
	}
}

func TestIsRuntimeRule(t *testing.T) {
	for rule, want := range map[string]bool{
		ResolverRule: true,
		"net.dns-broker[unix:/private/run/dns.sock]": true,
		"net.dns-broker[unix:relative]":              false,
		"net.dns-broker[unix:/private/run/dns.sock":  false,
		"net.dns.allow[0]":                           false,
		"net.dns-broker":                             false,
		"net.capture[127.0.0.1:9]":                   true,
		"net[api.x.com]":                             false,
		"net.capture":                                false,
		"":                                           false,
		"exec[net.resolver]":                         false,
		"fs.harness-state[/r/hook-state]":            true,
		"fs.harness-state[r/hook-state]":             false,
		"fs.harness-state":                           false,
	} {
		if got := IsRuntimeRule(rule); got != want {
			t.Errorf("IsRuntimeRule(%q) = %v", rule, got)
		}
	}
}

func TestCaptureModeRankOrdersCeilings(t *testing.T) {
	order := []CaptureMode{CaptureOff, CaptureForwarder, CaptureUprobe, CaptureAuto}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() >= order[i].Rank() {
			t.Errorf("%s must rank below %s", order[i-1], order[i])
		}
	}
	if CaptureMode("").Rank() != CaptureAuto.Rank() {
		t.Error("the unset mode reads as auto")
	}
	if CaptureMode("bogus").Rank() >= CaptureOff.Rank() {
		t.Error("an unknown mode must rank below every real one, never above a ceiling")
	}
}

func TestBoundedSeparatesUnaskedFromZero(t *testing.T) {
	if (ResolvedLimits{}).Bounded(BudgetPids) {
		t.Error("nothing asked: unbounded")
	}
	if !(ResolvedLimits{Set: BudgetPids}).Bounded(BudgetPids) {
		t.Error("the Set bit is what says a zero was asked for")
	}
	if (ResolvedLimits{Set: BudgetMemory}).Bounded(BudgetPids) {
		t.Error("another dimension's bit must not bound pids")
	}
	for k, l := range map[BudgetSet]ResolvedLimits{
		BudgetCPU:        {CPU: "1.0"},
		BudgetCPUWeight:  {CPUWeight: 5},
		BudgetMemory:     {MemoryB: 1},
		BudgetMemoryHigh: {MemoryHigh: 1},
		BudgetPids:       {Pids: 1},
		BudgetTokens:     {Tokens: 1},
		BudgetCostUSD:    {CostUSD: 1},
		BudgetWall:       {Wall: 1},
		BudgetStallAfter: {StallAfter: 1},
		BudgetRepeats:    {Repeats: 1},
	} {
		if !l.Bounded(k) {
			t.Errorf("a value for %b must bound it", k)
		}
	}
	if (ResolvedLimits{Pids: 1}).Bounded(BudgetSet(1 << 15)) {
		t.Error("an unknown dimension is never bounded")
	}
}

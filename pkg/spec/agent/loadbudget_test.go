// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type budgetProfiles struct {
	data  map[string]string
	calls int
	after func()
}

func (p *budgetProfiles) Resolve(name string) (string, []byte, error) {
	p.calls++
	if p.after != nil {
		p.after()
	}
	return name + ".yaml", []byte(p.data[name]), nil
}
func graphLimits() LoadLimits {
	return LoadLimits{SourceBytes: 1 << 20, Profiles: 128, ExpandedBytes: 16 << 20, Diagnostics: 64, DiagnosticBytes: 64 << 10}
}

const budgetTop = "version: 0\nname: shared\ncommand: [true]\nextends: [a, b]\n"

func TestLoadBytesBoundedGraph(t *testing.T) {
	// Eight parents each name eight distinct leaves, the review's branching graph.
	p := &budgetProfiles{data: map[string]string{}}
	var parents []string
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("parent%d", i)
		parents = append(parents, name)
		var leaves []string
		for j := 0; j < 8; j++ {
			leaf := fmt.Sprintf("leaf%d-%d", i, j)
			leaves = append(leaves, leaf)
			p.data[leaf] = "version: 0\n"
		}
		p.data[name] = "version: 0\nextends: [" + strings.Join(leaves, ",") + "]\n"
	}
	top := "version: 0\nname: shared\ncommand: [true]\nextends: [" + strings.Join(parents, ",") + "]\n"
	limits := graphLimits()
	limits.Profiles = 10
	c, ds, err := LoadBytesBounded(context.Background(), "general.yaml", []byte(top), p, limits)
	if c != nil || !errors.Is(err, ErrLoadBudget) || p.calls != 10 || !strings.Contains(err.Error(), "profile count") {
		t.Fatalf("partial graph: contract=%v diagnostics=%d calls=%d err=%v", c, len(ds), p.calls, err)
	}
}

func TestLoadBytesBoundedResources(t *testing.T) {
	for _, kind := range []string{"source bytes", "expanded output", "expanded merge output", "diagnostic count", "diagnostic bytes"} {
		t.Run(kind, func(t *testing.T) {
			limits := graphLimits()
			body := budgetTop
			p := &budgetProfiles{data: map[string]string{"a": "version: 0\n", "b": "version: 0\n"}}
			switch kind {
			case "source bytes":
				limits.SourceBytes = int64(len(body) + len(p.data["a"]))
			case "expanded output":
				limits.ExpandedBytes = 50
			case "expanded merge output":
				limits.ExpandedBytes = 2000
			case "diagnostic count":
				limits.Diagnostics = 2
				body = "version: 0\nname: shared\ncommand: [true]\nbad1: x\nbad2: x\nbad3: x\n"
			case "diagnostic bytes":
				limits.DiagnosticBytes = 4
				body = "bad: x\n"
			}
			c, ds, err := LoadBytesBounded(context.Background(), "general.yaml", []byte(body), p, limits)
			if c != nil || !errors.Is(err, ErrLoadBudget) || !strings.Contains(err.Error(), kind) {
				t.Fatalf("unbounded %s: contract=%v diagnostics=%d err=%v", kind, c, len(ds), err)
			}
			if len(ds) > limits.Diagnostics {
				t.Fatalf("diagnostic count %d", len(ds))
			}
		})
	}
}

func TestLoadBytesBoundedCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &budgetProfiles{data: map[string]string{"a": "version: 0\n"}, after: cancel}
	c, _, err := LoadBytesBounded(ctx, "general.yaml", []byte(budgetTop), p, graphLimits())
	if c != nil || !errors.Is(err, context.Canceled) || p.calls != 1 {
		t.Fatalf("contract=%v calls=%d err=%v", c, p.calls, err)
	}
}

func TestLoadBytesBoundedPreservesCanonical(t *testing.T) {
	p := &budgetProfiles{data: map[string]string{"a": "version: 0\nenv: {pass: [PATH]}\n", "b": "version: 0\nfs: {write: [.] }\n"}}
	ordinary, ds, err := LoadBytes("general.yaml", []byte(budgetTop), p)
	if err != nil {
		t.Fatalf("ordinary %v %v", ds, err)
	}
	bounded, ds, err := LoadBytesBounded(context.Background(), "general.yaml", []byte(budgetTop), p, graphLimits())
	if err != nil {
		t.Fatalf("bounded %v %v", ds, err)
	}
	a, err := ordinary.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, err := bounded.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical changed:\n%s\n%s", a, b)
	}
}

// Profile aliases must pay for every read, even when the merge deduplicates them.
type aliasBudgetProfiles struct{ calls int }

func (p *aliasBudgetProfiles) Resolve(string) (string, []byte, error) {
	p.calls++
	return "same.yaml", []byte("version: 0\n"), nil
}
func TestLoadBytesBoundedAliasReads(t *testing.T) {
	p := &aliasBudgetProfiles{}
	limits := graphLimits()
	top := strings.Replace(budgetTop, "[a, b]", "[a, b, c]", 1)
	limits.SourceBytes = int64(len(top) + 2*len("version: 0\n"))
	c, _, err := LoadBytesBounded(context.Background(), "general.yaml", []byte(top), p, limits)
	if c != nil || !errors.Is(err, ErrLoadBudget) || p.calls != 3 {
		t.Fatalf("alias read budget: contract=%v calls=%d err=%v", c, p.calls, err)
	}
}

func TestLoadBytesBoundedDiagnosticsReleaseRequest(t *testing.T) {
	c, ds, err := LoadBytesBounded(context.Background(), "general.yaml", []byte("version: 0\nname: shared\ncommand: [true]\nbad: value\n"), nil, graphLimits())
	if c != nil || err == nil || len(ds) == 0 {
		t.Fatalf("invalid fixture: %v %v %v", c, ds, err)
	}
	for _, d := range ds {
		if d.budget != nil {
			t.Fatal("diagnostics retain the request and merged graph")
		}
	}
	var d Diagnostic
	if !errors.As(err, &d) || d.budget != nil {
		t.Fatal("wrapped diagnostic retains the request and merged graph")
	}
}

func TestLoadBytesBoundedTaggedExpansion(t *testing.T) {
	body := "version: 0\nname: shared\ncommand: [true]\ngate:\n  rules: [&item !<tag:example.com,2026:" + strings.Repeat("x", 1000) + "> {\"exec matches a\": 10}, *item, *item, *item]\n"
	if _, ds, err := LoadBytes("general.yaml", []byte(body), nil); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("ordinary tag refusal: %v %v", ds, err)
	}
	limits := graphLimits()
	limits.ExpandedBytes = 8000
	c, _, err := LoadBytesBounded(context.Background(), "general.yaml", []byte(body), nil, limits)
	if c != nil || !errors.Is(err, ErrLoadBudget) {
		t.Fatalf("tag bytes escaped expansion budget: contract=%v err=%v", c, err)
	}
}

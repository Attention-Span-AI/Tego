// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/dnspolicy"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func compiledBinding(sources string, before, after *agent.RuleTable) ([]byte, error) {
	return compiledBindingWithGrammar(sources, before, after, "")
}

func TestCompiledBindingGrammarRegistrationMatchesFingerprint(t *testing.T) {
	full := &snapshotEncoder{builtin: map[snapshotPointer]string{}}
	if _, err := full.value(reflect.ValueOf(rows.Builtin().All()), "builtin", true); err != nil {
		t.Fatal(err)
	}
	cheap := &snapshotEncoder{builtin: map[snapshotPointer]string{}}
	cheap.registerGrammar(reflect.ValueOf(rows.Builtin().All()), "builtin")
	if !reflect.DeepEqual(full.builtin, cheap.builtin) {
		t.Fatal("child grammar references differ from the parent's fingerprint slots")
	}
}

func TestCompiledBindingPointerMapKeyTies(t *testing.T) {
	type key struct{ Entry string }
	values := map[*key]string{{"same"}: "first", {"same"}: "second", {"same"}: "third"}
	var want []byte
	for i := 0; i < 32; i++ {
		e := &snapshotEncoder{builtin: map[snapshotPointer]string{}, active: map[snapshotPointer]bool{}}
		x, err := e.value(reflect.ValueOf(values), "test", false)
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			want = got
		} else if !bytes.Equal(want, got) {
			t.Fatal("structurally identical pointer keys produce nondeterministic pair ordering")
		}
	}
}

func commandSnapshotFixture(t *testing.T) *agent.RuleTable {
	t.Helper()
	p, err := execmatch.Parse("git status", execmatch.ListAllow, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	candidates := execmatch.NewCandidates([]string{"status", "stash"}, []string{"status"})
	ids := map[execmatch.ID]string{{Dev: 1, Ino: 2}: "git"}
	loaders := map[execmatch.ID]bool{{Dev: 3, Ino: 4}: true}
	return &agent.RuleTable{ExecCommands: &agent.ExecCommands{
		Entries:    []agent.ExecCommandEntry{{Pattern: p}},
		Identities: ids, Loaders: loaders, Candidates: candidates,
		Index: execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{
			Candidates: candidates, Identities: ids, Loaders: loaders,
		}),
	}}
}

func TestCompiledBindingCommandSnapshotIsDeterministic(t *testing.T) {
	a, err := compiledBinding("sources", nil, commandSnapshotFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := compiledBinding("sources", nil, commandSnapshotFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("equivalent separately built command indexes bind differently")
	}
	for _, row := range agentdiff.Compare(commandSnapshotFixture(t), commandSnapshotFixture(t)) {
		if row.Family == "program arguments" && row.Direction != agentdiff.Unchanged {
			t.Fatalf("equal command rules require spurious review: %+v", row)
		}
	}
	if len(a) == 0 {
		t.Fatal("empty snapshot")
	}
}

func TestCompiledBindingIncludesEveryCommandFact(t *testing.T) {
	base, err := compiledBinding("sources", nil, commandSnapshotFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*agent.ExecCommands)
	}{
		{"entry pattern", func(e *agent.ExecCommands) { e.Entries[0].Pattern.Path = []string{"push"} }},
		{"entry position", func(e *agent.ExecCommands) { e.Entries[0].Pos.Line++ }},
		{"entry note", func(e *agent.ExecCommands) { e.Entries[0].Notes = []string{"changed"} }},
		{"file identity", func(e *agent.ExecCommands) { e.Identities[execmatch.ID{Dev: 8, Ino: 9}] = "git" }},
		{"loader identity", func(e *agent.ExecCommands) { e.Loaders[execmatch.ID{Dev: 8, Ino: 9}] = true }},
		{"candidate names", func(e *agent.ExecCommands) { e.Candidates = execmatch.NewCandidates([]string{"push"}, nil) }},
		{"candidate common group", func(e *agent.ExecCommands) {
			e.Candidates = execmatch.NewCandidates([]string{"status", "stash"}, []string{"stash"})
		}},
		{"helper image", func(e *agent.ExecCommands) { e.Helpers = []string{"/a/git-helper"} }},
		{"implicit grant", func(e *agent.ExecCommands) { e.Unconstrained = map[string]string{"git": "command"} }},
		{"private index constraint", func(e *agent.ExecCommands) {
			e.Index = execmatch.NewIndex(rows.Builtin(), e.Index.Patterns(), execmatch.IndexOptions{Candidates: e.Candidates, Identities: e.Identities, Loaders: e.Loaders, Unconstrained: map[string]bool{"git": true}})
		}},
		{"private index identities", func(e *agent.ExecCommands) {
			e.Index = execmatch.NewIndex(rows.Builtin(), e.Index.Patterns(), execmatch.IndexOptions{Candidates: e.Candidates, Identities: map[execmatch.ID]string{{Dev: 8, Ino: 9}: "git"}, Loaders: e.Loaders})
		}},
		{"private index candidates", func(e *agent.ExecCommands) {
			e.Index = execmatch.NewIndex(rows.Builtin(), e.Index.Patterns(), execmatch.IndexOptions{Candidates: execmatch.NewCandidates([]string{"push"}, nil), Identities: e.Identities, Loaders: e.Loaders})
		}},
		{"private index bare pattern", func(e *agent.ExecCommands) {
			p, _ := execmatch.Parse("git", execmatch.ListAllow, rows.Builtin())
			e.Index = execmatch.NewIndex(rows.Builtin(), append(e.Index.Patterns(), p), execmatch.IndexOptions{Candidates: e.Candidates, Identities: e.Identities, Loaders: e.Loaders})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := commandSnapshotFixture(t)
			tc.change(rt.ExecCommands)
			got, err := compiledBinding("sources", nil, rt)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(base, got) {
				t.Fatal("changed compiled command fact was omitted from binding")
			}
		})
	}
}

func TestCompiledBindingRefusesUnknownGrammarCode(t *testing.T) {
	rt := commandSnapshotFixture(t)
	rt.ExecCommands.Entries[0].Pattern.Row = &execmatch.Row{Tool: "git"}
	if _, err := compiledBinding("sources", nil, rt); err == nil {
		t.Fatal("unregistered grammar accepted as trusted built-in code")
	}
}

func TestCompiledBindingIncludesOpaquePolicies(t *testing.T) {
	for _, family := range []string{"DNS", "HTTP", "proxy", "gate", "gate command"} {
		t.Run(family, func(t *testing.T) {
			a, b := &agent.RuleTable{}, &agent.RuleTable{}
			// The raw contract and source digest remain identical. Only an
			// opaque compiled policy changes, which ordinary JSON hides as {}.
			a.Contract, b.Contract = &agent.Contract{Name: "same"}, &agent.Contract{Name: "same"}
			switch family {
			case "DNS":
				a.DNSQueries, _ = dnspolicy.Compile([]string{"a.example"}, []string{"A"})
				b.DNSQueries, _ = dnspolicy.Compile([]string{"b.example"}, []string{"A"})
			case "HTTP":
				a.HTTP, _ = httppolicy.Compile([]httppolicy.Rule{{Host: "api.example", Port: 443, Allow: []string{"/a"}}})
				b.HTTP, _ = httppolicy.Compile([]httppolicy.Rule{{Host: "api.example", Port: 443, Allow: []string{"/b"}}})
			case "proxy":
				c := &agent.Contract{Capture: agent.CaptureForwarder, Models: []agent.ModelEndpoint{{Host: "api.example", Port: 443}}, Net: &agent.NetSection{Proxy: &agent.ProxyPolicy{HTTP2: true, MaxStreams: 32}}}
				var err error
				a.Proxy, err = agent.CompileProxyPolicy(c)
				if err != nil {
					t.Fatal(err)
				}
				c.Net.Proxy.MaxStreams = 64
				b.Proxy, err = agent.CompileProxyPolicy(c)
				if err != nil {
					t.Fatal(err)
				}
			case "gate":
				a.Gate, _ = gate.New([]gate.Rule{{Predicate: gate.WriteOutsideWorktree, Score: 1}}, 1, 2)
				b.Gate, _ = gate.New([]gate.Rule{{Predicate: gate.WriteOutsideWorktree, Score: 2}}, 1, 2)
			case "gate command":
				a.Gate, _ = gate.New([]gate.Rule{{Predicate: gate.ExecMatches, Argument: "git status", Score: 1}}, 1, 2)
				b.Gate, _ = gate.New([]gate.Rule{{Predicate: gate.ExecMatches, Argument: "git push", Score: 1}}, 1, 2)
			}
			x, err := compiledBinding("same-sources", nil, a)
			if err != nil {
				t.Fatal(err)
			}
			y, err := compiledBinding("same-sources", nil, b)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(x, y) {
				t.Fatal("changed opaque compiled authority was omitted")
			}
		})
	}
}

// unresolvedSnapshotHost keeps this real compiler fixture offline, like nextrun.
type unresolvedSnapshotHost struct{}

func (unresolvedSnapshotHost) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("offline fixture")
}

func TestCompiledBindingOfflineClockAdvance(t *testing.T) {
	for _, scope := range []struct {
		list     string
		maxStale bool
	}{{"allow", false}, {"ask", false}, {"allow", true}, {"ask", true}} {
		list := scope.list
		for _, edit := range []bool{false, true} {
			name := list + "/new"
			if edit {
				name = list + "/edit"
			}
			if scope.maxStale {
				name += "/max-stale"
			}
			t.Run(name, func(t *testing.T) {
				home := t.TempDir()
				path := filepath.Join(home, "agent.yaml")
				text := []byte("version: 0\nname: same\ncommand: [sh]\nnet:\n  " + list + ": ['api.example:443']\n")
				if scope.maxStale {
					text = append(text, []byte("  dns: {max_stale: 30s}\n")...)
				}
				contract, ds, err := agent.LoadBytes(path, text, nil)
				if err != nil {
					t.Fatalf("load: %v %v", err, ds)
				}
				compileAt := func(now time.Time) *agent.RuleTable {
					t.Helper()
					rt, ds, err := agent.Compile(contract, config.Builtin(), agent.Offline(), agent.WithResolver(unresolvedSnapshotHost{}), agent.WithClock(func() time.Time { return now }), agent.WithHome(home), agent.WithCwd(home), agent.WithPATH("/usr/bin:/bin"), agent.WithOwnBinaries(""), agent.WithMountInfo(""))
					if err != nil {
						t.Fatalf("compile: %v %v", err, ds)
					}
					return rt
				}
				previewTime := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
				preview, save := compileAt(previewTime), compileAt(previewTime.Add(time.Hour))
				rules := func(rt *agent.RuleTable) []agent.NetRule {
					if list == "ask" {
						return rt.NetAsk
					}
					return rt.Net
				}
				if len(rules(preview)) != 1 || !rules(preview)[0].ResolvedAt.IsZero() || !rules(save)[0].ResolvedAt.IsZero() {
					t.Fatal("failed offline lookups carried DNS evidence timestamps")
				}
				if scope.maxStale && rules(save)[0].ExpiresAt != time.Unix(0, 1) {
					t.Fatal("missing offline DNS evidence did not keep the fail-closed expiry")
				}
				bind := func(rt *agent.RuleTable) []byte {
					t.Helper()
					var before *agent.RuleTable
					if edit {
						before = rt
					}
					b, err := compiledBinding("same", before, rt)
					if err != nil {
						t.Fatal(err)
					}
					return b
				}
				x, y := bind(preview), bind(save)
				if !bytes.Equal(x, y) {
					t.Fatal("unchanged offline hostname review went stale when the compilation clock advanced")
				}
				expiry := rules(save)[0].ExpiresAt
				rules(save)[0].ExpiresAt = previewTime.Add(2 * time.Hour)
				if bytes.Equal(x, bind(save)) {
					t.Fatal("authority-bearing network expiry was omitted")
				}
				rules(save)[0].ExpiresAt = expiry
				rules(save)[0].TTL += time.Second
				if bytes.Equal(x, bind(save)) {
					t.Fatal("network TTL was omitted")
				}
			})
		}
	}
}

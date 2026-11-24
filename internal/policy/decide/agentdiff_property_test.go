// SPDX-License-Identifier: Apache-2.0

package decide_test

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The rule editor and the builder tell a person which way a change moves what the next run may do from
// agentdiff.Compare of the two compiled tables, never from the file's text. This holds that comparison to the decision
// engine, which agentdiff never links: over random pairs of contracts, a pair the comparison folds to "narrows" must
// not let any probed action through more than before, at any tier. The reverse (widens) is not held: a family that
// widened may narrow elsewhere. A pair it will not order says mixed and is never narrowing.

const propertyFiles = "a b a/x a/y a/x/f a/y/f b/x b/x/f"

func propertyProject(t *testing.T) (root string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"home", "ledger", "a/x", "a/y", "b/x"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range strings.Fields(propertyFiles) {
		if st, err := os.Stat(filepath.Join(root, f)); err == nil && st.IsDir() {
			continue
		}
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

type propertyEntries struct {
	// profile is the body of the profile the contract extends ("" for none): its own fs entries.
	profile                                  string
	write, denyRead, askRead, ask, denyWrite []string
	execAllow, netAllow, netAsk              []string
}

func pick(r *rand.Rand, from []string) []string {
	var out []string
	for _, e := range from {
		if r.Intn(3) == 0 {
			out = append(out, e)
		}
	}
	return out
}

// scenarios are the shapes the plain random pick reaches too rarely: a deny_write beneath a write grant, a pattern, a
// refusal nested inside a write grant, a refusal and a question side by side.
func scenario(r *rand.Rand, e propertyEntries) propertyEntries {
	switch r.Intn(5) {
	case 0:
		e.write, e.denyWrite = []string{"./a/"}, []string{"./a/x/", "./a/y/"}
	case 1:
		e.write, e.denyRead = []string{"./a/"}, append(e.denyRead, "./a/y/")
	case 2:
		e.denyRead = append(e.denyRead, "./a/*/f")
	case 3:
		e.denyRead, e.askRead = []string{"./b/x/"}, []string{"./b/"}
	case 4:
		e.profile = []string{"fs:\n  ask_read: [./docs-none/]\n", "fs:\n  write: [./a/]\n", "fs:\n  deny_read: [./b/x/]\n  write: [./a/]\n"}[r.Intn(3)]
	}
	return e
}

func randomEntries(r *rand.Rand) propertyEntries {
	e := plainEntries(r)
	if r.Intn(2) == 0 {
		e = scenario(r, e)
	}
	if r.Intn(5) == 0 && e.profile == "" {
		e.profile = []string{"fs:\n  write: [./a/]\n", "fs:\n  deny_read: [./b/x/]\n", "fs:\n  ask: [./a/y/]\n"}[r.Intn(3)]
	}
	return e
}

func plainEntries(r *rand.Rand) propertyEntries {
	return propertyEntries{
		write:     pick(r, []string{"./a/", "./b/", "./a/x/", "./b/x/"}),
		denyRead:  pick(r, []string{"./a/", "./a/y/", "./b/", "./b/x/", "./a/x/f", "./a/*/f"}),
		askRead:   pick(r, []string{"./a/x/", "./b/x/", "./a/y/f", "./b/"}),
		ask:       pick(r, []string{"./a/", "./a/y/", "./b/x/"}),
		denyWrite: pick(r, []string{"./a/x/", "./b/x/", "./a/y/"}),
		execAllow: pick(r, []string{"sh", "cat", "ls"}),
		netAllow:  pick(r, []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:80"}),
		netAsk:    pick(r, []string{"192.0.2.1:443", "192.0.2.4:443"}),
	}
}

func (e propertyEntries) yaml() string {
	list := func(name string, es []string) string {
		if len(es) == 0 {
			return ""
		}
		return "  " + name + ": [" + strings.Join(es, ", ") + "]\n"
	}
	var b strings.Builder
	b.WriteString("version: 0\nname: prop\ncommand: [sh]\ntier: landlock\n")
	if e.profile != "" {
		b.WriteString("extends: shared\n")
	}
	b.WriteString("exec:\n  allow: [sh" + strings.Join(append([]string{""}, e.execAllow...), ", ") + "]\n")
	b.WriteString("fs:\n" + list("write", e.write) + list("deny_read", e.denyRead) + list("ask_read", e.askRead) +
		list("ask", e.ask) + list("deny_write", e.denyWrite))
	b.WriteString("net:\n  allow: [" + strings.Join(append([]string{"192.0.2.9:443"}, e.netAllow...), ", ") + "]\n" + list("ask", e.netAsk))
	return b.String()
}

// edited returns e with one list changed: an entry added, removed, or an ask moved to a refusal.
func (e propertyEntries) edited(r *rand.Rand) propertyEntries {
	out := e
	lists := []*[]string{&out.write, &out.denyRead, &out.askRead, &out.ask, &out.denyWrite, &out.execAllow, &out.netAllow, &out.netAsk}
	universe := [][]string{
		{"./a/", "./b/", "./a/x/", "./b/x/"}, {"./a/", "./a/y/", "./b/", "./b/x/", "./a/x/f", "./a/*/f"}, {"./a/x/", "./b/x/", "./a/y/f", "./b/"},
		{"./a/", "./a/y/", "./b/x/"}, {"./a/x/", "./b/x/", "./a/y/"}, {"cat", "ls"}, {"192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:80"}, {"192.0.2.1:443", "192.0.2.4:443"},
	}
	switch r.Intn(6) {
	case 0: // a refusal made a question, or a question a refusal, at the same path
		if len(out.denyRead) > 0 {
			out.askRead = append(append([]string(nil), out.askRead...), out.denyRead[0])
			out.denyRead = out.denyRead[1:]
			return out
		}
	case 1: // a deny_write, a pattern or a nested refusal goes
		if len(out.denyWrite) > 0 {
			out.denyWrite = out.denyWrite[1:]
			return out
		}
		for j, d := range out.denyRead {
			if strings.Contains(d, "*") || len(out.write) > 0 {
				out.denyRead = append(append([]string(nil), out.denyRead[:j]...), out.denyRead[j+1:]...)
				return out
			}
		}
	}
	for range 1 + r.Intn(2) {
		i := r.Intn(len(lists))
		cur := append([]string(nil), *lists[i]...)
		if len(cur) > 0 && r.Intn(2) == 0 {
			j := r.Intn(len(cur))
			if i == 2 && r.Intn(2) == 0 { // never: an ask_read entry moves to deny_read
				out.denyRead = append(append([]string(nil), out.denyRead...), cur[j])
			}
			cur = append(cur[:j], cur[j+1:]...)
		} else {
			cur = append(cur, universe[i][r.Intn(len(universe[i]))])
		}
		*lists[i] = cur
	}
	return out
}

func compileProperty(t *testing.T, root, text string) *agent.RuleTable {
	t.Helper()
	path := filepath.Join(root, "agent.yaml")
	chain := &agent.ProfileChain{}
	chain.WithDir(profilesrc.Dir{Root: filepath.Join(root, "profiles")})
	c, ds, err := agent.LoadBytes(path, []byte(text), chain)
	if err != nil {
		return nil
	}
	_ = ds
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(root, "ledger")
	rt, _, err := agent.Compile(c, m, agent.WithCwd(root), agent.WithHome(filepath.Join(root, "home")), agent.WithMountInfo(""), agent.Offline(), agent.WithPATH("/usr/bin:/bin"))
	if err != nil {
		return nil
	}
	return rt
}

// rank is how much the engine lets one probe through: 2 allowed, 1 asked (the person is asked: the engine says refused
// with an ask rule's name, or asks), 0 refused. Telling a question from a refusal is what orders deny_read below
// ask_read, and a pair that turns a refusal into a question lets the person approve a read.
func rank(a agent.Action, res agent.EvalResult) int {
	switch {
	case res.Verdict == agent.VerdictAllow:
		return 2
	case res.Verdict == agent.VerdictAsk,
		a.Kind == agent.ActionFSRead && strings.HasPrefix(res.Rule, "fs.ask_read["),
		a.Kind == agent.ActionFSWrite && strings.HasPrefix(res.Rule, "fs.ask["),
		a.Kind == agent.ActionNetConnect && strings.HasPrefix(res.Rule, "net.ask["):
		return 1
	}
	return 0
}

func propertyProbes(root string) []agent.Action {
	var out []agent.Action
	for _, f := range strings.Fields(propertyFiles) {
		p := filepath.Join(root, f)
		out = append(out, agent.Action{Kind: agent.ActionFSRead, Path: p}, agent.Action{Kind: agent.ActionFSWrite, Path: p},
			agent.Action{Kind: agent.ActionFSWrite, Path: p + "/new"}, agent.Action{Kind: agent.ActionFSRead, Path: p + "/new"})
	}
	for _, h := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.9"} {
		for _, port := range []int{443, 80} {
			out = append(out, agent.Action{Kind: agent.ActionNetConnect, Host: h, Port: port, Proto: "tcp"})
		}
	}
	for _, p := range []string{"/usr/bin/sh", "/usr/bin/cat", "/usr/bin/ls"} {
		out = append(out, agent.Action{Kind: agent.ActionExec, Path: p})
	}
	return out
}

func TestAgentdiffNeverCallsLooserTighter(t *testing.T) {
	root := propertyProject(t)
	probes := propertyProbes(root)
	r := rand.New(rand.NewSource(20261121))
	pairs, narrowing, strictly, refusals := 0, 0, 0, 0
	rounds := 1800
	if testing.Short() {
		rounds = 300
	}
	for i := 0; i < rounds; i++ {
		e := randomEntries(r)
		f := e.edited(r)
		if err := os.MkdirAll(filepath.Join(root, "profiles"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "profiles", "shared.yaml"), []byte("version: 0\nname: shared\n"+e.profile), 0o600); err != nil {
			t.Fatal(err)
		}
		a, b := compileProperty(t, root, e.yaml()), compileProperty(t, root, f.yaml())
		if a == nil || b == nil {
			continue
		}
		pairs++
		got, why := agentdiff.Fold(agentdiff.Compare(a, b))
		if got != agentdiff.OverallNarrows {
			continue
		}
		narrowing++
		for _, f := range why {
			if f == "filesystem" || f == "filesystem protection" {
				refusals++
				break
			}
		}
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			for _, p := range probes {
				before, after := decide.Evaluate(a, p, tier), decide.Evaluate(b, p, tier)
				if rank(p, after) > rank(p, before) {
					t.Fatalf("a change the comparison calls narrowing (%v) lets %s %s through more at %s: %s -> %s (%s)\nbefore:\n%s\nafter:\n%s",
						why, p.Kind, strings.TrimPrefix(p.Path+p.Host, root), tier, before.Verdict, after.Verdict, after.Rule, e.yaml(), f.yaml())
				}
				if rank(p, after) < rank(p, before) {
					strictly++
				}
			}
		}
	}
	t.Logf("%d compiled pairs, %d called narrowing (%d by a file family), %d probes made stricter", pairs, narrowing, refusals, strictly)
	// The floors are proportional to the rounds, so -short holds the property to the same fraction of its stream as the
	// full run: the seed is fixed, the full run's 1800 rounds find 15 pairs narrowing by a file family (81 narrowing in
	// 234 compiled pairs), and its first 300 find 1 (13 in 39). A floor of 10 for both made -short fail on a property
	// that holds, in the public cut test and in `go test -short ./...` of the private tree alike.
	if pairs < rounds/8 || narrowing < pairs/10 || strictly == 0 || refusals < rounds/180 {
		t.Fatalf("the property is vacuous: %s", fmt.Sprint(pairs, narrowing, strictly, refusals))
	}
}

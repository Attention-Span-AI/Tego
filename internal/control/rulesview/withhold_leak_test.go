// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/internal/check/learn"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// proposalText is learn.Proposal.Contract for a run that wrote one file in its folder and connected
// to each of dsts over TCP (the first twice), so Withhold reads the very text the dashboard serves.
func proposalText(t *testing.T, dsts ...string) string {
	t.Helper()
	l := learn.New(learn.Options{Executable: func(string) bool { return true }})
	seq := uint64(0)
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	add := func(kind record.Kind, verdict record.Verdict, payload any) {
		t.Helper()
		e := &record.Event{V: record.Version, Seq: seq, Run: "r-12345678-0aaaaaaaaaaaa-abcdef", Agent: "a", PID: 100,
			TS: t0.Add(time.Duration(seq) * time.Millisecond), Kind: kind, Verdict: verdict}
		seq++
		if err := e.SetPayload(payload); err != nil {
			t.Fatal(err)
		}
		if err := l.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	add(record.KindRunStart, "", record.RunStartPayload{Command: []string{"agent"}, Cwd: "/work/proj", Tier: "observe"})
	add(record.KindFS, record.VerdictObserved, record.FSPayload{Op: record.FSOpen, Path: "/work/proj/out/log.txt", Flags: 0o101})
	for i, d := range dsts {
		add(record.KindNet, record.VerdictObserved, record.NetPayload{Proto: "tcp", Dst: d})
		if i == 0 {
			add(record.KindNet, record.VerdictObserved, record.NetPayload{Proto: "tcp", Dst: d})
		}
	}
	p, err := l.Proposal()
	if err != nil {
		t.Fatal(err)
	}
	return p.Contract()
}

// netAllow parses text as YAML and returns net.allow, failing when it does not parse.
func netAllow(t *testing.T, text string) (net []string, fs, exec []string) {
	t.Helper()
	var c struct {
		FS   struct{ Write []string } `yaml:"fs"`
		Exec struct{ Allow []string } `yaml:"exec"`
		Net  struct{ Allow []string } `yaml:"net"`
	}
	if err := yaml.Unmarshal([]byte(text), &c); err != nil {
		t.Fatalf("not YAML: %v\n%s", err, text)
	}
	return c.Net.Allow, c.FS.Write, c.Exec.Allow
}

// TestWithholdLeakDest (QA PW-1): a proposal made from a run that leaked never allows where the secrets went; the
// address is a comment that says why, the top line warns, and everything else stays as learn wrote it.
func TestWithholdLeakDest(t *testing.T) {
	const sink = "127.0.0.1:8801"
	t.Run("the only item leaves allow: []", func(t *testing.T) {
		in := proposalText(t, sink)
		if !strings.Contains(in, `- "tcp://`+sink+`"  # seen 2 times`) {
			t.Fatalf("fixture lacks the item:\n%s", in)
		}
		out, got := Withhold(in, []string{sink})
		if !slices.Equal(got, []string{sink}) {
			t.Fatalf("withheld %v", got)
		}
		if strings.Contains(out, `- "tcp://`+sink+`"`) {
			t.Fatalf("the sink is still allowed:\n%s", out)
		}
		for _, want := range []string{
			"# WARNING: secrets may have gone to " + sink + ": first reached next to a secret read. The proposal leaves that address out. Review every entry before you use it.\n",
			"\n  allow: []\n    # NOT allowed: \"tcp://" + sink + "\" (seen 2 times): first reached next to a secret read, so secrets may have gone there\n",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in:\n%s", want, out)
			}
		}
		if !strings.HasPrefix(out, "# WARNING") {
			t.Fatalf("warning not on top:\n%s", out)
		}
		net, fs, exec := netAllow(t, out)
		if len(net) != 0 {
			t.Fatalf("net.allow = %v, want none", net)
		}
		_, fs0, exec0 := netAllow(t, in)
		if !slices.Equal(fs, fs0) || !slices.Equal(exec, exec0) || len(fs0) == 0 {
			t.Fatalf("fs %v exec %v changed from %v %v", fs, exec, fs0, exec0)
		}
	})
	t.Run("another item stays", func(t *testing.T) {
		in := proposalText(t, sink, "10.0.0.7:443")
		out, got := Withhold(in, []string{sink})
		if !slices.Equal(got, []string{sink}) {
			t.Fatalf("withheld %v", got)
		}
		net, _, _ := netAllow(t, out)
		if !slices.Equal(net, []string{"tcp://10.0.0.7:443"}) {
			t.Fatalf("net.allow = %v\n%s", net, out)
		}
		if strings.Contains(out, "allow: []") && strings.Count(out, "allow: []") != strings.Count(in, "allow: []") {
			t.Fatalf("a list with an item left became empty:\n%s", out)
		}
	})
	t.Run("two leak dests, both withheld, dests order", func(t *testing.T) {
		in := proposalText(t, "10.0.0.7:443", sink)
		out, got := Withhold(in, []string{sink, "10.0.0.7:443"})
		if !slices.Equal(got, []string{sink, "10.0.0.7:443"}) {
			t.Fatalf("withheld %v", got)
		}
		if !strings.Contains(out, "secrets may have gone to "+sink+", 10.0.0.7:443: first reached next to a secret read. The proposal leaves those addresses out") {
			t.Fatalf("warning:\n%s", out)
		}
		if net, _, _ := netAllow(t, out); len(net) != 0 {
			t.Fatalf("net.allow = %v", net)
		}
	})
	t.Run("no match or no dests: unchanged", func(t *testing.T) {
		in := proposalText(t, sink)
		for _, dests := range [][]string{nil, {}, {"127.0.0.1:9999"}, {"attacker.example:443"}, {"127.0.0.1"}} {
			out, got := Withhold(in, dests)
			if out != in || got != nil {
				t.Fatalf("dests %v changed the text (withheld %v):\n%s", dests, got, out)
			}
		}
	})
	t.Run("fs, exec and comments are never touched", func(t *testing.T) {
		// A dest that only a comment or another section names stays where it is.
		in := "version: 0\nname: x\n# tcp://" + sink + " in a top comment\ncommand: [\"agent\"]\n\nfs:\n  write:\n    - \"tcp://" + sink +
			"\"  # seen once\n\nexec:\n  allow:\n    - \"tcp://" + sink + "\"\n\nnet:\n  # \"tcp://" + sink + "\" in a comment\n  allow:\n    - \"udp://" + sink + "\"  # seen once\n" +
			"  # observed, not allowed: tcp " + sink + " (seen once): x\n\n# limits: none\n"
		out, got := Withhold(in, []string{sink})
		if !slices.Equal(got, []string{sink}) {
			t.Fatalf("withheld %v", got)
		}
		want := "# WARNING: secrets may have gone to " + sink + ": first reached next to a secret read. The proposal leaves that address out. Review every entry before you use it.\n" +
			strings.Replace(in, "  allow:\n    - \"udp://"+sink+"\"  # seen once\n",
				"  allow: []\n    # NOT allowed: \"udp://"+sink+"\" (seen once): first reached next to a secret read, so secrets may have gone there\n", 1)
		if out != want {
			t.Fatalf("got:\n%s\nwant:\n%s", out, want)
		}
	})
	t.Run("an IPv6 address matches as parsed", func(t *testing.T) {
		in := proposalText(t, "[::1]:8801")
		out, got := Withhold(in, []string{"[0:0::1]:8801"})
		if len(got) != 1 || strings.Contains(out, `- "tcp://[::1]:8801"`) {
			t.Fatalf("withheld %v:\n%s", got, out)
		}
	})
	t.Run("one address written two ways is named as dests first writes it", func(t *testing.T) {
		in := proposalText(t, "[::1]:8801")
		out, got := Withhold(in, []string{"[0:0::1]:8801", "[::1]:8801"})
		if !slices.Equal(got, []string{"[0:0::1]:8801"}) || strings.Contains(out, `- "tcp://[::1]:8801"`) {
			t.Fatalf("withheld %v:\n%s", got, out)
		}
	})
	t.Run("a zone is no part of the address learn writes", func(t *testing.T) {
		const dst = "[fe80::1%eth0]:8801"
		in := proposalText(t, dst)
		if !strings.Contains(in, `- "tcp://[fe80::1]:8801"`) {
			t.Fatalf("fixture lacks the item:\n%s", in)
		}
		out, got := Withhold(in, []string{dst})
		if !slices.Equal(got, []string{dst}) || strings.Contains(out, `- "tcp://[fe80::1]:8801"`) {
			t.Fatalf("withheld %v:\n%s", got, out)
		}
	})
}

// TestWithholdCostGrowsWithItsDests: a leak's host name can stand for an address per DNS answer, NeverAllow names each,
// and learn proposes each. Parsing every dest for every item took 16 s at 20,000 addresses, on each request for the
// leak run's least-privilege page, its download and each new agent made from it.
func TestWithholdCostGrowsWithItsDests(t *testing.T) {
	sample := func(n int) func() {
		dests := []string{"evil.example:443"}
		var b strings.Builder
		b.WriteString("version: 0\nname: x\n\nnet:\n  allow:\n")
		for i := range n {
			a := fmt.Sprintf("10.%d.%d.%d:443", i>>16&255, i>>8&255, i&255)
			dests = append(dests, a)
			fmt.Fprintf(&b, "    - \"tcp://%s\"  # seen once\n", a)
		}
		in := b.String()
		return func() {
			out, got := Withhold(in, dests)
			if len(got) != n || got[0] != dests[1] || got[n-1] != dests[n] || !strings.Contains(out, "\n  allow: []\n") {
				t.Errorf("%d addresses: withheld %d", n, len(got))
			}
		}
	}
	const small, large = 1_000, 20_000
	m := testutil.MinOf(testutil.ThreadCPU, 3, sample(small), sample(large))
	t.Logf("%v at %d dests, %v at %d", m[0], small, m[1], large)
	if m[1] > 100*m[0]+10*time.Millisecond {
		t.Errorf("Withhold costs %v at %d dests against %v at %d: its cost grows faster than its dests", m[1], large, m[0], small)
	}
}

// TestWithholdKeepsTheAddressWordTrue: learn's header warns that the proposal allows addresses, not host names. When
// Withhold comments out the last address, that line goes with it; while one is left, it stays.
func TestWithholdKeepsTheAddressWordTrue(t *testing.T) {
	const sink, api = "127.0.0.1:8801", "203.0.113.9:443"
	const warning = "# WARNING: net.allow has entries that are addresses, not host names"
	in := proposalText(t, sink)
	if !strings.Contains(in, warning) {
		t.Fatalf("learn's proposal of an address lacks the address warning:\n%s", in)
	}
	out, _ := Withhold(in, []string{sink})
	if strings.Contains(out, "not host names") {
		t.Errorf("the address warning is left after the last address was withheld:\n%s", out)
	}
	out, _ = Withhold(proposalText(t, sink, api), []string{sink})
	if !strings.Contains(out, warning) {
		t.Errorf("the address warning went while %s is still allowed:\n%s", api, out)
	}
}

// TestWithholdPutsTheResolverBack: learn leaves the machine's resolver out beside a TCP or UDP entry, since Landlock
// grants port 53 beside one (learn keepResolvers). When Withhold comments out the last such entry, the resolver goes
// back in as learn would have kept it; while one is left, it stays out (review M1 of 2026-11-11).
func TestWithholdPutsTheResolverBack(t *testing.T) {
	const sink, api, resolver = "203.0.113.66:443", "203.0.113.9:443", "udp://10.0.2.3:53"
	text := func(dsts ...string) string {
		t.Helper()
		l := learn.New(learn.Options{Executable: func(string) bool { return true }, LeaveLeaksToCaller: true})
		t0 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
		var seq uint64
		add := func(kind record.Kind, rule string, payload any) {
			t.Helper()
			e := &record.Event{V: record.Version, Seq: seq, Run: "r-12345678-0aaaaaaaaaaaa-abcdef", Agent: "a", PID: 100,
				TS: t0.Add(time.Duration(seq) * time.Millisecond), Kind: kind, Rule: rule, Source: record.SourceSupervisor}
			if kind != record.KindRunStart {
				e.Verdict = record.VerdictObserved
			}
			seq++
			if err := e.SetPayload(payload); err != nil {
				t.Fatal(err)
			}
			if err := l.Add(e); err != nil {
				t.Fatal(err)
			}
		}
		add(record.KindRunStart, "", record.RunStartPayload{Command: []string{"agent"}, Cwd: "/work/proj", Tier: "observe"})
		add(record.KindNet, "unmatched", record.NetPayload{Proto: "unix", Dst: "unix:/var/run/nscd/socket"})
		add(record.KindNet, "net.resolver", record.NetPayload{Proto: "udp", Dst: "10.0.2.3:53", Host: "10.0.2.3"})
		for _, d := range dsts {
			add(record.KindNet, "unmatched", record.NetPayload{Proto: "tcp", Dst: d})
		}
		p, err := l.Proposal()
		if err != nil {
			t.Fatal(err)
		}
		return p.Contract()
	}
	in := text(sink)
	if got, _, _ := netAllow(t, in); slices.Contains(got, resolver) {
		t.Fatalf("learn kept the resolver beside a TCP entry:\n%s", in)
	}
	out, held := Withhold(in, []string{sink})
	got, _, _ := netAllow(t, out)
	if !slices.Equal(held, []string{sink}) || !slices.Equal(got, []string{resolver, "unix:/var/run/nscd/socket"}) && !slices.Equal(got, []string{"unix:/var/run/nscd/socket", resolver}) {
		t.Errorf("withheld %q, net.allow = %q, want the resolver back beside the socket:\n%s", held, got, out)
	}
	if strings.Contains(out, "# left out: "+resolver) {
		t.Errorf("the resolver is back and still called left out:\n%s", out)
	}
	out, _ = Withhold(text(sink, api), []string{sink})
	if got, _, _ := netAllow(t, out); slices.Contains(got, resolver) {
		t.Errorf("the resolver is back while %s is still allowed: %q\n%s", api, got, out)
	}
}

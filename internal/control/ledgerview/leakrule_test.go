// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/learn"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLeakRuleAgreesWithTheVerdict: tego learn's leak rule and the dashboard's verdict read the same lines and name
// the same destinations, so the terminal and the page say the same of one run (QA PW-1). It is here because the
// verdict may import learn's package in a test, and learn may not import this one.
func TestLeakRuleAgreesWithTheVerdict(t *testing.T) {
	const (
		key   = `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/home/u/.ssh/id_rsa"`
		plain = `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/usr/lib/x.py"`
		sink  = `"rule":"unmatched","verdict":"observed","dst":"203.0.113.9:443","proto":"tcp"`
	)
	type ln struct{ kind, extra string }
	pad := func(n int) []ln { return slices.Repeat([]ln{{"fs", plain}}, n) }
	cases := []struct {
		name  string
		lines []ln
		want  []string
	}{
		{"a read, then a send", []ln{{"fs", key}, {"net", sink}}, []string{"203.0.113.9:443"}},
		{"a send, then a read", []ln{{"net", sink}, {"fs", key}}, []string{"203.0.113.9:443"}},
		{"too far apart", slices.Concat([]ln{{"fs", key}}, pad(16), []ln{{"net", sink}}), nil},
		{"two places", []ln{{"fs", key}, {"net", sink}, {"net", `"rule":"unmatched","verdict":"observed","dst":"198.51.100.4:80","proto":"tcp"`}},
			[]string{"203.0.113.9:443", "198.51.100.4:80"}},
		{"the contract names it", []ln{{"fs", key}, {"net", `"rule":"net[203.0.113.9:443]","verdict":"allow","dst":"203.0.113.9:443","proto":"tcp"`}}, nil},
		{"by name and address", []ln{{"fs", key}, {"net", `"rule":"unmatched","verdict":"observed","dst":"203.0.113.9:443","host":"evil.example","proto":"tcp"`}}, []string{"evil.example:443"}},
		{"by name alone", []ln{{"fs", key}, {"net", `"rule":"unmatched","verdict":"observed","dst":"evil.example:443","host":"evil.example","proto":"tcp"`}}, []string{"evil.example:443"}},
		// Port 53 is a lookup on this machine, or where the engine named a resolver; elsewhere it is a send to both.
		{"the resolver", []ln{{"fs", key}, {"net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.53:53","proto":"udp"`}}, nil},
		{"a resolver the engine named", []ln{{"fs", key}, {"net", `"rule":"net.resolver","verdict":"allow","dst":"10.0.0.2:53","proto":"udp"`}}, nil},
		{"port 53 elsewhere", []ln{{"fs", key}, {"net", `"rule":"unmatched","verdict":"observed","dst":"203.0.113.9:53","proto":"tcp"`}}, []string{"203.0.113.9:53"}},
		{"nscd", []ln{{"fs", key}, {"net", `"rule":"unmatched","verdict":"observed","dst":"unix:/var/run/nscd/socket","proto":"unix"`}}, nil},
		{"a refused read", []ln{{"refused", `"rule":"fs.deny_read[/home/u/.ssh/]","reason":"read-denied","op":"open","target":"/home/u/.ssh/id_rsa"`}, {"net", sink}}, nil},
		{"a refused send", []ln{{"fs", key}, {"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`}}, nil},
		{"a guarded read, then a send", []ln{{"fs", `"rule":"fs.ask_read[/p/plan.txt]","verdict":"allow","op":"open","flags":0,"path":"/p/plan.txt"`}, {"net", sink}}, []string{"203.0.113.9:443"}},
		{"a re-read, then a send", slices.Concat([]ln{{"fs", key}}, pad(30), []ln{{"fs", key}, {"net", sink}}), []string{"203.0.113.9:443"}},
		{"a send, then a re-read", slices.Concat([]ln{{"fs", key}}, pad(30), []ln{{"net", sink}, {"fs", key}}), []string{"203.0.113.9:443"}},
		{"asked, read later, then a send", slices.Concat([]ln{{"ask", `"ask_id":"q-1","ask_rule":"fs.ask_read[/p/]","hold":"open","op":"read","target":"/home/u/.ssh/id_rsa"`}}, pad(30), []ln{{"fs", key}, {"net", sink}}), []string{"203.0.113.9:443"}},
		{"a failed open, then a send", []ln{{"fs", `"rule":"unmatched","verdict":"observed","op":"open","errno":2,"path":"/home/u/.ssh/id_rsa"`}, {"net", sink}}, nil},
		{"a create, then a send", []ln{{"fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":577,"path":"/work/server.key"`}, {"net", sink}}, nil},
		{"an unlink, then a send", []ln{{"fs", `"rule":"unmatched","verdict":"observed","op":"unlink","path":"/home/u/.ssh/id_rsa"`}, {"net", sink}}, nil},
		{"a failed open next to the send, the read far from it", slices.Concat([]ln{{"fs", `"rule":"unmatched","verdict":"observed","op":"open","errno":2,"path":"/home/u/.ssh/id_rsa"`}, {"net", sink}}, pad(30), []ln{{"fs", key}}), nil},
		{"a refused read next to the send, the read far from it", slices.Concat([]ln{{"refused", `"rule":"fs.deny_read[/home/u/.ssh/]","reason":"read-denied","op":"open","target":"/home/u/.ssh/id_rsa"`}, {"net", sink}}, pad(30), []ln{{"fs", key}}), nil},
		{"an ask, then a send", []ln{{"ask", `"ask_id":"q-1","ask_rule":"fs.ask_read[/p/]","hold":"open","op":"read","target":"/home/u/.ssh/id_rsa"`}, {"net", sink}}, nil},
	}
	const id = "r-12345678-0aaaaaaaaaaaa-abcdef"
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text := []string{line(id, "watch-a", 0, t0, "run_start", `"tier":"observe","command":["a"],"cwd":"/p"`)}
			for i, l := range c.lines {
				text = append(text, line(id, "watch-a", i+1, t0.Add(time.Duration(i+1)*time.Millisecond), l.kind, l.extra))
			}
			root := t.TempDir()
			writeRun(t, root, id, text...)
			r, err := LoadRun(root, id)
			if err != nil {
				t.Fatal(err)
			}
			v := RunVerdict(r, Signal(r, Sensitive{Cwd: r.Cwd}))

			l := learn.New(learn.Options{Executable: func(string) bool { return true }})
			for _, s := range text {
				e, err := record.Decode([]byte(strings.TrimSuffix(s, "\n")))
				if err != nil {
					t.Fatal(err)
				}
				if err := l.Add(e); err != nil {
					t.Fatal(err)
				}
			}
			p, err := l.Proposal()
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, lk := range p.Leaks {
				got = append(got, lk.Dest)
			}
			var page []string
			if v.Kind == VerdictLeak {
				page = v.Dests
			}
			// The page orders by closeness to the secret and learn by first contact: the set is the promise.
			a, b, want := slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(page)), slices.Sorted(slices.Values(c.want))
			if !slices.Equal(a, b) {
				t.Errorf("learn says %v, the page says %v (kind %s)", got, page, v.Kind)
			}
			if !slices.Equal(a, want) {
				t.Errorf("learn says %v, want %v", got, c.want)
			}
		})
	}
}

// TestVerdictSaysReadOnlyOfAFileRead: a watched run whose only secret line failed read no secret, as its receipt says,
// and one with a read of the file says it read one.
func TestVerdictSaysReadOnlyOfAFileRead(t *testing.T) {
	const id = "r-12345678-0aaaaaaaaaaaa-abcdef"
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name, extra string
		read        []string
	}{
		{"a failed open", `"rule":"unmatched","verdict":"observed","op":"open","errno":2,"path":"/home/u/.ssh/id_rsa"`, nil},
		{"an unlink", `"rule":"unmatched","verdict":"observed","op":"unlink","path":"/home/u/.ssh/id_rsa"`, nil},
		{"a read", `"rule":"unmatched","verdict":"observed","op":"open","path":"/home/u/.ssh/id_rsa"`, []string{"/home/u/.ssh/id_rsa"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeRun(t, root, id, line(id, "watch-a", 0, t0, "run_start", `"tier":"observe","command":["a"],"cwd":"/p"`),
				line(id, "watch-a", 1, t0.Add(time.Millisecond), "fs", c.extra))
			r, err := LoadRun(root, id)
			if err != nil {
				t.Fatal(err)
			}
			if v := RunVerdict(r, Signal(r, Sensitive{Cwd: r.Cwd})); !slices.Equal(v.Read, c.read) {
				t.Errorf("read %v, want %v (kind %s)", v.Read, c.read, v.Kind)
			}
		})
	}
}

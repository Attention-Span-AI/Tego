// SPDX-License-Identifier: Apache-2.0

package ledgerview

import "testing"

// A destination that was only ever refused has no net line to carry its host: the refused line is all the ledger
// holds. The Host filter and the Host facet must find it whatever the refusal's reason, not only the net-* ones
// (a first delivery a person denied or that timed out is refused with ask-denied or ask-timeout).
func TestHostFilterFindsRefusedOnlyDestinations(t *testing.T) {
	root := t.TempDir()
	const run = "r-aaaa-0003-hostrf"
	writeRun(t, root, run,
		qline(run, "alpha", 0, 0, 100, "run_start", "supervisor", `"tier":"landlock","command":["codex"],"cwd":"/w/x/proj"`),
		qline(run, "alpha", 1, 1, 101, "refused", "supervisor", `"rule":"net.ask[x]","reason":"ask-denied","op":"first_write","target":"203.0.113.9:443"`),
		qline(run, "alpha", 2, 2, 101, "refused", "supervisor", `"rule":"net.ask[y]","reason":"ask-timeout","op":"connect","target":"Example.org:8443"`),
		qline(run, "alpha", 3, 3, 102, "refused", "supervisor", `"rule":"fs.deny_read[x]","reason":"read-denied","op":"open","target":"secret"`),
		qline(run, "alpha", 4, 4, 100, "run_end", "supervisor", `"reason":"exit","exit_code":0`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host string
		want int
	}{{"203.0.113.9", 1}, {"example.org", 1}, {"secret", 0}} {
		pg := s.Query(Filter{Hosts: []string{c.host}, Kinds: []string{"refused"}})
		if pg.Matched != c.want {
			t.Errorf("host:%s kind:refused matched %d, want %d", c.host, pg.Matched, c.want)
		}
	}
	// The search with no kind lists these lines too: they are no action's mirror.
	if pg := s.Query(Filter{Hosts: []string{"203.0.113.9"}}); pg.Matched != 1 {
		t.Errorf("host:203.0.113.9 matched %d, want 1", pg.Matched)
	}
	pg := s.Query(Filter{Facets: true})
	got := map[string]int{}
	for _, v := range pg.Facets.Host.Values {
		got[v.Value] = v.Count
	}
	if got["203.0.113.9"] != 1 || got["example.org"] != 1 || len(got) != 2 {
		t.Errorf("Host facet = %v, want the two refused-only destinations", got)
	}
}

// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"testing"
)

// TestGroupRuleKeepsObservedLinesApart (PW-3): By rule gathers a rule's lines that nothing decided (verdict observed)
// apart from the lines it decided. A watched run's read under the contract's deny_read entry is not counted with the
// enforced run's refusal by that entry, and its group is marked watched; an enforced run's own observed lines are
// apart too, but not watched, and a group holding both is not watched either. Each rule group is what its rule and
// verdict name in a query, so its count is the lines its link lists.
func TestGroupRuleKeepsObservedLinesApart(t *testing.T) {
	root := t.TempDir()
	const watched, enforced = "r-aaaa-0005-watchx", "r-aaaa-0006-enforx"
	deny := `"rule":"fs.deny_read[~/.ssh]","authority":"rule","op":"open","path":"/w/x/home/.ssh/id_rsa","flags":0`
	writeRun(t, root, watched,
		qline(watched, "watch-codex", 0, 0, 300, "run_start", "supervisor", `"tier":"observe","command":["codex"],"cwd":"/w/x/proj"`),
		qline(watched, "watch-codex", 1, 1, 301, "fs", "supervisor", `"verdict":"observed",`+deny),
		qline(watched, "watch-codex", 2, 2, 301, "net", "supervisor", `"verdict":"observed","rule":"unmatched","authority":"rule","proto":"tcp","dst":"127.0.0.1:8802"`),
		qline(watched, "watch-codex", 3, 3, 300, "run_end", "supervisor", `"reason":"exit","exit_code":0`))
	writeRun(t, root, enforced,
		qline(enforced, "codex", 0, 0, 400, "run_start", "supervisor", `"tier":"landlock","command":["codex"],"cwd":"/w/x/proj"`),
		qline(enforced, "codex", 1, 1, 401, "fs", "supervisor", `"verdict":"refused","reason":"read-denied",`+deny),
		qline(enforced, "codex", 2, 1, 401, "refused", "supervisor", `"rule":"fs.deny_read[~/.ssh]","reason":"read-denied","op":"open","target":"/w/x/home/.ssh/id_rsa"`),
		qline(enforced, "codex", 3, 2, 402, "net", "supervisor", `"verdict":"refused","rule":"unmatched","authority":"rule","reason":"net-not-allowed","proto":"tcp","dst":"127.0.0.1:8802"`),
		qline(enforced, "codex", 4, 3, 402, "refused", "supervisor", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"127.0.0.1:8802"`),
		qline(enforced, "codex", 5, 4, 403, "net", "supervisor", `"verdict":"observed","rule":"unmatched","proto":"tcp","dst":"10.0.0.9:443"`),
		qline(enforced, "codex", 6, 5, 403, "fs", "supervisor", `"verdict":"observed","rule":"path-unreliable","authority":"rule","op":"open","path":"/w/x/proj/a","flags":0`),
		qline(enforced, "codex", 7, 6, 400, "run_end", "supervisor", `"reason":"exit","exit_code":0`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	g := s.Group(Filter{}, GroupRule, 0, nil)
	find := func(rule string, observed bool) *GroupRow {
		i := slices.IndexFunc(g.Rows, func(r GroupRow) bool { return r.Rule == rule && r.Observed == observed })
		if i < 0 {
			t.Fatalf("no group of %s (observed %v) in %+v", rule, observed, g.Rows)
		}
		return &g.Rows[i]
	}
	type grp struct {
		lines, refused int
		watched, split bool
		run            string
	}
	for _, c := range []struct {
		rule     string
		observed bool
		want     grp
	}{
		// The enforced run's refusal is the deny_read entry's own group; the watched run's read under it is apart.
		{"fs.deny_read[~/.ssh]", false, grp{1, 1, false, true, enforced}},
		{"fs.deny_read[~/.ssh]", true, grp{1, 0, true, true, watched}},
		// unmatched decided one connection (refused); the watched send and the enforced run's recorded connection it
		// decided nothing about, and one of them is not of a watched run.
		{"unmatched", false, grp{1, 1, false, true, enforced}},
		{"unmatched", true, grp{2, 0, false, true, ""}},
		// An enforced run's line its rule only names is apart, and not watched.
		{"path-unreliable", true, grp{1, 0, false, false, enforced}},
	} {
		row := find(c.rule, c.observed)
		got := grp{row.Lines, row.Refused, row.Watched, row.Split, row.Run}
		if got != c.want {
			t.Errorf("%s (observed %v): %+v, want %+v", c.rule, c.observed, got, c.want)
		}
		f := Filter{Rules: []string{c.rule}}
		switch {
		case c.observed:
			f.Verdicts = []string{"observed"}
		case row.Split:
			f.Not.Verdicts = []string{"observed"}
		}
		if n := s.Query(f).Matched; n != row.Lines {
			t.Errorf("%s (observed %v): rule and verdict name %d lines, the group holds %d", c.rule, c.observed, n, row.Lines)
		}
	}
	if row := find("", false); row.Observed || row.Watched || row.Split || row.Lines != 4 {
		t.Errorf("the lines no rule names (runs' starts and ends): %+v", row)
	}
	sum := g.Keyless
	for _, row := range g.Rows {
		sum += row.Lines
	}
	if m := s.Query(Filter{}).Matched; sum != m || g.Matched != m {
		t.Errorf("the groups hold %d lines (Matched %d), the search %d", sum, g.Matched, m)
	}
	// One run alone: its observed lines are still apart, and nothing beside them splits the rule.
	one := s.Group(Filter{Runs: []string{watched}}, GroupRule, 0, nil)
	for _, row := range one.Rows {
		if row.Rule != "" && (!row.Observed || !row.Watched || row.Split || row.Run != watched) {
			t.Errorf("the watched run alone: %+v", row)
		}
	}
	if again := s.Group(Filter{}, GroupRule, 0, nil); !slices.Equal(again.Rows, g.Rows) {
		t.Errorf("a second call (the runs' cached groups) differs:\n%+v\n%+v", again.Rows, g.Rows)
	}
}

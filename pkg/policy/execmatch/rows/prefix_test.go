// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"sort"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// defaultLevel is one level of a row that runs a default subcommand when none is named, with the subcommand words
// that reach it, the default, and another subcommand of the level.
type defaultLevel struct {
	row          *execmatch.Row
	path         []string
	def, sibling string
}

// defaultLevels lists every level of every built-in row that has a Default, in a stable order.
func defaultLevels() []defaultLevel {
	var out []defaultLevel
	var walk func(r *execmatch.Row, lv *execmatch.Level, path []string)
	walk = func(r *execmatch.Row, lv *execmatch.Level, path []string) {
		if lv == nil || lv.Subs == nil {
			return
		}
		names := make([]string, 0, len(lv.Subs))
		for n := range lv.Subs {
			names = append(names, n)
		}
		sort.Strings(names)
		if lv.Default != "" {
			for _, n := range names {
				if n != lv.Default {
					out = append(out, defaultLevel{row: r, path: append([]string(nil), path...), def: lv.Default, sibling: n})
					break
				}
			}
		}
		for _, n := range names {
			walk(r, lv.Subs[n], append(append([]string(nil), path...), n))
		}
	}
	for _, r := range Builtin().All() {
		walk(r, r.Root, nil)
	}
	return out
}

// TestPrefixEndEntersNoDefault is ADR 0048 (3)'s staged read on every row level with a default subcommand: a vector
// cut right after the level's word (git stash, git reflog, git notes, git submodule) is not that level's default.
// The prefix reading stays at the level, not Located, so a deny entry naming another subcommand of the level and an
// allow entry naming the default both ask for more argv instead of settling on the prefix; the whole vector then
// decides each.
func TestPrefixEndEntersNoDefault(t *testing.T) {
	levels := defaultLevels()
	if len(levels) == 0 {
		t.Fatal("no row level has a default subcommand: the table this test walks is gone")
	}
	for _, d := range levels {
		name := d.row.Tool + " " + strings.Join(d.path, " ")
		nz := execmatch.NewNormalizer(d.row, nil)
		for _, r := range nz.NormalizeOpen(d.path, true) {
			if r.Located || len(r.Path) > len(d.path) {
				t.Errorf("%s cut after the level: reading %v located %v, want the level itself and not located", name, r.Path, r.Located)
			}
		}
		if rs := nz.Normalize(d.path); len(rs) == 0 || len(rs[0].Path) != len(d.path)+1 || rs[0].Path[len(d.path)] != d.def {
			t.Errorf("%s as a whole vector: readings %v, want the default %s", name, rs, d.def)
		}
		prefix := append([]string{d.row.Tool}, d.path...)
		whole := append(append([]string(nil), prefix...), d.sibling)
		deny := rules(t, "deny: "+name+" "+d.sibling)
		allow := rules(t, "allow: "+name+" "+d.def)
		for _, c := range []struct {
			list string
			ix   *execmatch.Index
		}{{"deny", deny}, {"allow", allow}} {
			f := execmatch.Facts{Requested: d.row.Tool, Image: d.row.Tool, Argv0: d.row.Tool, Argv: prefix}
			if r := c.ix.Decide(&f); r.Final {
				t.Errorf("%s, %s entry, vector cut after the level: %s settled on the prefix", name, c.list, decided(r))
			}
			f.Argv, f.ArgvComplete = whole, true
			if r := c.ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
				t.Errorf("%s, %s entry, whole vector ending in %s: %s, want refused", name, c.list, d.sibling, decided(r))
			}
		}
	}
}

// TestPrefixStashDrop is the probe that found the staged read's fail-open: git with 15 `-c a.b=c` pairs and then
// `stash drop` is 33 elements, so the 32-element prefix ends at stash. That prefix is not `stash push`: deny: [git
// stash drop] and allow: [git stash push] both read on, and deny: [git reflog expire] the same at reflog.
func TestPrefixStashDrop(t *testing.T) {
	long := func(sub ...string) []string {
		argv := []string{"git"}
		for range 15 {
			argv = append(argv, "-c", "a.b=c")
		}
		return append(argv, sub...)
	}
	for _, c := range []struct {
		entry string
		sub   []string
	}{
		{"deny: git stash drop", []string{"stash", "drop"}},
		{"allow: git stash push", []string{"stash", "drop"}},
		{"deny: git reflog expire", []string{"reflog", "expire"}},
		{"deny: git notes remove", []string{"notes", "remove"}},
		{"deny: git submodule deinit", []string{"submodule", "deinit"}},
	} {
		ix := rules(t, c.entry)
		whole := long(c.sub...)
		f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: whole[:32]}
		if r := ix.Decide(&f); r.Final {
			t.Errorf("%s on the 32-element prefix of %v: %s settled", c.entry, c.sub, decided(r))
		}
		f.Argv, f.ArgvComplete = whole, true
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
			t.Errorf("%s on the whole vector of %v: %s, want refused", c.entry, c.sub, decided(r))
		}
	}
}

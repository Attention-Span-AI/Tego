// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// TestHitCountsDoNotDependOnTheTextOfALine (C150): a rule's hits are what the record holds, however the line spells
// it. The same eight lines are written canonically and then in other spellings the decoder reads alike: the nested
// attribution before the rule, spaces around the colons, an escaped key and an escaped value, the command entry's
// fields in another order. The scan of the ledger and the read model's count (which decodes every line) must agree on
// each, and give the canonical count. A count that searched the line's text for `"rule":"` before its first nested
// object lost every one of the reordered lines.
func TestHitCountsDoNotDependOnTheTextOfALine(t *testing.T) {
	const attr = `"attribution":{"confidence":"unattributed","method":"none"}`
	fsLine := func(ruleMember string) string {
		return `"kind":"fs","source":"landlock",` + ruleMember + `"verdict":"allow","authority":"rule",` + attr + `,"op":"write","path":"/p/out/f"`
	}
	f := newFixtureWith(t, "r-aaaaaaaa-0000000000150-ctext1", hitsText, "")
	// Canonical: the rule is the common field before the attribution.
	f.add(fsLine(`"rule":"fs.write[./out/]",`))
	// The attribution (a nested object) comes before the rule.
	f.add(`"kind":"fs","source":"landlock",` + attr + `,"rule":"fs.write[./out/]","verdict":"allow","authority":"rule","op":"write","path":"/p/out/f"`)
	// Spaces around the colons, in the key and the value of the rule.
	f.add(`"kind" : "fs","source":"landlock","rule" : "fs.write[./out/]","verdict":"allow","authority":"rule",` + attr + `,"op":"write","path":"/p/out/f"`)
	// The key spelled with an escape.
	f.add(`"kind":"fs","source":"landlock","ru\u006ce":"fs.write[./out/]","verdict":"allow","authority":"rule",` + attr + `,"op":"write","path":"/p/out/f"`)
	// The value spelled with an escape.
	f.add(`"kind":"fs","source":"landlock","rule":"fs.write[./out\/]","verdict":"allow","authority":"rule",` + attr + `,"op":"write","path":"/p/out/f"`)
	// An exec line whose command entry's fields come in another order and with spaces, and the rule after them.
	f.add(`"kind":"exec","source":"seccomp","command_list" : "allow","command_rule" : "git status","rule":"exec[git]","verdict":"allow","authority":"rule","argv":["git","x"],"exec_id":"x/10/1","path":"/usr/bin/git"`)
	f.add(`"kind":"exec","source":"seccomp",` + attr + `,"command_rule":"git status","command_list":"allow","rule":"exec[git]","verdict":"allow","authority":"rule","argv":["git","x"],"exec_id":"x/10/2","path":"/usr/bin/git"`)
	f.add(execLine("3", "git status"))
	f.inForce(t) // writes the ledger
	dir := filepath.Join(f.root, f.run)
	scanned, err := scanRun(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ledgerview.Open(f.root).Run(f.run)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := cachedScan(dir, r)
	if err != nil {
		t.Fatal(err)
	}
	for name, sc := range map[string]*runScan{"ledger scan": scanned, "read model": cached} {
		if n := sc.rules["fs.write[./out/]"]; n != 5 {
			t.Errorf("%s: fs.write[./out/] has %d hits, want 5 (every spelling of the rule counts)", name, n)
		}
		if n := sc.rules["exec[git]"]; n != 3 {
			t.Errorf("%s: exec[git] has %d hits, want 3", name, n)
		}
		if n := sc.commands["git status"]; n != 3 {
			t.Errorf("%s: command entry \"git status\" has %d hits, want 3 (every field order and spacing counts)", name, n)
		}
	}
	for name, v := range both(t, f) {
		if r := rule(t, v, "fs.write", "./out/"); r.Hits != 5 {
			t.Errorf("%s: the view's fs.write ./out/ has %d hits, want 5", name, r.Hits)
		}
		if r := rule(t, v, "exec.allow", "git status"); r.Hits != 3 {
			t.Errorf("%s: the view's exec.allow \"git status\" has %d hits, want 3", name, r.Hits)
		}
	}
}

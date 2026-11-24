// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestPlaneKeysNoOtherName (ADR 0011, amended 2026-11-19, round 5): the entries compile adds for another name the mount
// table gives a file (FSRule.AliasOf: a write entry's, a deny_read entry's and a deny_write target's) are that file's
// inode, which the original entry's row keys, and the plane decides by inode. They key no row of their own: the plane
// keys one row per inode, and a second row of one inode is a table its fill refuses (ErrPlaneSharedInode), which would
// refuse every root-tier run on a machine with a bind of the home (or WSLg's /mnt/wslg/distro).
func TestPlaneKeysNoOtherName(t *testing.T) {
	rt := &agent.RuleTable{
		FS: []agent.FSRule{
			{Path: "/p/w", Resolved: "/p/w", Kind: agent.FSWrite, Access: agent.AccessWriteSet, Raw: "/p/w/"},
			{Path: "/p/w/secret", Resolved: "/p/w/secret", Kind: agent.FSDenyRead, Raw: "/p/w/secret/", Unenforced: true},
			{Path: "/alias/w", Resolved: "/alias/w", Kind: agent.FSWrite, Access: agent.AccessWriteSet, Raw: "/p/w/", AliasOf: "/p/w"},
			{Path: "/alias/w/secret", Resolved: "/alias/w/secret", Kind: agent.FSDenyRead, Raw: "/p/w/secret/", Unenforced: true,
				AliasOf: "/p/w/secret"},
		},
		DenyWrite: []agent.FSRule{
			{Path: "/p/w/locked", Resolved: "/p/w/locked", Kind: agent.FSDenyWrite, Raw: "/p/w/locked", Unenforced: true},
			{Path: "/alias/w/locked", Resolved: "/alias/w/locked", Kind: agent.FSDenyWrite, Raw: "/p/w/locked", Unenforced: true,
				AliasOf: "/p/w/locked"},
		},
	}
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, r := range s.FS {
		have[r.Path] = true
	}
	for _, p := range []string{"/p/w", "/p/w/secret", "/p/w/locked"} {
		if !have[p] {
			t.Errorf("no row keys %s: %v", p, s.FS)
		}
	}
	for _, p := range []string{"/alias/w", "/alias/w/secret", "/alias/w/locked", "/alias"} {
		if have[p] {
			t.Errorf("a row keys %s, another name of a file an entry's row keys: %v", p, s.FS)
		}
	}
}

// TestHeldReadFloorUnderAnOtherName (ADR 0011, amended 2026-11-19, round 5; review F2): a file a name rule covers that
// is made during the run (a .env beneath a scan root, a file a declared deny_read glob matches) is refused by the
// held-read floor under every other name the mount table gives the rule's scope root (Reads.Aliases), under the rule's
// own name; a path under no alias, and a name no rule covers, are not.
func TestHeldReadFloorUnderAnOtherName(t *testing.T) {
	rt := &agent.RuleTable{}
	rt.Reads.Mode = agent.ReadsHeld
	rt.Reads.Names = agent.BuiltInEnvEntries([]agent.NameScope{{Canonical: "/p", Spelling: "/p"}})
	rt.Reads.Patterns = []agent.DenyReadPattern{{Pattern: "/p/secrets/*.pem", Rule: "fs.deny_read[/p/secrets/*.pem]"}}
	rt.Reads.Aliases = []agent.NameAlias{{Alias: "/mnt/wslg/distro/p", Original: "/p"}, {Alias: "/srv/sub", Original: "/p/sub"}}
	x := NewHeldReadIndex(rt)
	for _, c := range []struct {
		path, rule string
	}{
		{"/p/sub/.env", "fs.deny_read[/p/**/.env]"},
		{"/mnt/wslg/distro/p/sub/.env", "fs.deny_read[/p/**/.env]"},
		{"/srv/sub/deeper/.env", "fs.deny_read[/p/**/.env]"},
		{"/mnt/wslg/distro/p/secrets/new.pem", "fs.deny_read[/p/secrets/*.pem]"},
		{"/p/secrets/new.pem", "fs.deny_read[/p/secrets/*.pem]"},
	} {
		rule, refused := x.Refusal(nil, c.path, false)
		if !refused || rule != c.rule {
			t.Errorf("%s: refused=%v by %q; want refused by %q", c.path, refused, rule, c.rule)
		}
	}
	for _, p := range []string{"/mnt/wslg/distro/p/notes.txt", "/elsewhere/.env", "/mnt/wslg/distro/px/.env"} {
		if rule, refused := x.Refusal(nil, p, false); refused {
			t.Errorf("%s: refused by %q; want allowed", p, rule)
		}
	}
}

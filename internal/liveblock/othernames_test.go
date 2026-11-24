// SPDX-License-Identifier: Apache-2.0

package liveblock

import "testing"

// TestSetMatchesEveryOtherName (ADR 0011, amended 2026-11-19, round 5; review F7): a path, read or write block refuses
// its file under every other name the mount table gave it when the block was added (Resolved.Others, from
// agent.OtherNames: a bind of the home, WSLg's /mnt/wslg/distro), under the value's own rule, beneath each name, and a
// rename of a folder above one carries it; names of the block's Real are taken too. A sibling sharing a prefix is not
// refused, and with no other names the block refuses its own names alone.
func TestSetMatchesEveryOtherName(t *testing.T) {
	for _, k := range []Kind{KindPath, KindRead, KindWrite} {
		t.Run(string(k), func(t *testing.T) {
			e := Entry{Kind: k, Value: "/home/u/notes", Real: "/data/notes", By: "uid:1 pid:2 cli", At: t0}
			res := Resolved{Others: map[string][]string{
				"/home/u/notes": {"/mnt/wslg/distro/home/u/notes", "/srv/u/notes"},
				"/data/notes":   {"/mnt/wslg/distro/data/notes"},
			}}
			s := CompileEntries([]Entry{e}, 1, res)
			acc := k.Access()
			for _, p := range []string{"/mnt/wslg/distro/home/u/notes", "/mnt/wslg/distro/home/u/notes/a.txt", "/srv/u/notes/b/c",
				"/mnt/wslg/distro/data/notes/d"} {
				got, ok := s.MatchPath(p, acc)
				if !ok || got.Rule() != Rule(k, e.Value) {
					t.Errorf("MatchPath(%q) = %v %q, want the value's rule %q", p, ok, got.Rule(), Rule(k, e.Value))
				}
			}
			if _, ok := s.MatchPath("/srv/u/notesy", acc); ok {
				t.Error("a sibling sharing a prefix of another name is refused")
			}
			if _, ok := s.MatchWithin("/srv/u", acc); !ok {
				t.Error("MatchWithin(/srv/u): a rename above another name of the block is not caught")
			}
			if _, ok := CompileEntries([]Entry{e}, 1, Resolved{}).MatchPath("/srv/u/notes", acc); ok {
				t.Error("with no other names given, another spelling is refused")
			}
			e.Fence = true
			if n := CompileEntries([]Entry{e}, 1, res).Fenced(); n != 1 {
				t.Errorf("Fenced %d: a fence refusal with other names counts once", n)
			}
		})
	}
}

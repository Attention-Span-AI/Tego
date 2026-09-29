// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// A generated cross-check of Evaluate (compile --test), FSDecider (tier 3 and the recorder's
// chooser) and the tier-2 listener's decideOpen, over every table of up to three entries drawn from a pool
// that includes a symlinked spelling (/l -> /w/a), and every path of a small universe, canonical and through
// the link. Tables Compile refuses (a write and a deny_read on one resolved path, a write covering an
// implicit entry) are skipped; Unenforced is stamped as Compile stamps it.

type r4Entry struct {
	kind          agent.FSKind
	path, resolve string
}

var r4Pool = func() []r4Entry {
	var out []r4Entry
	paths := [][2]string{{"/w", ""}, {"/w/a", ""}, {"/w/a/b", ""}, {"/w/a/b/c", ""}, {"/x", ""}, {"/l", "/w/a"}, {"/l/b", "/w/a/b"}}
	for _, k := range []agent.FSKind{agent.FSWrite, agent.FSDenyRead, agent.FSWatch, agent.FSImplicit} {
		for _, p := range paths {
			out = append(out, r4Entry{k, p[0], p[1]})
		}
	}
	return out
}()

func r4Res(e r4Entry) string {
	if e.resolve != "" {
		return e.resolve
	}
	return e.path
}

func r4Under(anc, p string) bool { return anc == p || strings.HasPrefix(p, anc+"/") }

func r4Table(es []r4Entry) (*agent.RuleTable, bool) {
	var fs []agent.FSRule
	for i, e := range es {
		for j, o := range es {
			if i == j {
				continue
			}
			if e.kind == agent.FSWrite && o.kind == agent.FSDenyRead && r4Res(e) == r4Res(o) {
				return nil, false // R10 contradiction
			}
			if e.kind == agent.FSWrite && o.kind == agent.FSImplicit && r4Under(r4Res(e), r4Res(o)) {
				return nil, false // R10 contradiction
			}
			if e.path == o.path && e.kind == o.kind {
				return nil, false
			}
		}
		r := agent.FSRule{Kind: e.kind, Path: e.path, Raw: e.path, Resolved: r4Res(e)}
		if e.kind == agent.FSWrite {
			r.Access = agent.AccessWriteSet
		}
		fs = append(fs, r)
	}
	for i := range fs {
		if fs[i].Kind != agent.FSDenyRead {
			continue
		}
		for _, o := range fs {
			if o.Kind == agent.FSWrite && r4Under(o.Resolved, fs[i].Resolved) {
				fs[i].Unenforced = true
			}
		}
	}
	return &agent.RuleTable{FS: fs, Tier: backend.TierCgroup, Record: agent.RecordFull}, true
}

var r4Paths = []string{"/w", "/w/f", "/w/a", "/w/a/f", "/w/a/b", "/w/a/b/f", "/w/a/b/c", "/w/a/b/c/f", "/x/f", "/y/f",
	"/l/f", "/l/b/f", "/l/b/c/f"}

func r4Canon(p string) string {
	if r4Under("/l", p) {
		return "/w/a" + strings.TrimPrefix(p, "/l")
	}
	return p
}

func allow(r agent.EvalResult) bool { return r.Verdict == agent.VerdictAllow }

func TestCrossCheckTiers(t *testing.T) {
	seen := map[string]int{}
	examples := map[string]string{}
	add := func(class, ex string) {
		seen[class]++
		if _, ok := examples[class]; !ok {
			examples[class] = ex
		}
	}
	n := len(r4Pool)
	tables := 0
	var combos [][]int
	for a := 0; a < n; a++ {
		combos = append(combos, []int{a})
		for b := a + 1; b < n; b++ {
			combos = append(combos, []int{a, b})
			for c := b + 1; c < n; c++ {
				combos = append(combos, []int{a, b, c})
			}
		}
	}
	for _, idx := range combos {
		var es []r4Entry
		for _, i := range idx {
			es = append(es, r4Pool[i])
		}
		rt, ok := r4Table(es)
		if !ok {
			continue
		}
		tables++
		p := parityPolicy(rt)
		desc := ""
		for _, e := range es {
			desc += fmt.Sprintf("%s:%s ", e.kind, e.path)
		}
		entryAt := map[string]bool{}
		for _, e := range es {
			entryAt[r4Res(e)] = true
			entryAt[e.path] = true
		}
		for _, q := range r4Paths {
			canon := r4Canon(q)
			if q != canon && !r4ThroughDeclaredLink(es, q) {
				// No symlinked entry lies at or above q: Evaluate makes no I/O (I6) and cannot know the link.
				// /l/b declared as /w/a/b does not tell it where /l/f goes, since /l/b may be the link itself.
				continue
			}
			open := p.decideOpen(canon).allow // the kernel reports the canonical path
			// Tier 2 truth: the inherited Landlock ruleset (Evaluate's own landlock model) and the listener.
			llRead := allow(rt.Evaluate(agent.Action{Kind: agent.ActionFSRead, Path: canon}, backend.TierLandlock))
			llWrite := allow(rt.Evaluate(agent.Action{Kind: agent.ActionFSWrite, Path: canon}, backend.TierLandlock))
			for _, spell := range []string{q, canon} {
				ev := allow(rt.Evaluate(agent.Action{Kind: agent.ActionFSRead, Path: spell}, backend.TierCgroup))
				if ev != (open && llRead) {
					add(fmt.Sprintf("t2-read spelled=%v evaluate=%v truth=%v", spell == canon, ev, open && llRead), desc+" path="+spell)
				}
				ew := allow(rt.Evaluate(agent.Action{Kind: agent.ActionFSWrite, Path: spell}, backend.TierCgroup))
				if ew != (open && llWrite) {
					add(fmt.Sprintf("t2-write spelled=%v evaluate=%v truth=%v", spell == canon, ew, open && llWrite), desc+" path="+spell)
				}
				// Tier 3 / recorder chooser.
				for _, k := range []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir} {
					read := k == agent.ActionFSRead
					d, ok := rt.FSDecider(spell, read)
					var want bool
					if read {
						want = !ok || d.Kind != agent.FSDenyRead
					} else {
						want = ok && d.Kind == agent.FSWrite
					}
					want3 := want
					if k == agent.ActionFSDelete {
						// Tier 3 keeps the Landlock ruleset under its plane, and the ruleset asks an unlink's
						// REMOVE_* of the directory it removes from: the plane's answer on the object and the
						// floor's on its directory, where the kernel's walk lands the name (no final name in
						// the universe is a link), both hold (decide.LandlockDeleteRefusal). A write entry's own root, whose parent no
						// entry grants, is refused.
						_, floorRefuses := decide.LandlockDeleteRefusal(rt, r4Canon(spell))
						want3 = want && !floorRefuses
					}
					got := allow(rt.Evaluate(agent.Action{Kind: k, Path: spell}, backend.TierBPFLSM))
					if got != want3 {
						add(fmt.Sprintf("t3-%s evaluate=%v fsdecider=%v", k, got, want3), desc+" path="+spell)
					}
					// S3's supervisor mutation fallback combines the same nearest-wins decision with the
					// inherited Landlock floor. In particular a deny_read entry itself is refused even if
					// REMOVE_* on its parent would pass the floor; its supervisor refusal is the action's
					// line, not the older recorder-only parent inference.
					if !read {
						floor := allow(rt.Evaluate(agent.Action{Kind: k, Path: spell}, backend.TierLandlock))
						l := allow(rt.Evaluate(agent.Action{Kind: k, Path: spell}, backend.TierCgroup))
						if want && floor != l || !want && l {
							add(fmt.Sprintf("t2-%s root=%v floor=%v evaluate(cgroup)=%v entryItself=%v", k, want, floor, l, entryAt[spell]), desc+" path="+spell)
						}
					}
				}
			}
		}
	}
	var keys []string
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("%d tables x %d paths", tables, len(r4Paths))
	for _, k := range keys {
		t.Errorf("%-70s x%-5d e.g. %s", k, seen[k], examples[k])
	}
}

// r4ThroughDeclaredLink reports whether some symlinked entry of the table lies at or above q, the only links
// a table-only Evaluate can follow.
func r4ThroughDeclaredLink(es []r4Entry, q string) bool {
	for _, e := range es {
		if e.resolve != "" && r4Under(e.path, q) {
			return true
		}
	}
	return false
}

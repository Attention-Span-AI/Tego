// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// genEntry is one fs entry of a generated table: its kind, its declared path, and the path it resolves to
// ("" when the declared path has no link in it).
type genEntry struct {
	kind          agent.FSKind
	path, resolve string
}

// genPool is every entry a generated table draws from: each kind at each path of a small tree, one of them a
// symlink (/l -> /w/a) declared both as the link and beneath it.
var genPool = func() []genEntry {
	var out []genEntry
	paths := [][2]string{{"/w", ""}, {"/w/a", ""}, {"/w/a/b", ""}, {"/w/a/b/c", ""}, {"/x", ""}, {"/l", "/w/a"}, {"/l/b", "/w/a/b"}, {"/", ""}}
	for _, k := range []agent.FSKind{agent.FSWrite, agent.FSDenyRead, agent.FSWatch, agent.FSImplicit} {
		for _, p := range paths {
			out = append(out, genEntry{k, p[0], p[1]})
		}
	}
	return out
}()

// genPaths is the canonical paths every generated table is asked about.
var genPaths = []string{"/", "/w", "/w/f", "/w/a", "/w/a/f", "/w/a/b", "/w/a/b/f", "/w/a/b/c", "/w/a/b/c/f", "/x/f", "/y/f", "/y"}

func genRes(e genEntry) string {
	if e.resolve != "" {
		return e.resolve
	}
	return e.path
}

func genUnder(anc, p string) bool { return anc == p || anc == "/" || strings.HasPrefix(p, anc+"/") }

// genTable is the table Compile would build from es, Unenforced stamped as Compile stamps it, or false for a
// set Compile refuses (a write and a deny_read on one resolved path, a write covering an implicit entry, one
// entry twice).
func genTable(es []genEntry, tier backend.Tier) (*agent.RuleTable, bool) {
	var fs []agent.FSRule
	for i, e := range es {
		for j, o := range es {
			if i == j {
				continue
			}
			if e.kind == agent.FSWrite && o.kind == agent.FSDenyRead && genRes(e) == genRes(o) {
				return nil, false
			}
			if e.kind == agent.FSWrite && o.kind == agent.FSImplicit && genUnder(genRes(e), genRes(o)) {
				return nil, false
			}
			if e.path == o.path && e.kind == o.kind {
				return nil, false
			}
			if e.kind == agent.FSDenyRead && genRes(e) == "/" {
				return nil, false // E5
			}
		}
		r := agent.FSRule{Kind: e.kind, Path: e.path, Raw: e.path, Resolved: genRes(e)}
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
			if o.Kind == agent.FSWrite && genUnder(o.Resolved, fs[i].Resolved) {
				fs[i].Unenforced = true
			}
		}
	}
	return &agent.RuleTable{FS: fs, Tier: tier, Record: agent.RecordFull}, true
}

// genTables calls fn with every table of one to three entries of genPool that Compile accepts.
func genTables(tier backend.Tier, fn func(desc string, rt *agent.RuleTable)) int {
	n := len(genPool)
	count := 0
	visit := func(idx ...int) {
		var es []genEntry
		desc := ""
		for _, i := range idx {
			es = append(es, genPool[i])
			desc += string(genPool[i].kind) + ":" + genPool[i].path + " "
		}
		if rt, ok := genTable(es, tier); ok {
			count++
			fn(desc, rt)
		}
	}
	for a := 0; a < n; a++ {
		visit(a)
		for b := a + 1; b < n; b++ {
			visit(a, b)
			for c := b + 1; c < n; c++ {
				visit(a, b, c)
			}
		}
	}
	return count
}

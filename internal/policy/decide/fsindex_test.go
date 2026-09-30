// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"math/rand/v2"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// envPadded is realisticTable with n more .env deny_read entries, as the built-in .env scan writes one for
// every .env file under the project root, up to 50,000 (agent.Compile's envScanMaxEntries).
func envPadded(tier backend.Tier, n int) *agent.RuleTable {
	rt := realisticTable(tier)
	for i := range n {
		p := "/home/u/proj/gen/d" + strconv.Itoa(i/100) + "/" + strconv.Itoa(i) + "/.env"
		rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSDenyRead, Path: p, Raw: p, Resolved: p, Unenforced: true})
	}
	return rt
}

// TestFSIndexMatchesScans: the index answers every recorder question as the scans it replaces do, on random
// tables of nested entries of every kind, symlinked entries among them, and paths at, under and beside them.
func TestFSIndexMatchesScans(t *testing.T) {
	comps := []string{"a", "b", "c", "ab"}
	randPath := func(r *rand.Rand, depth int) string {
		p := ""
		for range 1 + r.IntN(depth) {
			p += "/" + comps[r.IntN(len(comps))]
		}
		return p
	}
	kinds := []agent.FSKind{agent.FSWrite, agent.FSDenyRead, agent.FSWatch, agent.FSImplicit, agent.FSAsk}
	ops := []string{record.FSOpen, record.FSUnlink, record.FSRename, record.FSMkdir}
	for seed := range uint64(400) {
		r := rand.New(rand.NewPCG(seed, 7))
		rt := &agent.RuleTable{Tier: []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}[r.IntN(3)]}
		for range 1 + r.IntN(12) {
			p := randPath(r, 4)
			switch {
			case r.IntN(10) == 0:
				p = "/"
			case len(rt.FS) > 0 && r.IntN(3) == 0:
				// Another entry's path or target: a write entry at a deny_read target, the nested read
				// grant's case (E26), and a tie between entries at one path.
				o := rt.FS[r.IntN(len(rt.FS))]
				p = o.Path
				if o.Resolved != "" && r.IntN(2) == 0 {
					p = o.Resolved
				}
			}
			e := agent.FSRule{Kind: kinds[r.IntN(len(kinds))], Path: p, Raw: p, Resolved: p, Unenforced: r.IntN(4) == 0}
			switch r.IntN(4) {
			case 0:
				e.Resolved = randPath(r, 4) // a symlinked entry
			case 1:
				e.Resolved = ""
			}
			if e.Kind == agent.FSWrite {
				e.Access = agent.AccessWriteSet
			}
			rt.FS = append(rt.FS, e)
		}
		ix := NewFSIndex(rt)
		for range 60 {
			p := randPath(r, 6)
			if got, want := ix.Canonical(p), Canonical(rt, p); got != want {
				t.Fatalf("seed %d: Canonical(%s) = %s, scan %s; table %+v", seed, p, got, want, rt.FS)
			}
			gi, gok := ix.Nearest(p)
			wi, wok := nearestNamedByLength(rt, p)
			if gi != wi || gok != wok {
				t.Fatalf("seed %d: Nearest(%s) = %d %v, scan %d %v; table %+v", seed, p, gi, gok, wi, wok, rt.FS)
			}
			lg, lgok := ix.ListenerOpenRefused(p)
			lw, lwok := ListenerOpenRefused(rt, p)
			if lgok != lwok || lg.Path != lw.Path || lg.Kind != lw.Kind || lg.Raw != lw.Raw {
				t.Fatalf("seed %d: ListenerOpenRefused(%s) = %+v %v, scan %+v %v; table %+v", seed, p, lg, lgok, lw, lwok, rt.FS)
			}
			for _, op := range ops {
				g, gok := ix.GrantName(op, p)
				w, wok := GrantName(rt, op, p)
				if g != w || gok != wok {
					t.Fatalf("seed %d: GrantName(%s, %s) = %q %v, scan %q %v; table %+v", seed, op, p, g, gok, w, wok, rt.FS)
				}
			}
			for _, read := range []bool{true, false} {
				g, gok := ix.FSDecider(p, read)
				w, wok := FSDecider(rt, p, read)
				if g != w || gok != wok {
					t.Fatalf("seed %d: FSDecider(%s, read %v) = %v, scan %v; table %+v", seed, p, read, g, w, rt.FS)
				}
			}
			if !gok {
				continue
			}
			e := &rt.FS[gi]
			gm, wm := ix.NewFSMatch(p, e.RuleName(), e), NewFSMatch(rt, p, e.RuleName(), e)
			if gm != wm {
				t.Fatalf("seed %d: NewFSMatch(%s) = %+v, scan %+v", seed, p, gm, wm)
			}
			for _, op := range ops {
				for _, write := range []bool{true, false} {
					gv, gr := ix.InferFS(op, write, gm)
					wv, wr := InferFS(rt, op, write, wm)
					if gv != wv || gr != wr {
						t.Fatalf("seed %d: InferFS(%s, %s, %v) = %s %s, scan %s %s", seed, op, p, write, gv, gr, wv, wr)
					}
				}
			}
		}
	}
}

// nearestNamedByLength is the recorder's scan as it was (observe.ruleIndex.matchFS): every entry with a declared
// path under each of its spellings, longest first and in table order among equal lengths, the first covering path.
func nearestNamedByLength(rt *agent.RuleTable, path string) (int, bool) {
	best, bestLen := -1, -1
	for i := range rt.FS {
		if rt.FS[i].Path == "" {
			continue
		}
		for _, s := range rt.FS[i].Spellings() {
			if len(s) > bestLen && agent.Covers(s, path) {
				best, bestLen = i, len(s)
			}
		}
	}
	return best, best >= 0
}

// TestFSIndexCostDoesNotGrowWithEntries: the recorder's questions of a sample cost about the same against the
// realistic table and against one the .env scan filled with 50,000 entries, and allocate nothing. By scan a
// sample cost about 1 ms at 1,000 entries and 53–65 ms at 50,000.
func TestFSIndexCostDoesNotGrowWithEntries(t *testing.T) {
	ask := func(ix *FSIndex) {
		for _, p := range []string{benchRead, benchDenied, benchNested, benchOutside} {
			if i, ok := ix.Nearest(p); ok {
				ix.NewFSMatch(p, "", &ix.rt.FS[i])
			}
		}
	}
	index := func(rt *agent.RuleTable) *FSIndex {
		ix := NewFSIndex(rt)
		if n := testing.AllocsPerRun(10, func() { ask(ix) }); n != 0 {
			t.Errorf("%d entries: the questions make %v allocations, want 0", len(rt.FS), n)
		}
		return ix
	}
	// One sample is 200 rounds of the four questions; the least thread CPU time of 20 samples of each table,
	// interleaved.
	const rounds = 200
	sx, lx := index(realisticTable(backend.TierCgroup)), index(envPadded(backend.TierCgroup, 50_000))
	m := testutil.MinOf(testutil.ThreadCPU, 20,
		func() {
			for range rounds {
				ask(sx)
			}
		},
		func() {
			for range rounds {
				ask(lx)
			}
		})
	small, large := m[0]/(rounds*4), m[1]/(rounds*4)
	t.Logf("per sample: %v at 47 entries, %v at 50,047", small, large)
	// A scan costs a thousand times more at 50,000 entries; an index a few map lookups more at worst.
	if large > 20*small+20*time.Microsecond {
		t.Errorf("a sample costs %v at 50,047 entries against %v at 47: the cost grows with the entries", large, small)
	}
}

func BenchmarkFSIndexNewFSMatch50k(b *testing.B) {
	rt := envPadded(backend.TierCgroup, 50_000)
	ix := NewFSIndex(rt)
	i, _ := ix.Nearest(benchRead)
	e := &rt.FS[i]
	b.ReportAllocs()
	for b.Loop() {
		ix.NewFSMatch(benchRead, "", e)
	}
}

// TestFSIndexEvaluateExecMatchesEvaluate: the recorder's exec question asked of the index (EvaluateExec) answers
// as Evaluate's scans do, in every tier, on random tables of nested fs entries of every kind (symlinked ones,
// ones with no declared path, one at /) and exec entries by path, by directory and by name, with and without an
// exec: section, for programs, #! scripts and loaders at, under and beside them, and beyond the walk's bound.
func TestFSIndexEvaluateExecMatchesEvaluate(t *testing.T) {
	comps := []string{"a", "b", "c", "ab"}
	randPath := func(r *rand.Rand, depth int) string {
		p := ""
		for range 1 + r.IntN(depth) {
			p += "/" + comps[r.IntN(len(comps))]
		}
		return p
	}
	deep := strings.Repeat("/d", agent.MaxWalk+2)
	kinds := []agent.FSKind{agent.FSWrite, agent.FSDenyRead, agent.FSWatch, agent.FSImplicit, agent.FSAsk}
	tiers := []backend.Tier{backend.TierObserve, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM, ""}
	for seed := range uint64(400) {
		r := rand.New(rand.NewPCG(seed, 11))
		c := &agent.Contract{}
		rt := &agent.RuleTable{Contract: c, Tier: tiers[1+r.IntN(3)]}
		for range 1 + r.IntN(12) {
			p := randPath(r, 4)
			switch r.IntN(12) {
			case 0:
				p = "/"
			case 1:
				p = "/a" + deep
			}
			e := agent.FSRule{Kind: kinds[r.IntN(len(kinds))], Path: p, Raw: p, Resolved: p, Unenforced: r.IntN(4) == 0}
			switch r.IntN(5) {
			case 0:
				e.Resolved = randPath(r, 4)
			case 1:
				e.Resolved = ""
			case 2:
				if e.Resolved != "/" {
					e.Path, e.Raw = "", "" // an entry known only by its target
				}
			}
			if e.Kind == agent.FSWrite {
				e.Access = agent.AccessWriteSet
			}
			rt.FS = append(rt.FS, e)
		}
		if r.IntN(2) == 0 {
			c.Exec = &agent.ExecSection{}
			for range 1 + r.IntN(4) {
				p := randPath(r, 4)
				x := agent.ExecRule{Raw: p, Path: p, Resolved: p, Basename: filepath.Base(p), Verdict: agent.VerdictAllow,
					IsDir: r.IntN(4) == 0, ByName: r.IntN(3) == 0}
				if r.IntN(3) == 0 {
					x.Interp = randPath(r, 4)
				}
				rt.Exec = append(rt.Exec, x)
			}
		}
		ix := NewFSIndex(rt)
		for range 40 {
			a := agent.Action{Kind: agent.ActionExec, Path: randPath(r, 6)}
			switch r.IntN(6) {
			case 0:
				a.Path = "/a" + deep + "/x"
			case 1:
				a.Script = randPath(r, 6)
			case 2:
				if len(rt.Exec) > 0 {
					a.Path = rt.Exec[r.IntN(len(rt.Exec))].Path
				}
			}
			for _, tier := range tiers {
				if got, want := ix.EvaluateExec(a, tier), Evaluate(rt, a, tier); got != want {
					t.Fatalf("seed %d tier %q: EvaluateExec(%+v) = %+v, Evaluate %+v; fs %+v exec %+v", seed, tier, a, got, want, rt.FS, rt.Exec)
				}
			}
		}
	}
	sh := agent.Action{Kind: agent.ActionExec, Path: "/bin/sh"}
	if got, want := (*FSIndex)(nil).EvaluateExec(sh, backend.TierCgroup), Evaluate(nil, sh, backend.TierCgroup); got != want {
		t.Fatalf("a nil index answers %+v, a nil table %+v", got, want)
	}
}

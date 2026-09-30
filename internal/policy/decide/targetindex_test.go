// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestDenyReadMoveTargetMatchesScan: the index names the entry the scan (agent.RuleTable.DenyReadMoveTarget)
// names, the lowest position among several, for paths at, under, above and beside random nested entries of
// every kind, enforced and not, with symlinked spellings, one at /, and relative and unclean queries.
func TestDenyReadMoveTargetMatchesScan(t *testing.T) {
	comps := []string{"a", "b", "c", "ab", "a.b"}
	randPath := func(r *rand.Rand, depth int) string {
		p := ""
		for range 1 + r.IntN(depth) {
			p += "/" + comps[r.IntN(len(comps))]
		}
		return p
	}
	kinds := []agent.FSKind{agent.FSWrite, agent.FSDenyRead, agent.FSDenyRead, agent.FSWatch}
	for seed := range uint64(500) {
		r := rand.New(rand.NewPCG(seed, 11))
		rt := &agent.RuleTable{Tier: backend.TierCgroup}
		for range 1 + r.IntN(12) {
			p := randPath(r, 4)
			if r.IntN(12) == 0 {
				p = "/"
			}
			e := agent.FSRule{Kind: kinds[r.IntN(len(kinds))], Path: p, Resolved: p, Unenforced: r.IntN(3) != 0}
			switch r.IntN(4) {
			case 0:
				e.Resolved = randPath(r, 4)
			case 1:
				e.Resolved = ""
			}
			rt.FS = append(rt.FS, e)
		}
		ix := NewFSIndex(rt)
		for range 60 {
			p := randPath(r, 5)
			switch r.IntN(8) {
			case 0:
				p = "/"
			case 1:
				p += "/"
			case 2:
				p = p[1:]
			case 3:
				p = "/" + p
			}
			for _, anc := range []bool{false, true} {
				want, wok := rt.DenyReadMoveTarget(p, anc)
				got, gok := ix.DenyReadMoveTarget(p, anc)
				if wok != gok || want.Path != got.Path || want.Resolved != got.Resolved || want.Kind != got.Kind {
					t.Fatalf("seed %d: DenyReadMoveTarget(%q, %v) = %+v %v, scan says %+v %v", seed, p, anc, got, gok, want, wok)
				}
			}
		}
		if ix.HasDenyReadMove() != HasDenyReadMove(rt) {
			t.Fatalf("seed %d: HasDenyReadMove disagrees", seed)
		}
	}
}

// TestDenyReadMoveTargetCostDoesNotGrowWithEntries: the supervisor asks this for every link and rename at tier
// 2 (supervisor.md R15d). By scan a miss cost 12–15 ms against the 50,000 entries the .env scan can plant; on
// the index it costs about the same at 47 entries and at 50,047, and allocates nothing.
func TestDenyReadMoveTargetCostDoesNotGrowWithEntries(t *testing.T) {
	queries := []string{benchRead, benchDenied, benchNested, benchOutside, "/home/u/proj/gen", "/home/u/proj/other/deep/file.o"}
	ask := func(ix *FSIndex) {
		for _, p := range queries {
			ix.DenyReadMoveTarget(p, true)
			ix.DenyReadMoveTarget(p, false)
		}
	}
	index := func(rt *agent.RuleTable) *FSIndex {
		ix := NewFSIndex(rt)
		if n := testing.AllocsPerRun(10, func() { ask(ix) }); n != 0 {
			t.Errorf("%d entries: %v allocations, want 0", len(rt.FS), n)
		}
		return ix
	}
	small, large := perQuestion(index(realisticTable(backend.TierCgroup)), index(envPadded(backend.TierCgroup, 50_000)),
		ask, 2*len(queries))
	t.Logf("per question: %v at 47 entries, %v at 50,047", small, large)
	if large > 20*small+20*time.Microsecond {
		t.Errorf("a question costs %v at 50,047 entries against %v at 47: the cost grows with the entries", large, small)
	}
}

// perQuestion is the cost of one of ask's n questions of the small index and of the large one: one sample is 200
// rounds of ask, and each figure the least thread CPU time of 20 samples, the two interleaved.
func perQuestion(small, large *FSIndex, ask func(*FSIndex), n int) (time.Duration, time.Duration) {
	const rounds = 200
	m := testutil.MinOf(testutil.ThreadCPU, 20,
		func() {
			for range rounds {
				ask(small)
			}
		},
		func() {
			for range rounds {
				ask(large)
			}
		})
	per := time.Duration(rounds * n)
	return m[0] / per, m[1] / per
}

// TestTargetIndexMatchesScan: both indexes answer as their scans do, the same entry (the lowest-indexed match)
// or none, on random tables of nested, symlinked, relative and root entries, unclean spellings among them (the
// index then falls to the scan), and paths at, under, above and beside them, with and without ancestors.
func TestTargetIndexMatchesScan(t *testing.T) {
	comps := []string{"a", "b", "ab", ".git"}
	randPath := func(r *rand.Rand) string {
		p := ""
		for range r.IntN(4) {
			p += "/" + comps[r.IntN(len(comps))]
		}
		switch r.IntN(10) {
		case 0:
			return strings.TrimPrefix(p, "/") // relative, "" when no element
		case 1:
			return p + "/" // unclean
		case 2:
			return "." + p
		}
		if p == "" {
			return "/"
		}
		return p
	}
	kinds := []agent.FSKind{agent.FSWrite, agent.FSDenyRead, agent.FSWatch}
	for seed := range uint64(2000) {
		r := rand.New(rand.NewPCG(seed, 11))
		rt := &agent.RuleTable{Tier: backend.TierCgroup}
		for range r.IntN(10) {
			p := randPath(r)
			res := p
			if r.IntN(3) == 0 {
				res = randPath(r)
			} else if r.IntN(4) == 0 {
				res = ""
			}
			rt.FS = append(rt.FS, agent.FSRule{Kind: kinds[r.IntN(len(kinds))], Path: p, Resolved: res, Unenforced: r.IntN(3) > 0})
			rt.DenyWrite = append(rt.DenyWrite, agent.FSRule{Kind: agent.FSDenyWrite, Path: randPath(r), Resolved: randPath(r), BuiltIn: true, Unenforced: true})
		}
		ix := NewFSIndex(rt)
		for range 30 {
			p := randPath(r)
			for _, anc := range []bool{false, true} {
				want, wok := rt.DenyWriteTarget(p, anc)
				got, gok := ix.DenyWriteTarget(p, anc)
				if gok != wok || got != want {
					t.Fatalf("seed %d: DenyWriteTarget(%q, %v) = %+v %v, scan %+v %v\ntable %+v", seed, p, anc, got, gok, want, wok, rt.DenyWrite)
				}
				want, wok = rt.DenyReadMoveTarget(p, anc)
				got, gok = ix.DenyReadMoveTarget(p, anc)
				if gok != wok || got != want {
					t.Fatalf("seed %d: DenyReadMoveTarget(%q, %v) = %+v %v, scan %+v %v\ntable %+v", seed, p, anc, got, gok, want, wok, rt.FS)
				}
			}
		}
	}
	var nilIx *FSIndex
	if _, ok := nilIx.DenyWriteTarget("/a", true); ok {
		t.Error("a nil index found a deny_write target")
	}
}

// denyWritePadded is realisticTable with n built-in deny_write targets, as the repository search plants one
// set per repository it finds beneath a write entry (agent-contract R20).
func denyWritePadded(n int) *agent.RuleTable {
	rt := realisticTable(backend.TierCgroup)
	for i := range n {
		p := "/home/u/proj/vendor/r" + strconv.Itoa(i/100) + "/" + strconv.Itoa(i) + "/.git/hooks"
		rt.DenyWrite = append(rt.DenyWrite, agent.FSRule{Kind: agent.FSDenyWrite, Path: p, Resolved: p, BuiltIn: true, Unenforced: true})
	}
	return rt
}

// TestDenyWriteTargetCostDoesNotGrowWithEntries: the supervisor asks DenyWriteTarget for each end of every
// notified modification while the deny_write set is not empty (supervisor.md R15c), and a rename with ancestors.
// By scan a miss walked every target; on the index it costs about the same against 50,000 as against 40, and
// allocates nothing.
func TestDenyWriteTargetCostDoesNotGrowWithEntries(t *testing.T) {
	queries := []string{benchRead, benchNested, benchOutside, "/home/u/proj/vendor", "/home/u/proj/vendor/r0/7/.git/hooks/pre-commit"}
	ask := func(ix *FSIndex) {
		for _, p := range queries {
			ix.DenyWriteTarget(p, true)
			ix.DenyWriteTarget(p, false)
		}
	}
	index := func(rt *agent.RuleTable) *FSIndex {
		ix := NewFSIndex(rt)
		if _, ok := ix.DenyWriteTarget(queries[4], false); !ok {
			t.Fatalf("%d targets: %s not found", len(rt.DenyWrite), queries[4])
		}
		if _, ok := ix.DenyWriteTarget(queries[3], true); !ok {
			t.Fatalf("%d targets: a rename of the directory above every target is not found", len(rt.DenyWrite))
		}
		if n := testing.AllocsPerRun(10, func() { ask(ix) }); n != 0 {
			t.Errorf("%d targets: %v allocations, want 0", len(rt.DenyWrite), n)
		}
		return ix
	}
	small, large := perQuestion(index(denyWritePadded(40)), index(denyWritePadded(50_000)), ask, 2*len(queries))
	t.Logf("per question: %v at 40 targets, %v at 50,000", small, large)
	if large > 20*small+20*time.Microsecond {
		t.Errorf("a question costs %v at 50,000 targets against %v at 40: the cost grows with the targets", large, small)
	}
}

// TestCmpSlash: cmpSlash and underSlash answer as the join they save would.
func TestCmpSlash(t *testing.T) {
	words := []string{"", "/", "a", "a/", "a/b", "a.", "a0", "ab", "/a", "/a/", "/a/b", "/a.b", "/a0", "/ab"}
	for _, s := range words {
		for _, b := range words {
			if got, want := cmpSlash(s, b), strings.Compare(s, b+"/"); got != want {
				t.Errorf("cmpSlash(%q, %q) = %d, want %d", s, b, got, want)
			}
			if got, want := underSlash(s, b), strings.HasPrefix(s, b+"/"); got != want {
				t.Errorf("underSlash(%q, %q) = %v, want %v", s, b, got, want)
			}
		}
	}
}

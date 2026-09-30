// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"math/rand/v2"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// scanNearestWhere is the walk NearestWhere replaced: the first entry of the list, longest path first, that
// encloses p and keep accepts.
func scanNearestWhere(rules []AdvisoryRule, p string, keep func(*AdvisoryRule) bool) *AdvisoryRule {
	if p == "" {
		return nil
	}
	for i := range rules {
		r := &rules[i]
		if r.Path == "" || (keep != nil && !keep(r)) {
			continue
		}
		if r.Path == "/" {
			if strings.HasPrefix(p, "/") {
				return r
			}
			continue
		}
		if p == r.Path || strings.HasPrefix(p, r.Path+"/") {
			return r
		}
	}
	return nil
}

// TestAdvisoryIndexMatchesScans: the advisory tables asked by index answer as the scans they replace do, on
// random tables of nested entries of every kind (symlinked ones, ones at /, ones with a trailing slash, two at
// one path), for paths at, under, above and beside them, at every tier: the nearest entry (NearestWhere and its
// kinds), the advisory verdict of every operation (AdvisoryFS, whose listener and exec-grant questions ask the
// table's index or, for a list built from entries alone, scan), REFER's rule and the exec grant.
func TestAdvisoryIndexMatchesScans(t *testing.T) {
	comps := []string{"a", "b", "c", "ab"}
	randPath := func(r *rand.Rand, depth int) string {
		p := ""
		for range 1 + r.IntN(depth) {
			p += "/" + comps[r.IntN(len(comps))]
		}
		return p
	}
	kinds := []agent.FSKind{agent.FSWrite, agent.FSDenyRead, agent.FSWatch, agent.FSImplicit, agent.FSAsk}
	accesses := []agent.AccessSet{agent.AccessWriteSet, agent.AccessRefer, agent.AccessReadFile, 0}
	tiers := []backend.Tier{backend.TierObserve, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}
	ops := []string{record.FSOpen, record.FSUnlink, record.FSRename, record.FSMkdir}
	for seed := range uint64(400) {
		r := rand.New(rand.NewPCG(seed, 23))
		rt := &agent.RuleTable{Tier: tiers[r.IntN(len(tiers))]}
		for range 1 + r.IntN(14) {
			p := randPath(r, 4)
			if r.IntN(12) == 0 {
				p = "/"
			}
			e := agent.FSRule{Kind: kinds[r.IntN(len(kinds))], Path: p, Raw: p, Resolved: p, Unenforced: r.IntN(4) == 0}
			switch r.IntN(6) {
			case 0:
				e.Resolved = randPath(r, 4)
			case 1:
				e.Resolved = ""
			case 2:
				if p != "/" {
					e.Path += "/"
				}
			}
			if e.Kind == agent.FSWrite || e.Kind == agent.FSAsk {
				e.Access = accesses[r.IntN(len(accesses))]
			}
			rt.FS = append(rt.FS, e)
		}
		if r.IntN(2) == 0 {
			rt.Contract = &agent.Contract{Exec: &agent.ExecSection{}}
			for range 1 + r.IntN(4) {
				p := randPath(r, 4)
				rt.Exec = append(rt.Exec, agent.ExecRule{Raw: p, Path: p, Resolved: p, Basename: filepath.Base(p),
					Verdict: agent.VerdictAllow, IsDir: r.IntN(3) == 0})
			}
		}
		by := NewAdvisoryTablesFor(rt)
		scan := NewAdvisoryTables(rt.FS)
		ix := NewFSIndex(rt)
		for range 40 {
			p, q := randPath(r, 6), randPath(r, 6)
			if r.IntN(8) == 0 {
				p = "/"
			}
			for name, pair := range map[string][2]*AdvisoryList{"declared": {by.Declared, scan.Declared}, "resolved": {by.Resolved, scan.Resolved}, "both": {by.Both, scan.Both}} {
				for _, keep := range []func(*AdvisoryRule) bool{nil, func(r *AdvisoryRule) bool { return r.Write }, func(r *AdvisoryRule) bool { return r.DenyRead }} {
					got, want := NearestWhere(pair[0], p, keep), scanNearestWhere(pair[1].Rules, p, keep)
					if (got == nil) != (want == nil) || (got != nil && *got != *want) {
						t.Fatalf("seed %d %s: NearestWhere(%q) = %+v, the scan %+v; fs %+v", seed, name, p, got, want, rt.FS)
					}
				}
			}
			for _, op := range ops {
				for _, flags := range []int{0, 1} {
					g1, g2, g3 := AdvisoryFS(rt, by.Both, p, op, flags, false)
					w1, w2, w3 := AdvisoryFS(rt, scan.Both, p, op, flags, false)
					if g1 != w1 || g2 != w2 || g3 != w3 {
						t.Fatalf("seed %d tier %q: AdvisoryFS(%q, %s, %d) = %v %v %v, by scan %v %v %v; fs %+v exec %+v", seed, rt.Tier, p, op, flags, g1, g2, g3, w1, w2, w3, rt.FS, rt.Exec)
					}
				}
			}
			if got, want := ix.RenameGained(p, q), RenameGained(rt, p, q); got != want {
				t.Fatalf("seed %d: RenameGained(%q, %q) = %v, the scan %v; fs %+v exec %+v", seed, p, q, got, want, rt.FS, rt.Exec)
			}
			if got, want := ix.LinkGains(p, q), LinkGains(rt, p, q); got != want {
				t.Fatalf("seed %d: LinkGains(%q, %q) = %v, the scan %v; fs %+v exec %+v", seed, p, q, got, want, rt.FS, rt.Exec)
			}
			gx, gok := ix.ExecReadGrant(p)
			wx, wok := ExecReadGrant(rt, p)
			if gok != wok || gx != wx {
				t.Fatalf("seed %d: ExecReadGrant(%q) = %v %v, the scan %v %v; fs %+v exec %+v", seed, p, gx, gok, wx, wok, rt.FS, rt.Exec)
			}
		}
	}
}

// TestAdvisoryCostDoesNotGrowWithEntries: the supervisor's advisory verdicts and the questions behind them cost
// about the same against the realistic table and against one the .env scan filled with 50,000 deny_read entries.
// Each fs syscall the supervisor is notified of holds the agent's thread until answered, and by scan a tier-1
// read-open cost 2.6 ms at 50,000 entries, a tier-2 write-open 14 ms and a rename 33 to 44 ms.
func TestAdvisoryCostDoesNotGrowWithEntries(t *testing.T) {
	ask := func(rt *agent.RuleTable, tabs AdvisoryTables) {
		for _, p := range []string{benchRead, benchDenied, benchNested, benchOutside} {
			AdvisoryFS(rt, tabs.Both, p, record.FSOpen, 0, false)
			AdvisoryFS(rt, tabs.Both, p, record.FSOpen, 1, false)
			AdvisoryFS(rt, tabs.Both, p, record.FSUnlink, 0, false)
			tabs.FS.RenameGains(p, benchRead, false)
			tabs.FS.ExecReadGrant(p)
		}
	}
	// One sample is 100 rounds of the 20 questions; the least thread CPU time of 20 samples of each table,
	// interleaved.
	const rounds = 100
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		smallRT, largeRT := realisticTable(tier), envPadded(tier, 50_000)
		smallTabs, largeTabs := NewAdvisoryTablesFor(smallRT), NewAdvisoryTablesFor(largeRT)
		m := testutil.MinOf(testutil.ThreadCPU, 20,
			func() {
				for range rounds {
					ask(smallRT, smallTabs)
				}
			},
			func() {
				for range rounds {
					ask(largeRT, largeTabs)
				}
			})
		small, large := m[0]/(rounds*20), m[1]/(rounds*20)
		t.Logf("tier %s, per question: %v at 47 entries, %v at 50,047", tier, small, large)
		if large > 20*small+20*time.Microsecond {
			t.Errorf("tier %s: a question costs %v at 50,047 entries against %v at 47: the cost grows with the entries", tier, large, small)
		}
	}
}

func BenchmarkAdvisoryFS50k(b *testing.B) {
	rt := envPadded(backend.TierCgroup, 50_000)
	tabs := NewAdvisoryTablesFor(rt)
	b.ReportAllocs()
	for b.Loop() {
		AdvisoryFS(rt, tabs.Both, benchRead, record.FSOpen, 0, false)
		AdvisoryFS(rt, tabs.Both, benchRead, record.FSOpen, 1, false)
		tabs.FS.RenameGains(benchRead, benchNested, false)
	}
}

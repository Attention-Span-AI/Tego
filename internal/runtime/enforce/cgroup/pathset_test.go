// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// longestMatch is what pathSet.match answers, by the definition: walk every entry, keep the longest that covers
// the path, the first of equals. The policy walked its lists this way until the walk's cost, which grows with
// the entries, was put on the read loop (§6 E35); it stays here as the answer the index is checked against.
func longestMatch(entries []fsEntry, path string) (fsEntry, bool) {
	best, found := fsEntry{}, false
	for _, e := range entries {
		if !covers(e, path) {
			continue
		}
		if !found || len(e.path) > len(best.path) {
			best, found = e, true
		}
	}
	return best, found
}

// covers reports whether an entry names a path: the same path, or, for a directory entry, one beneath it.
func covers(e fsEntry, path string) bool {
	if e.path == path {
		return true
	}
	if !e.dir {
		return false
	}
	return underPath(e.path, path)
}

// underPath reports whether child is strictly beneath parent, comparing whole path components so "/a/bc" is
// never treated as being under "/a/b".
func underPath(parent, child string) bool {
	if parent == "" || child == "" {
		return false
	}
	parent = strings.TrimSuffix(parent, "/")
	if parent == "" {
		return child != "/" // everything is under the root
	}
	return strings.HasPrefix(child, parent+"/")
}

// TestPathSetMatchesTheWalk: the index gives the entry the walk over every entry gives, for every path, including
// the spellings no readlink returns (a trailing or doubled "/", a relative path, the root, ""), since a verdict the
// two disagree on is a refusal lost or invented. Entries and paths are drawn from a few components so that they
// nest, share prefixes ("a" and "ab") and name one path several times under different rules.
func TestPathSetMatchesTheWalk(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(20260923, 3))
	parts := []string{"", "a", "b", "ab", ".env"}
	path := func() string {
		var b strings.Builder
		if rng.IntN(5) != 0 {
			b.WriteByte('/')
		}
		for i := range rng.IntN(5) {
			if i > 0 {
				b.WriteByte('/')
			}
			b.WriteString(parts[rng.IntN(len(parts))])
		}
		if rng.IntN(6) == 0 {
			b.WriteByte('/')
		}
		return b.String()
	}
	for set := range 3000 {
		entries := make([]fsEntry, rng.IntN(12))
		for i := range entries {
			entries[i] = fsEntry{path: path(), dir: rng.IntN(4) != 0, rule: fmt.Sprintf("rule%d", i)}
		}
		s := newPathSet(entries)
		for range 40 {
			p := path()
			want, wantOK := longestMatch(entries, p)
			got, gotOK := s.match(p)
			if got != want || gotOK != wantOK {
				t.Fatalf("set %d, entries %+v: match(%q) = %+v, %v; the walk gives %+v, %v", set, entries, p, got,
					gotOK, want, wantOK)
			}
		}
	}
	// The component-wise prefix at its edges, as TestUnderPath has it, through the index.
	for _, tc := range []struct {
		parent, child string
		want          bool
	}{
		{"/a", "/a/b", true}, {"/a", "/ab", false}, {"/a/b", "/a/b/c/d", true}, {"/a/", "/a/b", true},
		{"/", "/anything", true}, {"/", "/", true}, {"", "/a", false}, {"/a", "", false},
	} {
		s := newPathSet([]fsEntry{{path: tc.parent, dir: true, rule: "r"}})
		if _, ok := s.match(tc.child); ok != tc.want {
			t.Errorf("a directory entry %q covers %q: %v, want %v", tc.parent, tc.child, ok, tc.want)
		}
	}
	var zero pathSet
	if e, ok := zero.match("/a"); ok {
		t.Errorf("an empty set matched %+v", e)
	}
}

// entryCountPolicy is a policy of the shape the built-in .env scan gives a project it found n .env files in: one
// deny_read entry each, as agent.Compile writes them, inside a write entry, beside two home-directory entries.
func entryCountPolicy(tb testing.TB, n int) *policy {
	tb.Helper()
	fs := []agent.FSRule{
		fsRule(agent.FSDenyRead, "/home/u/.ssh", "/home", "~/.ssh"),
		fsRule(agent.FSDenyRead, "/home/u/.aws", "/home", "~/.aws"),
		fsRule(agent.FSWrite, "/home/u/work", "/home", "~/work"),
	}
	for i := range n {
		fs = append(fs, fsRule(agent.FSDenyRead, fmt.Sprintf("/home/u/work/pkg%d/sub%d/.env", i%97, i), "/home",
			fmt.Sprintf("work/pkg%d/sub%d/.env", i%97, i)))
	}
	return newPolicy(policyTable(fs, nil), "/run.scope")
}

// TestDecideOpenCostDoesNotGrowWithEntries: the read loop answers every open a mark reports with this decision,
// by any process on the host (§6 E35), so its cost must not grow with the deny_read entries, whose number the
// agent can raise to 50,000 by creating .env files. Walking the entries, an open cost about 3,400 times more
// against 50,000 entries than against 20; the bound here is ten times, with the fastest of several rounds taken
// so that a loaded machine does not decide it. The verdicts are checked too, the refusal naming its own entry.
func TestDecideOpenCostDoesNotGrowWithEntries(t *testing.T) {
	small, large := entryCountPolicy(t, 20), entryCountPolicy(t, 50_000)
	const allowedPath, refusedPath = "/home/u/work/pkg3/sub7/main.go", "/home/u/work/pkg3/sub3/.env"
	for _, p := range []*policy{small, large} {
		if v := p.decideOpen(allowedPath); !v.allow {
			t.Fatalf("%s refused by %s", allowedPath, v.rule)
		}
		if v := p.decideOpen(refusedPath); v.allow || v.rule != "fs.deny_read[work/pkg3/sub3/.env]" ||
			v.reason != record.ReasonReadDenied {
			t.Fatalf("%s: %+v, want refused by its own entry", refusedPath, v)
		}
	}
	// One sample is 2000 decisions; each figure the least thread CPU time of 9 samples, small and large interleaved.
	sample := func(p *policy, path string) func() {
		return func() {
			for range 2000 {
				p.decideOpen(path)
			}
		}
	}
	for _, path := range []string{allowedPath, refusedPath} {
		m := testutil.MinOf(testutil.ThreadCPU, 9, sample(small, path), sample(large, path))
		s, l := m[0]/2000, m[1]/2000
		if l > 10*max(s, 50*time.Nanosecond) {
			t.Errorf("decideOpen(%s) takes %v against 50,000 entries and %v against 20: it grows with the entries",
				path, l, s)
		}
	}
}

// BenchmarkDecideOpenByEntryCount measures the decision the read loop makes for every open a mark reports,
// against as many .env entries as the built-in scan writes at most, and at two smaller counts.
func BenchmarkDecideOpenByEntryCount(b *testing.B) {
	for _, n := range []int{20, 1000, 50_000} {
		p := entryCountPolicy(b, n)
		b.Run(fmt.Sprintf("allowed/%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if v := p.decideOpen("/home/u/work/pkg3/sub7/main.go"); !v.allow {
					b.Fatal("refused")
				}
			}
		})
		b.Run(fmt.Sprintf("refused/%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if v := p.decideOpen("/home/u/work/pkg3/sub3/.env"); v.allow {
					b.Fatal("allowed")
				}
			}
		})
	}
}

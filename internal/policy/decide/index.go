// SPDX-License-Identifier: Apache-2.0

package decide

import "strings"

// IndexEntry is one path a PathIndex holds: an entry covers the path it names, and a directory entry every
// path beneath it as well.
type IndexEntry struct {
	Path string
	Dir  bool
}

// PathIndex is a list of entries indexed for one question: which entry is the most specific one covering a
// path. An entry covers the path it names, and a directory entry covers every path beneath it as well,
// component by component, so "/a/bc" is never beneath "/a/b"; the most specific is the one with the longest
// path, the first listed of several naming one path.
//
// It is indexed, not walked, because the walk cost grew with the entries and tier 2's fanotify listener asks
// on its read loop, for every open and exec its marks report by any process on the host (settleByPath,
// enforce-cgroup-observe §6 E35). The number of entries is not the contract author's to bound: the built-in
// .env scan writes a deny_read entry for every .env file under the project root, up to 50,000 (agent.Compile),
// the agent can create those files in an earlier run, and every deny_read entry marks its mount for opens
// (§5 R8), usually "/". Walked, one allowed open cost 0.5 µs against 20 entries, 21 µs against 1,000 and
// 1.7–1.9 ms against 50,000 (i7-10870H), which held the whole host's opens on that mount to about 550 a
// second. Match costs one map lookup of the path and at most one of each of its components, whatever the
// number of entries: 0.18–0.20 µs for an allowed open and 0.36–0.40 µs for a refused one at each of those
// three counts (internal/runtime/enforce/cgroup BenchmarkDecideOpenByEntryCount,
// TestDecideOpenCostDoesNotGrowWithEntries). It allocates nothing on Match.
//
// The zero PathIndex holds no entry and matches nothing.
type PathIndex struct {
	paths []string
	// exact is the first entry naming each path.
	exact map[string]int
	// edges and ends hold the directory entries as a tree of path components, so the directories above a
	// path are looked up one component at a time. A node is a number; node 0 is where every path starts, edges
	// leads from a node through one component to the next, and ends[n] is the most specific directory entry
	// whose path ends at node n, or -1. One map of edges rather than a map in every node: the .env scan's
	// entries each end two components below a directory of their own, and with a map in each of those nodes a
	// policy of 50,000 took 25 MB of heap, against 13 MB this way. "/" is held apart (root): it covers every path
	// but itself, and a relative one too, and it has no component to be found by.
	edges   map[pathEdge]int32
	ends    []int32
	root    int
	hasRoot bool
}

// pathEdge is one step down the tree of directory entries: from node from, through the component name. A
// trailing "/" on an entry's path is dropped before its components are taken, as the component-wise prefix
// does, so "/a/" and "/a" end on the same node.
type pathEdge struct {
	from int32
	name string
}

// NewPathIndex indexes entries, keeping their order for the one choice it decides: between entries naming the
// same path, the first. Match returns positions in entries.
func NewPathIndex(entries []IndexEntry) PathIndex {
	s := PathIndex{paths: make([]string, len(entries)), exact: make(map[string]int, len(entries))}
	for i, e := range entries {
		s.paths[i] = e.Path
		if _, dup := s.exact[e.Path]; !dup {
			s.exact[e.Path] = i
		}
		if !e.Dir || e.Path == "" {
			continue // a file entry covers only its own path, and an empty one names nothing to be beneath
		}
		key := strings.TrimSuffix(e.Path, "/")
		if key == "" {
			if !s.hasRoot || s.moreSpecific(i, s.root) {
				s.root, s.hasRoot = i, true
			}
			continue
		}
		if s.edges == nil {
			s.edges, s.ends = map[pathEdge]int32{}, []int32{-1}
		}
		var n int32
		for c := range strings.SplitSeq(key, "/") {
			next, ok := s.edges[pathEdge{n, c}]
			if !ok {
				next = int32(len(s.ends))
				s.ends = append(s.ends, -1)
				s.edges[pathEdge{n, c}] = next
			}
			n = next
		}
		if at := s.ends[n]; at < 0 || s.moreSpecific(i, int(at)) {
			s.ends[n] = int32(i)
		}
	}
	return s
}

// Path is the path of entry i.
func (s *PathIndex) Path(i int) string { return s.paths[i] }

// moreSpecific reports whether entry i is chosen over entry j when both cover a path: the longer path, and of
// two equally long, the one listed first.
func (s *PathIndex) moreSpecific(i, j int) bool {
	li, lj := len(s.paths[i]), len(s.paths[j])
	return li > lj || (li == lj && i < j)
}

// Match returns the position of the most specific entry covering path, and false when none does. The
// candidates are the entry naming path, "/", and the directory entry ending on each directory above path, and
// each is weighed against the others rather than one taken first: an entry naming path is longer than every
// other candidate but "/", which is as long as a relative path of one character.
func (s *PathIndex) Match(path string) (int, bool) {
	best, found := s.exact[path]
	if s.hasRoot && path != "" && path != "/" && (!found || s.moreSpecific(s.root, best)) {
		best, found = s.root, true
	}
	// Every component that a "/" follows ends a directory above path. The last component ends path itself,
	// which only an entry naming it covers, and exact has those.
	var n int32
	for rest := path; len(s.edges) > 0; {
		c, after, more := strings.Cut(rest, "/")
		if !more {
			break
		}
		next, ok := s.edges[pathEdge{n, c}]
		if !ok {
			break
		}
		n = next
		if at := int(s.ends[n]); at >= 0 && (!found || s.moreSpecific(at, best)) {
			best, found = at, true
		}
		rest = after
	}
	if !found {
		return -1, false
	}
	return best, true
}

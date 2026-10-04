// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestResolveTellsDeletedNameFromUnlink is R6/E8: readlink spells an unlinked directory "<path> (deleted)", and a
// live directory may be named that way too. Only an unlinked one loses the suffix and is marked unreliable; a
// path joined to either is left to the walk.
func TestResolveTellsDeletedNameFromUnlink(t *testing.T) {
	for _, tc := range []struct {
		name       string
		live       bool
		want       string
		unreliable bool
	}{
		{name: "live directory with that name", live: true, want: "/work/foo (deleted)/f"},
		{name: "unlinked directory", want: "/work/foo/f", unreliable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.links["/proc/42/fd/9"] = "/work/foo (deleted)"
			f.live = map[string]bool{"/proc/42/fd/9": tc.live}
			r, _, _ := testReader(t, f)
			got := r.resolve(9, "f")
			if got != tc.want {
				t.Errorf("resolve = %q, want %q", got, tc.want)
			}
			if (r.note == rulePathUnreliable) != tc.unreliable {
				t.Errorf("marked = %v, want %v", r.note == rulePathUnreliable, tc.unreliable)
			}
			if !r.joinedToDeleted(pathQuery{dirfd: 9, path: "f", joined: got}) {
				t.Error("the joined spelling is not left to the walk")
			}
			if r.joinedToDeleted(pathQuery{dirfd: atFDCWD, path: got, joined: got}) {
				t.Error("an absolute path of the same spelling is left to the walk too")
			}
		})
	}
}

// TestHeldFileKeepsALiveDeletedName: linkat's AT_EMPTY_PATH end is named as its descriptor's link spells it,
// and a live file named "<x> (deleted)" keeps its name; an unlinked one (an O_TMPFILE) loses the marker.
func TestHeldFileKeepsALiveDeletedName(t *testing.T) {
	for _, tc := range []struct {
		live bool
		want string
	}{
		{live: true, want: "/work/x (deleted)"},
		{live: false, want: "/work/x"},
	} {
		f := newFake()
		f.links["/proc/42/fd/7"] = "/work/x (deleted)"
		f.live = map[string]bool{"/proc/42/fd/7": tc.live}
		r, _, _ := testReader(t, f)
		if got := r.heldFile(7); got != tc.want {
			t.Errorf("live=%v: heldFile = %q, want %q", tc.live, got, tc.want)
		}
		if (r.note == rulePathUnreliable) == tc.live {
			t.Errorf("live=%v: marked = %v", tc.live, r.note == rulePathUnreliable)
		}
	}
}

// TestFSDeletedNamedCwdGoesToTheWalk: an open relative to a cwd whose link ends in " (deleted)" is decided where
// the walk from the cwd lands, never by the walk cache on the spelling. A live directory "/work/out (deleted)"
// beside the write entry /work/out is not inside it, and a stripped unlinked spelling that names the live
// /work/out is not taken at its word.
func TestFSDeletedNamedCwdGoesToTheWalk(t *testing.T) {
	for _, tc := range []struct {
		name     string
		live     bool
		wantPath string
		inEntry  bool
	}{
		{name: "live directory with that name", live: true, wantPath: "/work/out (deleted)/a.go"},
		{name: "unlinked directory", wantPath: "/work/out/a.go", inEntry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, f, sink := cacheLoop(t)
			f.links["/proc/42/cwd"] = "/work/out (deleted)"
			f.live = map[string]bool{"/proc/42/cwd": tc.live}
			f.put(0x10000, cstr("a.go"))
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000, 0x241))
			ev := sink.one(t)
			var p record.FSPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", p.Path, tc.wantPath)
			}
			if got := strings.HasPrefix(ev.Rule, "fs.write["); got != tc.inEntry {
				t.Errorf("rule = %q, want inside the write entry: %v", ev.Rule, tc.inEntry)
			}
			f.mu.Lock()
			qs := append([]pathQuery(nil), f.fsQueries...)
			f.mu.Unlock()
			if len(qs) != 1 || !qs[0].deletedBase {
				t.Errorf("walks = %+v, want the one walk, marked deletedBase", qs)
			}
		})
	}
}

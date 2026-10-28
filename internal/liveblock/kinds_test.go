// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestReadWriteKinds: read and write are kinds every reader of an overlay accepts: ParseKind names them, Normalize
// cleans them as a path, the overlay holds a path, a read and a write block of one path as three blocks, and each
// rule names its own kind.
func TestReadWriteKinds(t *testing.T) {
	for _, name := range []string{"exec", "net", "path", "read", "write"} {
		k, err := ParseKind(name)
		if err != nil || string(k) != name {
			t.Errorf("ParseKind(%q) = %q, %v", name, k, err)
		}
	}
	if _, err := ParseKind("mmap"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "read or write") {
		t.Errorf("ParseKind(mmap) = %v", err)
	}
	for _, k := range []Kind{KindRead, KindWrite} {
		if v, err := Normalize(k, " /p/proj/tmp/../tmp/ "); err != nil || v != "/p/proj/tmp" {
			t.Errorf("Normalize(%s) = %q, %v", k, v, err)
		}
		if _, err := Normalize(k, "./tmp"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Normalize(%s, relative) = %v, want ErrInvalid", k, err)
		}
	}
	o := New(testRun)
	for _, k := range []Kind{KindPath, KindRead, KindWrite} {
		if _, ok, err := o.Add(k, "/p/x", "t", time.Now()); !ok || err != nil {
			t.Fatalf("Add(%s) = %v, %v", k, ok, err)
		}
	}
	if len(o.Blocks) != 3 {
		t.Fatalf("blocks = %v", o.Blocks)
	}
	if got := o.Blocks[1].Rule(); got != "live.block[read:/p/x]" {
		t.Errorf("read rule = %q", got)
	}
	if got := o.Blocks[2].Rule(); got != "live.block[write:/p/x]" {
		t.Errorf("write rule = %q", got)
	}
	b, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(b, testRun); err != nil {
		t.Fatalf("Decode of read and write blocks: %v", err)
	}
	// The run page keeps offering the three kinds it words; every kind is parsed.
	if len(Kinds) != 3 || len(AllKinds) != 5 {
		t.Errorf("Kinds = %v, AllKinds = %v", Kinds, AllKinds)
	}
}

// TestUnknownKindFailsClosed: an overlay holding a kind this reader does not know is refused whole (ErrInvalid), so
// the launcher keeps the blocks it last put in force and records live-block-unreadable (internal/runtime,
// pollLiveBlocks). This is how a launcher built before the read and write kinds reads an overlay that holds one: it
// fails closed, never dropping a block nor reading a narrower one as wider.
func TestUnknownKindFailsClosed(t *testing.T) {
	o := New(testRun)
	if _, _, err := o.Add(KindPath, "/p/x", "t", time.Now()); err != nil {
		t.Fatal(err)
	}
	b, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// A kind added after this reader: in the blocks, then only in the changes.
	for _, where := range []string{"blocks", "changes"} {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		m[where].([]any)[0].(map[string]any)["kind"] = "mmap"
		nb, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(nb, testRun); !errors.Is(err, ErrInvalid) {
			t.Errorf("an unknown kind in %s decoded: %v", where, err)
		}
	}
}

// TestMatchPathAccess: a path block matches reads and changes, a read block reads only, a write block changes only;
// each matches its path and everything beneath it, never a sibling with the same prefix; MatchWithin finds a block
// beneath a folder (what a rename of the folder would carry away), never the folder's own block.
func TestMatchPathAccess(t *testing.T) {
	o := New(testRun)
	for _, kv := range [][2]string{{"read", "/p/secret"}, {"write", "/p/tmp"}, {"path", "/p/both"}} {
		if _, _, err := o.Add(Kind(kv[0]), kv[1], "t", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	s := Compile(o, Resolved{})
	if !s.HasPath() || !s.HasAccess(AccessRead) || !s.HasAccess(AccessWrite) || s.HasAccess(0) {
		t.Fatal("HasPath or HasAccess")
	}
	ro := New(testRun)
	if _, _, err := ro.Add(KindRead, "/p/secret", "t", time.Now()); err != nil {
		t.Fatal(err)
	}
	if rs := Compile(ro, Resolved{}); rs.HasAccess(AccessWrite) || !rs.HasAccess(AccessRead) {
		t.Error("a read block's set blocks changes, or no reads")
	}
	rw := AccessRead | AccessWrite
	for _, c := range []struct {
		p    string
		acc  Access
		want string // rule, "" for none
	}{
		{"/p/secret", AccessRead, "live.block[read:/p/secret]"},
		{"/p/secret/a/b", AccessRead, "live.block[read:/p/secret]"},
		{"/p/secret", AccessWrite, ""},
		{"/p/secret/a", AccessWrite, ""},
		{"/p/secret", rw, "live.block[read:/p/secret]"},
		{"/p/secrets", AccessRead, ""},
		{"/p/tmp/log.txt", AccessWrite, "live.block[write:/p/tmp]"},
		{"/p/tmp/log.txt", AccessRead, ""},
		{"/p/tmp", rw, "live.block[write:/p/tmp]"},
		{"/p/both/x", AccessRead, "live.block[path:/p/both]"},
		{"/p/both/x", AccessWrite, "live.block[path:/p/both]"},
		{"/p/both/x", 0, ""},
		{"/p", rw, ""},
		{"relative", rw, ""},
	} {
		e, ok := s.MatchPath(c.p, c.acc)
		got := ""
		if ok {
			got = e.Rule()
		}
		if got != c.want {
			t.Errorf("MatchPath(%q, %d) = %q, want %q", c.p, c.acc, got, c.want)
		}
	}
	for _, c := range []struct {
		p    string
		acc  Access
		want string
	}{
		{"/p", AccessRead, "live.block[read:/p/secret]"},
		{"/p", AccessWrite, "live.block[write:/p/tmp]"},
		{"/", AccessWrite, "live.block[write:/p/tmp]"},
		{"/p/secret", AccessRead, ""}, // its own block is MatchPath's
		{"/p/sec", AccessRead, ""},
		{"/q", rw, ""},
	} {
		e, ok := s.MatchWithin(c.p, c.acc)
		got := ""
		if ok {
			got = e.Rule()
		}
		if got != c.want {
			t.Errorf("MatchWithin(%q, %d) = %q, want %q", c.p, c.acc, got, c.want)
		}
	}
	var none *Set
	if _, ok := none.MatchWithin("/", rw); ok || none.HasPath() {
		t.Error("a nil Set matched")
	}
	if KindExec.Access() != 0 || KindNet.Access() != 0 || KindPath.Access() != rw {
		t.Error("Access of a kind")
	}
}

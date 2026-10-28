// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// realTree is a temporary tree with /data/secret, a link /home/link -> data, a loop, and its own real root (TempDir
// may itself be reached through a link).
func realTree(t *testing.T) (root string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"data/secret", "home"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "data"), filepath.Join(root, "home", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("rel", filepath.Join(root, "home", "rellink")); err != nil {
		t.Fatal(err)
	}
	for _, l := range [][2]string{{"loop", "loop"}, {"pong", "home/ping"}, {"ping", "home/pong"}} {
		if err := os.Symlink(l[0], filepath.Join(root, l[1])); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestRealPath: a value through a link resolves to where it leads, a missing tail is appended
// as written, and a value that is its own real path, or cannot be resolved, has none. A relative dangling link is read
// against the real folder it is in, not the folder as written.
func TestRealPath(t *testing.T) {
	root := realTree(t)
	// proj/link -> ../data, data/out -> ../exfil (missing): the kernel lands at root/exfil, not root/proj/exfil.
	if err := os.MkdirAll(filepath.Join(root, "proj"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, l := range [][2]string{{"../data", "proj/link"}, {"../exfil", "data/out"}, {"../data/secret/f", "home/flink"}} {
		if err := os.Symlink(l[0], filepath.Join(root, l[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "data", "secret", "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, value, want string
	}{
		{"through a linked folder", root + "/home/link/secret", root + "/data/secret"},
		{"the link itself", root + "/home/link", root + "/data"},
		{"a missing tail", root + "/home/link/secret/not/yet", root + "/data/secret/not/yet"},
		{"a missing file under the link", root + "/home/link/new.txt", root + "/data/new.txt"},
		{"a dangling relative link", root + "/home/rellink/x", root + "/home/rel/x"},
		{"a dangling relative link behind a linked folder", root + "/proj/link/out/x", root + "/exfil/x"},
		{"a link to a file", root + "/home/flink", root + "/data/secret/f"},
		{"a file with elements after it", root + "/home/flink/x", ""},
		{"a dangling link loop", root + "/home/ping/x", ""},
		{"already real", root + "/data/secret", ""},
		{"missing, no link", root + "/data/none/deeper", ""},
		{"a loop", root + "/loop/x", ""},
		{"not absolute", "home/link", ""},
		{"not cleaned", root + "/home/link/../link", ""},
		{"the root", "/", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := RealPath(c.value); got != c.want || err != nil {
				t.Fatalf("RealPath(%q) = %q, %v; want %q", c.value, got, err, c.want)
			}
		})
	}
}

// TestSetMatchesBothSpellings: a path, read or write block with a Real refuses beneath its value and beneath its
// Real, under the value's rule, and a rename of a folder above either carries it (MatchWithin). Fenced counts it once.
func TestSetMatchesBothSpellings(t *testing.T) {
	for _, k := range []Kind{KindPath, KindRead, KindWrite} {
		t.Run(string(k), func(t *testing.T) {
			e := Entry{Kind: k, Value: "/home/u/link/secret", Real: "/data/secret", By: "uid:1 pid:2 cli", At: t0}
			s := CompileEntries([]Entry{e}, 1, Resolved{})
			acc := k.Access()
			for _, p := range []string{"/home/u/link/secret/a.txt", "/data/secret", "/data/secret/b/c"} {
				got, ok := s.MatchPath(p, acc)
				if !ok || got.Rule() != Rule(k, e.Value) {
					t.Fatalf("MatchPath(%q) = %v %q, want the value's rule %q", p, ok, got.Rule(), Rule(k, e.Value))
				}
			}
			if _, ok := s.MatchPath("/data/secretive", acc); ok {
				t.Fatal("a sibling sharing a prefix of the Real is refused")
			}
			for _, p := range []string{"/data", "/home/u/link"} {
				if _, ok := s.MatchWithin(p, acc); !ok {
					t.Fatalf("MatchWithin(%q): a rename above a spelling of the block is not caught", p)
				}
			}
			if _, ok := s.MatchWithin("/data/secret", acc); ok {
				t.Fatal("MatchWithin matched the Real itself, which MatchPath decides")
			}
			e.Fence = true
			if n := CompileEntries([]Entry{e}, 1, Resolved{}).Fenced(); n != 1 {
				t.Fatalf("Fenced %d: a fence refusal with two spellings counts once", n)
			}
		})
	}
}

// chainTree is a tree a governed agent could plant to slow RealPath down: a folder a and links
// l0 … l<n-1>, each a dangling link whose target walks "a/.." hops times before it names the next link. It returns
// a value through the whole chain.
func chainTree(t *testing.T, n, hops int) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		target := strings.Repeat("a/../", hops) + "l" + strconv.Itoa(i+1)
		if err := os.Symlink(target, filepath.Join(root, "l"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(root, "l0", "secret")
}

// TestRealPathBudget: a chain of links built to cost many lookups stops at maxRealCalls with
// ErrRealBudget, fast, where the walk before it took minutes; a deadline already passed stops it at once; and a chain
// cheap enough is still followed to the end.
func TestRealPathBudget(t *testing.T) {
	value := chainTree(t, 20, 700) // 14 000 lookups: far past the budget
	start := time.Now()
	got, err := RealPath(value)
	if !errors.Is(err, ErrRealBudget) || got != "" {
		t.Fatalf("RealPath of a costly chain = %q, %v; want ErrRealBudget", got, err)
	}
	if took := time.Since(start); took > realWait+time.Second {
		t.Fatalf("RealPath of a costly chain took %v, want at most about %v", took, realWait)
	}
	if _, err := realPath(value, 1<<30, time.Now()); !errors.Is(err, ErrRealBudget) {
		t.Fatalf("a passed deadline: %v, want ErrRealBudget", err)
	}
	cheap := chainTree(t, 3, 2)
	root := filepath.Dir(filepath.Dir(cheap))
	if got, err := RealPath(cheap); err != nil || got != filepath.Join(root, "l3", "secret") {
		t.Fatalf("RealPath of a cheap chain = %q, %v; want %q", got, err, filepath.Join(root, "l3", "secret"))
	}
}

// TestSetRealKeepsEverySpelling: SetReal stores the resolved spelling on a held block as no change (the add has its
// line), refuses one that is no fs kind's or not normalized, and never drops or replaces a held one; a later add of the
// block keeps it.
func TestSetRealKeepsEverySpelling(t *testing.T) {
	const by = "uid:1 pid:2 cli"
	o := New(testRun)
	if o.SetReal(KindRead, "/home/u/link/secret", "/data/secret") {
		t.Fatal("SetReal on a block the overlay does not hold changed it")
	}
	if _, _, err := o.Add(KindRead, "/home/u/link/secret", by, t0); err != nil {
		t.Fatal(err)
	}
	serial := o.Serial
	if !o.SetReal(KindRead, "/home/u/link/secret", "/data/secret") || o.Serial != serial {
		t.Fatalf("SetReal: serial %d (was %d); want the Real set with no change recorded", o.Serial, serial)
	}
	if e, _ := o.Find(KindRead, "/home/u/link/secret"); e.Real != "/data/secret" {
		t.Fatalf("Real %q, want /data/secret", e.Real)
	}
	// A later resolution elsewhere keeps the held spelling (the link was moved).
	if o.SetReal(KindRead, "/home/u/link/secret", "/elsewhere") {
		t.Fatal("SetReal replaced a held Real")
	}
	// A re-add, and a dormant block put back in force, keep the spelling.
	if _, ok, err := o.Add(KindRead, "/home/u/link/secret", by, t0); err != nil || ok {
		t.Fatalf("re-add: changed %v %v, want already blocked", ok, err)
	}
	o.V = VersionTimed
	if _, _, err := o.RemoveUntil(KindRead, "/home/u/link/secret", by, t0, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.Add(KindRead, "/home/u/link/secret", by, t0); err != nil {
		t.Fatal(err)
	}
	if e, _ := o.Find(KindRead, "/home/u/link/secret"); e.Real != "/data/secret" || !e.From.IsZero() {
		t.Fatalf("after unblock-until and block: %+v, want the block in force with its Real", e)
	}
	// Spellings the Set could not match are refused, not stored.
	for _, c := range []struct {
		kind       Kind
		value, got string
	}{
		{KindExec, "/usr/bin/curl", "/usr/bin/curl.real"},
		{KindNet, "/run/sock", "/run/real.sock"},
		{KindWrite, "/home/u/w", "relative"},
		{KindWrite, "/home/u/x", "/data/../data/x"},
		{KindWrite, "/home/u/y", "/home/u/y"},
	} {
		if _, _, err := o.Add(c.kind, c.value, by, t0); err != nil {
			t.Fatal(err)
		}
		if o.SetReal(c.kind, c.value, c.got) {
			t.Fatalf("%s %s took Real %q", c.kind, c.value, c.got)
		}
	}
	b, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(b, testRun)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := back.Find(KindRead, "/home/u/link/secret"); e.Real != "/data/secret" || back.V != VersionReal {
		t.Fatalf("after a round trip: Real %q, version %d; want /data/secret at %d", e.Real, back.V, VersionReal)
	}
}

// TestRealNeedsItsVersion: an overlay that holds a Real is written at VersionReal, which a writer
// or launcher that predates it refuses (its Validate accepts up to VersionModes) instead of dropping the real path
// without notice; a file that claims an older version and holds a Real is invalid; and dropping the last Real goes
// back to the lowest version, byte for byte what the base build wrote.
func TestRealNeedsItsVersion(t *testing.T) {
	o := New(testRun)
	if _, _, err := o.Add(KindPath, "/home/u/link/secret", "uid:1 pid:2 cli", t0); err != nil {
		t.Fatal(err)
	}
	plain, err := o.Encode()
	if err != nil || o.V != Version {
		t.Fatalf("no Real: version %d, %v; want %d", o.V, err, Version)
	}
	o.SetReal(KindPath, "/home/u/link/secret", "/data/secret")
	b, err := o.Encode()
	if err != nil || o.V != VersionReal || VersionReal <= VersionModes || !strings.Contains(string(b), `"v":4,`) {
		t.Fatalf("with a Real: version %d, %v, %s; want %d, above every version an older build reads", o.V, err, b, VersionReal)
	}
	for _, v := range []int{Version, VersionTimed, VersionModes} {
		old := strings.Replace(string(b), `"v":4,`, `"v":`+strconv.Itoa(v)+`,`, 1)
		if _, err := Decode([]byte(old), testRun); !errors.Is(err, ErrInvalid) {
			t.Errorf("a version %d file holding a real path: %v, want ErrInvalid", v, err)
		}
	}
	o.Blocks[0].Real = ""
	if again, err := o.Encode(); err != nil || string(again) != string(plain) {
		t.Fatalf("Real dropped: %s, %v; want the version %d bytes %s", again, err, Version, plain)
	}
}

// TestAddReal: the second step of a block's add stores the real path only for a run whose launcher made the mark
// (TakesReal), reports it as Uncovered for an older one and leaves the file as it was, says Unknown for a value whose
// walk runs out of budget, and leaves an exec block and a block no longer held alone.
func TestAddReal(t *testing.T) {
	root := realTree(t)
	ctx := context.Background()
	value, want := root+"/home/link/secret", root+"/data/secret"
	add := func(t *testing.T, dir string, kind Kind, value string) Entry {
		t.Helper()
		var held Entry
		if _, err := Update(ctx, dir, testRun, func(o *Overlay) (bool, error) {
			_, ok, err := o.Add(kind, value, "uid:1 pid:2 cli", time.Now())
			held, _ = o.Find(kind, value)
			return ok, err
		}); err != nil {
			t.Fatal(err)
		}
		return held
	}
	t.Run("an older launcher", func(t *testing.T) {
		dir := t.TempDir()
		got, err := AddReal(ctx, dir, testRun, KindPath, value, add(t, dir, KindPath, value))
		if err != nil || got != (RealOutcome{Uncovered: want}) {
			t.Fatalf("AddReal = %+v, %v; want Uncovered %q", got, err, want)
		}
		if o, err := Read(dir, testRun); err != nil || o.V != Version || o.Blocks[0].Real != "" {
			t.Fatalf("overlay %+v, %v: an older launcher's run must keep a version %d file", o, err, Version)
		}
	})
	t.Run("a launcher that reads it", func(t *testing.T) {
		dir := t.TempDir()
		if err := MarkReal(dir); err != nil {
			t.Fatal(err)
		}
		held := add(t, dir, KindRead, value)
		got, err := AddReal(ctx, dir, testRun, KindRead, value, held)
		if err != nil || got != (RealOutcome{Real: want}) {
			t.Fatalf("AddReal = %+v, %v; want Real %q", got, err, want)
		}
		o, err := Read(dir, testRun)
		if err != nil || o.V != VersionReal || o.Blocks[0].Real != want || o.Serial != 1 {
			t.Fatalf("overlay %+v, %v; want the Real at version %d and one change", o, err, VersionReal)
		}
		held.Real = want
		if again, err := AddReal(ctx, dir, testRun, KindRead, value, held); err != nil || again.Real != want {
			t.Fatalf("a held Real: %+v, %v", again, err)
		}
		if got, err := AddReal(ctx, dir, testRun, KindExec, value, Entry{Kind: KindExec, Value: value}); err != nil || got != (RealOutcome{}) {
			t.Fatalf("an exec block: %+v, %v; want nothing", got, err)
		}
		if got, err := AddReal(ctx, dir, testRun, KindPath, value, Entry{}); err != nil || got != (RealOutcome{}) {
			t.Fatalf("a block no longer held: %+v, %v; want nothing", got, err)
		}
	})
	t.Run("out of budget", func(t *testing.T) {
		dir := t.TempDir()
		if err := MarkReal(dir); err != nil {
			t.Fatal(err)
		}
		chain := chainTree(t, 20, 700)
		got, err := AddReal(ctx, dir, testRun, KindPath, chain, add(t, dir, KindPath, chain))
		if err != nil || got != (RealOutcome{Unknown: true}) {
			t.Fatalf("AddReal = %+v, %v; want Unknown", got, err)
		}
		if o, err := Read(dir, testRun); err != nil || len(o.Blocks) != 1 || o.Blocks[0].Real != "" {
			t.Fatalf("overlay %+v, %v: want the block in force with its value alone", o, err)
		}
	})
}

// TestValidateReal: a file whose Real is on an exec or net block, not normalized, or its own value is invalid, so a
// reader keeps the blocks it last put in force (fail closed).
func TestValidateReal(t *testing.T) {
	for _, e := range []Entry{
		{Kind: KindExec, Value: "/usr/bin/curl", Real: "/usr/bin/x"},
		{Kind: KindNet, Value: "example.com", Real: "/x"},
		{Kind: KindPath, Value: "/a", Real: "/b/../c"},
		{Kind: KindPath, Value: "/a", Real: "b"},
		{Kind: KindPath, Value: "/a", Real: "/a"},
	} {
		o := New(testRun)
		o.V = VersionReal // invalid for the Real itself, not for the version
		e.By, e.At = "uid:1 pid:2 cli", t0
		o.Blocks = []Entry{e}
		if err := o.Validate(testRun); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: Validate %v, want ErrInvalid", e, err)
		}
	}
}

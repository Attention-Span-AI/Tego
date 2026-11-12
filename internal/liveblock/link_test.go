// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestLinkBlockAsksTheGrant: a block that matches by link (MatchLink, "Also apply now" of an exec.allow entry removed)
// refuses exactly what the running contract grants under the entry at its value (Grant), whatever names or identity
// the exec has: another name of a multi-call file that the entry does not grant is left to the contract, though it is
// the same file, and an exec the entry grants is refused by any name. Where the contract holds no entry at the value
// (no Grant, or one that holds none), the block matches the whole file, as a person's block by path always does.
func TestLinkBlockAsksTheGrant(t *testing.T) {
	const ls, sleep = "/usr/bin/ls", "/usr/bin/sleep"
	file := FileID{Dev: 8, Ino: 42} // ls and sleep are one file
	res := Resolved{Files: map[string]FileID{ls: file}}
	link := New(testRun)
	if _, ok, err := link.AddLink(KindExec, ls, "uid:1 pid:2 dashboard", t0); !ok || err != nil {
		t.Fatalf("AddLink = %v, %v", ok, err)
	}
	if e, _ := link.Find(KindExec, ls); e.Match != MatchLink {
		t.Fatalf("the block's match is %q, want %q", e.Match, MatchLink)
	}
	whole := New(testRun)
	if _, _, err := whole.Add(KindExec, ls, "uid:1 pid:2 cli", t0); err != nil {
		t.Fatal(err)
	}
	linkSet, wholeSet := Compile(link, res), Compile(whole, res)

	var asked []string
	grantIf := func(grants bool) Grant {
		return func(v string) (bool, bool) {
			asked = append(asked, v)
			return true, grants
		}
	}
	none := func(string) (bool, bool) { return false, false }
	for _, c := range []struct {
		name  string
		names []string
		g     Grant
		link  bool // the link block refuses it
	}{
		{"what the entry grants, by its name", []string{ls}, grantIf(true), true},
		{"what the entry grants, by a descriptor", []string{"/proc/self/fd/9", "/opt/elsewhere/xls"}, grantIf(true), true},
		{"sleep, the same file, which the entry does not grant", []string{sleep}, grantIf(false), false},
		{"the value's own name, which the entry does not grant now", []string{ls}, grantIf(false), false},
		{"no entry at the value: the whole file", []string{sleep}, none, true},
		{"no grant at all: the whole file", []string{sleep}, nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			asked = nil
			e, ok := linkSet.MatchExec(c.names, file, true, c.g)
			if ok != c.link {
				t.Errorf("link block: matched %v, want %v", ok, c.link)
			}
			if ok && e.Rule() != "live.block[exec:"+ls+"]" {
				t.Errorf("refused under %s", e.Rule())
			}
			if c.g != nil && len(asked) > 0 && asked[0] != ls {
				t.Errorf("the grant was asked of %q, want the block's value", asked[0])
			}
			if _, ok := wholeSet.MatchExec(c.names, file, true, c.g); !ok {
				t.Error("a whole-file block must refuse every name of the file, whatever the contract grants")
			}
		})
	}
	// With no walk at all, a name equal to the value is refused where no entry is held.
	if _, ok := linkSet.MatchExec([]string{ls}, FileID{}, false, none); !ok {
		t.Errorf("%s by name, no entry held: not refused", ls)
	}
}

// TestAddLinkOnlyNarrows: a link block is never made of a block that refuses the whole file, a person's add of a held
// link block widens it to the whole file (it refuses more), and a value that cannot match by link (a bare name, a
// folder, another kind) is added as Add adds it.
func TestAddLinkOnlyNarrows(t *testing.T) {
	o := New(testRun)
	if _, _, err := o.Add(KindExec, "/bin/ls", "cli", t0); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := o.AddLink(KindExec, "/bin/ls", "dashboard", t0); ok || err != nil {
		t.Fatalf("AddLink over a whole-file block = %v, %v; want no change", ok, err)
	}
	if e, _ := o.Find(KindExec, "/bin/ls"); e.Match != "" {
		t.Fatalf("a whole-file block was narrowed to %q", e.Match)
	}

	o = New(testRun)
	if _, _, err := o.AddLink(KindExec, "/bin/ls", "dashboard", t0); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := o.AddLink(KindExec, "/bin/ls", "dashboard", t0); ok {
		t.Error("a second AddLink changed the overlay")
	}
	c, ok, err := o.Add(KindExec, "/bin/ls", "cli", t0)
	if !ok || err != nil || c.Op != OpAdd {
		t.Fatalf("a person's add over a link block = %+v, %v, %v; want a recorded add", c, ok, err)
	}
	if e, _ := o.Find(KindExec, "/bin/ls"); e.Match != "" {
		t.Errorf("after a person's add the block matches %q, want the whole file", e.Match)
	}

	for _, v := range []struct {
		k Kind
		v string
	}{{KindExec, "ls"}, {KindExec, "/opt/tools/"}, {KindPath, "/srv/x"}} {
		o := New(testRun)
		if _, _, err := o.AddLink(v.k, v.v, "dashboard", t0); err != nil {
			t.Fatal(err)
		}
		if o.Blocks[0].Match != "" || o.MinVersion() != Version {
			t.Errorf("%s:%s: match %q at version %d, want a plain block", v.k, v.v, o.Blocks[0].Match, o.MinVersion())
		}
	}
}

// TestLinkNeedsItsVersion: an overlay that holds a link block is written at VersionLink, which a launcher that predates
// it refuses (it reads up to VersionReal) instead of reading the block as a whole-file one or dropping it; a file that
// claims an older version, an unknown match, or a match on what cannot match by link is invalid; and dropping the
// match goes back to the lowest version.
func TestLinkNeedsItsVersion(t *testing.T) {
	o := New(testRun)
	if _, _, err := o.Add(KindExec, "/bin/ls", "cli", t0); err != nil {
		t.Fatal(err)
	}
	plain, err := o.Encode()
	if err != nil || o.V != Version {
		t.Fatalf("no match: version %d, %v", o.V, err)
	}
	o.Blocks[0].Match = MatchLink
	b, err := o.Encode()
	if err != nil || o.V != VersionLink || VersionLink <= VersionReal || !strings.Contains(string(b), `"v":5,`) ||
		!strings.Contains(string(b), `"match":"link"`) {
		t.Fatalf("with a match: version %d, %v, %s; want %d, above every version an older launcher reads", o.V, err, b, VersionLink)
	}
	back, err := Decode(b, testRun)
	if err != nil || back.Blocks[0].Match != MatchLink {
		t.Fatalf("round trip: %+v, %v", back, err)
	}
	for _, v := range []int{Version, VersionTimed, VersionModes, VersionReal} {
		old := strings.Replace(string(b), `"v":5,`, `"v":`+strconv.Itoa(v)+`,`, 1)
		if _, err := Decode([]byte(old), testRun); !errors.Is(err, ErrInvalid) {
			t.Errorf("a version %d file holding a match: %v, want ErrInvalid", v, err)
		}
	}
	for name, body := range map[string]string{
		"unknown match":   strings.Replace(string(b), `"match":"link"`, `"match":"name"`, 1),
		"match on a name": strings.ReplaceAll(string(b), `"/bin/ls"`, `"ls"`),
		"match on a dir":  strings.ReplaceAll(string(b), `"/bin/ls"`, `"/bin/"`),
		"match on a path": strings.ReplaceAll(string(b), `"kind":"exec"`, `"kind":"path"`),
	} {
		if _, err := Decode([]byte(body), testRun); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	o.Blocks[0].Match = ""
	if again, err := o.Encode(); err != nil || string(again) != string(plain) {
		t.Fatalf("match dropped: %s, %v; want %s", again, err, plain)
	}
}

// TestTakesLink: the launcher's mark that it reads a link block, as MarkReal's.
func TestTakesLink(t *testing.T) {
	dir := t.TempDir()
	if TakesLink(dir) {
		t.Fatal("a run directory with no mark takes a link block")
	}
	if err := MarkLink(dir); err != nil {
		t.Fatal(err)
	}
	if !TakesLink(dir) || TakesReal(dir) || TakesControl(dir) {
		t.Fatal("the link mark must say that and nothing else")
	}
	other := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, LinkName), filepath.Join(other, LinkName)); err != nil {
		t.Fatal(err)
	}
	if TakesLink(other) {
		t.Error("a symbolic link stands for the mark")
	}
}

// TestSameFileNote: a refusal under an absolute exec block of a path other than the block's own is said as the same
// program file; every other line, none.
func TestSameFileNote(t *testing.T) {
	const want = "same program file as /bin/ls, which is blocked"
	for _, c := range []struct {
		rule, path, want string
	}{
		{"live.block[exec:/bin/ls]", "/bin/sleep", want},
		{"live.block[exec:/bin/ls]", "/usr/bin/sleep", want},
		{"live.block[exec:/bin/ls]", "/home/u/proj/xls", want},
		{"live.block[exec:/bin/ls]", "/bin/ls", ""},
		{"live.block[exec:/bin/ls]", "/bin/./ls", ""},
		{"live.block[exec:/bin/ls]", "", ""},
		{"live.block[exec:/bin/ls]", "sleep", ""},
		{"live.block[exec:ls]", "/usr/bin/ls", ""},
		{"live.block[exec:/opt/tools/]", "/opt/tools/x", ""},
		{"live.fence[exec:/bin/ls]", "/bin/sleep", ""},
		{"live.block[path:/bin/ls]", "/bin/sleep", ""},
		{"exec[/bin/sleep]", "/bin/sleep", ""},
		{"live.block[exec:/bin/ls", "/bin/sleep", ""},
	} {
		if got := SameFileNote(c.rule, c.path); got != c.want {
			t.Errorf("SameFileNote(%q, %q) = %q, want %q", c.rule, c.path, got, c.want)
		}
	}
}

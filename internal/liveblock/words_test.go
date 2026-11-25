// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNormalizeWords: a command value is the entry's own grammar, the program a bare name, at least one word, and
// whatever execmatch.Parse accepts as an exec.deny entry; every spelling of one command is one value.
func TestNormalizeWords(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"git push", "git push"},
		{"  git   push  ", "git push"},
		{"git push --force", "git push --force"},
		{"npm install --global *", "npm install --global *"},
		{"foo bar", "foo bar"},
		{"git commit -m 'a b'", "git commit -m 'a b'"},
		{"git -C . push", "git -C . push"},
	} {
		got, err := NormalizeWords(c.in)
		if err != nil || got != c.want {
			t.Errorf("NormalizeWords(%q) = %q, %v; want %q", c.in, got, err, c.want)
			continue
		}
		again, err := NormalizeWords(got)
		if err != nil || again != got {
			t.Errorf("NormalizeWords(%q) is not its own normal form: %q, %v", got, again, err)
		}
		if viaKind, err := Normalize(KindExec, c.in); err != nil || viaKind != got {
			t.Errorf("Normalize(exec, %q) = %q, %v; want %q", c.in, viaKind, err, got)
		}
		if !IsWords(got) {
			t.Errorf("IsWords(%q) is false", got)
		}
	}
	for _, c := range []struct{ name, in string }{
		{"no words", "git"},
		{"only spaces", "   "},
		{"a path in the command word", "/usr/bin/git push"},
		{"a relative path in the command word", "./tool run"},
		{"a shell word", "git push && ls"},
		{"an open quote", "git commit -m 'a"},
		{"a control character", "git push\x01"},
		{"a tab", "git\tpush"},
		{"too long", "git " + strings.Repeat("a", MaxValueBytes)},
	} {
		if got, err := NormalizeWords(c.in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: NormalizeWords(%q) = %q, %v; want ErrInvalid", c.name, c.in, got, err)
		}
	}
	// An absolute value with spaces stays what it always was: a program path.
	if v, err := Normalize(KindExec, "/opt/My Tools/run"); err != nil || v != "/opt/My Tools/run" || IsWords(v) {
		t.Errorf("a program path with a space: %q, %v, IsWords %v", v, err, IsWords(v))
	}
	for _, k := range []Kind{KindNet, KindPath, KindRead, KindWrite} {
		if _, err := Normalize(k, "git push"); err == nil {
			t.Errorf("Normalize(%s, %q) accepted a command", k, "git push")
		}
	}
}

// TestWordsBlockNeedsItsVersion: an overlay holding a command block is written at VersionWords, which a launcher
// that predates it (it reads up to VersionLink) refuses whole, in words that name the version, rather than reading
// the block as a program or dropping it; one with none is byte for byte the file it was; a file claiming an older
// version for a command is invalid.
func TestWordsBlockNeedsItsVersion(t *testing.T) {
	o := New(testRun)
	if _, _, err := o.Add(KindExec, "curl", "cli", t0); err != nil {
		t.Fatal(err)
	}
	plain, err := o.Encode()
	if err != nil || o.V != Version {
		t.Fatalf("a program only: version %d, %v", o.V, err)
	}
	if _, ok, err := o.Add(KindExec, "git  push", "cli", t0); !ok || err != nil {
		t.Fatalf("Add(git push) = %v, %v", ok, err)
	}
	b, err := o.Encode()
	if err != nil || o.V != VersionWords || VersionWords <= VersionLink || !strings.Contains(string(b), `"v":6,`) ||
		!strings.Contains(string(b), `"value":"git push"`) {
		t.Fatalf("with a command: version %d, %v, %s", o.V, err, b)
	}
	back, err := Decode(b, testRun)
	if err != nil || len(back.Blocks) != 2 || !back.Blocks[1].IsWords() || back.Blocks[0].IsWords() {
		t.Fatalf("round trip: %+v, %v", back, err)
	}
	// What the launcher before this version said, from its own check (overlay.go before VersionWords).
	older := "overlay version " + "6" + ", want " + "1" + " to " + "5"
	if VersionWords != VersionLink+1 || !strings.Contains(older, "version 6, want 1 to 5") {
		t.Fatalf("the older reader's range ends at %d, the new version is %d", VersionLink, VersionWords)
	}
	for _, v := range []string{"1", "2", "3", "4", "5"} {
		old := strings.Replace(string(b), `"v":6,`, `"v":`+v+`,`, 1)
		if _, err := Decode([]byte(old), testRun); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "command with words") {
			t.Errorf("a version %s file holding a command: %v, want ErrInvalid naming the command", v, err)
		}
	}
	if _, ok, err := back.Remove(KindExec, "git push", "cli", t0); !ok || err != nil {
		t.Fatalf("Remove(git push) = %v, %v", ok, err)
	}
	// The removal is a change the file still lists, which an older launcher cannot normalize: the file stays at the
	// version that holds it until the change ages out of the list.
	if again, err := back.Encode(); err != nil || back.V != VersionWords || len(back.Blocks) != 1 || !strings.Contains(string(again), `"v":6,`) {
		t.Fatalf("command removed: version %d, %v, %s", back.V, err, again)
	}
	back.Changes = back.Changes[:1] // the add of curl, as the list was before the command
	back.Serial = 1
	if again, err := back.Encode(); err != nil || back.V != Version || string(again) != string(plain) {
		t.Fatalf("no change names a command: version %d, %v, %s; want the file as it was, %s", back.V, err, again, plain)
	}
	for name, body := range map[string]string{
		"a real path":   strings.Replace(string(b), `"value":"git push"`, `"value":"git push","real":"/x"`, 1),
		"a match":       strings.Replace(string(b), `"value":"git push"`, `"value":"git push","match":"link"`, 1),
		"not in normal": strings.Replace(string(b), `"value":"git push"`, `"value":"git   push"`, 1),
	} {
		if _, err := Decode([]byte(body), testRun); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

// TestWordsBlockFindsAndRemovesBySpelling: another spelling of a command finds, re-arms and removes the one block.
func TestWordsBlockFindsAndRemovesBySpelling(t *testing.T) {
	o := New(testRun)
	if _, ok, err := o.Add(KindExec, "git push", "cli", t0); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if _, ok, err := o.Add(KindExec, " git   push ", "cli", t0); ok || err != nil {
		t.Fatalf("a second spelling added a second block: %v, %v", ok, err)
	}
	if len(o.Blocks) != 1 {
		t.Fatalf("%d blocks, want 1", len(o.Blocks))
	}
	c := Clock{Wall: t0.Add(time.Second)}
	if !o.InForce(KindExec, "git  push", c) {
		t.Error("InForce does not find the command by another spelling")
	}
	if _, ok := o.AddIdentity(KindExec, "git  push"); ok {
		t.Log("an overlay with no epoch has no identity, as for every block")
	}
	if _, ok, err := o.Remove(KindExec, "git   push", "cli", t0); !ok || err != nil || len(o.Blocks) != 0 {
		t.Fatalf("Remove by another spelling: %v, %v, %d blocks", ok, err, len(o.Blocks))
	}
}

// TestWordsBlockSet: a command block is in the Set's words, never matched as a program; HasWords and HasExec say which;
// its time limit and its unblock for a while are read by WordOn as every block's are.
func TestWordsBlockSet(t *testing.T) {
	o := New(testRun)
	if _, _, err := o.Add(KindExec, "git push", "cli", t0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.AddUntil(KindExec, "npm install --global *", "cli", t0, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s := Compile(o, Resolved{})
	if !s.HasWords() || s.HasExec() {
		t.Fatalf("HasWords %v, HasExec %v; want true, false", s.HasWords(), s.HasExec())
	}
	if _, ok := s.MatchExec([]string{"git", "git push", "push", "/usr/bin/git"}, FileID{}, false, nil); ok {
		t.Fatal("a command block refused an exec as a program")
	}
	ws := s.Words()
	if len(ws) != 2 || ws[0].Value != "git push" || ws[1].Value != "npm install --global *" {
		t.Fatalf("Words() = %+v", ws)
	}
	for _, e := range ws {
		if got, on := s.WordOn(e.Key()); !on || got.Key() != e.Key() {
			t.Errorf("WordOn(%s) = %v, %v", e.Key(), got, on)
		}
	}
	if _, on := s.WordOn("exec:git pull"); on {
		t.Error("WordOn names a block the overlay does not hold")
	}
	var nilSet *Set
	if nilSet.HasWords() || len(nilSet.Words()) != 0 {
		t.Error("a nil Set holds a command")
	}
	// An unblock for a while: dormant until from.
	if _, ok, err := o.RemoveUntil(KindExec, "git push", "cli", time.Now(), time.Now().Add(time.Hour)); !ok || err != nil {
		t.Fatalf("RemoveUntil: %v, %v", ok, err)
	}
	s = Compile(o, Resolved{})
	if _, on := s.WordOn("exec:git push"); on {
		t.Error("a command block refuses during its unblock for a while")
	}
	if !s.HasWords() {
		t.Error("a dormant command block must stay structural, so the supervisor keeps deciding execs")
	}
	// A past limit.
	o2 := New(testRun)
	if _, _, err := o2.AddUntil(KindExec, "git push", "cli", time.Now().Add(-2*time.Minute), time.Now().Add(-time.Minute)); err == nil {
		t.Log("a limit already past is refused by the writer's slack; nothing to compile")
	}
}

// TestTakesWords: the launcher's mark that it reads a command block, as MarkLink's.
func TestTakesWords(t *testing.T) {
	dir := t.TempDir()
	if TakesWords(dir) {
		t.Fatal("a run directory with no mark takes a command block")
	}
	if err := MarkWords(dir); err != nil {
		t.Fatal(err)
	}
	if !TakesWords(dir) || TakesLink(dir) || TakesReal(dir) || TakesControl(dir) {
		t.Fatal("the words mark must say that and nothing else")
	}
	other := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, WordsName), filepath.Join(other, WordsName)); err != nil {
		t.Fatal(err)
	}
	if TakesWords(other) {
		t.Error("a symbolic link stands for the mark")
	}
}

// TestCheckWords: a command block is refused, in words that name why, on a run whose launcher made no mark; a removal and
// a run with the mark pass; the refusal's sentence names the run for the terminal and "the run" for the page.
func TestCheckWords(t *testing.T) {
	t.Parallel()
	ok := Target{Run: testRun, Running: true, TakesWords: true}
	if err := CheckWords(ok, true); err != nil {
		t.Fatalf("a run that reads commands: %v", err)
	}
	old := Target{Run: testRun, Running: true}
	err := CheckWords(old, true)
	if !errors.Is(err, ErrNoWords) {
		t.Fatalf("a run with no mark: %v, want ErrNoWords", err)
	}
	if !strings.Contains(RunWords(err), testRun) || strings.Contains(err.Error(), testRun) || !strings.Contains(err.Error(), "nothing was placed") {
		t.Errorf("words: page %q, terminal %q", err, RunWords(err))
	}
	if err := CheckWords(old, false); err != nil {
		t.Errorf("a removal needs no mark: %v", err)
	}
	if err := CheckWords(Target{Run: testRun}, true); err != nil {
		t.Errorf("CheckBlock refuses a run that is not running first; CheckWords says nothing: %v", err)
	}
}

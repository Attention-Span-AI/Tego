// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

const (
	textA = "version: 0\nname: demo\n# keep me\nfs:\n  read: [./]\n"
	textB = "version: 0\nname: demo\n# keep me\nfs:\n  read: [./]\n  deny_read: [./secret.txt]\n"
	textC = "version: 0\nname: demo\n# keep me\nfs:\n  read: [./]\n  deny_read: [./secret.txt, ./token]\n"
)

// fixture is a ledger root and, in a folder of its own, a contract holding textA (mode 0600); the guard refuses a
// tego home under the test's temp directory too.
func fixture(t *testing.T) (Guard, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "ledger")
	proj := filepath.Join(base, "proj")
	for _, d := range []string{root, proj} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(proj, "agent.yaml")
	if err := os.WriteFile(path, []byte(textA), 0o600); err != nil {
		t.Fatal(err)
	}
	return Guard{LedgerRoot: root, Refuse: []string{filepath.Join(base, "home", ".tego")}}, path
}

// setHook installs hook for the test.
func setHook(t *testing.T, fn func(string) error) {
	t.Helper()
	hook = fn
	t.Cleanup(func() { hook = nil })
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestReplaceWritesBakAndJournal: a write lands the new text with the old mode, keeps .bak, journals the change with
// both texts as blobs, and leaves no temporary file.
func TestReplaceWritesBakAndJournal(t *testing.T) {
	g, path := fixture(t)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	e, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{Via: "cli", Run: "r-x", Line: 3, Summary: "block"})
	if err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, path); got != textB {
		t.Errorf("file holds %q", got)
	}
	if got := mustRead(t, path+".bak"); got != textA {
		t.Errorf(".bak holds %q", got)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, %v; want 0640", st.Mode(), err)
	}
	if e.Bak != path+".bak" || e.Op != OpChange || e.OldSHA256 != Sum([]byte(textA)) || e.NewSHA256 != Sum([]byte(textB)) ||
		e.Contract != path || e.Via != "cli" || e.Run != "r-x" || e.Line != 3 || !strings.HasPrefix(e.ID, "rc-") {
		t.Errorf("entry %+v", e)
	}
	for _, s := range []string{textA, textB} {
		if b, err := Blob(g.LedgerRoot, Sum([]byte(s))); err != nil || string(b) != s {
			t.Errorf("blob of %q: %q, %v", s, b, err)
		}
	}
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ents {
		if d.Name() != "agent.yaml" && d.Name() != "agent.yaml.bak" {
			t.Errorf("left behind %s", d.Name())
		}
	}
	st, err = os.Stat(filepath.Join(g.LedgerRoot, JournalDirName))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("journal dir %v, %v", st.Mode(), err)
	}
}

// TestReadRefuses: every file and folder the guards refuse, each with ErrGuard and nothing written.
func TestReadRefuses(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, g *Guard, path string) string // returns the path to try
		want  string
	}{
		{"symlink file", func(t *testing.T, _ *Guard, path string) string {
			l := filepath.Join(filepath.Dir(path), "link.yaml")
			if err := os.Symlink(path, l); err != nil {
				t.Fatal(err)
			}
			return l
		}, "is a symlink"},
		{"hard link", func(t *testing.T, _ *Guard, path string) string {
			if err := os.Link(path, filepath.Join(filepath.Dir(path), "other.yaml")); err != nil {
				t.Fatal(err)
			}
			return path
		}, "hard links"},
		{"foreign owner", func(t *testing.T, _ *Guard, path string) string {
			uid := os.Geteuid()
			geteuid = func() int { return uid + 4242 }
			t.Cleanup(func() { geteuid = os.Geteuid })
			return path
		}, "owned by uid"},
		{"world-writable file", func(t *testing.T, _ *Guard, path string) string {
			if err := os.Chmod(path, 0o602); err != nil {
				t.Fatal(err)
			}
			return path
		}, "writable by every user"},
		{"group-writable, not a private group", func(t *testing.T, _ *Guard, path string) string {
			if err := os.Chmod(path, 0o620); err != nil {
				t.Fatal(err)
			}
			groupDB(t, fmt.Sprintf("me:x:%d:someone\n", os.Getegid()))
			return path
		}, "not your private group"},
		{"world-writable folder", func(t *testing.T, _ *Guard, path string) string {
			if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
				t.Fatal(err)
			}
			return path
		}, "not sticky"},
		{"under the ledger root", func(t *testing.T, g *Guard, _ string) string {
			p := filepath.Join(g.LedgerRoot, "agent.yaml")
			if err := os.WriteFile(p, []byte(textA), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}, "tego's own"},
		{"under tego's home", func(t *testing.T, g *Guard, _ string) string {
			if err := os.MkdirAll(g.Refuse[0], 0o700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(g.Refuse[0], "agent.yaml")
			if err := os.WriteFile(p, []byte(textA), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}, "tego's own"},
		{"too large", func(t *testing.T, _ *Guard, path string) string {
			if err := os.WriteFile(path, []byte(strings.Repeat("#", agent.MaxContractSize+1)), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}, "more than a contract"},
		{"relative path", func(*testing.T, *Guard, string) string { return "proj/agent.yaml" }, "not an absolute path"},
		{"a folder", func(_ *testing.T, _ *Guard, path string) string { return filepath.Dir(path) }, "not a regular file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, path := fixture(t)
			p := tc.setup(t, &g, path)
			before, _ := os.ReadFile(p)
			_, err := Read(p, g)
			if !errors.Is(err, ErrGuard) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Read: %v; want ErrGuard with %q", err, tc.want)
			}
			if _, err := Replace(context.Background(), g, p, Sum(before), []byte(textB), Change{}); !errors.Is(err, ErrGuard) {
				t.Fatalf("Replace: %v; want ErrGuard", err)
			}
			if after, _ := os.ReadFile(p); string(after) != string(before) {
				t.Error("a refused write changed the file")
			}
			if es, _ := ReadJournal(g.LedgerRoot); len(es) != 0 {
				t.Errorf("a refused write was journaled: %+v", es)
			}
		})
	}
}

// groupDB points the private-group test at a group file holding rows and a passwd file naming this user with this
// group as primary.
func groupDB(t *testing.T, rows string) {
	t.Helper()
	d := t.TempDir()
	gf, pf := filepath.Join(d, "group"), filepath.Join(d, "passwd")
	if err := os.WriteFile(gf, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	pw := fmt.Sprintf("root:x:0:0:root:/root:/bin/sh\nme:x:%d:%d::/home/me:/bin/sh\n", os.Geteuid(), os.Getegid())
	if os.Geteuid() == 0 {
		pw = fmt.Sprintf("me:x:0:%d::/home/me:/bin/sh\n", os.Getegid())
	}
	if err := os.WriteFile(pf, []byte(pw), 0o600); err != nil {
		t.Fatal(err)
	}
	groupFile, passwdFile = gf, pf
	t.Cleanup(func() { groupFile, passwdFile = "/etc/group", "/etc/passwd" })
}

// TestPrivateGroup: a group-writable contract is accepted only when its group is the user's private group.
func TestPrivateGroup(t *testing.T) {
	gid, uid := uint32(os.Getegid()), uint32(os.Geteuid())
	tests := []struct {
		name, group string
		extraPasswd string
		want        bool
	}{
		{"private", fmt.Sprintf("me:x:%d:\n", gid), "", true},
		{"private, listing the user", fmt.Sprintf("me:x:%d:me\n", gid), "", true},
		{"another member", fmt.Sprintf("me:x:%d:me,bob\n", gid), "", false},
		{"not named", "other:x:99999:\n", "", false},
		{"another user's primary group", fmt.Sprintf("me:x:%d:\n", gid), fmt.Sprintf("bob:x:%d:%d::/home/bob:/bin/sh\n", uid+7, gid), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			groupDB(t, tc.group)
			if tc.extraPasswd != "" {
				b, _ := os.ReadFile(passwdFile)
				if err := os.WriteFile(passwdFile, append(b, tc.extraPasswd...), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := privateGroup(gid, uid); got != tc.want {
				t.Errorf("privateGroup = %v, want %v", got, tc.want)
			}
		})
	}
	if privateGroup(gid+1, uid) {
		t.Error("a group other than the process's is private")
	}
	// The demo's case: a 0664 contract written under umask 0002 by a user with a private group is changed.
	g, path := fixture(t)
	groupDB(t, fmt.Sprintf("me:x:%d:\n", gid))
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{}); err != nil {
		t.Fatalf("0664 with a private group: %v", err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o664 {
		t.Errorf("mode %v, want 0664 kept", st.Mode())
	}
}

// TestStickyWorldWritableFolderOK: a world-writable folder is accepted when it is sticky, as /tmp is.
func TestStickyWorldWritableFolderOK(t *testing.T) {
	g, path := fixture(t)
	if err := os.Chmod(filepath.Dir(path), os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, g); err != nil {
		t.Fatal(err)
	}
}

// TestSymlinkedHomeWorks: a contract reached through a symlinked folder (a symlinked home) is resolved once and
// written in the real folder.
func TestSymlinkedHomeWorks(t *testing.T) {
	g, path := fixture(t)
	link := filepath.Join(filepath.Dir(g.LedgerRoot), "home-link")
	if err := os.Symlink(filepath.Dir(path), link); err != nil {
		t.Fatal(err)
	}
	via := filepath.Join(link, "agent.yaml")
	f, err := Read(via, g)
	if err != nil {
		t.Fatal(err)
	}
	if f.Path != path {
		t.Errorf("resolved to %s, want %s", f.Path, path)
	}
	if _, err := Replace(context.Background(), g, via, f.SHA256, []byte(textB), Change{}); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, path); got != textB {
		t.Errorf("file holds %q", got)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced")
	}
}

// TestParentSwappedAfterResolve: a folder swapped for a symlink between the resolve and the pin is refused.
func TestParentSwappedAfterResolve(t *testing.T) {
	g, path := fixture(t)
	proj := filepath.Dir(path)
	decoy := filepath.Join(filepath.Dir(proj), "decoy")
	if err := os.Mkdir(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	setHook(t, func(s string) error {
		if s == "resolved" {
			if err := os.Rename(proj, proj+".moved"); err != nil {
				return err
			}
			return os.Symlink(decoy, proj)
		}
		return nil
	})
	_, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{})
	if !errors.Is(err, ErrGuard) {
		t.Fatalf("Replace: %v; want ErrGuard", err)
	}
	if ents, _ := os.ReadDir(decoy); len(ents) != 0 {
		t.Errorf("wrote into the symlink's target: %v", ents)
	}
	if got := mustRead(t, filepath.Join(proj+".moved", "agent.yaml")); got != textA {
		t.Errorf("the real file holds %q", got)
	}
}

// TestParentSwappedAfterPin: a folder swapped for a symlink after the pin changes nothing: the write lands in the
// pinned folder, wherever it was moved, and never in the symlink's target.
func TestParentSwappedAfterPin(t *testing.T) {
	g, path := fixture(t)
	proj := filepath.Dir(path)
	decoy := filepath.Join(filepath.Dir(proj), "decoy")
	if err := os.Mkdir(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(decoy, "agent.yaml"), []byte(textA), 0o600); err != nil {
		t.Fatal(err)
	}
	setHook(t, func(s string) error {
		if s == "read" {
			if err := os.Rename(proj, proj+".moved"); err != nil {
				return err
			}
			return os.Symlink(decoy, proj)
		}
		return nil
	})
	if _, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{}); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, filepath.Join(decoy, "agent.yaml")); got != textA {
		t.Errorf("the decoy holds %q", got)
	}
	if _, err := os.Stat(filepath.Join(decoy, "agent.yaml.bak")); err == nil {
		t.Error("a .bak was written in the decoy")
	}
	if got := mustRead(t, filepath.Join(proj+".moved", "agent.yaml")); got != textB {
		t.Errorf("the pinned file holds %q", got)
	}
}

// TestFaultLeavesOld: a write that fails at any step leaves the old text in place, no temporary file, and no
// journal line.
func TestFaultLeavesOld(t *testing.T) {
	for _, at := range []string{"bak", "temp", "rename"} {
		t.Run(at, func(t *testing.T) {
			g, path := fixture(t)
			setHook(t, func(s string) error {
				if s == at {
					return errors.New("injected fault")
				}
				return nil
			})
			_, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{})
			if err == nil || !strings.Contains(err.Error(), "injected fault") {
				t.Fatalf("Replace: %v", err)
			}
			if got := mustRead(t, path); got != textA {
				t.Errorf("file holds %q", got)
			}
			ents, _ := os.ReadDir(filepath.Dir(path))
			for _, d := range ents {
				if strings.Contains(d.Name(), ".tego-rule-") {
					t.Errorf("left behind %s", d.Name())
				}
			}
			if es, _ := ReadJournal(g.LedgerRoot); len(es) != 0 {
				t.Errorf("journaled %+v", es)
			}
		})
	}
}

// TestJournalFaultSaysWritten: a journal that cannot be written after the file was replaced is ErrJournal, and the
// error says the file holds the new text and where the old one is.
func TestJournalFaultSaysWritten(t *testing.T) {
	g, path := fixture(t)
	setHook(t, func(s string) error {
		if s == "journal" {
			return errors.New("disk full")
		}
		return nil
	})
	e, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{})
	if !errors.Is(err, ErrJournal) || e == nil || !strings.Contains(err.Error(), ".bak") {
		t.Fatalf("Replace: %v, %+v", err, e)
	}
	if got := mustRead(t, path); got != textB {
		t.Errorf("file holds %q", got)
	}
}

// TestConcurrentReaderOldOrNew: while one writer replaces the file again and again, a reader always sees one whole
// text, never a part.
func TestConcurrentReaderOldOrNew(t *testing.T) {
	g, path := fixture(t)
	done := make(chan struct{})
	var bad []string
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			b, err := os.ReadFile(path)
			if err != nil {
				bad = append(bad, err.Error())
				continue
			}
			if s := string(b); s != textA && s != textB {
				bad = append(bad, s)
			}
		}
	})
	cur, next := textA, textB
	for range 40 {
		if _, err := Replace(context.Background(), g, path, Sum([]byte(cur)), []byte(next), Change{}); err != nil {
			close(done)
			wg.Wait()
			t.Fatal(err)
		}
		cur, next = next, cur
	}
	close(done)
	wg.Wait()
	if len(bad) > 0 {
		t.Errorf("the reader saw %d reads that were neither text, first %q", len(bad), bad[0])
	}
}

// TestTwoWritersOneWins: two writers from the same base: one lands, the other is ErrStale and writes nothing.
func TestTwoWritersOneWins(t *testing.T) {
	g, path := fixture(t)
	base := Sum([]byte(textA))
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, text := range []string{textB, textC} {
		wg.Go(func() {
			_, errs[i] = Replace(context.Background(), g, path, base, []byte(text), Change{})
		})
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrStale):
			t.Errorf("loser: %v; want ErrStale", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d writers won: %v", won, errs)
	}
	if got := mustRead(t, path); got != textB && got != textC {
		t.Errorf("file holds %q", got)
	}
	if es, _ := ReadJournal(g.LedgerRoot); len(es) != 1 {
		t.Errorf("journal has %d lines, want 1", len(es))
	}
}

// TestStaleBaseAndSame: a base the file no longer holds is ErrStale, the text it already holds ErrSame; neither
// writes.
func TestStaleBaseAndSame(t *testing.T) {
	g, path := fixture(t)
	if _, err := Replace(context.Background(), g, path, Sum([]byte("other")), []byte(textB), Change{}); !errors.Is(err, ErrStale) {
		t.Errorf("stale base: %v", err)
	}
	if _, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textA), Change{}); !errors.Is(err, ErrSame) {
		t.Errorf("same text: %v", err)
	}
	if got := mustRead(t, path); got != textA {
		t.Errorf("file holds %q", got)
	}
	if _, err := os.Stat(path + ".bak"); err == nil {
		t.Error("a .bak was written")
	}
}

// TestEditorBeforeRename: an editor that rewrites the file in place while the new text is being written (it takes no
// lock) is caught by the last read: ErrStale, and the editor's text stays.
func TestEditorBeforeRename(t *testing.T) {
	g, path := fixture(t)
	setHook(t, func(s string) error {
		if s == "temp" {
			return os.WriteFile(path, []byte(textC), 0o600)
		}
		return nil
	})
	if _, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{}); !errors.Is(err, ErrStale) {
		t.Fatalf("Replace: %v; want ErrStale", err)
	}
	if got := mustRead(t, path); got != textC {
		t.Errorf("file holds %q", got)
	}
}

// TestNoLedgerRootNoWrite: a write with nowhere to journal it is refused.
func TestNoLedgerRootNoWrite(t *testing.T) {
	g, path := fixture(t)
	g.LedgerRoot = ""
	if _, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{}); err == nil {
		t.Fatal("wrote with no journal")
	}
	if got := mustRead(t, path); got != textA {
		t.Errorf("file holds %q", got)
	}
}

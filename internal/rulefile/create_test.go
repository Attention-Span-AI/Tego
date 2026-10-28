// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCreateWritesOnceAndJournals: Create writes a new contract that Read accepts, journals it as op create with the
// text as a blob, and History lists it.
func TestCreateWritesOnceAndJournals(t *testing.T) {
	g, existing := fixture(t)
	path := filepath.Join(filepath.Dir(existing), "new.yaml")
	e, err := Create(context.Background(), g, path, []byte(textB), Change{Via: "dashboard", Summary: "set up demo"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Op != OpCreate || e.NewSHA256 != Sum([]byte(textB)) || e.OldSHA256 != "" || e.Bak != "" || e.Contract != path {
		t.Fatalf("entry = %+v", e)
	}
	f, err := Read(path, g)
	if err != nil {
		t.Fatalf("Read of the new file: %v", err)
	}
	if string(f.Text) != textB || f.Mode != createMode {
		t.Fatalf("file = %q mode %o", f.Text, f.Mode)
	}
	if b, err := Blob(g.LedgerRoot, e.NewSHA256); err != nil || string(b) != textB {
		t.Fatalf("blob = %q, %v", b, err)
	}
	h, err := History(g.LedgerRoot, path)
	if err != nil || len(h) != 1 || h[0].ID != e.ID {
		t.Fatalf("history = %+v, %v", h, err)
	}
	ents, _ := os.ReadDir(filepath.Dir(path))
	for _, d := range ents {
		if strings.Contains(d.Name(), ".tego-new-") {
			t.Errorf("a temporary file was left: %s", d.Name())
		}
	}
	// An Undo has nothing to undo: a creation is not reverted (the file would have to go).
	if _, err := Undo(context.Background(), g, path, RevertOptions{}); !errors.Is(err, ErrNoChange) {
		t.Errorf("Undo of a created file = %v, want ErrNoChange", err)
	}
}

// TestCreateNeverOverwrites: a file, a dangling link or a directory at the name refuses Create with ErrExists and
// leaves it as it was; a file that appears between the check and the move does too.
func TestCreateNeverOverwrites(t *testing.T) {
	g, existing := fixture(t)
	dir := filepath.Dir(existing)
	if _, err := Create(context.Background(), g, existing, []byte(textB), Change{}); !errors.Is(err, ErrExists) {
		t.Fatalf("over a file: %v", err)
	}
	if got := mustRead(t, existing); got != textA {
		t.Fatalf("the existing file changed: %q", got)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), g, link, []byte(textB), Change{}); !errors.Is(err, ErrExists) {
		t.Fatalf("over a dangling link: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "nowhere")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the link's target was created")
	}
	sub := filepath.Join(dir, "sub.yaml")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), g, sub, []byte(textB), Change{}); !errors.Is(err, ErrExists) {
		t.Fatalf("over a directory: %v", err)
	}
	race := filepath.Join(dir, "race.yaml")
	setHook(t, func(s string) error {
		if s == "rename" {
			return os.WriteFile(race, []byte("theirs\n"), 0o600)
		}
		return nil
	})
	if _, err := Create(context.Background(), g, race, []byte(textB), Change{}); !errors.Is(err, ErrExists) {
		t.Fatalf("a file that appeared meanwhile: %v", err)
	}
	if got := mustRead(t, race); got != "theirs\n" {
		t.Fatalf("the file that appeared was overwritten: %q", got)
	}
	if es, _ := ReadJournal(g.LedgerRoot); len(es) != 0 {
		t.Fatalf("a refused create was journaled: %+v", es)
	}
}

// TestCreateGuards: Create refuses a folder under the ledger root or tego's home, one that is not this user's or
// root's, one writable by every user, and a relative path; it journals nothing without a ledger root.
func TestCreateGuards(t *testing.T) {
	g, existing := fixture(t)
	base := filepath.Dir(filepath.Dir(existing))
	inLedger := filepath.Join(g.LedgerRoot, "agent.yaml")
	if _, err := Create(context.Background(), g, inLedger, []byte(textA), Change{}); !errors.Is(err, ErrGuard) {
		t.Errorf("under the ledger root: %v", err)
	}
	home := filepath.Join(base, "home", ".tego", "p")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), g, filepath.Join(home, "agent.yaml"), []byte(textA), Change{}); !errors.Is(err, ErrGuard) {
		t.Errorf("under tego's home: %v", err)
	}
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), g, filepath.Join(open, "agent.yaml"), []byte(textA), Change{}); !errors.Is(err, ErrGuard) {
		t.Errorf("a folder every user writes: %v", err)
	}
	if _, err := Create(context.Background(), g, "agent.yaml", []byte(textA), Change{}); !errors.Is(err, ErrGuard) {
		t.Errorf("a relative path: %v", err)
	}
	if _, err := Create(context.Background(), Guard{}, filepath.Join(filepath.Dir(existing), "x.yaml"), []byte(textA), Change{}); err == nil {
		t.Error("no ledger root: written unjournaled")
	}
	geteuid = func() int { return 4242 }
	t.Cleanup(func() { geteuid = os.Geteuid })
	if _, err := Create(context.Background(), g, filepath.Join(filepath.Dir(existing), "y.yaml"), []byte(textA), Change{}); !errors.Is(err, ErrGuard) {
		t.Errorf("another user's folder: %v", err)
	}
}

// TestCreateJournalFailure: a journal append that fails after the write is ErrJournal with the entry, and the file
// holds the text.
func TestCreateJournalFailure(t *testing.T) {
	g, existing := fixture(t)
	path := filepath.Join(filepath.Dir(existing), "j.yaml")
	setHook(t, func(s string) error {
		if s == "journal" {
			return errors.New("disk full")
		}
		return nil
	})
	e, err := Create(context.Background(), g, path, []byte(textB), Change{})
	if !errors.Is(err, ErrJournal) || e == nil {
		t.Fatalf("Create = %v, %v", e, err)
	}
	if got := mustRead(t, path); got != textB {
		t.Fatalf("file = %q", got)
	}
}

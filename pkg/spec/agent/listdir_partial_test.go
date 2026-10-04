// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// failListing makes every listing of dir return its first entry and then EIO, as getdents does on a failing
// disk or a network or FUSE file system, for the rest of the test.
func failListing(t *testing.T, dir string) {
	t.Helper()
	orig := readDirN
	readDirN = func(f *os.File, n int) ([]os.DirEntry, error) {
		es, err := orig(f, n)
		if f.Name() != dir {
			return es, err
		}
		slices.SortFunc(es, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
		return es[:min(1, len(es))], syscall.EIO
	}
	t.Cleanup(func() { readDirN = orig })
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestListDirKeepsAMidListingError: a listing that fails partway returns the entries read before the error
// and the error, not the entries alone. Dropped, the part read as the whole directory, with nothing left
// unread, so the .env scan said nothing of the names it never saw.
func TestListDirKeepsAMidListingError(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	failListing(t, dir)
	es, more, err := listDir(dir, 10)
	var partial *partialListError
	if len(es) != 1 || more || !errors.As(err, &partial) || !errors.Is(err, syscall.EIO) {
		t.Fatalf("listDir = %d entries, more %v, err %v; want 1 entry and a partial-listing EIO", len(es), more, err)
	}
}

// TestEnvScanSaysWhatItCouldNotRead: the built-in .env scan warns about a directory it listed only in part,
// and about one of the operator's it could not open, as it warns about a scan cut short; each left a .env
// file in it out of deny_read in silence.
func TestEnvScanSaysWhatItCouldNotRead(t *testing.T) {
	scanWarns := func(ds []Diagnostic, dir, what string) bool {
		return slices.ContainsFunc(ds, func(d Diagnostic) bool {
			return d.Code == CodeUnenforced && strings.Contains(d.Message, "could not read "+dir+" ("+what)
		})
	}
	t.Run("partial", func(t *testing.T) {
		f := newFixture(t)
		sub := filepath.Join(f.project, "sub")
		mkdir(t, sub)
		f.file(filepath.Join(sub, ".a"), "", 0o644) // sorts first, so the listing stops before .env
		f.file(filepath.Join(sub, ".env"), "SECRET=1\n", 0o600)
		failListing(t, sub)
		envs, _, _, unread := envFiles([]string{f.project}, time.Now().Add(time.Hour))
		if slices.Contains(envs, filepath.Join(sub, ".env")) || len(unread) != 1 {
			t.Fatalf("envFiles = %v, unread %v; want sub/.env unseen and sub named unread", envs, unread)
		}
		_, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\n"))
		if !scanWarns(ds, sub, "listed only in part: input/output error") {
			t.Errorf("compile must say the .env scan listed %s only in part:\n%s", sub, render(ds))
		}
	})
	t.Run("unopenable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root opens a mode-000 directory")
		}
		f := newFixture(t)
		sub := filepath.Join(f.project, "locked")
		mkdir(t, sub)
		f.file(filepath.Join(sub, ".env"), "SECRET=1\n", 0o600)
		if err := os.Chmod(sub, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
		_, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\n"))
		if !scanWarns(ds, sub, "could not open: permission denied") {
			t.Errorf("compile must say the .env scan could not open %s:\n%s", sub, render(ds))
		}
	})
	t.Run("clean", func(t *testing.T) {
		f := newFixture(t)
		if _, _, _, unread := envFiles([]string{f.project}, time.Now().Add(time.Hour)); len(unread) != 0 {
			t.Errorf("a scan that read everything names %v unread", unread)
		}
	})
}

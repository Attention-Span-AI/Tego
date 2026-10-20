// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMkdirTempAtRetriesATakenNameAndStopsOnAnyOtherError is dns_directory.go's mkdirTempAt (ADR 0023 C9's mkdirat
// beneath the verified /tmp, in place of os.MkdirTemp on its /proc/self/fd path): a name already taken, by a
// directory or anything else, is passed over for the next number; a parent with every name taken ends after its
// bounded tries; and any other mkdirat failure ends it at once with that errno.
func TestMkdirTempAtRetriesATakenNameAndStopsOnAnyOtherError(t *testing.T) {
	parent := t.TempDir()
	dir, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	if err := os.Mkdir(filepath.Join(parent, "tego-dns-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "tego-dns-2"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// numbers hands out seq in order, then its last value for ever, counting the calls.
	numbers := func(seq ...uint32) (func() uint32, *int) {
		calls := 0
		return func() uint32 {
			v := seq[min(calls, len(seq)-1)]
			calls++
			return v
		}, &calls
	}

	next, calls := numbers(1, 2, 3)
	name, err := mkdirTempAt(int(dir.Fd()), "tego-dns-", next)
	if err != nil || name != "tego-dns-3" || *calls != 3 {
		t.Fatalf("mkdirTempAt past two taken names = %q, %v after %d tries, want tego-dns-3 after 3", name, err, *calls)
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(parent, name), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		st.Mode&0o777 != 0o700 {
		t.Fatalf("made %s mode %#o (%v), want a 0700 directory", name, st.Mode, err)
	}

	next, calls = numbers(1)
	if name, err := mkdirTempAt(int(dir.Fd()), "tego-dns-", next); err == nil ||
		!strings.Contains(err.Error(), "too many names taken") || *calls != 10000 {
		t.Fatalf("mkdirTempAt with every name taken = %q, %v after %d tries, want its bound's error after 10000",
			name, err, *calls)
	}

	regular, err := os.Open(filepath.Join(parent, "tego-dns-2"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = regular.Close() }()
	next, calls = numbers(4)
	if name, err := mkdirTempAt(int(regular.Fd()), "tego-dns-", next); !errors.Is(err, unix.ENOTDIR) || *calls != 1 {
		t.Fatalf("mkdirTempAt beneath a regular file = %q, %v after %d tries, want ENOTDIR after 1", name, err, *calls)
	}
	if os.Geteuid() != 0 { // root's mkdirat ignores the directory's mode
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(parent, 0o700) }()
		next, calls = numbers(5)
		if name, err := mkdirTempAt(int(dir.Fd()), "tego-dns-", next); !errors.Is(err, unix.EACCES) || *calls != 1 {
			t.Fatalf("mkdirTempAt beneath a read-only parent = %q, %v after %d tries, want EACCES after 1", name, err,
				*calls)
		}
	}
}

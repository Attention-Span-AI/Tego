// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMakeDirsCreatesPrivateDirectories: MakeDirs is MkdirAll(path, 0700) for an unprivileged caller,
// and accepts a path that already exists.
func TestMakeDirsCreatesPrivateDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "c")
	if err := MakeDirs(path); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Dir(filepath.Dir(path)), filepath.Dir(path), path} {
		st, err := os.Stat(p)
		if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", p, st, err)
		}
	}
	if err := MakeDirs(path); err != nil {
		t.Fatalf("an existing path: %v", err)
	}
}

// TestHandOverRunUnprivileged: only root hands anything over, so an unprivileged writer's Close touches
// no ownership.
func TestHandOverRunUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root: the integration suite covers the privileged half")
	}
	if err := HandOverRun(filepath.Join(t.TempDir(), "r")); err != nil {
		t.Fatalf("HandOverRun: %v", err)
	}
}

// TestGiveTreeHandsOverOnlyWhatTheWriterMakes is the walk's filter: directories and single-link regular
// files are handed over, deepest first, and a symlink (never followed), a hard link and a FIFO (whose open
// must not block) are left alone — they are not what a writer creates, and the directory's owner could
// have planted them to aim root's chown at someone else's file.
func TestGiveTreeHandsOverOnlyWhatTheWriterMakes(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A file with one link, which the walk would hand over if it followed a link to it (the open's O_NOFOLLOW).
	single := filepath.Join(t.TempDir(), "single")
	if err := os.WriteFile(single, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(t.TempDir(), "r")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(run, "blobs"), 0o700))
	must(os.WriteFile(filepath.Join(run, EventsFile), []byte("{}\n"), 0o600))
	must(os.WriteFile(filepath.Join(run, "blobs", "b1"), []byte("b"), 0o600))
	must(os.Symlink(outside, filepath.Join(run, "link")))
	must(os.Symlink(single, filepath.Join(run, "link-to-single")))
	must(os.Link(outside, filepath.Join(run, "hard")))
	must(syscall.Mkfifo(filepath.Join(run, "fifo"), 0o600))

	var (
		mu  sync.Mutex
		got []string
	)
	names := map[uint64]string{}
	for _, p := range []string{run, filepath.Join(run, "blobs"), filepath.Join(run, EventsFile), filepath.Join(run, "blobs", "b1")} {
		var st unix.Stat_t
		must(unix.Stat(p, &st))
		names[st.Ino] = p
	}
	prev := fchown
	fchown = func(f *sys.FD, uid, gid int) error {
		var st unix.Stat_t
		if err := f.Fstat(&st); err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		name, ok := names[st.Ino]
		if !ok {
			name = "unexpected inode"
		}
		got = append(got, name)
		return nil
	}
	defer func() { fchown = prev }()

	testutil.NoFDLeak(t) // every entry the walk opens is closed, the left-alone ones too
	dfd, err := sys.Own(unix.Open(run, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	must(err)
	defer func() { _ = dfd.Close() }()
	errs := giveTree(dfd, run, owner{uid: os.Getuid(), gid: os.Getgid()}, handOverDepth)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	want := []string{filepath.Join(run, "blobs", "b1"), filepath.Join(run, "blobs"), filepath.Join(run, EventsFile)}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("handed over %v\nwant %v", got, want)
	}
}

// A backup alias writable by a governed run must not stay attached to a ledger or
// anchor that a later run trusts (ADR 0059). This applies to the ordinary owner too.
func TestLedgerRefusesHardLinkedFiles(t *testing.T) {
	for _, name := range []string{EventsFile, LockFile, "chain.log"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(t.TempDir(), "writable-backup")
			if err := os.Link(path, alias); err != nil {
				t.Fatal(err)
			}
			if name == "chain.log" {
				if err := ProbeAnchor(path); err == nil {
					t.Fatal("accepted an anchor with a writable hard-link alias")
				}
				return
			}
			w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
			if err == nil {
				_ = w.Abandon()
				t.Fatal("accepted a ledger with a writable hard-link alias")
			}
		})
	}
}

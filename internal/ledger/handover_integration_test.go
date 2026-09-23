// SPDX-License-Identifier: Apache-2.0

//go:build integration

// The hand-over rule needs root: only root can create a file and give it to another uid. These tests
// skip for anyone else and run as root in the KVM guest (test/vm/kvm-run.sh), where they are the
// SUDO-LEDGER-OWNERSHIP acceptance: what a root launcher writes into a user's directory ends up that
// user's, and nothing a user plants there can turn root's writes or chowns onto another file.
package ledger

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// nobody is the uid and gid the tests hand things to: a user that is not this process.
const nobody = 65534

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the hand-over rule is what a root launcher does")
	}
}

// userHome is a directory owned by nobody, the way a user's home is owned by that user.
func userHome(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, nobody, nobody); err != nil {
		t.Fatal(err)
	}
	return home
}

func ownerOfPath(t *testing.T, p string) (uint32, uint32) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(p, &st); err != nil {
		t.Fatalf("lstat %s: %v", p, err)
	}
	return st.Uid, st.Gid
}

func wantOwner(t *testing.T, p string, uid uint32) {
	t.Helper()
	if u, g := ownerOfPath(t, p); u != uid || g != uid {
		t.Errorf("%s is %d:%d, want %d:%d", p, u, g, uid, uid)
	}
}

// rootRun writes one closed run into root with a blob and a contract copy, anchored at anchor.
func rootRun(t *testing.T, root, anchor string) (string, error) {
	t.Helper()
	if err := MakeDirs(root); err != nil {
		t.Fatalf("MakeDirs: %v", err)
	}
	dir := filepath.Join(root, testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(NewFileChainAnchor(anchor)),
		WithClock(newStepClock(time.Now(), 1, time.Millisecond)), WithContract([]byte("version: 0\n")))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Blob(bytes.Repeat([]byte("b"), 5000)); err != nil {
		t.Fatal(err)
	}
	return dir, w.Close(record.RunEndPayload{Reason: record.RunEndExit})
}

// TestIntegrationRootRunIsTheUsers: ~/.tego, ~/.tego/runs, the run directory, every file the writer
// made in it and chain.log all end up the user's, so their own `tego status` can read the run and their
// own next run can create its directory and append its anchor.
func TestIntegrationRootRunIsTheUsers(t *testing.T) {
	requireRoot(t)
	home := userHome(t)
	state := filepath.Join(home, ".tego")
	root := filepath.Join(state, "runs")
	anchor := filepath.Join(state, ChainLogFile)
	dir, err := rootRun(t, root, anchor)
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, p := range []string{state, root, dir, filepath.Join(dir, EventsFile), filepath.Join(dir, LockFile),
		filepath.Join(dir, ContractFile), filepath.Join(dir, "blobs"), anchor} {
		wantOwner(t, p, nobody)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "blobs"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("blobs: %v %v", entries, err)
	}
	for _, e := range entries {
		wantOwner(t, filepath.Join(dir, "blobs", e.Name()), nobody)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if rep, err := r.Verify(t.Context(), NewFileChainAnchor(anchor)); err != nil || !rep.Anchored {
		t.Fatalf("verify: %+v %v", rep, err)
	}
}

// TestIntegrationRootOwnedLedgerRootStaysRoots: a ledger root root owns (a server's /var/lib/tego/runs)
// keeps what root made in it.
func TestIntegrationRootOwnedLedgerRootStaysRoots(t *testing.T) {
	requireRoot(t)
	root := filepath.Join(t.TempDir(), "srv", "runs")
	dir, err := rootRun(t, root, filepath.Join(filepath.Dir(root), ChainLogFile))
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, p := range []string{root, dir, filepath.Join(dir, EventsFile), filepath.Join(filepath.Dir(root), ChainLogFile)} {
		wantOwner(t, p, 0)
	}
}

// TestIntegrationPlantedLinksAreNotFollowed: a chain.log the user replaced with a symlink or a hard link
// to a file root owns is refused (the run's own data is intact and the anchor failure is ErrAnchorWrite),
// and a symlink planted in the run directory is neither followed nor handed over. The victim file keeps
// its content and its owner.
func TestIntegrationPlantedLinksAreNotFollowed(t *testing.T) {
	requireRoot(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, plant := range map[string]func(anchor string) error{
		"symlink":   func(anchor string) error { return os.Symlink(victim, anchor) },
		"hard link": func(anchor string) error { return os.Link(victim, anchor) },
	} {
		t.Run(name, func(t *testing.T) {
			home := userHome(t)
			state := filepath.Join(home, ".tego")
			if err := MakeDirs(state); err != nil {
				t.Fatal(err)
			}
			anchor := filepath.Join(state, ChainLogFile)
			if err := plant(anchor); err != nil {
				t.Fatal(err)
			}
			_, err := rootRun(t, filepath.Join(state, "runs"), anchor)
			if !errors.Is(err, ErrAnchorWrite) {
				t.Fatalf("Close through a planted %s: %v, want ErrAnchorWrite", name, err)
			}
			if b, _ := os.ReadFile(victim); string(b) != "secret\n" {
				t.Fatalf("the victim was written: %q", b)
			}
			wantOwner(t, victim, 0)
		})
	}
	t.Run("symlink in the run directory", func(t *testing.T) {
		home := userHome(t)
		root := filepath.Join(home, ".tego", "runs")
		if err := MakeDirs(root); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, testRef.ID)
		w, err := Open(dir, testRef, WithAnchor(&memAnchor{}), WithClock(newStepClock(time.Now(), 1, time.Millisecond)))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WriteRunStart(startPayload()); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(dir, "evil")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
		wantOwner(t, dir, nobody)
		wantOwner(t, victim, 0)
		if u, _ := ownerOfPath(t, filepath.Join(dir, "evil")); u != 0 {
			t.Errorf("the planted symlink itself was handed over")
		}
	})
}

// TestIntegrationRootRefusesASymlinkedStateDir is the review's reproduction as root: with ~/.tego
// replaced by a symlink to a directory root owns, fileChainAnchor.Append created a root-owned
// <victim>/chain.log holding the run's line, and a later `sudo tego run` would write wherever the link
// named. The walk refuses the link in the user's home, so the anchor, the up-front probe and the ledger
// root are all refused and nothing lands in the victim directory.
func TestIntegrationRootRefusesASymlinkedStateDir(t *testing.T) {
	requireRoot(t)
	home := userHome(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".tego")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(link, nobody, nobody); err != nil { // the user planted it
		t.Fatal(err)
	}
	anchor := filepath.Join(link, ChainLogFile)
	if err := NewFileChainAnchor(anchor).Append(testRef.ID, strings.Repeat("ab", record.IDLen/2)); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("Append: %v, want ErrLinkRefused", err)
	}
	if err := ProbeAnchor(anchor); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("ProbeAnchor: %v, want ErrLinkRefused", err)
	}
	if err := MakeRunDir(filepath.Join(link, "runs"), testRef.ID); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("MakeRunDir: %v, want ErrLinkRefused", err)
	}
	if _, err := GC(t.Context(), link, keepAll, false); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("GC: %v, want ErrLinkRefused before binding the root", err)
	}
	if _, err := SweepLive(t.Context(), link); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("SweepLive: %v, want ErrLinkRefused", err)
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Fatalf("root wrote into the link's target: %v", entries)
	}
}

// TestIntegrationRootFollowsARootLink: a link in a directory only root can change is the operator's —
// a ledger root moved to a bigger disk — and root follows it as before.
func TestIntegrationRootFollowsARootLink(t *testing.T) {
	requireRoot(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "disk")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "tego")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := MakeRunDir(filepath.Join(link, "runs"), testRef.ID); err != nil {
		t.Fatalf("MakeRunDir through root's own link: %v", err)
	}
	if err := ProbeAnchor(filepath.Join(link, ChainLogFile)); err != nil {
		t.Fatalf("ProbeAnchor through root's own link: %v", err)
	}
	if _, err := GC(t.Context(), filepath.Join(link, "runs"), keepAll, true); err != nil {
		t.Fatalf("GC through root's own link: %v", err)
	}
	for _, p := range []string{filepath.Join(real, "runs", testRef.ID), filepath.Join(real, ChainLogFile)} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
}

// TestIntegrationAChainLogRootDidNotCreateKeepsItsOwner: a root-owned file the user renamed into
// ~/.tego/chain.log (they own ~/.tego, so `mv` is theirs to do) is not handed to them by ProbeAnchor or
// Append. Chowning whatever root-owned file sat under the name gave the user its contents: renaming a
// file never let them read it (reproduced as root in the KVM guest with a 0600 "root secret").
func TestIntegrationAChainLogRootDidNotCreateKeepsItsOwner(t *testing.T) {
	requireRoot(t)
	home := userHome(t)
	state := filepath.Join(home, ".tego")
	if err := MakeDirs(state); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(state, ChainLogFile)
	if err := os.WriteFile(anchor, []byte("root secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ProbeAnchor(anchor); err != nil {
		t.Fatalf("ProbeAnchor: %v", err)
	}
	wantOwner(t, anchor, 0)
	if err := NewFileChainAnchor(anchor).Append(testRef.ID, strings.Repeat("ab", record.IDLen/2)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	wantOwner(t, anchor, 0)

	t.Run("a chain.log root creates is still the user's", func(t *testing.T) {
		home := userHome(t)
		anchor := filepath.Join(home, ".tego", ChainLogFile)
		if err := ProbeAnchor(anchor); err != nil {
			t.Fatal(err)
		}
		wantOwner(t, filepath.Join(home, ".tego"), nobody)
		wantOwner(t, anchor, nobody)
	})
}

// TestIntegrationASweepHandsOverOnlyWhatItCreates: a root sweep ending a user's own orphan writes into a
// run directory the user owns. What the sweep creates there (the lock file the orphan lacked) is the
// user's, and a root-owned file the user planted in the run directory or its blobs/ keeps its owner: the
// walk at Close used to chown every root-owned single-link file it found, two levels deep.
func TestIntegrationASweepHandsOverOnlyWhatItCreates(t *testing.T) {
	requireRoot(t)
	home := userHome(t)
	root := filepath.Join(home, ".tego", "runs")
	if err := MakeDirs(root); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}), WithClock(newStepClock(time.Now(), 1, time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	// The launcher dies: its descriptors close with no run_end, and the orphan is the user's own run.
	_ = w.events.Close()
	_ = w.lock.Close()
	w.closeDirs()
	if err := os.Remove(filepath.Join(dir, LockFile)); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, nobody, nobody)
	}); err != nil {
		t.Fatal(err)
	}
	planted := []string{filepath.Join(dir, "secret"), filepath.Join(dir, BlobsDir, "secret")}
	for _, p := range planted {
		if err := os.WriteFile(p, []byte("root secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	sweep, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatalf("the sweep's Open: %v", err)
	}
	if err := sweep.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}); err != nil {
		t.Fatalf("the sweep's Close: %v", err)
	}
	for _, p := range planted {
		wantOwner(t, p, 0)
	}
	wantOwner(t, filepath.Join(dir, LockFile), nobody)
	wantOwner(t, dir, nobody)
	wantOwner(t, filepath.Join(dir, EventsFile), nobody)
}

// TestIntegrationALiveRootRunIgnoresASwappedLedgerRoot is the review's reproduction as root: after
// MakeRunDir and Open, the user moves ~/.tego/runs aside and links ~/.tego/runs to a tree of their own
// in which the run's blobs/ is a link to a directory root owns. By path, the writer's next blob was a
// root-owned file holding agent-chosen bytes in that directory — /etc/cron.d as readily as any. The
// Writer writes through the run directory it opened, so the victim stays empty, and Close hands the run
// directory it wrote — not whatever the path names by then — to the user.
func TestIntegrationALiveRootRunIgnoresASwappedLedgerRoot(t *testing.T) {
	requireRoot(t)
	home := userHome(t)
	root := filepath.Join(home, ".tego", "runs")
	if err := MakeRunDir(root, testRef.ID); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}), WithFreshRunDir(),
		WithClock(newStepClock(time.Now(), 1, time.Millisecond)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	moved := swapLedgerRoot(t, dir, victim)
	for _, p := range []string{root, filepath.Join(filepath.Dir(root), "evil"), filepath.Join(filepath.Dir(root), "evil", testRef.ID),
		filepath.Join(filepath.Dir(root), "evil", testRef.ID, BlobsDir)} {
		if err := os.Lchown(p, nobody, nobody); err != nil { // the user made them
			t.Fatal(err)
		}
	}
	if _, err := w.Blob(bytes.Repeat([]byte("* * * * * root sh -c evil\n"), 200)); err != nil {
		t.Fatalf("Blob: %v", err)
	}
	if err := w.WriteLockInfo([]byte("1 2\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Fatalf("root wrote into the directory the user's link named: %v", entries)
	}
	wantOwner(t, victim, 0)
	for _, p := range []string{moved, filepath.Join(moved, EventsFile), filepath.Join(moved, BlobsDir)} {
		wantOwner(t, p, nobody)
	}
}

// TestIntegrationFreshRunDirRefusesTheUsersDirectory: between MakeRunDir and Open the user, who owns the
// ledger root, replaces the run directory with one of their own. The launcher's Open refuses it
// (os.ErrExist) instead of writing the run into a directory whose entries the user controls.
func TestIntegrationFreshRunDirRefusesTheUsersDirectory(t *testing.T) {
	requireRoot(t)
	home := userHome(t)
	root := filepath.Join(home, ".tego", "runs")
	if err := MakeRunDir(root, testRef.ID); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, testRef.ID)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, nobody, nobody); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, testRef, WithAnchor(&memAnchor{}), WithFreshRunDir()); !errors.Is(err, os.ErrExist) {
		t.Fatalf("Open on the user's directory: %v, want os.ErrExist", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("root wrote into the user's directory: %v", entries)
	}
}

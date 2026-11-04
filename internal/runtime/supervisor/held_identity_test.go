// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestHeldReadFollowsLaunchIdentity(t *testing.T) {
	for _, how := range []string{"rename", "hardlink", "preexisting-hardlink", "directory-rename", "directory-hardlink"} {
		t.Run(how, func(t *testing.T) {
			x, secret := heldReadsFixture(t, agent.RecordFull)
			alias := filepath.Join(x.dir, "innocent")
			if how == "directory-rename" || how == "directory-hardlink" {
				secret = filepath.Join(x.denied, "key")
			}
			move := func() {
				t.Helper()
				var err error
				switch how {
				case "rename":
					err = os.Rename(secret, alias)
				case "directory-rename":
					err = os.Rename(x.denied, alias)
					alias = filepath.Join(alias, "key")
				default:
					err = os.Link(secret, alias)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if how == "preexisting-hardlink" {
				move()
			}
			l, _, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			if how != "preexisting-hardlink" {
				move()
			}
			for _, flags := range []int{unix.O_RDONLY, unix.O_RDWR} {
				x.openAs(t, l, alias, flags, 0)
				res, _ := x.f.lastResp()
				if res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 {
					t.Fatalf("flags %d: answer %+v, delivered %q: moved secret escaped", flags, res, x.k.heldDelivered)
				}
			}
			// A launch pin must not turn every later file into a secret.
			x.openAs(t, l, filepath.Join(x.dir, "src", "a.txt"), unix.O_RDONLY, 0)
			if len(x.k.heldDelivered) != 1 || x.k.heldDelivered[0] != "benign" {
				t.Fatalf("benign read: %q", x.k.heldDelivered)
			}
		})
	}
}

// Removing a child while its directory is being enumerated can hide it from
// the snapshot. After sealing, its retained pin makes that removal harmless.
func TestHeldReadSnapshotRemovalFailsClosed(t *testing.T) {
	for _, mask := range []uint32{unix.IN_DELETE, unix.IN_MOVED_FROM} {
		p := &heldReadPins{watches: map[int]*heldReadWatch{1: {all: true}}}
		var event [unix.SizeofInotifyEvent + 8]byte
		binary.NativeEndian.PutUint32(event[:], 1)
		binary.NativeEndian.PutUint32(event[4:], mask)
		binary.NativeEndian.PutUint32(event[12:], 8)
		copy(event[unix.SizeofInotifyEvent:], "secret")
		p.events(event[:])
		if !p.unknown {
			t.Fatalf("mask %#x: removal while building did not lose certainty", mask)
		}
	}
}

func TestHeldReadReplacementThenMoveFailsClosed(t *testing.T) {
	for _, how := range []string{"rename", "hardlink", "ancestor-replaced"} {
		t.Run(how, func(t *testing.T) {
			x, secret := heldReadsFixture(t, agent.RecordFull)
			l, _, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			alias := filepath.Join(x.dir, "escaped")
			if how == "ancestor-replaced" {
				if err := os.Rename(x.dir, x.dir+"-old"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(x.dir + "-old") })
				if err := os.Mkdir(x.dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			fresh := filepath.Join(x.dir, "replacement")
			if err := os.WriteFile(fresh, []byte("NEW SECRET"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(fresh, secret); err != nil {
				t.Fatal(err)
			}
			var err error
			if how == "hardlink" {
				err = os.Link(secret, alias)
			} else {
				err = os.Rename(secret, alias)
			}
			if err != nil {
				t.Fatal(err)
			}
			x.openAs(t, l, alias, unix.O_RDONLY, 0)
			res, _ := x.f.lastResp()
			if res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 {
				t.Fatalf("answer %+v, delivered %q: replacement escaped", res, x.k.heldDelivered)
			}
		})
	}
}

// An object installed at a protected name while a held read is in flight is pinned before the opened descriptor is
// checked: the object being read, moved onto the name, is refused under the target's rule; a replacement by another
// object leaves the benign read delivered and protects the new object under any later name.
func TestHeldReadReplacementDuringOpenIsPinned(t *testing.T) {
	for _, when := range []string{"after-pin", "after-open"} {
		for _, what := range []string{"the-object-read", "another-object"} {
			t.Run(when+"/"+what, func(t *testing.T) {
				x, secret := heldReadsFixture(t, agent.RecordFull)
				l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
				benign := filepath.Join(x.dir, "src", "a.txt")
				fresh := filepath.Join(x.dir, "replacement")
				replace := func() {
					from := benign
					if what == "another-object" {
						if err := os.WriteFile(fresh, []byte("NEW SECRET"), 0o600); err != nil {
							t.Fatal(err)
						}
						from = fresh
					}
					if err := os.Rename(from, secret); err != nil {
						t.Fatal(err)
					}
				}
				if when == "after-pin" {
					x.dep.afterPin = replace
				} else {
					x.dep.afterOpen = func(int, string) { replace() }
				}
				x.openAs(t, l, benign, unix.O_RDONLY, 0)
				res, _ := x.f.lastResp()
				if what == "the-object-read" {
					evs := sink.all()
					if res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 || len(evs) != 1 || evs[0].Rule != "fs.deny_read["+secret+"]" {
						t.Fatalf("answer %+v, delivered %q, lines %+v: an object moved onto the protected name was delivered", res, x.k.heldDelivered, evs)
					}
					return
				}
				if res.Error != 0 || len(x.k.heldDelivered) != 1 {
					t.Fatalf("answer %+v, delivered %q: a replacement elsewhere refused a benign read", res, x.k.heldDelivered)
				}
				alias := filepath.Join(x.dir, "escaped")
				if err := os.Rename(secret, alias); err != nil {
					t.Fatal(err)
				}
				x.openAs(t, l, alias, unix.O_RDONLY, 0)
				if res, _ := x.f.lastResp(); res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 1 {
					t.Fatalf("answer %+v, delivered %q: the replacement escaped by rename", res, x.k.heldDelivered)
				}
			})
		}
	}
}

// O_CREAT pins the parent of an absent name. A hard link installed at the leaf
// before open must still be checked against the protected file's launch identity.
func TestHeldReadCreateChecksTheOpenedIdentity(t *testing.T) {
	for _, flags := range []int{unix.O_RDONLY | unix.O_CREAT, unix.O_RDWR | unix.O_CREAT} {
		t.Run(strconv.Itoa(flags), func(t *testing.T) {
			x, secret := heldReadsFixture(t, agent.RecordFull)
			alias := filepath.Join(x.dir, "new")
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			x.dep.beforeOpen = func(_ int, leaf string) {
				if leaf != "new" {
					t.Fatalf("leaf %q: want an absent name pinned by its parent", leaf)
				}
				if err := os.Link(secret, alias); err != nil {
					t.Fatal(err)
				}
			}
			x.openAs(t, l, alias, flags, 0o600)
			res, _ := x.f.lastResp()
			if res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 {
				t.Fatalf("answer %+v, delivered %q: the planted leaf escaped", res, x.k.heldDelivered)
			}
			evs := sink.all()
			if len(evs) != 1 || evs[0].Rule != "fs.deny_read["+secret+"]" {
				t.Fatalf("lines %+v: want the protected identity's rule", evs)
			}
			p := decodeHeldOutcome(t, evs[0])
			if p.OperationCompleted == nil || !*p.OperationCompleted || p.FDDelivered || p.SyscallRet == nil || *p.SyscallRet != -int64(unix.EACCES) {
				t.Fatalf("payload %s: want the open recorded as made and not delivered", evs[0].Payload)
			}
		})
	}
}

func TestHeldReadPinsFailClosedOnMissingTarget(t *testing.T) {
	x, secret := heldReadsFixture(t, agent.RecordFull)
	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	l, err := New(testListener(), x.pol, &testSink{}, Options{kernel: x.k, openDeputy: x.dep})
	if err == nil {
		l.closeAskScopes()
		t.Fatal("started without establishing the protected identity")
	}
}

func TestHeldReadPinsRefuseAfterQueueLoss(t *testing.T) {
	x, _ := heldReadsFixture(t, agent.RecordFull)
	l, _, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	var event [unix.SizeofInotifyEvent]byte
	binary.NativeEndian.PutUint32(event[:], ^uint32(0))
	binary.NativeEndian.PutUint32(event[4:], unix.IN_Q_OVERFLOW)
	l.heldPins.events(event[:])
	for range 2 {
		x.openAs(t, l, filepath.Join(x.dir, "src", "a.txt"), unix.O_RDONLY, 0)
		res, _ := x.f.lastResp()
		if res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 {
			t.Fatalf("answer %+v: an unknown identity history was accepted", res)
		}
	}
}

func TestHeldReadPinsRefuseUnobservableFilesystem(t *testing.T) {
	for _, magic := range []uint32{unix.NFS_SUPER_MAGIC, unix.CIFS_SUPER_MAGIC, unix.FUSE_SUPER_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, 0x12345678} {
		t.Run(strconv.FormatUint(uint64(magic), 16), func(t *testing.T) {
			x, _ := heldReadsFixture(t, agent.RecordFull)
			previous := heldReadFSType
			heldReadFSType = func(*sys.FD) (uint32, error) { return magic, nil }
			t.Cleanup(func() { heldReadFSType = previous })
			l, err := New(testListener(), x.pol, &testSink{}, Options{kernel: x.k, openDeputy: x.dep})
			if err == nil {
				l.closeAskScopes()
				t.Fatal("started with an unobservable replacement history")
			}
		})
	}
}

func TestHeldReadPinsCheckEveryFilesystemView(t *testing.T) {
	x, secret := heldReadsFixture(t, agent.RecordFull)
	alias := filepath.Join(x.dir, "second-view")
	if err := os.Link(secret, alias); err != nil {
		t.Fatal(err)
	}
	x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: alias, Resolved: alias, Kind: agent.FSDenyRead, Unenforced: true})
	var target unix.Stat_t
	if err := unix.Stat(secret, &target); err != nil {
		t.Fatal(err)
	}
	previous := heldReadFSType
	t.Cleanup(func() { heldReadFSType = previous })
	views := 0
	heldReadFSType = func(fd *sys.FD) (uint32, error) {
		var st unix.Stat_t
		if err := fd.Fstat(&st); err != nil {
			return 0, err
		}
		if st.Dev == target.Dev && st.Ino == target.Ino {
			views++
			if views == 2 {
				return unix.OVERLAYFS_SUPER_MAGIC, nil
			}
		}
		return previous(fd)
	}
	l, err := New(testListener(), x.pol, &testSink{}, Options{kernel: x.k, openDeputy: x.dep})
	if err == nil {
		l.closeAskScopes()
		t.Fatalf("accepted an unstable duplicate filesystem view (%d views checked)", views)
	}
	if views != 2 {
		t.Fatalf("refused before checking the second view (%d): %v", views, err)
	}
}

func TestHeldReadPinsKeepNearerWriteReadable(t *testing.T) {
	x, _ := heldReadsFixture(t, agent.RecordFull)
	write := filepath.Join(x.denied, "out")
	if err := os.Mkdir(write, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(write, "public")
	if err := os.WriteFile(path, []byte("public"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: write, Resolved: write, Kind: agent.FSWrite, Raw: write, Access: agent.AccessWriteSet})
	l, _, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	alias := filepath.Join(x.dir, "public-alias")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	x.openAs(t, l, alias, unix.O_RDONLY, 0)
	if len(x.k.heldDelivered) != 1 || x.k.heldDelivered[0] != "public" {
		t.Fatalf("nearer write entry: delivered %q, want the public file", x.k.heldDelivered)
	}
}

func TestHeldReadPinsBoundAliasedTree(t *testing.T) {
	x, _ := heldReadsFixture(t, agent.RecordFull)
	key := filepath.Join(x.denied, "key")
	for i := range maxHeldReadPins {
		if err := os.Link(key, filepath.Join(x.denied, "alias"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	l, err := New(testListener(), x.pol, &testSink{}, Options{kernel: x.k, openDeputy: x.dep})
	if err == nil {
		l.closeAskScopes()
		t.Fatal("started after walking more than the bound through aliases of one inode")
	}
}

func TestHeldReadPinsRefuseAfterBarrierLoss(t *testing.T) {
	x, _ := heldReadsFixture(t, agent.RecordFull)
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	x.dep.afterOpen = func(int, string) {
		for _, w := range l.heldPins.watches {
			if err := w.directory.Close(); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	x.openAs(t, l, filepath.Join(x.dir, "src", "a.txt"), unix.O_RDONLY, 0)
	res, _ := x.f.lastResp()
	if res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 {
		t.Fatalf("answer %+v, delivered %q: an empty queue certified an unsettled history", res, x.k.heldDelivered)
	}
	if evs := sink.all(); len(evs) != 1 || evs[0].Rule != ruleHeldIdentityUnknown {
		t.Fatalf("lines %+v: want the unknown-identity refusal", evs)
	}
}

func TestHeldReadPinsRefuseChangedAncestorSymlink(t *testing.T) {
	x, _ := heldReadsFixture(t, agent.RecordFull)
	moved := x.dir + "-moved"
	if err := os.Rename(x.dir, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(x.dir)
		_ = os.Rename(moved, x.dir)
	})
	if err := os.Symlink(moved, x.dir); err != nil {
		t.Fatal(err)
	}
	l, err := New(testListener(), x.pol, &testSink{}, Options{kernel: x.k, openDeputy: x.dep})
	if err == nil {
		l.closeAskScopes()
		t.Fatal("followed a changed canonical ancestor into an unwatched chain")
	}
}

// Objects placed in a protected place during the run are followed, not latched: the agent's own create, link,
// symlink, mkdir and exchange inside a nested denied directory leave a benign read delivered (the conformance fs
// space's cells), and each new file stays refused under any later name. What cannot be followed (an object installed
// and deleted in one round, two installs of one name, a move out of sight) refuses every held read.
func TestHeldReadPinsFollowObjectsMadeDuringTheRun(t *testing.T) {
	benignRead := func(t *testing.T, x *heldAskFixture, l *Loop, sink *testSink) {
		t.Helper()
		before, lines := len(x.k.heldDelivered), len(sink.all())
		x.openAs(t, l, filepath.Join(x.dir, "src", "a.txt"), unix.O_RDONLY, 0)
		// A delivered held open is answered by ADDFD|SEND (DeliverHeld), not by a response.
		if evs := sink.all(); len(x.k.heldDelivered) != before+1 || len(evs) != lines+1 || evs[lines].Verdict != record.VerdictAllow {
			t.Fatalf("delivered %q, lines %+v: a benign read was refused after the agent wrote into a denied directory", x.k.heldDelivered, evs[lines:])
		}
	}
	refused := func(t *testing.T, x *heldAskFixture, l *Loop, sink *testSink, path, rule string) {
		t.Helper()
		before, lines := len(x.k.heldDelivered), len(sink.all())
		x.openAs(t, l, path, unix.O_RDONLY, 0)
		res, _ := x.f.lastResp()
		evs := sink.all()
		if res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != before || len(evs) != lines+1 || evs[lines].Rule != rule {
			t.Fatalf("answer %+v, lines %+v: %s not refused by %s", res, evs[lines:], path, rule)
		}
	}
	write := func(t *testing.T, p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("made-in-a-denied-directory-then-moved", func(t *testing.T) {
		x, _ := heldReadsFixture(t, agent.RecordFull)
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
		rule := "fs.deny_read[" + x.denied + "]"
		made := filepath.Join(x.denied, "made")
		write(t, made, "MADE")
		benignRead(t, x, l, sink)
		if err := os.Symlink("key", filepath.Join(x.denied, "ln")); err != nil {
			t.Fatal(err)
		}
		benignRead(t, x, l, sink)
		if err := os.Mkdir(filepath.Join(x.denied, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		benignRead(t, x, l, sink)
		moved := filepath.Join(x.dir, "src", "moved")
		if err := os.Rename(made, moved); err != nil {
			t.Fatal(err)
		}
		refused(t, x, l, sink, moved, rule)
		benignRead(t, x, l, sink)
	})
	t.Run("made-and-moved-out-in-one-round", func(t *testing.T) {
		x, _ := heldReadsFixture(t, agent.RecordFull)
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
		made := filepath.Join(x.denied, "made")
		write(t, made, "MADE")
		moved := filepath.Join(x.dir, "moved") // the write entry's root: a watched directory, followed there
		if err := os.Rename(made, moved); err != nil {
			t.Fatal(err)
		}
		refused(t, x, l, sink, moved, "fs.deny_read["+x.denied+"]")
		benignRead(t, x, l, sink)
	})
	t.Run("linked-in", func(t *testing.T) {
		x, _ := heldReadsFixture(t, agent.RecordFull)
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
		outside := filepath.Join(x.dir, "src", "li.txt")
		write(t, outside, "x")
		if err := os.Link(outside, filepath.Join(x.denied, "li.txt")); err != nil {
			t.Fatal(err)
		}
		benignRead(t, x, l, sink)
		refused(t, x, l, sink, outside, "fs.deny_read["+x.denied+"]")
	})
	t.Run("exchanged-in", func(t *testing.T) {
		x, _ := heldReadsFixture(t, agent.RecordFull)
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
		outside := filepath.Join(x.dir, "xa.txt")
		write(t, outside, "x")
		if err := unix.Renameat2(unix.AT_FDCWD, outside, unix.AT_FDCWD, filepath.Join(x.denied, "key"), unix.RENAME_EXCHANGE); err != nil {
			t.Fatal(err)
		}
		benignRead(t, x, l, sink)
		refused(t, x, l, sink, outside, "fs.deny_read["+x.denied+"]") // the launch key, now at xa.txt
	})
	for _, how := range []string{"made-and-deleted", "installed-twice", "moved-out-of-sight"} {
		t.Run(how, func(t *testing.T) {
			x, _ := heldReadsFixture(t, agent.RecordFull)
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			made := filepath.Join(x.denied, "made")
			write(t, made, "MADE")
			switch how {
			case "made-and-deleted":
				if err := os.Link(made, filepath.Join(x.dir, "src", "kept")); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(made); err != nil {
					t.Fatal(err)
				}
			case "installed-twice":
				if err := os.Link(made, filepath.Join(x.dir, "src", "kept")); err != nil {
					t.Fatal(err)
				}
				other := filepath.Join(x.dir, "other")
				write(t, other, "y")
				if err := os.Rename(other, made); err != nil {
					t.Fatal(err)
				}
			case "moved-out-of-sight":
				if err := os.Rename(made, filepath.Join(x.dir, "src", "kept")); err != nil {
					t.Fatal(err)
				}
			}
			x.openAs(t, l, filepath.Join(x.dir, "src", "a.txt"), unix.O_RDONLY, 0)
			res, _ := x.f.lastResp()
			if evs := sink.all(); res.Error != -int32(unix.EACCES) || len(evs) != 1 || evs[0].Rule != ruleHeldIdentityUnknown {
				t.Fatalf("answer %+v, lines %+v: an object that could not be followed was not uncertain", res, evs)
			}
		})
	}
}

// A denied subdirectory the launch walk watched, removed during the run, is no uncertainty: it was empty. One made
// again at its name is a directory installed at a launch name, and is.
func TestHeldReadPinsRemovedDeniedDirectory(t *testing.T) {
	for _, again := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed", true: "made-again"}[again], func(t *testing.T) {
			x, _ := heldReadsFixture(t, agent.RecordFull)
			sub := filepath.Join(x.denied, "sub")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			if err := os.Remove(sub); err != nil {
				t.Fatal(err)
			}
			if again {
				if err := os.Mkdir(sub, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 { // the second read meets the watch's IN_IGNORED, and the dead directory's barrier
				x.openAs(t, l, filepath.Join(x.dir, "src", "a.txt"), unix.O_RDONLY, 0)
			}
			evs := sink.all()
			if again {
				if len(evs) != 2 || evs[0].Rule != ruleHeldIdentityUnknown || len(x.k.heldDelivered) != 0 {
					t.Fatalf("lines %+v: a directory made again at a launch name was not uncertain", evs)
				}
				return
			}
			if len(x.k.heldDelivered) != 2 || len(evs) != 2 || evs[0].Verdict != record.VerdictAllow || evs[1].Verdict != record.VerdictAllow {
				t.Fatalf("delivered %q, lines %+v: removing an empty denied directory refused benign reads", x.k.heldDelivered, evs)
			}
		})
	}
}

// A protected replacement moved through a chain of names before the next held read (review round 2, finding 1):
// the protected name's replacement renamed to an unprotected name in a watched directory, renamed again, and the
// intermediate name made again with a harmless file or a symlink. Following only the first move pinned the harmless
// file and left the replacement readable at its last name. A chain is followed to its end; a name made again after
// its object left is uncertain.
func TestHeldReadPinsFollowAMoveChain(t *testing.T) {
	for _, again := range []string{"", "file", "symlink"} {
		t.Run("intermediate-made-again-"+again, func(t *testing.T) {
			x, secret := heldReadsFixture(t, agent.RecordFull)
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			fresh, mid, last := filepath.Join(x.dir, "fresh"), filepath.Join(x.dir, "mid"), filepath.Join(x.dir, "last")
			if err := os.WriteFile(fresh, []byte("NEW SECRET"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, mv := range [][2]string{{fresh, secret}, {secret, mid}, {mid, last}} {
				if err := os.Rename(mv[0], mv[1]); err != nil {
					t.Fatal(err)
				}
			}
			switch again {
			case "file":
				if err := os.WriteFile(mid, []byte("harmless"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(x.dir, "src", "a.txt"), mid); err != nil {
					t.Fatal(err)
				}
			}
			x.openAs(t, l, last, unix.O_RDONLY, 0)
			res, _ := x.f.lastResp()
			evs := sink.all()
			want := "fs.deny_read[" + secret + "]"
			if again != "" {
				want = ruleHeldIdentityUnknown
			}
			if res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 || len(evs) != 1 || evs[0].Rule != want {
				t.Fatalf("answer %+v, delivered %q, lines %+v: the replacement at the chain's end was not refused by %s", res, x.k.heldDelivered, evs, want)
			}
		})
	}
}

// The filesystem list holds the protected objects and the directories whose entries are protected (a target's
// parent, a denied directory) to local filesystems with stable identities; a directory above a target's parent may
// also be overlayfs, a container's / above a local work volume (review round 2, finding 4). Its targets stay
// protected; an overlay parent, or a remote, FUSE or unknown ancestor, refuses launch.
func TestHeldReadPinsAcceptAnOverlayAncestor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		parent bool   // the overlay is the target's parent (x.dir) rather than its ancestors
		magic  uint32 // what the ancestors report
		starts bool
	}{
		{"overlay-ancestors", false, unix.OVERLAYFS_SUPER_MAGIC, true},
		{"overlay-parent", true, unix.OVERLAYFS_SUPER_MAGIC, false},
		{"nfs-ancestors", false, unix.NFS_SUPER_MAGIC, false},
		{"fuse-ancestors", false, unix.FUSE_SUPER_MAGIC, false},
		{"unknown-ancestors", false, 0x12345678, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, secret := heldReadsFixture(t, agent.RecordFull)
			type id struct{ dev, ino uint64 }
			marked := map[id]bool{}
			mark := func(p string) {
				var st unix.Stat_t
				if err := unix.Stat(p, &st); err != nil {
					t.Fatal(err)
				}
				marked[id{st.Dev, st.Ino}] = true
			}
			if tc.parent {
				mark(x.dir)
			} else {
				for d := filepath.Dir(x.dir); ; d = filepath.Dir(d) {
					mark(d)
					if d == "/" {
						break
					}
				}
			}
			previous := heldReadFSType
			t.Cleanup(func() { heldReadFSType = previous })
			heldReadFSType = func(fd *sys.FD) (uint32, error) {
				var st unix.Stat_t
				if err := fd.Fstat(&st); err != nil {
					return 0, err
				}
				if marked[id{st.Dev, st.Ino}] {
					return tc.magic, nil
				}
				return previous(fd)
			}
			l, err := New(testListener(), x.pol, &testSink{}, Options{kernel: x.k, openDeputy: x.dep})
			if !tc.starts {
				if err == nil {
					l.closeAskScopes()
					t.Fatal("started with a protected place on a filesystem whose history or identities cannot be trusted")
				}
				return
			}
			if err != nil {
				t.Fatalf("an overlay ancestor above a local parent refused launch: %v", err)
			}
			t.Cleanup(l.closeAskScopes)
			alias := filepath.Join(x.dir, "innocent")
			if err := os.Rename(secret, alias); err != nil {
				t.Fatal(err)
			}
			x.openAs(t, l, alias, unix.O_RDONLY, 0)
			if res, _ := x.f.lastResp(); res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 {
				t.Fatalf("answer %+v, delivered %q: a renamed target escaped under an overlay ancestor", res, x.k.heldDelivered)
			}
		})
	}
}

// A followed destination stays under verification (review round 3, finding 1): the drain sees fresh -> .env -> mid,
// then, between the drain and the pin's open of mid, mid moves on to last and mid is made again with a harmless file
// (or, the must-stay row, is left empty). The pin opens the harmless file; the round that verifies it used to drop
// mid's and last's events as beside the watched entries, and certain answered true with the replacement readable at
// last. A name the last round pinned stays relevant, so its install is uncertain.
func TestHeldReadPinsVerifyAFollowedDestination(t *testing.T) {
	for _, again := range []bool{true, false} {
		t.Run(map[bool]string{true: "destination-made-again", false: "destination-moved-on"}[again], func(t *testing.T) {
			x, secret := heldReadsFixture(t, agent.RecordFull)
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			fresh, mid, last := filepath.Join(x.dir, "fresh"), filepath.Join(x.dir, "mid"), filepath.Join(x.dir, "last")
			if err := os.WriteFile(fresh, []byte("NEW SECRET"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, mv := range [][2]string{{fresh, secret}, {secret, mid}} {
				if err := os.Rename(mv[0], mv[1]); err != nil {
					t.Fatal(err)
				}
			}
			done := false
			heldReadBeforePin = func(name string) {
				if name != "mid" || done {
					return
				}
				done = true
				if err := os.Rename(mid, last); err != nil {
					t.Error(err)
				}
				if again {
					if err := os.WriteFile(mid, []byte("harmless"), 0o600); err != nil {
						t.Error(err)
					}
				}
			}
			t.Cleanup(func() { heldReadBeforePin = nil })
			// The first held read drains fresh -> .env -> mid and pins mid, the hook moving it on; the second reads
			// the replacement at its last name.
			x.openAs(t, l, filepath.Join(x.dir, "src", "a.txt"), unix.O_RDONLY, 0)
			x.openAs(t, l, last, unix.O_RDONLY, 0)
			res, _ := x.f.lastResp()
			evs := sink.all()
			if !done || res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 || len(evs) != 2 ||
				evs[0].Rule != ruleHeldIdentityUnknown || evs[1].Rule != ruleHeldIdentityUnknown {
				var rules []string
				for _, e := range evs {
					rules = append(rules, e.Rule)
				}
				t.Fatalf("hook ran %t, answer %+v, delivered %q, rules %q: a destination changed before its pin was certified", done, res, x.k.heldDelivered, rules)
			}
		})
	}
}

// A certified replacement survives unrelated mount activity (review round 4, finding 2): .env replaced atomically
// is pinned in turn and benign reads go on; a mount made elsewhere afterwards (a container starting, a snap) makes the
// mount table change, and the target's place is checked for its placement, not for the inode the replacement
// changed. Before, it was compared with the launch inode and every later held read was refused.
func TestHeldReadPinsUnrelatedMountAfterAReplacement(t *testing.T) {
	x, secret := heldReadsFixture(t, agent.RecordFull)
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	benign := filepath.Join(x.dir, "src", "a.txt")
	fresh := filepath.Join(x.dir, "fresh")
	if err := os.WriteFile(fresh, []byte("ROTATED SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fresh, secret); err != nil {
		t.Fatal(err)
	}
	x.openAs(t, l, benign, unix.O_RDONLY, 0) // certifies the replacement: pinned
	previous := heldReadMountTableChanged
	t.Cleanup(func() { heldReadMountTableChanged = previous })
	heldReadMountTableChanged = func(*sys.FD) bool { return true } // a mount made elsewhere
	x.openAs(t, l, benign, unix.O_RDONLY, 0)
	if len(x.k.heldDelivered) != 2 {
		t.Fatalf("delivered %q, lines %+v: an unrelated mount refused benign reads after a certified replacement", x.k.heldDelivered, sink.all())
	}
	alias := filepath.Join(x.dir, "src", "rotated")
	if err := os.Rename(secret, alias); err != nil {
		t.Fatal(err)
	}
	x.openAs(t, l, alias, unix.O_RDONLY, 0)
	evs := sink.all()
	if res, _ := x.f.lastResp(); res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 2 || evs[len(evs)-1].Rule != "fs.deny_read["+secret+"]" {
		t.Fatalf("answer %+v, delivered %q, last line %+v: the replacement escaped by rename", res, x.k.heldDelivered, evs[len(evs)-1])
	}
}

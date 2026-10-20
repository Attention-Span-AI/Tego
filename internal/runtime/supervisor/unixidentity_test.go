// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// identityLoop is a loop over a contract with a net: section, the write entry /work and the declared unix: entries
// decl, on a fake whose descriptors are unix datagram sockets.
func identityLoop(t *testing.T, f *fakeKernel, decl ...agent.NetRule) (*Loop, *testSink) {
	t.Helper()
	f.sockType, f.sockDomain = unix.SOCK_DGRAM, unix.AF_UNIX
	return newTestLoop(t, f, contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, decl,
		[]agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}))
}

// TestUnixDatagramIsDecidedWhereItLands is R11 and R11a for an addressed unix datagram: decided on the socket its name
// reaches when the task's own lookup resolves it (unixWalk), never on the name's spelling. Each refused case was
// admitted before, with nothing between the decision and the kernel's lookup to race: a symlink the agent put at a
// declared name sent the datagram outside every entry under that entry's allow; a ".."
// after a symlink was matched at its lexical spelling, the run's own socket, while the kernel climbed from where the
// symlink led; a procfs magic link was stat'ed as this process, so "/proc/self/cwd" was this
// process's cwd; a relative name from a task with a root of its own, and a place this process
// cannot see, were matched in this process's view. A declared entry reached through a symlinked directory matches at
// its resolved path.
func TestUnixDatagramIsDecidedWhereItLands(t *testing.T) {
	const own, otherOwn = "/work/own.dg", "/work/dd.dg"
	for _, tc := range []struct {
		name      string
		path      string            // the datagram's sun_path
		lands     map[string]string // where the task's own lookup of a name lands (symlinks)
		walkErr   error             // what that lookup meets instead
		stat      map[string]string // what a stat in this process's view names: the file of the path given
		otherRoot bool
		otherView string
		verdict   record.Verdict
		rule      string
		errno     unix.Errno // the refusal's errno; unused for an admit, which is continued
	}{
		{name: "the run's own socket", path: own,
			verdict: record.VerdictAllow, rule: "fs.write[/work]"},
		{name: "a relative name lands from the task's cwd", path: "dd.dg",
			verdict: record.VerdictAllow, rule: "fs.write[/work]"},
		{name: "a symlink at a declared name leads outside every entry", path: "/work/pg.dg",
			lands:   map[string]string{"/work/pg.dg": "/x/dd.dg"},
			verdict: record.VerdictRefused, rule: ruleUnmatched, errno: refusalErrno},
		{name: "a symlink at a declared name leads to a foreign socket under the write entry", path: "/work/alias.dg",
			lands:   map[string]string{"/work/alias.dg": "/work/foreign.dg"},
			verdict: record.VerdictRefused, rule: ruleUnixForeign, errno: refusalErrno},
		{name: "a symlink at a declared name leads to the run's own socket", path: "/work/alias.dg",
			lands:   map[string]string{"/work/alias.dg": own},
			verdict: record.VerdictAllow, rule: "fs.write[/work]"},
		{name: "a .. after a symlink climbs out of the write entry", path: "/work/lnk/../dd.dg",
			lands:   map[string]string{"/work/lnk/../dd.dg": "/x/dd.dg"},
			verdict: record.VerdictRefused, rule: ruleUnmatched, errno: refusalErrno},
		{name: "a .. that stays where it is spelled", path: "/work/sub/../dd.dg",
			lands:   map[string]string{"/work/sub/../dd.dg": otherOwn},
			verdict: record.VerdictAllow, rule: "fs.write[/work]"},
		{name: "a declared entry through a symlinked directory, by a .. name", path: "/var/run/x/../pg2.dg",
			lands:   map[string]string{"/var/run/x/../pg2.dg": "/run/pg2.dg"},
			verdict: record.VerdictAllow, rule: "net[unix:/var/run/pg2.dg]"},
		{name: "a declared entry through a symlinked directory", path: "/var/run/pg2.dg",
			lands:   map[string]string{"/var/run/pg2.dg": "/run/pg2.dg"},
			verdict: record.VerdictAllow, rule: "net[unix:/var/run/pg2.dg]"},
		{name: "a magic link on the way (out/me -> /proc/self/cwd)", path: "/work/me/mg.dg",
			walkErr: unix.ELOOP, stat: map[string]string{"/work/me/mg.dg": own},
			verdict: record.VerdictRefused, rule: rulePathUnreliable, errno: refusalErrno},
		{name: "a walk that ends on procfs", path: "/work/p/status",
			walkErr: errUnixProcfs,
			verdict: record.VerdictRefused, rule: rulePathUnreliable, errno: refusalErrno},
		{name: "a relative name from a task with a root of its own", path: "own.dg", otherRoot: true,
			verdict: record.VerdictRefused, rule: rulePathUnreliable, errno: refusalErrno},
		{name: "a place this process cannot see", path: own, otherView: own,
			verdict: record.VerdictRefused, rule: rulePathUnreliable, errno: refusalErrno},
		{name: "a name that names nothing", path: "/work/gone.dg", walkErr: unix.ENOENT,
			verdict: record.VerdictRefused, rule: ruleUnixAbsent, errno: unix.ENOENT},
		{name: "a name through a file", path: "/work/f/x.dg", walkErr: unix.ENOTDIR,
			verdict: record.VerdictRefused, rule: ruleUnixAbsent, errno: unix.ENOTDIR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.links["/var/run"] = "/run"
			f.links["/proc/4242/cwd"] = "/work"
			l, sink := identityLoop(t, f,
				unixRuleOf("unix:/work/pg.dg", "/work/pg.dg", false),
				unixRuleOf("unix:/work/alias.dg", "/work/alias.dg", false),
				unixRuleOf("unix:/var/run/pg2.dg", "/var/run/pg2.dg", false))
			f.bindsSocket(t, l, sockID{ino: 9500, cookie: 1}, own)
			f.bindsSocket(t, l, sockID{ino: 9501, cookie: 2}, otherOwn)
			// Planted after the run's binds, as an agent would.
			for k, v := range tc.lands {
				f.symlinks[k] = v
			}
			for k, v := range tc.stat {
				f.statIDs[k] = fakeID(v)
			}
			if tc.walkErr != nil {
				f.resolveErrs[tc.path] = tc.walkErr
			}
			f.otherRoot = tc.otherRoot
			if tc.otherView != "" {
				f.otherView[tc.otherView] = true
			}
			r, ev := sendUnixDgram(t, f, l, sink, tc.path)
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule {
				t.Errorf("line %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.verdict, tc.rule)
			}
			switch {
			case tc.verdict == record.VerdictAllow && r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0:
				t.Errorf("answer %+v, want CONTINUE", r)
			case tc.verdict != record.VerdictAllow && (r.Flags != 0 || r.Error != -int32(tc.errno)):
				t.Errorf("answer %+v, want error %d and nothing continued", r, -int32(tc.errno))
			}
		})
	}
}

// TestUnixDatagramBatchWalksANameOnce: a sendmmsg batch decides every addressed message, and a name many messages
// carry is resolved in the task's view once per notification (unixTarget), not once per message.
func TestUnixDatagramBatchWalksANameOnce(t *testing.T) {
	f := newFake()
	l, sink := identityLoop(t, f)
	f.bindsSocket(t, l, sockID{ino: 9600, cookie: 1}, "/work/a.dg")
	f.bindsSocket(t, l, sockID{ino: 9601, cookie: 2}, "/work/b.dg")
	f.mu.Lock()
	f.unixWalks = 0
	f.mu.Unlock()
	r, ev, _ := sendUnixBatch(t, f, l, sink, "/work/a.dg", "/work/b.dg")
	if ev.Verdict != record.VerdictAllow || r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("line %s/%s, answer %+v; want allow, continued", ev.Verdict, ev.Rule, r)
	}
	if f.unixWalks != 2 {
		t.Fatalf("%d walks for a batch of %d messages to two names, want 2", f.unixWalks, mmsgKernelMax)
	}
	// A batch cycling through many names walks each once too, however many there are.
	const names = 40
	for i := range names {
		f.bindsSocket(t, l, sockID{ino: uint64(9610 + i), cookie: uint64(10 + i)}, fmt.Sprintf("/work/n%02d.dg", i))
	}
	const arrayAddr, nameAddr = 0x2000000, 0x2100000
	for i := range names {
		f.put(nameAddr+uint64(i)*0x100, sockaddrUn(fmt.Sprintf("/work/n%02d.dg", i)))
	}
	f.put(arrayAddr, mmsgArray(mmsgKernelMax, func(i int) uint64 { return nameAddr + uint64(i%names)*0x100 }))
	f.mu.Lock()
	f.unixWalks = 0
	f.mu.Unlock()
	l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, mmsgKernelMax, 0))
	if r, _ := f.lastResp(); r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("a batch to %d of the run's own sockets answered %+v, want CONTINUE", names, r)
	}
	if f.unixWalks != names {
		t.Fatalf("%d walks for a batch cycling through %d names, want %d", f.unixWalks, names, names)
	}
}

// bindAs has task tid bind the socket every descriptor stands for in the fake (f.sockID) to the sun_path raw: one
// bind notification, which the loop records and continues.
func bindAs(t *testing.T, f *fakeKernel, l *Loop, tid int, id sockID, raw string) {
	t.Helper()
	bindRaw(t, f, l, tid, id, sockaddrUn(raw))
}

// bindRaw is bindAs with the address bytes as the loop reads them: what a sibling's rewrite after the loop's read
// makes the kernel bind is takes's to say.
func bindRaw(t *testing.T, f *fakeKernel, l *Loop, tid int, id sockID, sa []byte) {
	t.Helper()
	f.mu.Lock()
	f.sockID = id
	at := uint64(0x90000 + len(f.regions)*0x200) // the fake reads the first region mapped at an address
	f.mu.Unlock()
	f.put(at, sa)
	handleBind(l, notifFor(connectNR(), tid, 5, at, uint64(len(sa))))
	if r, _ := f.lastResp(); r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("bind %x answered %+v, want CONTINUE", sa, r)
	}
}

// takes has the kernel bind socket id to file now, whichever bind made it and by whatever bytes: the file is born
// now, as the kernel's bind makes it.
func takes(f *fakeKernel, id sockID, file fileID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.boundFiles == nil {
		f.boundFiles = map[sockID]fileID{}
	}
	f.boundFiles[id] = file
	delete(f.unboundSocks, id)
	f.bornLocked(file, time.Now().UnixNano())
}

// liveUnbound keeps socket id alive and bound to nothing, as a socket whose bind failed is.
func liveUnbound(f *fakeKernel, id sockID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unboundSocks == nil {
		f.unboundSocks = map[sockID]bool{}
	}
	f.unboundSocks[id] = true
}

// inetAddr is a sockaddr_in, what a bind's address reads as when the socket is an IP one, or when a sibling rewrites
// it to one after the loop's read.
func inetAddr() []byte {
	sa := make([]byte, 16)
	binary.NativeEndian.PutUint16(sa[0:], unix.AF_INET)
	sa[2], sa[3] = 0x1f, 0x90 // port 8080
	sa[4], sa[7] = 127, 1
	return sa
}

// TestR11aDecidesTheBoundFileByIdentity is R11a on btrfs, where two subvolumes under one superblock repeat inode
// numbers, so the (superblock, inode) UNIX_DIAG_VFS reports is no file's identity. /work is subvolume
// 32, /work/sub 33 and /work/new 34, all on superblock 31; a daemon's socket that predates the run is
// /work/daemon.dg, inode 257 in 32, and the run's socket is inode 257 in another subvolume, so the pair is shared.
//
// Every ordering here admitted the daemon's socket, allow/fs.write[/work], before the fix,
// because R11a attributed a bound socket to the directory of the recorded bind whose name the kernel reported:
// a ".." after a symlink and a magic link walked as this process, the first of two binds kept, an unread or rewritten
// bind, an unread bind after a symlink changed, a rewrite onto another recorded name, a descriptor swap, a bind
// continued with no record (an address read as abstract or as AF_INET, a descriptor of a socket bound already, its
// socket then bound by bytes matching its earlier record), a rewrite or a swap onto a recorded name after a symlink
// changed at leisure, and a swap whose other socket is gone, or bound since. Each was a name matched to a record;
// the run controls names. The
// socket file is decided by identity now: born while the run's socket was being bound, and no socket outside the run
// bound by the same pair in this network namespace (owns, alone). The daemon's file predates every bind of the run's
// socket, so it is refused unix-foreign whatever the binds' names were, and the run's own file is admitted.
func TestR11aDecidesTheBoundFileByIdentity(t *testing.T) {
	const daemon = "/work/daemon.dg"
	type check struct {
		path    string
		verdict record.Verdict
		rule    string
	}
	run := func(t *testing.T, btrfs bool, setup func(f *fakeKernel, l *Loop), checks ...check) {
		t.Helper()
		f := newFake()
		if btrfs {
			f.sdevs = map[uint64]uint64{32: 31, 33: 31, 34: 31}
			f.statIDs["/work"] = fileID{dev: 32, ino: 256}
			f.statIDs["/work/sub"] = fileID{dev: 33, ino: 256}
			f.statIDs["/work/new"] = fileID{dev: 34, ino: 256}
			f.statIDs[daemon] = fileID{dev: 32, ino: 257}
			f.statIDs["/work/sub/daemon.dg"] = fileID{dev: 33, ino: 257}
		}
		f.links["/proc/4242/cwd"] = "/work"
		f.links["/proc/4243/cwd"] = "/work/sub"
		l, sink := identityLoop(t, f)
		setup(f, l)
		for _, c := range checks {
			r, ev := sendUnixDgram(t, f, l, sink, c.path)
			if ev.Verdict != c.verdict || ev.Rule != c.rule {
				t.Errorf("%s: line %s/%s, want %s/%s", c.path, ev.Verdict, ev.Rule, c.verdict, c.rule)
			}
			if continued := r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; continued != (c.verdict == record.VerdictAllow) {
				t.Errorf("%s: answer %+v", c.path, r)
			}
		}
	}
	s, s2, s3 := sockID{ino: 9700, cookie: 1}, sockID{ino: 9701, cookie: 2}, sockID{ino: 9702, cookie: 3}
	sub257, top257 := fileID{dev: 33, ino: 257}, fileID{dev: 32, ino: 257}
	foreign, ownSub := check{daemon, record.VerdictRefused, ruleUnixForeign}, check{"/work/sub/x.dg", record.VerdictAllow, "fs.write[/work]"}
	ownIn := func(f *fakeKernel, p string, id fileID) { f.statIDs[p] = id }

	// A bind the loop continued without recording took the socket, with bytes matching the
	// socket's own earlier, failed record. Each admitted the daemon's socket before.
	for _, tc := range []struct {
		name  string
		first string
		then  func(t *testing.T, f *fakeKernel, l *Loop)
	}{
		{"a relative name, then a bind whose address read as abstract", "x.dg",
			func(t *testing.T, f *fakeKernel, l *Loop) { bindRaw(t, f, l, 4243, s, sockaddrUn("@x.dg")) }},
		{"a relative name, then a bind whose address read as AF_INET", "x.dg",
			func(t *testing.T, f *fakeKernel, l *Loop) { bindRaw(t, f, l, 4243, s, inetAddr()) }},
		{"an absolute name, then a bind whose address read as abstract", "/work/x.dg",
			func(t *testing.T, f *fakeKernel, l *Loop) { bindRaw(t, f, l, 4243, s, sockaddrUn("@/work/x.dg")) }},
		{"an absolute name, then a bind whose address read as AF_INET", "/work/x.dg",
			func(t *testing.T, f *fakeKernel, l *Loop) { bindRaw(t, f, l, 4243, s, inetAddr()) }},
		{"a bind on a descriptor of a socket bound already, swapped onto the run's", "x.dg",
			func(t *testing.T, f *fakeKernel, l *Loop) {
				takes(f, s3, fileID{dev: 33, ino: 300}) // bound already: its bind fails EINVAL, and is not recorded
				bindAs(t, f, l, 4243, s3, "x.dg")
			}},
		// A bind whose address could not be read at all (a non-dumpable task at tier landlock) is remembered as an
		// unrecorded bind at no known path, so a file no socket of the run's is bound to is named that, not foreign.
		{"an address that could not be read at all", "x.dg",
			func(t *testing.T, f *fakeKernel, l *Loop) { handleBind(l, notifFor(connectNR(), 4243, 5, 0x7a000, 20)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			theirs := foreign
			if strings.Contains(tc.name, "could not be read") {
				theirs.rule = ruleUnixBindUnrecorded
			}
			run(t, true, func(f *fakeKernel, l *Loop) {
				bindAs(t, f, l, 4242, s, tc.first) // from /work: the name is taken, EADDRINUSE
				liveUnbound(f, s)
				tc.then(t, f, l)
				ownIn(f, "/work/sub/x.dg", sub257)
				takes(f, s, sub257) // the unrecorded bind took, in /work/sub
			}, theirs, ownSub)
		})
	}
	t.Run("an absolute rewrite onto another recorded name after a symlink changed at leisure", func(t *testing.T) {
		// /work/lnk -> . when the first bind failed; the run repointed it to
		// sub, at leisure, and a sibling rewrote the next bind's "/work/b.dg" to "/work/lnk/x.dg".
		run(t, true, func(f *fakeKernel, l *Loop) {
			f.symlinks["/work/lnk/x.dg"] = "/work/x.dg"
			bindAs(t, f, l, 4242, s, "/work/lnk/x.dg")
			liveUnbound(f, s)
			f.symlinks["/work/lnk/x.dg"] = "/work/sub/x.dg"
			bindAs(t, f, l, 4242, s, "/work/b.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
		}, foreign, ownSub)
	})
	t.Run("a relative rewrite onto another recorded name from one cwd after a symlink changed", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4242, s, "lnk/x.dg")
			liveUnbound(f, s)
			bindAs(t, f, l, 4242, s, "b.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
		}, foreign, ownSub)
	})
	t.Run("a swap from another socket's bind of the recorded name, that socket gone", func(t *testing.T) {
		// dup2(S, 5) closed S2, whose bind of "x.dg" from /work took S.
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4243, s, "x.dg") // from /work/sub: fails
			liveUnbound(f, s)
			bindAs(t, f, l, 4242, s2, "x.dg") // from /work, swapped onto s; s2 is gone
			ownIn(f, "/work/x.dg", top257)
			takes(f, s, top257)
		}, check{"/work/sub/daemon.dg", record.VerdictRefused, ruleUnixForeign},
			check{"/work/x.dg", record.VerdictAllow, "fs.write[/work]"})
	})
	t.Run("a swap from another socket's bind of the recorded name, that socket bound since", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4243, s, "x.dg")
			liveUnbound(f, s)
			bindAs(t, f, l, 4242, s2, "x.dg")
			ownIn(f, "/work/x.dg", top257)
			takes(f, s, top257)
			bindAs(t, f, l, 4242, s2, "y.dg")
			takes(f, s2, fileID{dev: 32, ino: 258})
		}, check{"/work/sub/daemon.dg", record.VerdictRefused, ruleUnixForeign},
			check{"/work/x.dg", record.VerdictAllow, "fs.write[/work]"})
	})
	t.Run("an absolute swap whose other socket walked the name elsewhere", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			f.symlinks["/work/lnk/x.dg"] = "/work/x.dg"
			bindAs(t, f, l, 4242, s, "/work/lnk/x.dg")
			liveUnbound(f, s)
			f.symlinks["/work/lnk/x.dg"] = "/work/sub/x.dg"
			bindAs(t, f, l, 4242, s2, "/work/lnk/x.dg") // swapped onto s
			liveUnbound(f, s2)
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
		}, foreign, ownSub)
	})
	// The orderings of the earlier rounds, which the directory attribution closed one at a time.
	t.Run("a .. after a symlink places the socket in another subvolume", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			f.symlinks["/work/lnk/../x.dg"] = "/work/sub/x.dg" // lnk -> sub/deep
			bindAs(t, f, l, 4242, s, "/work/lnk/../x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
		}, foreign, ownSub)
	})
	t.Run("a magic link on the way", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			f.resolveErrs["/work/me/x.dg"] = unix.ELOOP // /work/me -> /proc/self/cwd
			bindAs(t, f, l, 4243, s, "/work/me/x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
		}, foreign, ownSub)
	})
	t.Run("a second bind after a failed one", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4242, s, daemon) // the name is taken: EADDRINUSE
			liveUnbound(f, s)
			bindAs(t, f, l, 4242, s, "/work/sub/x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
		}, foreign, ownSub)
	})
	t.Run("a hard link and a rename of the run's socket file", func(t *testing.T) {
		// The file is the socket's whatever names it: a link or a rename keeps its inode and its birth time.
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4242, s, "/work/sub/x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
			ownIn(f, "/work/sub/link.dg", sub257)
			ownIn(f, "/work/sub/renamed.dg", sub257)
		}, foreign, check{"/work/sub/link.dg", record.VerdictAllow, "fs.write[/work]"},
			check{"/work/sub/renamed.dg", record.VerdictAllow, "fs.write[/work]"})
	})
	t.Run("one relative name bound from two cwds", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4242, s, "x.dg")
			bindAs(t, f, l, 4243, s, "x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
		}, foreign, ownSub)
	})
	t.Run("a bind whose directory was not there yet", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			f.resolveErrs["/work/new/x.dg"] = unix.ENOENT
			bindAs(t, f, l, 4242, s, "/work/new/x.dg")
			delete(f.resolveErrs, "/work/new/x.dg")
			ownIn(f, "/work/new/x.dg", fileID{dev: 34, ino: 257})
			takes(f, s, fileID{dev: 34, ino: 257})
		}, foreign, check{"/work/new/x.dg", record.VerdictAllow, "fs.write[/work]"})
	})
	t.Run("ext4: the superblock and the inode number are the file", func(t *testing.T) {
		run(t, false, func(f *fakeKernel, l *Loop) {
			f.resolveErrs["/work/me/own.dg"] = unix.ELOOP
			bindAs(t, f, l, 4242, s, "/work/me/own.dg")
			takes(f, s, fakeID("/work/own.dg"))
		}, check{"/work/own.dg", record.VerdictAllow, "fs.write[/work]"},
			check{"/work/other.dg", record.VerdictRefused, ruleUnixForeign})
	})

	// What the identity cannot settle, refused.
	t.Run("a live foreign socket that predates the run shares the pair", func(t *testing.T) {
		// The daemon is listed in this namespace: its file is refused by its birth time, and the run's own, which
		// UNIX_DIAG_VFS cannot tell from it, by the dump (fail closed).
		run(t, true, func(f *fakeKernel, l *Loop) {
			f.foreignSocks = map[sockID]fileID{{ino: 5000, cookie: 9}: top257}
			bindAs(t, f, l, 4242, s, "/work/sub/x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
		}, foreign, check{"/work/sub/x.dg", record.VerdictRefused, ruleUnixOriginUnread})
	})
	t.Run("a foreign socket bound during the run's bind, in this namespace", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4242, s, "/work/sub/x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
			takes(f, sockID{ino: 5000, cookie: 9}, top257) // born now, by a process outside the run
			f.mu.Lock()
			f.foreignSocks = map[sockID]fileID{{ino: 5000, cookie: 9}: top257}
			delete(f.boundFiles, sockID{ino: 5000, cookie: 9})
			f.mu.Unlock()
		}, check{daemon, record.VerdictRefused, ruleUnixOriginUnread},
			check{"/work/sub/x.dg", record.VerdictRefused, ruleUnixOriginUnread})
	})
	t.Run("a birth time the filesystem does not report", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4242, s, "/work/sub/x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
			f.noBirth = map[fileID]bool{sub257: true, top257: true}
		}, check{daemon, record.VerdictRefused, ruleUnixOriginUnread},
			check{"/work/sub/x.dg", record.VerdictRefused, ruleUnixOriginUnread})
	})
	t.Run("a dump the kernel refuses", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4242, s, "/work/sub/x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
			f.dumpErr = unix.EPERM
		}, foreign, check{"/work/sub/x.dg", record.VerdictRefused, ruleUnixOriginUnread})
	})
	t.Run("a namespace with more sockets than a dump reads", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4242, s, "/work/sub/x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
			f.foreignSocks = map[sockID]fileID{}
			for i := range unixDumpMax {
				f.foreignSocks[sockID{ino: uint64(1<<24 + i), cookie: 1}] = fileID{dev: 2, ino: uint64(i)}
			}
		}, check{"/work/sub/x.dg", record.VerdictRefused, ruleUnixOriginUnread})
	})
	t.Run("a file born after every recorded bind of a socket bound more times than are recorded", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			past := time.Now().Add(-time.Hour).UnixNano()
			l.runSockets.clock = func() int64 { return past }
			for i := range bindRecsMax + 1 {
				bindAs(t, f, l, 4242, s, fmt.Sprintf("/work/sub/s%d.dg", i))
			}
			l.runSockets.clock = nil
			liveUnbound(f, s)
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257) // by the fifth bind, which the loop did not record
		}, foreign, check{"/work/sub/x.dg", record.VerdictRefused, ruleUnixBindUnrecorded})
	})
	t.Run("a file born long after the run's only bind of it", func(t *testing.T) {
		// A bind made bindBornWithin after the loop answered it — or one the loop never saw, through a swapped
		// descriptor — made the file; the loop cannot say which, and refuses.
		run(t, true, func(f *fakeKernel, l *Loop) {
			past := time.Now().Add(-time.Minute).UnixNano()
			l.runSockets.clock = func() int64 { return past }
			bindAs(t, f, l, 4242, s, "/work/sub/x.dg")
			l.runSockets.clock = nil
			liveUnbound(f, s)
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
		}, foreign, check{"/work/sub/x.dg", record.VerdictRefused, ruleUnixOriginUnread})
	})

	// Residual (4), pinned as disclosed: a socket bound during the run's bind by a process in another network
	// namespace, whose file is born then, is not in this namespace's dump, and UNIX_DIAG_VFS cannot tell its file from
	// the run's. The fake models it as a file born now that no listed socket is bound to.
	t.Run("residual (4): a foreign socket born during the bind in another network namespace", func(t *testing.T) {
		run(t, true, func(f *fakeKernel, l *Loop) {
			bindAs(t, f, l, 4242, s, "/work/sub/x.dg")
			ownIn(f, "/work/sub/x.dg", sub257)
			takes(f, s, sub257)
			f.mu.Lock()
			f.bornLocked(top257, time.Now().UnixNano())
			f.mu.Unlock()
		}, check{daemon, record.VerdictAllow, "fs.write[/work]"}, ownSub)
	})
}

// TestR11aDumpsOncePerNotification: a sendmmsg batch to the run's own sockets on btrfs, where every decision needs
// the namespace's dump, makes one dump for the files it reached before the dump was begun or that were born more than
// dumpSettle before it, and at most unixPassDumpMax in all, past which a decision is refused unix-origin-unread rather
// than dumped again.
func TestR11aDumpsOncePerNotification(t *testing.T) {
	f := newFake()
	l, sink := identityLoop(t, f)
	f.sdevs = map[uint64]uint64{32: 31}
	for i, p := range []string{"/work/a.dg", "/work/b.dg"} {
		f.statIDs[p] = fileID{dev: 32, ino: uint64(300 + i)}
		f.bindsSocket(t, l, sockID{ino: uint64(9900 + i), cookie: uint64(1 + i)}, p)
	}
	f.mu.Lock()
	f.dumps = 0
	f.mu.Unlock()
	r, ev, _ := sendUnixBatch(t, f, l, sink, "/work/a.dg", "/work/b.dg")
	if ev.Verdict != record.VerdictAllow || r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("line %s/%s, answer %+v; want allow, continued", ev.Verdict, ev.Rule, r)
	}
	// a.dg is reached, then the dump for it begun; b.dg is reached after, so it needs one more; every later message
	// reuses the second.
	if f.dumps != 2 {
		t.Fatalf("%d dumps for a batch of %d messages to two names, want 2", f.dumps, mmsgKernelMax)
	}
	// A batch cycling through more names than a pass dumps for is refused at the first name past the bound.
	const names = unixPassDumpMax + 1
	for i := range names {
		p := fmt.Sprintf("/work/n%02d.dg", i)
		f.statIDs[p] = fileID{dev: 32, ino: uint64(400 + i)}
		f.bindsSocket(t, l, sockID{ino: uint64(9910 + i), cookie: uint64(10 + i)}, p)
	}
	const arrayAddr, nameAddr = 0x2000000, 0x2100000
	for i := range names {
		f.put(nameAddr+uint64(i)*0x100, sockaddrUn(fmt.Sprintf("/work/n%02d.dg", i)))
	}
	f.put(arrayAddr, mmsgArray(names, func(i int) uint64 { return nameAddr + uint64(i)*0x100 }))
	f.mu.Lock()
	f.dumps = 0
	f.mu.Unlock()
	before := len(sink.all())
	l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, names, 0))
	if r, _ := f.lastResp(); r.Error != -int32(refusalErrno) {
		t.Fatalf("a batch to %d of the run's sockets past the dump bound answered %+v, want refused", names, r)
	}
	if f.dumps != unixPassDumpMax {
		t.Fatalf("%d dumps, want %d", f.dumps, unixPassDumpMax)
	}
	var rules []string
	for _, ev := range sink.all()[before:] {
		rules = append(rules, ev.Rule)
	}
	if !slices.Contains(rules, ruleUnixOriginUnread) {
		t.Fatalf("lines %v, want one refused %s", rules, ruleUnixOriginUnread)
	}
	// The same batch once its sockets' files were born well before: one dump lists every socket bound to them.
	f.mu.Lock()
	for i := range names {
		f.bornLocked(fileID{dev: 32, ino: uint64(400 + i)}, time.Now().Add(-3*dumpSettle).UnixNano())
	}
	f.dumps = 0
	f.mu.Unlock()
	l.runSockets.mu.Lock()
	for _, rs := range l.runSockets.ids {
		for i := range rs.binds {
			rs.binds[i] -= int64(3 * dumpSettle) // their binds as long ago, for the birth time
		}
		rs.seen -= int64(dumpSettle)
	}
	l.runSockets.mu.Unlock()
	f.put(arrayAddr+0x10000, mmsgArray(names, func(i int) uint64 { return nameAddr + uint64(i)*0x100 }))
	l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr+0x10000, names, 0))
	if r, _ := f.lastResp(); r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("a batch to %d of the run's sockets born before the notification answered %+v, want CONTINUE", names, r)
	}
	if f.dumps != 1 {
		t.Fatalf("%d dumps for a batch to sockets born before it, want 1", f.dumps)
	}
}

// TestUnixAbstractNamesAreNotPaths: an abstract name is matched by its bytes against the abstract entries only, never
// walked and never matched to a pathname entry its bytes spell, and a bind of one records nothing (it makes no file);
// a pathname is never matched to an abstract entry its bytes spell either.
func TestUnixAbstractNamesAreNotPaths(t *testing.T) {
	f := newFake()
	l, sink := identityLoop(t, f,
		unixRuleOf("unix:@bus", "bus", true),
		unixRuleOf("unix:/work/bus", "/work/bus", false))
	f.resolveErrs["bus"] = unix.ELOOP // a walk of the abstract name's bytes would fail: it must not be made
	f.links["/proc/4242/cwd"] = "/work"
	for _, tc := range []struct {
		path    string
		verdict record.Verdict
		rule    string
	}{
		{"@bus", record.VerdictAllow, "net[unix:@bus]"},
		{"@/work/bus", record.VerdictRefused, ruleUnmatched},
		{"/work/bus", record.VerdictAllow, "net[unix:/work/bus]"},
		// The same bytes as a relative pathname are a name under /work, walked as the task: that walk is the one that
		// fails here, as the abstract name's never is.
		{"bus", record.VerdictRefused, rulePathUnreliable},
	} {
		r, ev := sendUnixDgram(t, f, l, sink, tc.path)
		if ev.Verdict != tc.verdict || ev.Rule != tc.rule {
			t.Errorf("%s: line %s/%s, want %s/%s (answer %+v)", tc.path, ev.Verdict, ev.Rule, tc.verdict, tc.rule, r)
		}
	}
	f.mu.Lock()
	f.unixWalks = 0
	f.mu.Unlock()
	f.sockID = sockID{ino: 9800, cookie: 1}
	sa := sockaddrUn("@mine")
	f.put(0x9f000, sa)
	handleBind(l, notifFor(connectNR(), 4242, 5, 0x9f000, uint64(len(sa))))
	l.runSockets.mu.Lock()
	n := len(l.runSockets.ids)
	l.runSockets.mu.Unlock()
	if n != 0 || f.unixWalks != 0 {
		t.Fatalf("a bind of an abstract name remembered %d sockets and walked %d names, want none", n, f.unixWalks)
	}
}

// TestR11aConnectDumpIsOnePass's decision half on the fake kernel. Where a file's
// st_dev is not its superblock's, a relayed connect admits the run's own socket only on a dump of the namespace the
// kernel made in one pass (needConnect): of the unconnected sockets for a stream socket's connect, of every socket for
// a datagram socket's. A datagram's decision, best effort, takes the whole dump however it was read (needDatagram). In
// a namespace whose sockets do not fit one pass the connect is refused unix-origin-unread and nothing is connected,
// which before the fix was admitted on a dump the run's churn could have thinned; the datagram is still the run's own.
// A connected socket outside the run sharing the pair refuses the datagram and a datagram socket's connect, and not
// a stream socket's connect, which cannot reach it (a connected stream never listens, and a datagram socket is the
// wrong type). The run's own socket connected (a datagram socket another socket connected to) is left out of a stream
// socket's connect's list, so that connect, which the kernel would refuse (EPROTOTYPE), reads as not listed and is
// refused unix-origin-unread; the datagram socket's connect and the datagram, whose
// lists hold connected sockets, are the run's own.
func TestR11aConnectDumpIsOnePass(t *testing.T) {
	const own, addr = "/work/sub/own.sock", 0x41000
	type answer struct {
		verdict record.Verdict
		rule    string
	}
	allowed, unread := answer{record.VerdictAllow, "fs.write[/work]"}, answer{record.VerdictRefused, ruleUnixOriginUnread}
	for _, tc := range []struct {
		name      string
		split     bool // the namespace's sockets do not fit one pass
		connected bool // a connected socket outside the run shares the run's socket's pair
		ownConn   bool // the run's own socket is connected
		stream    answer
		dgram     answer // a datagram socket's connect
		datagram  answer // a datagram sent to the name
	}{
		{name: "one pass", stream: allowed, dgram: allowed, datagram: allowed},
		{name: "more than one pass holds", split: true, stream: unread, dgram: unread, datagram: allowed},
		{name: "a connected foreign socket shares the pair", connected: true, stream: allowed, dgram: unread, datagram: unread},
		{name: "the run's own socket is connected", ownConn: true, stream: unread, dgram: allowed, datagram: allowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			l, sink := identityLoop(t, f)
			f.sdevs = map[uint64]uint64{32: 31, 33: 31}
			f.statIDs["/work"] = fileID{dev: 32, ino: 256}
			f.statIDs["/work/sub"] = fileID{dev: 33, ino: 256}
			f.statIDs[own] = fileID{dev: 33, ino: 257}
			f.bindsSocket(t, l, sockID{ino: 9800, cookie: 1}, own)
			f.dumpSplit = tc.split
			if tc.ownConn {
				f.connectedSocks = map[sockID]bool{{ino: 9800, cookie: 1}: true}
			}
			if tc.connected {
				daemon := sockID{ino: 9801, cookie: 2}
				f.foreignSocks = map[sockID]fileID{daemon: {dev: 32, ino: 257}}
				f.connectedSocks = map[sockID]bool{daemon: true}
			}
			for _, c := range []struct {
				kind string
				typ  int
				want answer
				need dumpNeed
			}{
				{"a stream socket's connect", unix.SOCK_STREAM, tc.stream, needConnect(unix.SOCK_STREAM)},
				{"a datagram socket's connect", unix.SOCK_DGRAM, tc.dgram, needConnect(unix.SOCK_DGRAM)},
			} {
				f.mu.Lock()
				f.sockType, f.unixConnects, f.dumpNeeds = c.typ, nil, nil
				f.mu.Unlock()
				sa := sockaddrUn(own)
				f.put(addr+uint64(c.typ)*0x200, sa)
				before := len(sink.all())
				l.handle(notifFor(connectNR(), 4242, 5, addr+uint64(c.typ)*0x200, uint64(len(sa))))
				evs := sink.all()
				if len(evs) != before+1 {
					t.Fatalf("%s: %d lines", c.kind, len(evs)-before)
				}
				ev := evs[len(evs)-1]
				if ev.Verdict != c.want.verdict || ev.Rule != c.want.rule {
					t.Errorf("%s: line %s/%s, want %s/%s", c.kind, ev.Verdict, ev.Rule, c.want.verdict, c.want.rule)
				}
				if connected := len(f.unixConnects) == 1; connected != (c.want.verdict == record.VerdictAllow) {
					t.Errorf("%s: connected %q", c.kind, f.unixConnects)
				}
				if !slices.Contains(f.dumpNeeds, c.need) {
					t.Errorf("%s: dumps made for %+v, want one for %+v", c.kind, f.dumpNeeds, c.need)
				}
			}
			f.mu.Lock()
			f.sockType, f.dumpNeeds = unix.SOCK_DGRAM, nil
			f.mu.Unlock()
			r, ev := sendUnixDgram(t, f, l, sink, own)
			if ev.Verdict != tc.datagram.verdict || ev.Rule != tc.datagram.rule {
				t.Errorf("a datagram: line %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.datagram.verdict, tc.datagram.rule)
			}
			if continued := r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; continued != (tc.datagram.verdict == record.VerdictAllow) {
				t.Errorf("a datagram: answer %+v", r)
			}
			if !slices.Contains(f.dumpNeeds, needDatagram) {
				t.Errorf("a datagram: dumps made for %+v, want one for %+v", f.dumpNeeds, needDatagram)
			}
		})
	}
}

// TestR11aDumpBegunAfterTheFileIsReached: a dump of the namespace lists the sockets bound when it began, so a pass
// reuses it only for files it reached before. In a batch alternating between the run's own socket and a file in
// another subvolume repeating the inode number of another of the run's — born in that socket's bind window, so only
// the dump tells the two apart, and bound by a foreign socket that is listed only once its bind is done, after the
// first message's dump — the second name is reached after that dump, and a dump begun after it lists the foreign
// socket: the batch is refused unix-origin-unread. Reusing the first dump admitted it.
func TestR11aDumpBegunAfterTheFileIsReached(t *testing.T) {
	f := newFake()
	l, sink := identityLoop(t, f)
	f.sdevs = map[uint64]uint64{32: 31, 33: 31}
	f.statIDs["/work/a.dg"] = fileID{dev: 32, ino: 300}
	f.statIDs["/work/b.dg"] = fileID{dev: 32, ino: 301}
	f.statIDs["/work/sub/f.dg"] = fileID{dev: 33, ino: 301} // repeats b.dg's inode number in another subvolume
	f.bindsSocket(t, l, sockID{ino: 9950, cookie: 1}, "/work/a.dg")
	f.bindsSocket(t, l, sockID{ino: 9951, cookie: 2}, "/work/b.dg")
	f.mu.Lock()
	f.bornLocked(fileID{dev: 33, ino: 301}, time.Now().UnixNano()) // made by a bind still under way
	f.mu.Unlock()
	foreign := sockID{ino: 5100, cookie: 7}
	f.walkHook = func(q unixQuery) {
		if q.path != "/work/sub/f.dg" {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.foreignSocks = map[sockID]fileID{foreign: {dev: 33, ino: 301}} // that bind done: listed from now on
	}
	r, ev, _ := sendUnixBatch(t, f, l, sink, "/work/a.dg", "/work/sub/f.dg")
	if r.Error != -int32(refusalErrno) || r.Flags != 0 {
		t.Fatalf("the batch answered %+v, want refused: the foreign socket bound while it was walked is in the later dump", r)
	}
	var rules []string
	for _, e := range sink.all() {
		rules = append(rules, e.Rule)
	}
	if ev.Verdict != record.VerdictRefused || !slices.Contains(rules, ruleUnixOriginUnread) {
		t.Fatalf("line %s/%s (all %v), want refused with a %s line", ev.Verdict, ev.Rule, rules, ruleUnixOriginUnread)
	}
}

// TestParseUnixDump reads a dump's datagrams: each unix_diag_msg with its file, NLMSG_DONE at the end, an
// NLMSG_ERROR as the kernel's errno; a connected stream or seqpacket socket, which reports its listener's file or its
// own but which no connect or datagram can reach through it (unixDiagMsg.reachable), is not listed, and neither is a
// socket bound to no file. An exact lookup's reply is the same message.
func TestParseUnixDump(t *testing.T) {
	ne := binary.NativeEndian
	msg := func(typ, state uint8, ino uint32, vfs bool) []byte {
		body := make([]byte, unixDiagMsgLen)
		body[0], body[1], body[2] = unix.AF_UNIX, typ, state
		ne.PutUint32(body[4:], ino)
		ne.PutUint32(body[8:], ino*3)
		if vfs {
			a := make([]byte, nlaHdrLen+8)
			ne.PutUint16(a[0:], uint16(len(a)))
			ne.PutUint16(a[2:], unixDiagVFS)
			ne.PutUint32(a[4:], 257)
			ne.PutUint32(a[8:], 31) // superblock 0:31
			body = append(body, a...)
		}
		h := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(body))
		ne.PutUint32(h[0:], uint32(nlmsgHdrLen+len(body)))
		ne.PutUint16(h[4:], unix.SOCK_DIAG_BY_FAMILY)
		return append(h, body...)
	}
	control := func(typ uint16, errno int32) []byte {
		h := make([]byte, nlmsgHdrLen+4)
		ne.PutUint32(h[0:], uint32(len(h)))
		ne.PutUint16(h[4:], typ)
		ne.PutUint32(h[nlmsgHdrLen:], uint32(-errno))
		return h
	}
	var dgram []byte
	for _, m := range [][]byte{
		msg(unix.SOCK_STREAM, 10, 1, true),             // a listener
		msg(unix.SOCK_STREAM, tcpEstablished, 2, true), // a socket it accepted: its listener's file
		msg(unix.SOCK_STREAM, 7, 3, true),              // bound, not listening yet
		msg(unix.SOCK_SEQPACKET, tcpEstablished, 4, true),
		msg(unix.SOCK_DGRAM, tcpEstablished, 5, true), // a connected datagram socket may disconnect
		msg(unix.SOCK_DGRAM, 7, 6, false),             // bound to no file
	} {
		dgram = append(dgram, m...)
	}
	var got []uint64
	done, err := parseUnixDump(append(dgram, control(nlmsgDone, 0)...), func(m unixDiagMsg) bool {
		if m.reachable() {
			got = append(got, m.id.ino)
			if m.b.ino32 != 257 || m.b.major != 0 || m.b.minor != 31 || m.id.cookie != m.id.ino*3 {
				t.Errorf("socket %d: %+v", m.id.ino, m)
			}
		}
		return true
	})
	if !done || err != nil || !slices.Equal(got, []uint64{1, 3, 5}) {
		t.Fatalf("parsed %v, done %t, %v; want [1 3 5], done", got, done, err)
	}
	if done, err := parseUnixDump(dgram, func(unixDiagMsg) bool { return true }); done || err != nil {
		t.Fatalf("a datagram with no NLMSG_DONE: done %t, %v; want more to come", done, err)
	}
	if _, err := parseUnixDump(control(nlmsgError, int32(unix.ENOENT)), func(unixDiagMsg) bool { return true }); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("an error reply reads %v, want ENOENT", err)
	}
	// A dump the kernel ended early says so in NLMSG_DONE's payload: what came before it is not the whole namespace.
	if done, err := parseUnixDump(append(dgram, control(nlmsgDone, int32(unix.EINTR))...), func(unixDiagMsg) bool { return true }); done || !errors.Is(err, unix.EINTR) {
		t.Fatalf("a dump ended by EINTR: done %t, %v; want the error", done, err)
	}
	// An exact lookup's reply is one such message, checked against the socket asked about.
	if b, err := parseUnixDiagReply(msg(unix.SOCK_DGRAM, 7, 6, true), sockID{ino: 6, cookie: 18}); err != nil || !b.bound || b.ino32 != 257 {
		t.Fatalf("an exact reply reads %+v, %v", b, err)
	}
	if _, err := parseUnixDiagReply(msg(unix.SOCK_DGRAM, 7, 6, true), sockID{ino: 6, cookie: 19}); err == nil {
		t.Fatal("a reply naming another socket was taken for the one asked about")
	}
}

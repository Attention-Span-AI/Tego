// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLiveBlockAccessClasses is the op-class split, row by row for every fs syscall class at both ends of
// a move: a read block refuses an open that reads (O_RDONLY, O_RDWR, O_PATH, and one whose name lands under it) and a
// rename or a hard link with an end at or under it (which would give the file a name outside the block, or carry it
// away with a folder above it), and nothing else; a write block refuses every change at or under it (a write-open, a
// creat, an unlink, a rmdir, a mkdir, a mknod, a symlink's own name, a hard link and a rename at either end or of a
// folder above it, a truncate) and no plain read nor an O_PATH open; a path block refuses both. Each refusal is this
// loop's own EACCES (never CONTINUE), under live.block[<kind>:<value>]; everything else keeps the contract's allow.
// The contract is fs.write /w, which allows every action here, so only a live block can refuse.
func TestLiveBlockAccessClasses(t *testing.T) {
	const pathAddr, path2Addr, unmapped = 0x10000, 0x11000, 0x99000
	const (
		readS  = "live.block[read:/w/p/secret]"
		writeT = "live.block[write:/w/p/tmp]"
		pathB  = "live.block[path:/w/p/both]"
		allow  = "fs.write[/w]"
	)
	read := []string{"read", "/w/p/secret"}
	write := []string{"write", "/w/p/tmp"}
	both := []string{"path", "/w/p/both"}
	open := func(flags int) func(nr int32) *notif {
		return func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, uint64(flags)) }
	}
	two := func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr) }
	exchange := func(nr int32) *notif {
		return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr, unix.RENAME_EXCHANGE)
	}
	link := func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr, 0) }
	mkdir := func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0o755) }
	unlink := func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0) }
	rmdir := func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.AT_REMOVEDIR) }
	creat := func(nr int32) *notif { return notifFor(nr, 42, pathAddr, 0o644) }
	truncate := func(nr int32) *notif { return notifFor(nr, 42, pathAddr, 0) }
	mknod := func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.S_IFIFO|0o644, 0) }
	symlink := func(nr int32) *notif { return notifFor(nr, 42, pathAddr, argCWD, path2Addr) }
	for _, tc := range []struct {
		name        string
		blocks      []string
		syscall     string
		path, path2 string
		args        func(nr int32) *notif
		lands       map[string]string
		rule        string // the line's rule; refused unless it is allow
		reason      record.Reason
	}{
		// A read block: reads, and moves at either end, are refused; changes are not.
		{"read: open O_RDONLY", read, "openat", "/w/p/secret/token", "", open(unix.O_RDONLY), nil, readS, record.ReasonReadDenied},
		{"read: open beneath it", read, "openat", "/w/p/secret/a/b", "", open(unix.O_RDONLY), nil, readS, record.ReasonReadDenied},
		{"read: open O_RDWR", read, "openat", "/w/p/secret/token", "", open(unix.O_RDWR), nil, readS, record.ReasonReadDenied},
		{"read: open O_PATH", read, "openat", "/w/p/secret/token", "", open(unix.O_PATH), nil, readS, record.ReasonReadDenied},
		{"read: a symlink that lands in it", read, "openat", "/w/p/innocent", "", open(unix.O_RDONLY),
			map[string]string{"/w/p/innocent": "/w/p/secret/token"}, readS, record.ReasonReadDenied},
		{"read: a sibling with its prefix", read, "openat", "/w/p/secrets", "", open(unix.O_RDONLY), nil, allow, ""},
		{"read: open O_WRONLY|O_TRUNC", read, "openat", "/w/p/secret/token", "", open(unix.O_WRONLY | unix.O_TRUNC), nil, allow, ""},
		{"read: open O_WRONLY|O_CREAT", read, "openat", "/w/p/secret/new", "", open(unix.O_WRONLY | unix.O_CREAT), nil, allow, ""},
		{"read: creat", read, "creat", "/w/p/secret/new", "", creat, nil, allow, ""},
		{"read: unlink", read, "unlinkat", "/w/p/secret/token", "", unlink, nil, allow, ""},
		{"read: mkdir", read, "mkdirat", "/w/p/secret/d", "", mkdir, nil, allow, ""},
		{"read: mknod", read, "mknodat", "/w/p/secret/fifo", "", mknod, nil, allow, ""},
		{"read: a symlink's name in it", read, "symlinkat", "/tmp/x", "/w/p/secret/l", symlink, nil, allow, ""},
		{"read: truncate", read, "truncate", "/w/p/secret/token", "", truncate, nil, allow, ""},
		{"read: rename out of it (old end)", read, "renameat", "/w/p/secret/token", "/w/p/out", two, nil, readS, record.ReasonRenameOutsideContract},
		{"read: rename into it (new end)", read, "renameat", "/w/p/in", "/w/p/secret/x", two, nil, readS, record.ReasonRenameOutsideContract},
		{"read: rename a folder above it", read, "renameat", "/w/p", "/w/q", two, nil, readS, record.ReasonRenameOutsideContract},
		{"read: exchange with a folder above it (new end)", read, "renameat2", "/w/evil", "/w/p", exchange, nil, readS, record.ReasonRenameOutsideContract},
		{"read: a hard link out of it (old end)", read, "linkat", "/w/p/secret/token", "/w/p/t2", link, nil, readS, record.ReasonWriteOutsideContract},
		{"read: a hard link into it (new end)", read, "linkat", "/w/p/a", "/w/p/secret/a", link, nil, readS, record.ReasonWriteOutsideContract},
		{"read: a rename beside it", read, "renameat", "/w/p/a", "/w/p/b", two, nil, allow, ""},
		// A write block: every change is refused; reads are not.
		{"write: open O_RDONLY", write, "openat", "/w/p/tmp/log.txt", "", open(unix.O_RDONLY), nil, allow, ""},
		{"write: open O_PATH", write, "openat", "/w/p/tmp/log.txt", "", open(unix.O_PATH), nil, allow, ""},
		{"write: open O_WRONLY|O_APPEND", write, "openat", "/w/p/tmp/log.txt", "", open(unix.O_WRONLY | unix.O_APPEND), nil, writeT, record.ReasonWriteOutsideContract},
		{"write: open O_RDWR", write, "openat", "/w/p/tmp/log.txt", "", open(unix.O_RDWR), nil, writeT, record.ReasonWriteOutsideContract},
		{"write: open O_RDONLY|O_CREAT", write, "openat", "/w/p/tmp/new", "", open(unix.O_RDONLY | unix.O_CREAT), nil, writeT, record.ReasonWriteOutsideContract},
		{"write: a write through a symlink that lands in it", write, "openat", "/w/p/innocent", "", open(unix.O_WRONLY | unix.O_TRUNC),
			map[string]string{"/w/p/innocent": "/w/p/tmp/log.txt"}, writeT, record.ReasonWriteOutsideContract},
		{"write: creat", write, "creat", "/w/p/tmp/new", "", creat, nil, writeT, record.ReasonWriteOutsideContract},
		{"write: unlink", write, "unlinkat", "/w/p/tmp/log.txt", "", unlink, nil, writeT, record.ReasonDeleteOutsideContract},
		{"write: rmdir of the folder itself", write, "unlinkat", "/w/p/tmp", "", rmdir, nil, writeT, record.ReasonDeleteOutsideContract},
		{"write: mkdir", write, "mkdirat", "/w/p/tmp/d", "", mkdir, nil, writeT, record.ReasonMkdirOutsideContract},
		{"write: mknod", write, "mknodat", "/w/p/tmp/fifo", "", mknod, nil, writeT, record.ReasonWriteOutsideContract},
		{"write: a symlink's name in it", write, "symlinkat", "/tmp/x", "/w/p/tmp/l", symlink, nil, writeT, record.ReasonWriteOutsideContract},
		{"write: a symlink pointing into it", write, "symlinkat", "/w/p/tmp/x", "/w/p/l", symlink, nil, allow, ""},
		{"write: a hard link out of it (old end)", write, "linkat", "/w/p/tmp/log.txt", "/w/p/l2", link, nil, writeT, record.ReasonWriteOutsideContract},
		{"write: a hard link into it (new end)", write, "linkat", "/w/p/a", "/w/p/tmp/a", link, nil, writeT, record.ReasonWriteOutsideContract},
		{"write: rename out of it (old end)", write, "renameat", "/w/p/tmp/log.txt", "/w/p/out", two, nil, writeT, record.ReasonRenameOutsideContract},
		{"write: rename into it (new end)", write, "renameat", "/w/p/in", "/w/p/tmp/in", two, nil, writeT, record.ReasonRenameOutsideContract},
		{"write: rename a folder above it", write, "renameat", "/w/p", "/w/q", two, nil, writeT, record.ReasonRenameOutsideContract},
		{"write: exchange with a folder above it (new end)", write, "renameat2", "/w/evil", "/w/p", exchange, nil, writeT, record.ReasonRenameOutsideContract},
		{"write: truncate", write, "truncate", "/w/p/tmp/log.txt", "", truncate, nil, writeT, record.ReasonWriteOutsideContract},
		{"write: a write beside it", write, "openat", "/w/p/tmpx", "", open(unix.O_WRONLY | unix.O_CREAT), nil, allow, ""},
		// A path block: both.
		{"path: open O_RDONLY", both, "openat", "/w/p/both/f", "", open(unix.O_RDONLY), nil, pathB, record.ReasonReadDenied},
		{"path: open O_WRONLY", both, "openat", "/w/p/both/f", "", open(unix.O_WRONLY), nil, pathB, record.ReasonWriteOutsideContract},
		{"path: unlink", both, "unlinkat", "/w/p/both/f", "", unlink, nil, pathB, record.ReasonDeleteOutsideContract},
		{"path: rename a folder above it", both, "renameat", "/w/p", "/w/q", two, nil, pathB, record.ReasonRenameOutsideContract},
		// Fail closed where a block of the action's class exists and the name cannot be read.
		{"read: a read whose name cannot be read", read, "openat", "", "",
			func(nr int32) *notif { return notifFor(nr, 42, argCWD, unmapped, unix.O_RDONLY) }, nil, ruleArgsUnreadable, record.ReasonReadDenied},
		{"write: a write whose name cannot be read", write, "openat", "", "",
			func(nr int32) *notif { return notifFor(nr, 42, argCWD, unmapped, unix.O_WRONLY|unix.O_CREAT) }, nil, ruleArgsUnreadable, record.ReasonWriteOutsideContract},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			if tc.path != "" {
				f.put(pathAddr, cstr(tc.path))
			}
			if tc.path2 != "" {
				f.put(path2Addr, cstr(tc.path2))
			}
			for k, v := range tc.lands {
				f.fsTargets[k] = v
			}
			pol := testPolicy(nil, []agent.FSRule{{Path: "/w", Kind: agent.FSWrite}}, nil)
			pol.Record = agent.RecordFull
			set := liveSet(t, tc.blocks...)
			l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return set }})
			l.handle(tc.args(nrFor(t, tc.syscall)))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			ev := sink.one(t)
			if tc.rule == allow {
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response = %+v, want CONTINUE: no block of this action's class names it", got)
				}
				if ev.Rule != allow || ev.Verdict != record.VerdictAllow {
					t.Errorf("rule/verdict = %s/%s, want %s/allow", ev.Rule, ev.Verdict, allow)
				}
				return
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response = %+v, want this loop's EACCES", got)
			}
			if ev.Rule != tc.rule || ev.Verdict != record.VerdictRefused || ev.Reason != tc.reason {
				t.Errorf("rule/verdict/reason = %s/%s/%s, want %s/refused/%s", ev.Rule, ev.Verdict, ev.Reason, tc.rule, tc.reason)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("line does not validate: %v", err)
			}
		})
	}
}

// TestLiveAccess: the class of every fs operation and open mode that liveFS matches blocks for.
func TestLiveAccess(t *testing.T) {
	r, w := liveblock.AccessRead, liveblock.AccessWrite
	for _, c := range []struct {
		op    string
		flags int
		mknod bool
		want  liveblock.Access
	}{
		{record.FSOpen, unix.O_RDONLY, false, r},
		{record.FSOpen, unix.O_RDONLY | unix.O_APPEND, false, r},
		{record.FSOpen, unix.O_PATH, false, r},
		{record.FSOpen, unix.O_PATH | unix.O_WRONLY, false, r},
		{record.FSOpen, unix.O_WRONLY, false, w},
		{record.FSOpen, unix.O_WRONLY | unix.O_TRUNC, false, w},
		{record.FSOpen, unix.O_RDWR, false, r | w},
		{record.FSOpen, unix.O_RDONLY | unix.O_CREAT, false, r | w},
		{record.FSOpen, unix.O_RDONLY | unix.O_TRUNC, false, r | w},
		{record.FSOpen, mknodFlags, true, w},
		{"mknod", mknodFlags, false, w},
		{record.FSRename, 0, false, r | w},
		{record.FSLink, 0, false, r | w},
		{record.FSUnlink, 0, false, w},
		{record.FSMkdir, 0, false, w},
		{record.FSSymlink, 0, false, w},
		{record.FSTruncate, 0, false, w},
		{record.FSChmod, 0, false, w},
		{record.FSChown, 0, false, w},
		{record.FSXattr, 0, false, w},
	} {
		if got := liveAccess(c.op, c.flags, c.mknod); got != c.want {
			t.Errorf("liveAccess(%s, %#x, %v) = %d, want %d", c.op, c.flags, c.mknod, got, c.want)
		}
	}
}

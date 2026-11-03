// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// nrFor picks this architecture's number for a syscall named in the dispatch table.
func nrFor(t testing.TB, name string) int32 {
	t.Helper()
	for k, e := range buildDispatch() {
		if e.name == name {
			return k.nr
		}
	}
	t.Skipf("%s does not exist on this architecture", name)
	return 0
}

// TestFSRecording drives every record-only handler: each one answers CONTINUE and emits one advisory fs
// event whose verdict is the nearest-wins match of the compiled table (R15, R17, SEMANTICS §2).
func TestFSRecording(t *testing.T) {
	fs := []agent.FSRule{
		{Path: "/work/proj", Kind: agent.FSWrite},
		{Path: "/work/proj/secrets", Kind: agent.FSDenyRead},
		{Path: "/etc", Kind: agent.FSImplicit},
	}
	const pathAddr, path2Addr = 0x10000, 0x11000

	tests := []struct {
		name     string
		syscall  string
		path     string
		path2    string
		args     func(nr int32) *notif
		wantOp   string
		wantPath string
		wantP2   string
		wantRule string
		wantVerd record.Verdict
		wantRsn  record.Reason
		wantFlag int
	}{
		{
			name: "write open inside", syscall: "openat", path: "/work/proj/out.txt",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, 0x241)
			},
			wantOp: record.FSOpen, wantPath: "/work/proj/out.txt", wantRule: "fs.write[/work/proj]",
			wantVerd: record.VerdictAllow, wantFlag: 0x241,
		},
		{
			name: "write open outside", syscall: "openat", path: "/etc/passwd",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, 0x241)
			},
			wantOp: record.FSOpen, wantPath: "/etc/passwd", wantRule: "fs.implicit[/etc]",
			wantVerd: record.VerdictRefused, wantRsn: record.ReasonWriteOutsideContract, wantFlag: 0x241,
		},
		{
			name: "write open under a deny_read inside a write dir", syscall: "openat",
			path: "/work/proj/secrets/key",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, 0x241)
			},
			// Landlock unions the write entry's rights over the nested deny_read, so the write happens, and the
			// line says so (ADR 0016 step 1; it said refused).
			wantOp: record.FSOpen, wantPath: "/work/proj/secrets/key", wantRule: "fs.write[/work/proj]",
			wantVerd: record.VerdictAllow, wantFlag: 0x241,
		},
		{
			name: "unlink", syscall: "unlinkat", path: "/work/proj/tmp",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, 0)
			},
			wantOp: record.FSUnlink, wantPath: "/work/proj/tmp", wantRule: "fs.write[/work/proj]",
			wantVerd: record.VerdictAllow,
		},
		{
			name: "unlink outside", syscall: "unlinkat", path: "/var/lib/x",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, 0)
			},
			wantOp: record.FSUnlink, wantPath: "/var/lib/x", wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantRsn: record.ReasonDeleteOutsideContract,
		},
		{
			name: "mkdir", syscall: "mkdirat", path: "/work/proj/new",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, 0o755)
			},
			wantOp: record.FSMkdir, wantPath: "/work/proj/new", wantRule: "fs.write[/work/proj]",
			wantVerd: record.VerdictAllow,
		},
		{
			// record v1 has no mknod op: a mknod is the open that creates the same name, as tier 2's kernel
			// record writes it, with O_EXCL for mknod's own no-follow, no-replace semantics.
			name: "mknodat a FIFO", syscall: "mknodat", path: "/work/proj/fifo",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, unix.S_IFIFO|0o644, 0)
			},
			wantOp: record.FSOpen, wantPath: "/work/proj/fifo", wantRule: "fs.write[/work/proj]",
			wantVerd: record.VerdictAllow, wantFlag: unix.O_CREAT | unix.O_EXCL,
		},
		{
			name: "legacy mknod outside", syscall: "mknod", path: "/opt/f",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, pathAddr, unix.S_IFREG|0o755, 0)
			},
			wantOp: record.FSOpen, wantPath: "/opt/f", wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantRsn: record.ReasonWriteOutsideContract, wantFlag: unix.O_CREAT | unix.O_EXCL,
		},
		{
			name: "mkdir outside", syscall: "mkdirat", path: "/opt/new",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, 0o755)
			},
			wantOp: record.FSMkdir, wantPath: "/opt/new", wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantRsn: record.ReasonMkdirOutsideContract,
		},
		{
			name: "rename", syscall: "renameat", path: "/work/proj/a", path2: "/work/proj/b",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr)
			},
			wantOp: record.FSRename, wantPath: "/work/proj/a", wantP2: "/work/proj/b",
			wantRule: "fs.write[/work/proj]", wantVerd: record.VerdictAllow,
		},
		{
			name: "rename from outside", syscall: "renameat", path: "/srv/a", path2: "/work/proj/b",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr)
			},
			wantOp: record.FSRename, wantPath: "/srv/a", wantP2: "/work/proj/b",
			wantRule: ruleUnmatched, wantVerd: record.VerdictRefused,
			wantRsn: record.ReasonRenameOutsideContract,
		},
		{
			name: "symlink records the created link first", syscall: "symlinkat",
			path: "../../etc/shadow", path2: "/work/proj/link",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, pathAddr, argCWD, path2Addr)
			},
			wantOp: record.FSSymlink, wantPath: "/work/proj/link", wantP2: "../../etc/shadow",
			wantRule: "fs.write[/work/proj]", wantVerd: record.VerdictAllow,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nr := nrFor(t, tc.syscall)
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			if tc.path2 != "" {
				f.put(path2Addr, cstr(tc.path2))
			}
			l, sink := newTestLoop(t, f, testPolicy(nil, fs, nil))
			l.handle(tc.args(nr))
			got, ok := f.lastResp()
			if !ok || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want CONTINUE: this tier records, Landlock enforces (R15)", got)
			}
			ev := sink.one(t)
			if ev.Kind != record.KindFS || ev.Source != record.SourceSeccomp {
				t.Errorf("kind/source = %s/%s, want fs/seccomp (advisory)", ev.Kind, ev.Source)
			}
			if ev.Rule != tc.wantRule || ev.Verdict != tc.wantVerd || ev.Reason != tc.wantRsn {
				t.Errorf("rule/verdict/reason = %s/%s/%s, want %s/%s/%s",
					ev.Rule, ev.Verdict, ev.Reason, tc.wantRule, tc.wantVerd, tc.wantRsn)
			}
			var p record.FSPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatalf("payload: %v", err)
			}
			if p.Op != tc.wantOp || p.Path != tc.wantPath || p.Path2 != tc.wantP2 || p.Flags != tc.wantFlag {
				t.Errorf("payload = %+v, want {%s %s %s %d}", p, tc.wantOp, tc.wantPath, tc.wantP2, tc.wantFlag)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event does not validate: %v", err)
			}
		})
	}
}

// TestReadOpenVerdicts is the asymmetry of SEMANTICS §2: a read is allowed unless a deny_read entry is
// nearest, while every modification outside a write entry is refused. Read-opens only reach this package
// under record: full.
func TestReadOpenVerdicts(t *testing.T) {
	nr := nrFor(t, "openat")
	fs := []agent.FSRule{
		{Path: "/work/proj", Kind: agent.FSWrite},
		{Path: "/work/proj/.env", Kind: agent.FSDenyRead},
		{Path: "/home/u/.ssh", Kind: agent.FSDenyRead},
	}
	tests := []struct {
		name     string
		path     string
		flags    int
		wantRule string
		wantVerd record.Verdict
		wantRsn  record.Reason
	}{
		{
			name: "read outside every entry", path: "/usr/share/doc/x", flags: 0,
			wantRule: ruleUnmatched, wantVerd: record.VerdictAllow,
		},
		{
			name: "read inside a write dir", path: "/work/proj/main.go", flags: 0,
			wantRule: "fs.write[/work/proj]", wantVerd: record.VerdictAllow,
		},
		{
			name: "read under deny_read", path: "/home/u/.ssh/id_ed25519", flags: 0,
			wantRule: "fs.deny_read[/home/u/.ssh]", wantVerd: record.VerdictRefused, wantRsn: record.ReasonReadDenied,
		},
		{
			name: "deny_read nested in a write dir still refuses the read",
			path: "/work/proj/.env", flags: 0,
			wantRule: "fs.deny_read[/work/proj/.env]", wantVerd: record.VerdictRefused, wantRsn: record.ReasonReadDenied,
		},
		{
			name: "write to a deny_read path is a write refusal", path: "/home/u/.ssh/authorized_keys",
			flags: 0x241, wantRule: "fs.deny_read[/home/u/.ssh]", wantVerd: record.VerdictRefused,
			wantRsn: record.ReasonWriteOutsideContract,
		},
		{
			name: "O_TMPFILE counts as a write", path: "/tmp/x", flags: 0x410002,
			wantRule: ruleUnmatched, wantVerd: record.VerdictRefused,
			wantRsn: record.ReasonWriteOutsideContract,
		},
		{
			name: "O_RDONLY|O_CLOEXEC is a read", path: "/etc/hosts", flags: 0x80000,
			wantRule: ruleUnmatched, wantVerd: record.VerdictAllow,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(0x10000, cstr(tc.path))
			pol := testPolicy(nil, fs, nil)
			pol.Record = agent.RecordFull
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nr, 42, argCWD, 0x10000, uint64(uint32(tc.flags))))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want CONTINUE", got)
			}
			ev := sink.one(t)
			if ev.Rule != tc.wantRule || ev.Verdict != tc.wantVerd || ev.Reason != tc.wantRsn {
				t.Errorf("rule/verdict/reason = %s/%s/%s, want %s/%s/%s",
					ev.Rule, ev.Verdict, ev.Reason, tc.wantRule, tc.wantVerd, tc.wantRsn)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event does not validate: %v", err)
			}
		})
	}
}

// TestFSPathThroughDirfd is R6/E7: a relative path resolves through /proc/<pid>/fd/<n>, and an unlinked
// directory is marked rather than concatenated with its " (deleted)" suffix (E8).
func TestFSPathThroughDirfd(t *testing.T) {
	nr := nrFor(t, "openat")
	fs := []agent.FSRule{{Path: "/work/proj", Kind: agent.FSWrite}}
	tests := []struct {
		name     string
		link     string
		wantPath string
		wantRule string
	}{
		{name: "live dirfd", link: "/work/proj/sub", wantPath: "/work/proj/sub/f", wantRule: "fs.write[/work/proj]"},
		{name: "deleted dirfd", link: "/work/proj/gone (deleted)", wantPath: "/work/proj/gone/f", wantRule: "fs.write[/work/proj]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.links["/proc/42/fd/9"] = tc.link
			f.put(0x10000, cstr("f"))
			l, sink := newTestLoop(t, f, testPolicy(nil, fs, nil))
			l.handle(notifFor(nr, 42, 9, 0x10000, 0x241))
			ev := sink.one(t)
			var p record.FSPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", p.Path, tc.wantPath)
			}
			if ev.Rule != tc.wantRule {
				t.Errorf("rule = %q, want %q", ev.Rule, tc.wantRule)
			}
		})
	}
}

// TestFSUnreadablePathStillContinues is R5: a record-only handler never fails closed.
func TestFSUnreadablePathStillContinues(t *testing.T) {
	nr := nrFor(t, "openat")
	f := newFake() // nothing mapped
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(nr, 42, argCWD, 0x10000, 0x241))
	got, _ := f.lastResp()
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE even with an unreadable path (R5)", got)
	}
	ev := sink.one(t)
	if ev.Rule != ruleArgsUnreadable || ev.Verdict != record.VerdictObserved {
		t.Errorf("rule/verdict = %s/%s, want args-unreadable/observed", ev.Rule, ev.Verdict)
	}
}

// TestRecordOffKeepsRefusalsOnly is record-ledger.md R12 (the off half) on the supervisor. It checks what
// record: off does and does not suppress: the advisory record
// of an allowed operation goes, every refusal stays. A refusal with no ledger line would break the reason
// channel's second guarantee (REASON-CHANNEL §1), and this package is the only producer of the
// write/delete/rename/mkdir-outside-contract codes.
func TestRecordOffKeepsRefusalsOnly(t *testing.T) {
	nr := nrFor(t, "openat")
	fs := []agent.FSRule{{Path: "/work/proj", Kind: agent.FSWrite}}
	pol := testPolicy(nil, fs, nil)
	pol.Record = agent.RecordOff

	t.Run("allowed write is not recorded", func(t *testing.T) {
		f := newFake()
		f.put(0x10000, cstr("/work/proj/out.txt"))
		l, sink := newTestLoop(t, f, pol)
		l.handle(notifFor(nr, 42, argCWD, 0x10000, 0x241))
		if evs := sink.all(); len(evs) != 0 {
			t.Fatalf("events = %d under record: off, want none", len(evs))
		}
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Errorf("response = %+v, want CONTINUE", got)
		}
	})

	t.Run("refused write is recorded", func(t *testing.T) {
		f := newFake()
		f.put(0x10000, cstr("/tmp/x"))
		l, sink := newTestLoop(t, f, pol)
		l.handle(notifFor(nr, 42, argCWD, 0x10000, 0x241))
		ev := sink.one(t)
		if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonWriteOutsideContract {
			t.Errorf("event = {%s %s}, want refused/write-outside-contract", ev.Verdict, ev.Reason)
		}
	})

	t.Run("unreadable path is not recorded", func(t *testing.T) {
		f := newFake() // nothing mapped
		l, sink := newTestLoop(t, f, pol)
		l.handle(notifFor(nr, 42, argCWD, 0x10000, 0x241))
		if evs := sink.all(); len(evs) != 0 {
			t.Errorf("events = %d, want none: nothing was decided, so no refusal is owed", len(evs))
		}
	})

	t.Run("refused connect is recorded", func(t *testing.T) {
		f := newFake()
		f.put(0x40000, sockaddrIn4("203.0.113.9", 443))
		l, sink := newTestLoop(t, f, pol)
		l.handle(notifFor(connectNR(), 42, 5, 0x40000, 16))
		if ev := sink.one(t); ev.Verdict != record.VerdictRefused {
			t.Errorf("verdict = %s, want the refusal recorded under record: off", ev.Verdict)
		}
	})
}

// TestWatchEntryDoesNotShadowAWrite: an fs.watch entry selects what is recorded individually, it carries
// no rights (agent.FSRule) and Landlock unions rules within a layer, so a write under a watched directory
// inside a write directory is allowed. Treating the watch entry as the nearest rule would invent a
// refusal for a write that actually succeeds.
func TestWatchEntryDoesNotShadowAWrite(t *testing.T) {
	nr := nrFor(t, "openat")
	fs := []agent.FSRule{
		{Path: "/work/proj", Kind: agent.FSWrite},
		{Path: "/work/proj/logs", Kind: agent.FSWatch},
	}
	f := newFake()
	f.put(0x10000, cstr("/work/proj/logs/run.log"))
	l, sink := newTestLoop(t, f, testPolicy(nil, fs, nil))
	l.handle(notifFor(nr, 42, argCWD, 0x10000, 0x241))
	ev := sink.one(t)
	if ev.Verdict != record.VerdictAllow || ev.Rule != "fs.write[/work/proj]" {
		t.Errorf("verdict/rule = %s/%s, want allow/fs.write[/work/proj]", ev.Verdict, ev.Rule)
	}
}

// argCWD is AT_FDCWD as a syscall argument register holds it: sign-extended, then read back as an int32.
// It is a variable because Go refuses to convert the negative constant itself.
var (
	atFDCWDArg int32 = atFDCWD
	argCWD           = uint64(uint32(atFDCWDArg))
)

// cstr is a NUL-terminated fixture string.
func cstr(s string) []byte { return append([]byte(s), 0) }

// TestLegacyFSHandlers drives the dirfd-less syscall numbers x86-64 still carries (R1): open, creat,
// unlink, rmdir, rename, mkdir, symlink, link and chmod resolve their paths against /proc/<pid>/cwd and record the
// same events as their *at forms. arm64's generic table has none of them, so the test skips there.
func TestLegacyFSHandlers(t *testing.T) {
	if nativeAuditArch() != auditArchX86 {
		t.Skip("the legacy syscall forms exist on x86-64 only")
	}
	fs := []agent.FSRule{{Path: "/work/proj", Kind: agent.FSWrite}}
	const a1, a2 = 0x10000, 0x11000
	tests := []struct {
		name     string
		nr       int32
		args     []uint64
		paths    [2]string
		wantOp   string
		wantPath string
		wantP2   string
		wantVerd record.Verdict
		wantFlag int
	}{
		{
			name: "open", nr: nrX86Open, args: []uint64{a1, 0x241}, paths: [2]string{"out.txt"},
			wantOp: record.FSOpen, wantPath: "/work/proj/out.txt", wantVerd: record.VerdictAllow,
			wantFlag: 0x241,
		},
		{
			name: "creat", nr: nrX86Creat, args: []uint64{a1, 0o600}, paths: [2]string{"new.txt"},
			wantOp: record.FSOpen, wantPath: "/work/proj/new.txt", wantVerd: record.VerdictAllow,
			wantFlag: creatFlags,
		},
		{
			name: "unlink", nr: nrX86Unlink, args: []uint64{a1}, paths: [2]string{"gone.txt"},
			wantOp: record.FSUnlink, wantPath: "/work/proj/gone.txt", wantVerd: record.VerdictAllow,
		},
		{
			name: "mkdir", nr: nrX86Mkdir, args: []uint64{a1, 0o755}, paths: [2]string{"d"},
			wantOp: record.FSMkdir, wantPath: "/work/proj/d", wantVerd: record.VerdictAllow,
		},
		{
			// rmdir(2) deletes a directory with no line unless it is dispatched: glibc, Python and
			// coreutils all reach it on x86-64. Recorded as unlinkat(AT_REMOVEDIR) is.
			name: "rmdir", nr: nrX86Rmdir, args: []uint64{a1}, paths: [2]string{"d"},
			wantOp: record.FSUnlink, wantPath: "/work/proj/d", wantVerd: record.VerdictAllow,
		},
		{
			name: "rmdir outside the write entry", nr: nrX86Rmdir, args: []uint64{a1}, paths: [2]string{"/etc/d"},
			wantOp: record.FSUnlink, wantPath: "/etc/d", wantVerd: record.VerdictRefused,
		},
		{
			name: "rename", nr: nrX86Rename, args: []uint64{a1, a2}, paths: [2]string{"a", "b"},
			wantOp: record.FSRename, wantPath: "/work/proj/a", wantP2: "/work/proj/b",
			wantVerd: record.VerdictAllow,
		},
		{
			// Landlock decides a rename at both ends: out of the write entry into /etc is refused at the
			// destination (R17).
			name: "rename out of the write entry", nr: nrX86Rename, args: []uint64{a1, a2}, paths: [2]string{"a", "/etc/b"},
			wantOp: record.FSRename, wantPath: "/work/proj/a", wantP2: "/etc/b",
			wantVerd: record.VerdictRefused,
		},
		{
			name: "symlink", nr: nrX86Symlink, args: []uint64{a1, a2}, paths: [2]string{"../../etc/shadow", "link"},
			wantOp: record.FSSymlink, wantPath: "/work/proj/link", wantP2: "../../etc/shadow",
			wantVerd: record.VerdictAllow,
		},
		{
			name: "link", nr: nrX86Link, args: []uint64{a1, a2}, paths: [2]string{"a", "b"},
			wantOp: record.FSLink, wantPath: "/work/proj/a", wantP2: "/work/proj/b",
			wantVerd: record.VerdictAllow,
		},
		{
			// A second name outside the write entry is refused at the new end, as linkat's is.
			name: "link out of the write entry", nr: nrX86Link, args: []uint64{a1, a2}, paths: [2]string{"a", "/etc/b"},
			wantOp: record.FSLink, wantPath: "/work/proj/a", wantP2: "/etc/b",
			wantVerd: record.VerdictRefused,
		},
		{
			name: "chmod", nr: nrX86Chmod, args: []uint64{a1, 0o755}, paths: [2]string{"run.sh"},
			wantOp: record.FSChmod, wantPath: "/work/proj/run.sh", wantVerd: record.VerdictAllow,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.links["/proc/42/cwd"] = "/work/proj"
			f.put(a1, cstr(tc.paths[0]))
			if tc.paths[1] != "" {
				f.put(a2, cstr(tc.paths[1]))
			}
			l, sink := newTestLoop(t, f, testPolicy(nil, fs, nil))
			l.handle(notifFor(tc.nr, 42, tc.args...))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want CONTINUE", got)
			}
			ev := sink.one(t)
			if ev.Verdict != tc.wantVerd {
				t.Errorf("verdict = %s, want %s", ev.Verdict, tc.wantVerd)
			}
			var p record.FSPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Op != tc.wantOp || p.Path != tc.wantPath || p.Path2 != tc.wantP2 || p.Flags != tc.wantFlag {
				t.Errorf("payload = %+v, want {%s %s %s %d}", p, tc.wantOp, tc.wantPath, tc.wantP2, tc.wantFlag)
			}
		})
	}
}

// TestGlobEntryNamesOneDeclaration is the collision case rule indexes were hiding. A glob entry compiles
// to one rule per path it matched, every one carrying the glob text as its declared entry (pkg/spec/agent
// compile_fs), so two different paths are refused against one name — the entry the contract's author
// actually wrote. Naming them by position instead invented two entries no contract contains.
func TestGlobEntryNamesOneDeclaration(t *testing.T) {
	nr := nrFor(t, "openat")
	fs := []agent.FSRule{
		{Path: "/work/proj", Kind: agent.FSWrite, Raw: "./proj"},
		{Path: "/work/proj/a.key", Kind: agent.FSDenyRead, Raw: "./proj/*.key"},
		{Path: "/work/proj/b.key", Kind: agent.FSDenyRead, Raw: "./proj/*.key"},
	}
	for _, path := range []string{"/work/proj/a.key", "/work/proj/b.key"} {
		f := newFake()
		f.put(0x10000, cstr(path))
		l, sink := newTestLoop(t, f, testPolicy(nil, fs, nil))
		l.handle(notifFor(nr, 42, argCWD, 0x10000, 0))
		ev := sink.one(t)
		if ev.Rule != "fs.deny_read[./proj/*.key]" || ev.Verdict != record.VerdictRefused {
			t.Errorf("%s: rule/verdict = %s/%s, want fs.deny_read[./proj/*.key]/refused", path, ev.Rule, ev.Verdict)
		}
	}
}

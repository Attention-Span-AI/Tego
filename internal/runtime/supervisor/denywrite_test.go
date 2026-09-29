// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDenyWriteRefusedBySupervisor: beneath a write entry, a modification that reaches a built-in
// deny_write target (agent-contract R20) is refused by this loop itself — R10's errno, not CONTINUE, since
// Landlock grants the write entry's rights over the whole subtree and would let it through — and recorded
// refused under the target's rule. Every notified modification is covered: a write-open, a creat, an
// unlink, a mkdir, a mknod (a regular file or a FIFO), a symlink and a hard link inside a target, a hard link that gives a file inside one a
// second name, and a rename at either end or of a directory above a target. linkat's AT_EMPTY_PATH form
// names its old end by descriptor, which is read as the file the descriptor holds: an O_TMPFILE written in
// the worktree and linked in as a hook is refused on its new name and recorded with that file as its old
// one, a descriptor opened on a target is refused a second name for it, and a link whose old name cannot be
// read is refused on its new one. Every row runs under record: summary and
// under record: off, since a refusal this loop answers is never left out of the ledger (REASON-CHANNEL §1).
// An ordinary write in the same worktree, a read of a target and a rename beside one keep their verdicts
// and are continued.
func TestDenyWriteRefusedBySupervisor(t *testing.T) {
	const work = "/work/proj"
	fs := []agent.FSRule{{Path: work, Kind: agent.FSWrite}}
	deny := []agent.FSRule{
		{Path: work + "/.git/hooks", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: work + "/.git/hooks"},
		{Path: work + "/.git/config", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: work + "/.git/config"},
		// A home dotfile governed where it resolves, inside the worktree (R20's dotfiles case).
		{Path: "/home/u/.bashrc", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: work + "/dotfiles/bashrc"},
	}
	const hooks, config, bashrc = "fs.deny_write[" + work + "/.git/hooks]", "fs.deny_write[" + work + "/.git/config]", "fs.deny_write[/home/u/.bashrc]"
	const pathAddr, path2Addr, unmapped = 0x10000, 0x11000, 0x99000
	tests := []struct {
		name     string
		syscall  string
		path     string
		path2    string
		args     func(nr int32) *notif
		lands    map[string]string // where FSTarget says a spelling lands
		links    map[string]string // the task's /proc links (a descriptor's file)
		refused  bool
		wantRule string
		wantRsn  record.Reason
		// wantPaths, when set, is the payload's path and path2.
		wantPaths []string
	}{
		{name: "write a hook", syscall: "openat", path: work + "/.git/hooks/pre-commit",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0x241) },
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract},
		{name: "write the git config", syscall: "openat", path: work + "/.git/config",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_APPEND) },
			refused: true, wantRule: config, wantRsn: record.ReasonWriteOutsideContract},
		{name: "write the resolved home dotfile", syscall: "openat", path: work + "/dotfiles/bashrc",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_TRUNC) },
			refused: true, wantRule: bashrc, wantRsn: record.ReasonWriteOutsideContract},
		{name: "a symlink the agent made into the hooks directory", syscall: "openat", path: work + "/innocent",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0x241) },
			lands:   map[string]string{work + "/innocent": work + "/.git/hooks/post-checkout"},
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract},
		{name: "creat a hook", syscall: "creat", path: work + "/.git/hooks/pre-commit",
			args:    func(nr int32) *notif { return notifFor(nr, 42, pathAddr, 0o755) },
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract},
		{name: "O_CREAT through a dangling link at a hook name", syscall: "openat", path: work + "/notes.txt",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT) },
			lands:   map[string]string{work + "/notes.txt": work + "/.git/hooks/pre-commit"},
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract},
		{name: "unlink a hook", syscall: "unlinkat", path: work + "/.git/hooks/pre-push",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0) },
			refused: true, wantRule: hooks, wantRsn: record.ReasonDeleteOutsideContract},
		{name: "mkdir in the hooks directory", syscall: "mkdirat", path: work + "/.git/hooks/d",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0o755) },
			refused: true, wantRule: hooks, wantRsn: record.ReasonMkdirOutsideContract},
		{name: "mknod an empty executable hook", syscall: "mknodat", path: work + "/.git/hooks/pre-rebase",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.S_IFREG|0o755, 0) },
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract},
		{name: "mknod a FIFO as a hook", syscall: "mknodat", path: work + "/.git/hooks/pre-applypatch",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.S_IFIFO|0o644, 0) },
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract},
		{name: "a symlink planted as a hook", syscall: "symlinkat", path: "/tmp/payload", path2: work + "/.git/hooks/pre-commit",
			args:    func(nr int32) *notif { return notifFor(nr, 42, pathAddr, argCWD, path2Addr) },
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract},
		{name: "a hard link planted as a hook", syscall: "linkat", path: work + "/payload", path2: work + "/.git/hooks/pre-commit",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr, 0) },
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract},
		{name: "a second name for the git config", syscall: "linkat", path: work + "/.git/config", path2: work + "/cfg",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr, 0) },
			refused: true, wantRule: config, wantRsn: record.ReasonWriteOutsideContract},
		{name: "an O_TMPFILE linked in as a hook", syscall: "linkat", path: "", path2: work + "/.git/hooks/pre-commit",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, 7, pathAddr, argCWD, path2Addr, unix.AT_EMPTY_PATH)
			},
			links:   map[string]string{"/proc/42/fd/7": work + "/#1234 (deleted)"},
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract,
			wantPaths: []string{work + "/#1234", work + "/.git/hooks/pre-commit"}},
		{name: "an O_TMPFILE linked in as a hook, old name NULL", syscall: "linkat", path2: work + "/.git/hooks/pre-commit",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, 7, 0, argCWD, path2Addr, unix.AT_EMPTY_PATH)
			},
			links:   map[string]string{"/proc/42/fd/7": work + "/#1234 (deleted)"},
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract,
			wantPaths: []string{work + "/#1234", work + "/.git/hooks/pre-commit"}},
		{name: "a second name for the git config through its descriptor", syscall: "linkat", path: "", path2: work + "/cfg",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, 7, pathAddr, argCWD, path2Addr, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_FOLLOW)
			},
			links:   map[string]string{"/proc/42/fd/7": work + "/.git/config"},
			refused: true, wantRule: config, wantRsn: record.ReasonWriteOutsideContract,
			wantPaths: []string{work + "/.git/config", work + "/cfg"}},
		{name: "a hook linked from an old name that cannot be read", syscall: "linkat", path2: work + "/.git/hooks/pre-commit",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, unmapped, argCWD, path2Addr, 0)
			},
			refused: true, wantRule: hooks, wantRsn: record.ReasonWriteOutsideContract,
			wantPaths: []string{"", work + "/.git/hooks/pre-commit"}},
		{name: "rename onto a hook", syscall: "renameat", path: work + "/payload", path2: work + "/.git/hooks/pre-commit",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr) },
			refused: true, wantRule: hooks, wantRsn: record.ReasonRenameOutsideContract},
		{name: "rename the git directory away", syscall: "renameat", path: work + "/.git", path2: work + "/.git2",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr) },
			refused: true, wantRule: hooks, wantRsn: record.ReasonRenameOutsideContract},
		{name: "rename a prepared directory into place", syscall: "renameat2", path: work + "/evil", path2: work + "/.git",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr, unix.RENAME_EXCHANGE)
			},
			refused: true, wantRule: hooks, wantRsn: record.ReasonRenameOutsideContract},
		{name: "a FIFO made in the worktree", syscall: "mknodat", path: work + "/fifo",
			args:     func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.S_IFIFO|0o644, 0) },
			wantRule: "fs.write[" + work + "]"},
		{name: "an ordinary write in the worktree", syscall: "openat", path: work + "/main.go",
			args:     func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0x241) },
			wantRule: "fs.write[" + work + "]"},
		// The kernel drops O_WRONLY and O_TRUNC from an O_PATH open: it writes nothing, and each later use of
		// the descriptor (a linkat through it, a /proc/self/fd reopen) is checked on its own.
		{name: "an O_PATH descriptor on the git config", syscall: "openat", path: work + "/.git/config",
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, unix.O_PATH|unix.O_WRONLY|unix.O_TRUNC)
			},
			wantRule: "fs.write[" + work + "]"},
		{name: "a git commit's own writes", syscall: "openat", path: work + "/.git/index.lock",
			args:     func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0x2c1) },
			wantRule: "fs.write[" + work + "]"},
		{name: "a rename beside a target", syscall: "renameat", path: work + "/.git/index.lock", path2: work + "/.git/index",
			args:     func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr) },
			wantRule: "fs.write[" + work + "]"},
	}
	for _, mode := range []agent.RecordMode{agent.RecordSummary, agent.RecordOff} {
		for _, tc := range tests {
			t.Run(string(mode)+"/"+tc.name, func(t *testing.T) {
				nr := nrFor(t, tc.syscall)
				f := newFake()
				f.put(pathAddr, cstr(tc.path))
				if tc.path2 != "" {
					f.put(path2Addr, cstr(tc.path2))
				}
				for k, v := range tc.lands {
					f.fsTargets[k] = v
				}
				for k, v := range tc.links {
					f.links[k] = v
				}
				pol := testPolicy(nil, fs, nil)
				pol.Rules.DenyWrite = deny
				pol.Record = mode
				l, sink := newTestLoop(t, f, pol)
				l.handle(tc.args(nr))
				got, ok := f.lastResp()
				if !ok {
					t.Fatal("no response")
				}
				if !tc.refused && mode == agent.RecordOff {
					if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
						t.Fatalf("response = %+v, want CONTINUE: nothing here reaches a target", got)
					}
					if evs := sink.all(); len(evs) != 0 {
						t.Errorf("%d lines under record: off for a write that reaches no target, want none", len(evs))
					}
					return
				}
				checkDenyWrite(t, got, sink.one(t), tc.refused, tc.wantRule, tc.wantRsn, tc.wantPaths)
			})
		}
	}
}

// checkDenyWrite checks one TestDenyWriteRefusedBySupervisor row's answer and line: R10's errno and a
// refused line under the target's rule, or CONTINUE and the write entry's allow.
func checkDenyWrite(t *testing.T, got sysResp, ev *record.Event, refused bool, rule string, rsn record.Reason, paths []string) {
	t.Helper()
	if refused {
		if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
			t.Fatalf("response = %+v, want R10's errno: Landlock allows beneath the write entry, so only this loop can refuse", got)
		}
		if ev.Verdict != record.VerdictRefused || ev.Rule != rule || ev.Reason != rsn {
			t.Errorf("rule/verdict/reason = %s/%s/%s, want %s/refused/%s", ev.Rule, ev.Verdict, ev.Reason, rule, rsn)
		}
	} else {
		if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Fatalf("response = %+v, want CONTINUE: nothing here reaches a target", got)
		}
		if ev.Verdict != record.VerdictAllow || ev.Rule != rule {
			t.Errorf("rule/verdict = %s/%s, want %s/allow", ev.Rule, ev.Verdict, rule)
		}
	}
	if paths != nil {
		var p record.FSPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Path != paths[0] || p.Path2 != paths[1] {
			t.Errorf("path/path2 = %q/%q, want %q/%q", p.Path, p.Path2, paths[0], paths[1])
		}
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("event does not validate: %v", err)
	}
}

// TestDenyWriteReadAndObserve: a read of a target is not a modification and stays allowed under record:
// full, and an observe run (R30) records the write the enforcing run would refuse as observed and
// continues it, since nothing is enforced there.
func TestDenyWriteReadAndObserve(t *testing.T) {
	nr := nrFor(t, "openat")
	fs := []agent.FSRule{{Path: "/w", Kind: agent.FSWrite}}
	deny := []agent.FSRule{{Path: "/w/.git/config", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: "/w/.git/config"}}

	f := newFake()
	f.put(0x10000, cstr("/w/.git/config"))
	pol := testPolicy(nil, fs, nil)
	pol.Rules.DenyWrite = deny
	pol.Record = agent.RecordFull
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(nr, 42, argCWD, 0x10000, unix.O_RDONLY))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("read response = %+v, want CONTINUE", got)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictAllow {
		t.Errorf("a read of a deny_write target recorded %s, want allow", ev.Verdict)
	}

	f = newFake()
	f.put(0x10000, cstr("/w/.git/config"))
	pol = testPolicy(nil, fs, nil)
	pol.Rules.DenyWrite = deny
	pol.Observe = true
	l, sink = newTestLoop(t, f, pol)
	l.handle(notifFor(nr, 42, argCWD, 0x10000, unix.O_WRONLY))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("observe response = %+v, want CONTINUE: an observe run enforces nothing", got)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictObserved || ev.Rule != "fs.deny_write[/w/.git/config]" {
		t.Errorf("observe run recorded %s/%s, want observed under the target's rule", ev.Rule, ev.Verdict)
	}
}

// TestDenyWriteRefusesAnUnreadablePath is R15c's fail-closed half: once the deny_write set is non-empty, a
// modification whose pathname this loop cannot read whole is refused with R10's errno and recorded refused
// under the marker (args-unreadable when nothing was read, path-truncated when the read stopped before the
// NUL), under record: off too. Continued, it went wherever the kernel's own read of the name led: a target
// that made itself non-dumpable denies this process every read at tier 1, and with it every target. A read
// is not a modification and keeps R5's record-only answer, and so does every modification in a run whose
// set is empty.
func TestDenyWriteRefusesAnUnreadablePath(t *testing.T) {
	const pathAddr, unmapped = 0x10000, 0x99000
	fs := []agent.FSRule{{Path: "/w", Kind: agent.FSWrite}}
	deny := []agent.FSRule{{Path: "/w/.git/hooks", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: "/w/.git/hooks"}}
	for _, tc := range []struct {
		name    string
		syscall string
		args    func(nr int32) *notif
		put     []byte // at pathAddr
		mode    agent.RecordMode
		noDeny  bool
		refused bool
		rule    string
		reason  record.Reason
	}{
		{name: "a write-open whose path cannot be read", syscall: "openat", mode: agent.RecordSummary,
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, unmapped, unix.O_WRONLY|unix.O_CREAT) },
			refused: true, rule: ruleArgsUnreadable, reason: record.ReasonWriteOutsideContract},
		{name: "a write-open whose path is cut at the end of its mapping", syscall: "openat", mode: agent.RecordSummary,
			put:     []byte("/w/.git/hoo"), // no NUL: the rest is where this loop cannot read
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT) },
			refused: true, rule: rulePathTruncated, reason: record.ReasonWriteOutsideContract},
		{name: "a mkdir whose path is NULL", syscall: "mkdirat", mode: agent.RecordOff,
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, 0, 0o755) },
			refused: true, rule: ruleArgsUnreadable, reason: record.ReasonMkdirOutsideContract},
		{name: "an unlink whose path cannot be read", syscall: "unlinkat", mode: agent.RecordOff,
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, unmapped, 0) },
			refused: true, rule: ruleArgsUnreadable, reason: record.ReasonDeleteOutsideContract},
		{name: "a rename whose new name cannot be read", syscall: "renameat", mode: agent.RecordSummary,
			put: cstr("/w/payload"),
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, argCWD, unmapped)
			},
			refused: true, rule: ruleArgsUnreadable, reason: record.ReasonRenameOutsideContract},
		{name: "a read-open whose path cannot be read", syscall: "openat", mode: agent.RecordFull,
			args: func(nr int32) *notif { return notifFor(nr, 42, argCWD, unmapped, unix.O_RDONLY) }},
		{name: "a write-open whose path cannot be read, with no deny_write set", syscall: "openat", mode: agent.RecordSummary, noDeny: true,
			args: func(nr int32) *notif { return notifFor(nr, 42, argCWD, unmapped, unix.O_WRONLY|unix.O_CREAT) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			if tc.put != nil {
				f.put(pathAddr, tc.put)
			}
			pol := testPolicy(nil, fs, nil)
			if !tc.noDeny {
				pol.Rules.DenyWrite = deny
			}
			pol.Record = tc.mode
			l, sink := newTestLoop(t, f, pol)
			l.handle(tc.args(nrFor(t, tc.syscall)))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if !tc.refused {
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response = %+v, want CONTINUE: R5 keeps a record-only path open", got)
				}
				if ev := sink.one(t); ev.Verdict != record.VerdictObserved || ev.Rule != ruleArgsUnreadable {
					t.Errorf("line = %s/%s, want observed/%s", ev.Verdict, ev.Rule, ruleArgsUnreadable)
				}
				return
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response = %+v, want R10's errno", got)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Rule != tc.rule || ev.Reason != tc.reason {
				t.Errorf("line = %s/%s/%s, want refused/%s/%s", ev.Verdict, ev.Rule, ev.Reason, tc.rule, tc.reason)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("line does not validate: %v", err)
			}
		})
	}
}

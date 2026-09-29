// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestFSRefusalIsRetakenWhereThePathLands is the fs half of "the line says what the kernel decided" (R15b):
// a write through another spelling of a write entry — a /proc/self/fd magic link, a /dev/fd alias, a
// symlink into the entry, a system symlink such as /var/run — runs, because Landlock decides on where the
// path lands, so the line must not read refused; and a write or a read through a symlink planted in a write
// entry that leads out of it, or into a deny_read entry, is refused, so the line must not read allow. Every
// verdict is re-taken on the walked target, named by the entry the target lies under.
//
// Spec: docs/p0/enforce-landlock.md R15, R17.
func TestFSRefusalIsRetakenWhereThePathLands(t *testing.T) {
	fs := []agent.FSRule{
		{Path: "/work/proj", Kind: agent.FSWrite, Raw: "./proj"},
		{Path: "/etc", Kind: agent.FSImplicit},
	}
	const pathAddr = 0x10000
	for _, tc := range []struct {
		name     string
		syscall  string
		path     string
		flags    uint64
		lands    string // "" when the walk is not expected
		verdict  record.Verdict
		rule     string
		nofollow bool
	}{
		{"write through /proc/self/fd", "openat", "/proc/self/fd/5", 0x241, "/work/proj/out.txt",
			record.VerdictAllow, "fs.write[./proj]", false},
		{"create through a /dev/fd directory", "openat", "/dev/fd/7/new.txt", unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL, "/work/proj/new.txt",
			record.VerdictAllow, "fs.write[./proj]", true},
		{"O_NOFOLLOW decides on the entry itself", "openat", "/home/u/link", unix.O_WRONLY | unix.O_NOFOLLOW, "/work/proj/link",
			record.VerdictAllow, "fs.write[./proj]", true},
		{"mkdir through /var/run", "mkdirat", "/var/run/proj/sub", 0, "/work/proj/sub",
			record.VerdictAllow, "fs.write[./proj]", true},
		{"unlink through a symlinked directory", "unlinkat", "/home/u/proj/tmp", 0, "/work/proj/tmp",
			record.VerdictAllow, "fs.write[./proj]", true},
		{"a symlink out of nowhere into /etc stays refused, named where it lands", "openat", "/tmp/w/esc", 0x241, "/etc/shadow",
			record.VerdictRefused, "fs.implicit[/etc]", false},
		{"a refusal that lands where it was named stays refused", "openat", "/etc/passwd", 0x241, "/etc/passwd",
			record.VerdictRefused, "fs.implicit[/etc]", false},
		{"an allowed write that lands where it was named stays allowed", "openat", "/work/proj/a.txt", 0x241, "/work/proj/a.txt",
			record.VerdictAllow, "fs.write[./proj]", false},
		{"a write through a symlink in the write entry out of it is refused", "openat", "/work/proj/esc", 0x241, "/tmp/elsewhere",
			record.VerdictRefused, ruleUnmatched, false},
		{"an unlink through a symlinked directory out of the entry is refused", "unlinkat", "/work/proj/lnk/x", 0, "/tmp/x",
			record.VerdictRefused, ruleUnmatched, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			if tc.lands != "" {
				f.fsTargets[tc.path] = tc.lands
			}
			l, sink := newTestLoop(t, f, testPolicy(nil, fs, nil))
			switch tc.syscall {
			case "openat":
				l.handle(notifFor(nrFor(t, tc.syscall), 42, argCWD, pathAddr, tc.flags))
			default:
				l.handle(notifFor(nrFor(t, tc.syscall), 42, argCWD, pathAddr, 0))
			}
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want CONTINUE: Landlock decides the fs syscall (R15)", got)
			}
			ev := sink.one(t)
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule {
				t.Errorf("verdict/rule = %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.verdict, tc.rule)
			}
			var p record.FSPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Path != tc.path {
				t.Errorf("path = %q, want the spelling the task passed, %q", p.Path, tc.path)
			}
			switch {
			case len(f.fsQueries) != 1 || f.fsQueries[0].nofollow != tc.nofollow || f.fsQueries[0].path != tc.path:
				t.Errorf("walks = %+v, want one of %q with nofollow=%v", f.fsQueries, tc.path, tc.nofollow)
			}
		})
	}
}

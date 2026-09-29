// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDenyWriteRefusesAPathItCannotWalk is R15c's fail-closed half for the walk: once the deny_write set is
// non-empty, a modification whose spelling matches no target but whose walk fails other than as the task's
// own lookup fails (EMFILE, ENFILE, ENOMEM or EIO in this process, EXDEV) is refused under path-unreliable,
// since it may land on a target: /w/innocent may be a symlink to a hook, and Landlock allows the write under
// the enclosing write entry. A walk that fails as the task's lookup fails (ENOENT) keeps the verdict, as does
// one that reached a file with no path here (errOtherView: a pipe behind /dev/stdout). R15d's link and rename
// check at tier 2 fails the same way, once the table has an entry for it to protect.
//
// Spec: docs/p0/supervisor.md R15c, R15d.
func TestDenyWriteRefusesAPathItCannotWalk(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	for _, tc := range []struct {
		name    string
		err     error
		refused bool
	}{
		{"EMFILE", unix.EMFILE, true},
		{"ENFILE", unix.ENFILE, true},
		{"ENOMEM", unix.ENOMEM, true},
		{"EIO", unix.EIO, true},
		{"EXDEV", unix.EXDEV, true},
		{"ENOENT", unix.ENOENT, false},
		{"another view", errOtherView, false},
	} {
		t.Run("deny_write/"+tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr("/w/innocent"))
			f.fsTargetErrs["/w/innocent"] = tc.err
			pol := testPolicy(nil, []agent.FSRule{{Path: "/w", Kind: agent.FSWrite}}, nil)
			pol.Rules.DenyWrite = []agent.FSRule{{Path: "/w/.git/hooks", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: "/w/.git/hooks"}}
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT))
			got, _ := f.lastResp()
			refused := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0
			if refused != tc.refused {
				t.Fatalf("response = %+v: refused=%v, want %v", got, refused, tc.refused)
			}
			ev := sink.one(t)
			if !tc.refused {
				return
			}
			if got.Error != -int32(refusalErrno) || ev.Verdict != record.VerdictRefused || ev.Rule != rulePathUnreliable ||
				ev.Reason != record.ReasonWriteOutsideContract {
				t.Errorf("response %+v, line %s/%s/%s: want R10's errno, refused/%s", got, ev.Verdict, ev.Rule, ev.Reason, rulePathUnreliable)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("line does not validate: %v", err)
			}
		})
		t.Run("deny_read move/"+tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr("/work/out/a"))
			f.put(path2Addr, cstr("/work/out/b"))
			f.fsTargetErrs["/work/out/a"] = tc.err
			pol := testPolicy(nil, []agent.FSRule{
				{Path: "/work/out", Kind: agent.FSWrite},
				{Path: "/work/out/secret", Kind: agent.FSDenyRead, Unenforced: true},
			}, nil)
			pol.Rules.Tier = backend.TierCgroup
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, "renameat"), 42, argCWD, pathAddr, argCWD, path2Addr))
			got, _ := f.lastResp()
			refused := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0
			if refused != tc.refused {
				t.Fatalf("response = %+v: refused=%v, want %v", got, refused, tc.refused)
			}
			if ev := sink.one(t); tc.refused && (ev.Verdict != record.VerdictRefused || ev.Rule != rulePathUnreliable) {
				t.Errorf("line %s/%s, want refused/%s", ev.Verdict, ev.Rule, rulePathUnreliable)
			}
		})
	}
	// With no deny_read the Landlock ruleset leaves unenforced, R15d has nothing to protect, and a rename whose
	// walk fails keeps its verdict.
	f := newFake()
	f.put(pathAddr, cstr("/work/out/a"))
	f.put(path2Addr, cstr("/work/out/b"))
	f.fsTargetErrs["/work/out/a"] = unix.EMFILE
	pol := testPolicy(nil, []agent.FSRule{{Path: "/work/out", Kind: agent.FSWrite}}, nil)
	pol.Rules.Tier = backend.TierCgroup
	l, _ := newTestLoop(t, f, pol)
	l.handle(notifFor(nrFor(t, "renameat"), 42, argCWD, pathAddr, argCWD, path2Addr))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Errorf("response = %+v, want CONTINUE with no R15d entry", got)
	}
}

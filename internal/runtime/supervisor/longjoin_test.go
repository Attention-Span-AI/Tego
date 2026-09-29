// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// longJoin is a relative pathname read whole (under PATH_MAX) whose join to a cwd under PATH_MAX is over it:
// the kernel resolves a relative path from the cwd with no limit on the total, so this is a name it opens,
// while this loop's R6 spelling of it is "" (resolve marks path-truncated).
func longJoin(tail string) (cwd, raw string) {
	return "/w/" + strings.Repeat("a", 1990), strings.Repeat("./", 1500) + tail
}

// TestDenyWriteRefusesAPathItCannotJoin is R15c's fail-closed half for a name read whole whose join to its
// cwd is longer than PATH_MAX: the loop has no spelling to match the deny_write set against, so it refuses
// the modification under path-truncated, as it refuses a name cut by the read. It was continued: the empty
// spelling matched nothing, the walk was skipped for it, and the kernel opened .git/hooks/pre-commit.
func TestDenyWriteRefusesAPathItCannotJoin(t *testing.T) {
	const pathAddr = 0x10000
	cwd, raw := longJoin("../.git/hooks/pre-commit")
	fs := []agent.FSRule{{Path: "/w", Kind: agent.FSWrite}}
	deny := []agent.FSRule{{Path: "/w/.git/hooks", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: "/w/.git/hooks"}}
	f := newFake()
	f.links["/proc/42/cwd"] = cwd
	f.put(pathAddr, cstr(raw))
	pol := testPolicy(nil, fs, nil)
	pol.Rules.DenyWrite = deny
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT))
	got, ok := f.lastResp()
	if !ok {
		t.Fatal("no response")
	}
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
		t.Fatalf("response = %+v, want R10's errno", got)
	}
	ev := sink.one(t)
	if ev.Verdict != record.VerdictRefused || ev.Rule != rulePathTruncated || ev.Reason != record.ReasonWriteOutsideContract {
		t.Errorf("line = %s/%s/%s, want refused/%s/%s", ev.Verdict, ev.Rule, ev.Reason, rulePathTruncated, record.ReasonWriteOutsideContract)
	}
}

// TestDenyReadMoveWalksAPathItCannotJoin is R15d for the same name: at tier 2 a link whose old name has no
// R6 spelling is still walked where the task's lookup lands, so a file beneath an unenforced deny_read keeps
// its refusal. The walk was skipped for an empty spelling and the link was continued.
func TestDenyReadMoveWalksAPathItCannotJoin(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	cwd, raw := longJoin("../secret/key")
	fs := []agent.FSRule{
		{Path: "/w", Kind: agent.FSWrite},
		{Path: "/w/secret", Kind: agent.FSDenyRead, Unenforced: true},
	}
	f := newFake()
	f.links["/proc/42/cwd"] = cwd
	f.put(pathAddr, cstr(raw))
	f.put(path2Addr, cstr("/w/hl"))
	f.fsTargets[""] = "/w/secret/key" // the only end with no R6 spelling is the old name
	pol := testPolicy(nil, fs, nil)
	pol.Rules.Tier = backend.TierCgroup
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(nrFor(t, "linkat"), 42, argCWD, pathAddr, argCWD, path2Addr, 0))
	got, _ := f.lastResp()
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
		t.Fatalf("response = %+v, want a refusal", got)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != "fs.deny_read[/w/secret]" {
		t.Errorf("line = %s/%s, want refused under the deny_read", ev.Verdict, ev.Rule)
	}
}

// TestMoveToAPathItCannotJoinIsObserved is R5 for a rename's or a link's second end read whole whose join to
// its cwd is over PATH_MAX, with no deny_write target to refuse it under: decideMoveDest has no spelling to
// decide the destination by, so the line is observed under path-truncated, not the source's allow with an
// empty path2, and tier 2's hand-over names nothing for the recorder. Both were the source's allow.
func TestMoveToAPathItCannotJoinIsObserved(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	cwd, raw := longJoin("../../elsewhere/b")
	fs := []agent.FSRule{{Path: "/w", Kind: agent.FSWrite}}
	for _, sc := range []string{"renameat", "linkat"} {
		t.Run(sc, func(t *testing.T) {
			f := newFake()
			f.links["/proc/42/cwd"] = cwd
			f.put(pathAddr, cstr("/w/a"))
			f.put(path2Addr, cstr(raw))
			l, sink := newTestLoop(t, f, testPolicy(nil, fs, nil))
			args := []uint64{argCWD, pathAddr, argCWD, path2Addr}
			if sc == "linkat" {
				args = append(args, 0)
			}
			l.handle(notifFor(nrFor(t, sc), 42, args...))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want CONTINUE", got)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictObserved || ev.Rule != rulePathTruncated || ev.Reason != "" {
				t.Errorf("line = %s/%s/%s, want observed/%s", ev.Verdict, ev.Rule, ev.Reason, rulePathTruncated)
			}

			pol := testPolicy(nil, fs, nil)
			pol.Rules.Tier = backend.TierCgroup
			f = newFake()
			f.links["/proc/42/cwd"] = cwd
			f.put(pathAddr, cstr("/w/a"))
			f.put(path2Addr, cstr(raw))
			l, _ = newTestLoop(t, f, pol)
			l.kernelFS = func() bool { return true }
			l.handle(notifFor(nrFor(t, sc), 42, args...))
			op := record.FSRename
			if sc == "linkat" {
				op = record.FSLink
			}
			if n, ok := l.ContinuedFS(42, op, "a", ".", monotonicNS()); ok {
				t.Errorf("hand-over named %+v, want nothing", n)
			}
		})
	}
}

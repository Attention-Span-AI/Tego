// SPDX-License-Identifier: Apache-2.0
//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// attrNR is the native dispatch number of an attribute-change syscall. It fails, never skips, when the table has no
// entry, save for x86-64's legacy chown and lchown, which arm64's generic table does not have.
func attrNR(t *testing.T, name string) int32 {
	t.Helper()
	if name == "chown" || name == "lchown" {
		return nrFor(t, name)
	}
	for k, e := range buildDispatch() {
		if e.name == name {
			return k.nr
		}
	}
	t.Fatalf("the dispatch table has no entry for %s", name)
	return 0
}

// TestWriteGateScoresAnAttributeChange of GATE-STEP2-ROWS: a POSIX ACL set through
// setxattr(2) (system.posix_acl_access) rewrites the mode bits as a chmod does, and a write gate that refused
// `chmod 755 ../outside/o.txt` let `setfacl -m u::rwx,g::r-x,o::r-x ../outside/p.txt` make the file 0755, with no
// score and no line; a chown, which hands the group bits to another group, was the same gap. Every call that sets or
// removes an extended attribute, and every chown, is now scored as a write (recordAttr), the attribute's name never
// read: a racing thread could rewrite it between this loop's read and the kernel's, so scoring only the ACL names
// would be a check a peer defeats. The line's op is xattr or chown. Outside the worktree each form is refused fs-gate
// under the gate's authority; inside it the call is continued and recorded allow.
func TestWriteGateScoresAnAttributeChange(t *testing.T) {
	const (
		pathAddr = 0x10000
		nameAddr = 0x20000
		outside  = "/area/outside/p.txt"
		inside   = "/area/proj/a.txt"
	)
	fs := []agent.FSRule{{Path: "/area", Kind: agent.FSWrite, Raw: "/area"}}
	held := func(p string) map[string]string { return map[string]string{"/proc/42/fd/5": p} }
	for _, tc := range []struct {
		name, syscall, path string
		args                []uint64
		links               map[string]string
		op                  string
		refused             bool
		wantPath            string
	}{
		{name: "setxattr outside", syscall: "setxattr", path: outside, args: []uint64{pathAddr, nameAddr, 0, 0, 0}, op: record.FSXattr, refused: true},
		{name: "lsetxattr outside", syscall: "lsetxattr", path: outside, args: []uint64{pathAddr, nameAddr, 0, 0, 0}, op: record.FSXattr, refused: true},
		{name: "fsetxattr outside", syscall: "fsetxattr", args: []uint64{5, nameAddr, 0, 0, 0},
			links: held(outside), op: record.FSXattr, refused: true, wantPath: outside},
		{name: "removexattr outside", syscall: "removexattr", path: outside, args: []uint64{pathAddr, nameAddr}, op: record.FSXattr, refused: true},
		{name: "lremovexattr outside", syscall: "lremovexattr", path: outside, args: []uint64{pathAddr, nameAddr}, op: record.FSXattr, refused: true},
		{name: "fremovexattr outside", syscall: "fremovexattr", args: []uint64{5, nameAddr},
			links: held(outside), op: record.FSXattr, refused: true, wantPath: outside},
		{name: "setxattrat outside", syscall: "setxattrat", path: outside,
			args: []uint64{argCWD, pathAddr, 0, nameAddr, 0, 0}, op: record.FSXattr, refused: true},
		{name: "setxattrat AT_EMPTY_PATH names the descriptor's file", syscall: "setxattrat", path: "",
			args:  []uint64{5, pathAddr, unix.AT_EMPTY_PATH, nameAddr, 0, 0},
			links: held(outside), op: record.FSXattr, refused: true, wantPath: outside},
		// 6.13's *at forms take a NULL pathname with AT_EMPTY_PATH as the descriptor itself (getname_maybe_null).
		{name: "setxattrat NULL AT_EMPTY_PATH names the descriptor's file", syscall: "setxattrat",
			args:  []uint64{5, 0, unix.AT_EMPTY_PATH, nameAddr, 0, 0},
			links: held(outside), op: record.FSXattr, refused: true, wantPath: outside},
		{name: "removexattrat outside", syscall: "removexattrat", path: outside,
			args: []uint64{argCWD, pathAddr, unix.AT_SYMLINK_NOFOLLOW, nameAddr}, op: record.FSXattr, refused: true},
		{name: "chown outside", syscall: "chown", path: outside, args: []uint64{pathAddr, ^uint64(0), 100}, op: record.FSChown, refused: true},
		{name: "lchown outside", syscall: "lchown", path: outside, args: []uint64{pathAddr, ^uint64(0), 100}, op: record.FSChown, refused: true},
		{name: "fchown outside", syscall: "fchown", args: []uint64{5, ^uint64(0), 100},
			links: held(outside), op: record.FSChown, refused: true, wantPath: outside},
		{name: "fchownat outside", syscall: "fchownat", path: outside,
			args: []uint64{argCWD, pathAddr, ^uint64(0), 100, 0}, op: record.FSChown, refused: true},
		{name: "fchownat AT_EMPTY_PATH names the descriptor's file", syscall: "fchownat", path: "",
			args:  []uint64{5, pathAddr, ^uint64(0), 100, unix.AT_EMPTY_PATH},
			links: held(outside), op: record.FSChown, refused: true, wantPath: outside},
		{name: "setxattr inside the worktree", syscall: "setxattr", path: inside, args: []uint64{pathAddr, nameAddr, 0, 0, 0}, op: record.FSXattr},
		{name: "fremovexattr inside the worktree", syscall: "fremovexattr", args: []uint64{5, nameAddr},
			links: held(inside), op: record.FSXattr, wantPath: inside},
		{name: "fchownat inside the worktree", syscall: "fchownat", path: inside,
			args: []uint64{argCWD, pathAddr, ^uint64(0), 100, 0}, op: record.FSChown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nr := attrNR(t, tc.syscall)
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			f.put(nameAddr, cstr("system.posix_acl_access"))
			for k, v := range tc.links {
				f.links[k] = v
			}
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Tier = backend.TierLandlock
			pol.Rules.Workdir = "/area/proj"
			pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90)
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nr, 42, tc.args...))
			got, _ := f.lastResp()
			ev := sink.one(t)
			var p record.FSPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			want := tc.wantPath
			if want == "" {
				want = tc.path
			}
			if p.Op != tc.op || p.Path != want {
				t.Errorf("payload = %+v, want op %s path %s", p, tc.op, want)
			}
			if !tc.refused {
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || ev.Verdict != record.VerdictAllow {
					t.Fatalf("response %+v line %s/%s; want continued and recorded allow", got, ev.Verdict, ev.Rule)
				}
				return
			}
			if got.Flags != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response %+v; want the gate's refusal", got)
			}
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonFSGate || ev.Authority != record.AuthorityGate {
				t.Fatalf("line %+v; want refused fs-gate under the gate's authority", ev)
			}
		})
	}
}

// TestAttributeChangeIsNotScoredWithoutAWriteGate: the xattr and chown families reach this loop only under a write
// gate, but a handler that runs without one (a read gate alone) refuses nothing: no fs rule below a decision plane
// governs an attribute, so the line reads allow under the entry a modification there is named by, as a chmod's does.
func TestAttributeChangeIsNotScoredWithoutAWriteGate(t *testing.T) {
	const pathAddr, nameAddr = 0x10000, 0x20000
	for _, tc := range []struct {
		syscall string
		args    []uint64
	}{
		{"setxattr", []uint64{pathAddr, nameAddr, 0, 0, 0}},
		{"fchownat", []uint64{argCWD, pathAddr, ^uint64(0), 100, 0}},
	} {
		t.Run(tc.syscall, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr("/elsewhere/a.env"))
			f.put(nameAddr, cstr("user.x"))
			pol := testPolicy(nil, []agent.FSRule{{Path: "/area", Kind: agent.FSWrite, Raw: "/area"}}, nil)
			pol.Rules.Tier = backend.TierLandlock
			pol.Rules.Workdir = "/area"
			pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 95)
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(attrNR(t, tc.syscall), 42, tc.args...))
			got, _ := f.lastResp()
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response %+v; want continued", got)
			}
			if ev := sink.one(t); ev.Verdict != record.VerdictAllow || ev.Rule != ruleUnmatched {
				t.Fatalf("line %s/%s; want allow under %s", ev.Verdict, ev.Rule, ruleUnmatched)
			}
		})
	}
}

// TestAttributeChangeUnderThePlaneRefusesADenyWriteTarget: with a decision plane deciding the run (Options.PlaneAttrs),
// the kernel's path_chown and xattr hooks refuse an attribute change beneath a deny_write target (enforce-plane R12),
// so this loop refuses one it is notified of itself, by R15c's predicate, as it refuses a chmod
// (TestChmodUnderThePlaneRefusesADenyWriteTarget): the action's one line is that refusal, not an allow the kernel then
// overturns. A write gate is what notifies these families; the target is inside the worktree, so the gate allows it.
func TestAttributeChangeUnderThePlaneRefusesADenyWriteTarget(t *testing.T) {
	const work = "/work/proj"
	const pathAddr, nameAddr = 0x10000, 0x20000
	fs := []agent.FSRule{{Path: work, Kind: agent.FSWrite, Raw: "./proj/"}}
	deny := []agent.FSRule{{Path: work + "/.git", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: work + "/.git"}}
	for _, tc := range []struct {
		syscall string
		args    []uint64
		plane   bool
		refused bool
	}{
		{"setxattr", []uint64{pathAddr, nameAddr, 0, 0, 0}, true, true},
		{"fchownat", []uint64{argCWD, pathAddr, ^uint64(0), 100, 0}, true, true},
		{"setxattr", []uint64{pathAddr, nameAddr, 0, 0, 0}, false, false},
	} {
		t.Run(tc.syscall, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(work+"/.git/config"))
			f.put(nameAddr, cstr("user.x"))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Tier = backend.TierCgroup
			pol.Rules.Workdir = work
			pol.Rules.DenyWrite = deny
			pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90)
			l, sink := newTestLoop(t, f, pol)
			l.planeAttrs = tc.plane
			l.handle(notifFor(attrNR(t, tc.syscall), 42, tc.args...))
			got, _ := f.lastResp()
			if continued := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; continued == tc.refused {
				t.Fatalf("response = %+v, refused: want %v", got, tc.refused)
			}
			ev := sink.one(t)
			if tc.refused && (ev.Verdict != record.VerdictRefused || ev.Rule != "fs.deny_write["+work+"/.git]") {
				t.Errorf("verdict/rule = %s/%s, want refused under the target", ev.Verdict, ev.Rule)
			}
			if !tc.refused && ev.Verdict != record.VerdictAllow {
				t.Errorf("verdict = %s, want allow", ev.Verdict)
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestFSVerdictIsTakenWhereThePathLands is R15b for an allowed spelling: a read or a write through a symlink
// the contract does not declare, planted in a write entry, is decided by the kernel where it lands, so the line
// says refused under the entry there (ADR 0017's fs/read-through-undeclared-symlink-to-deny-read and
// link/write-open-outside-through-undeclared-symlink cells). A walk that fails as the task's own lookup fails
// keeps the spelling's verdict; one that cannot say where the path lands records observed, never allow.
//
// Spec: docs/p0/supervisor.md R15b.
func TestFSVerdictIsTakenWhereThePathLands(t *testing.T) {
	fs := []agent.FSRule{
		{Path: "/work/out", Kind: agent.FSWrite, Raw: "./out/"},
		{Path: "/work/secrets", Kind: agent.FSDenyRead, Raw: "./secrets/"},
	}
	const pathAddr = 0x10000
	for _, tc := range []struct {
		name    string
		path    string
		flags   uint64
		lands   string
		err     error
		verdict record.Verdict
		rule    string
	}{
		{"a read through a symlink into a deny_read", "/work/out/sl", 0, "/work/secrets/key", nil,
			record.VerdictRefused, "fs.deny_read[./secrets/]"},
		{"a write through a symlink out of the write entry", "/work/out/esc", 0x241, "/work/elsewhere/e", nil,
			record.VerdictRefused, ruleUnmatched},
		{"a read of a missing name keeps the spelling's verdict", "/work/out/none", 0, "", unix.ENOENT,
			record.VerdictAllow, "fs.write[./out/]"},
		{"a place in another view is unknown, not allowed", "/work/out/other", 0, "", errOtherView,
			record.VerdictObserved, rulePathUnreliable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			if tc.err != nil {
				f.fsTargetErrs[tc.path] = tc.err
			} else {
				f.fsTargets[tc.path] = tc.lands
			}
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Record = agent.RecordFull
			pol.Rules.Tier = backend.TierLandlock
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, tc.flags))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want CONTINUE", got)
			}
			ev := sink.one(t)
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule {
				t.Errorf("verdict/rule = %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.verdict, tc.rule)
			}
		})
	}
}

// TestRenameAndLinkAreDecidedAtBothEnds: Landlock decides a rename or a link at the destination too
// (the right to make the entry there, and REFER across directories) and refuses a move that gives the file a
// right its source did not grant, so a rename out of a write entry, whose source alone is allowed, is
// refused, named where it was refused (ADR 0017's fs/rename-out-of-write-entry).
//
// Spec: docs/p0/supervisor.md R17.
func TestRenameAndLinkAreDecidedAtBothEnds(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	fs := []agent.FSRule{
		{Path: "/work/out", Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet},
		{Path: "/work/wide", Kind: agent.FSWrite, Raw: "./wide/", Access: agent.AccessWriteSet | agent.AccessReadSet},
	}
	for _, tc := range []struct {
		name, syscall, from, to string
		verdict                 record.Verdict
		rule                    string
	}{
		{"rename within the entry", "renameat", "/work/out/a", "/work/out/b", record.VerdictAllow, "fs.write[./out/]"},
		{"rename out of the entry", "renameat", "/work/out/a", "/work/a", record.VerdictRefused, ruleUnmatched},
		{"link out of the entry", "linkat", "/work/out/a", "/work/a", record.VerdictRefused, ruleUnmatched},
		{"rename to where the file gains a right", "renameat", "/work/out/a", "/work/wide/a", record.VerdictRefused, "fs.write[./out/]"},
		{"rename to where it loses one", "renameat", "/work/wide/a", "/work/out/a", record.VerdictAllow, "fs.write[./wide/]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.from))
			f.put(path2Addr, cstr(tc.to))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Tier = backend.TierLandlock
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, tc.syscall), 42, argCWD, pathAddr, argCWD, path2Addr, 0))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want CONTINUE: Landlock refuses it", got)
			}
			ev := sink.one(t)
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule {
				t.Errorf("verdict/rule = %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.verdict, tc.rule)
			}
			if len(f.fsQueries) != 2 {
				t.Errorf("walked %d times, want once per end", len(f.fsQueries))
			}
		})
	}
}

// TestLinkLineIsWhatLandlockAnswers is R17 for a hard link as Landlock decides it (hook_path_link): MAKE_REG on the new
// name's directory, REFER on both directories when they differ, never on the file itself, and no file right gained at
// the new name's directory. Landlock refused (EXDEV) a cross-directory link of a file-level write entry and a link into
// an exec.allow directory, while this loop's line said allow: a ledger lie (security F3; ADR 0016).
// The line now says refused, the syscall is still continued so the refusal stays Landlock's, and the indexed table
// and the scan answer alike. A rename is held to hook_path_rename the same way: nothing compared within one
// directory, the new name's directory against the moved object (never a rule on the name it replaces), both ways
// under RENAME_EXCHANGE, and the file rights only for an object that is no directory. The atomic replace of an
// exec.allow file entry inside a write entry was recorded refused while Landlock allowed it, and
// so was a file moved where only a directory right is gained (F2).
//
// Spec: docs/p0/supervisor.md R17.
func TestLinkLineIsWhatLandlockAnswers(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	fs := []agent.FSRule{
		{Path: "/work/out", Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet},
		{Path: "/work/a.txt", Kind: agent.FSWrite, Raw: "./a.txt", Access: agent.AccessWriteSet, Regular: true},
		// A hand-built entry short of a directory right: a file linked or moved from it gains none of the file rights,
		// and a directory moved from it gains a right no_more_access compares for a directory.
		{Path: "/work/narrow", Kind: agent.FSWrite, Raw: "./narrow/", Access: agent.AccessWriteSet &^ agent.AccessMakeChar},
		// A symlink write entry, out/cur -> bin/v1, which a rename or a link acts on itself.
		{Path: "/work/out/cur", Resolved: "/work/out/bin/v1", Kind: agent.FSWrite, Raw: "./out/cur", Access: agent.AccessWriteSet},
	}
	exec := []agent.ExecRule{
		{Raw: "./out/bin/", Path: "/work/out/bin", IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
		{Raw: "./out/tool", Path: "/work/out/tool", Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
	}
	for _, tc := range []struct {
		name, syscall, from, to string
		flags                   uint64
		verdict                 record.Verdict
		rule                    string
		reason                  record.Reason
		dir                     bool // the moved object is a directory (FinalIsDir)
	}{
		// rename(2) and linkat(2) without AT_SYMLINK_FOLLOW act on a symlink entry's own name, in its own directory,
		// where Landlock has no rule: the atomic swap of out/cur and a move onto it gain nothing, and a
		// link or a move of the symlink into the exec.allow directory gains EXECUTE (EXDEV).
		{"A: the atomic swap of a symlink write entry", "renameat", "/work/out/cur.new", "/work/out/cur", 0, record.VerdictAllow, "fs.write[./out/]", "", false},
		{"B: a move onto the symlink entry", "renameat", "/work/out/sub/t", "/work/out/cur", 0, record.VerdictAllow, "fs.write[./out/]", "", false},
		{"C: a link of the symlink entry into the exec.allow directory", "linkat", "/work/out/cur", "/work/out/bin/x2", 0, record.VerdictRefused, "fs.write[./out/]", record.ReasonWriteOutsideContract, false},
		{"D: a move of the symlink entry into it", "renameat", "/work/out/cur", "/work/out/bin/cur2", 0, record.VerdictRefused, "fs.write[./out/]", record.ReasonRenameOutsideContract, false},
		{"a file-level write entry linked across directories", "linkat", "/work/a.txt", "/work/out/a2", 0, record.VerdictRefused, ruleUnmatched, record.ReasonWriteOutsideContract, false},
		{"a link into an exec.allow directory", "linkat", "/work/out/a", "/work/out/bin/a2", 0, record.VerdictRefused, "fs.write[./out/]", record.ReasonWriteOutsideContract, false},
		{"a rename into it", "renameat", "/work/out/a", "/work/out/bin/a2", 0, record.VerdictRefused, "fs.write[./out/]", record.ReasonRenameOutsideContract, false},
		{"a link out of it", "linkat", "/work/out/bin/t", "/work/out/t", 0, record.VerdictAllow, "fs.write[./out/]", "", false},
		{"a link within the write entry", "linkat", "/work/out/a", "/work/out/b", 0, record.VerdictAllow, "fs.write[./out/]", "", false},
		{"a link to where only a directory right is gained", "linkat", "/work/narrow/a", "/work/out/a", 0, record.VerdictAllow, "fs.write[./narrow/]", "", false},
		// no_more_access compares only the file rights for an object that is no directory.
		{"a rename to there", "renameat", "/work/narrow/a", "/work/out/a", 0, record.VerdictAllow, "fs.write[./narrow/]", "", false},
		{"a directory renamed to there", "renameat", "/work/narrow/d", "/work/out/d", 0, record.VerdictRefused, "fs.write[./narrow/]", record.ReasonRenameOutsideContract, true},
		// A rule on the name a rename replaces is never asked, and a rename within one directory compares nothing
		// (current_check_refer_path): the atomic replace of an exec.allow file entry.
		{"an atomic replace of an exec.allow file entry", "renameat", "/work/out/tool.new", "/work/out/tool", 0, record.VerdictAllow, "fs.write[./out/]", "", false},
		{"a move onto it from another directory", "renameat", "/work/out/sub/x", "/work/out/tool", 0, record.VerdictAllow, "fs.write[./out/]", "", false},
		{"an exchange with it", "renameat2", "/work/out/sub/x", "/work/out/tool", unix.RENAME_EXCHANGE, record.VerdictAllow, "fs.write[./out/]", "", false},
		{"a directory replacing the exec.allow directory", "renameat", "/work/out/newbin", "/work/out/bin", 0, record.VerdictAllow, "fs.write[./out/]", "", true},
		{"an exchange that lands a file in the exec.allow directory", "renameat2", "/work/out/bin/t", "/work/out/a", unix.RENAME_EXCHANGE, record.VerdictRefused, "fs.write[./out/]", record.ReasonRenameOutsideContract, false},
	} {
		for _, indexed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/indexed=%v", tc.name, indexed), func(t *testing.T) {
				f := newFake()
				f.put(pathAddr, cstr(tc.from))
				f.put(path2Addr, cstr(tc.to))
				if tc.dir {
					f.finalDirs = map[string]bool{tc.from: true}
				}
				pol := testPolicy(nil, fs, nil)
				pol.Rules.Exec = exec
				pol.Rules.Contract = &agent.Contract{Name: "links", Exec: &agent.ExecSection{Allow: []string{"./out/bin/", "./out/tool"}}}
				pol.Rules.Tier = backend.TierLandlock
				l, sink := newTestLoop(t, f, pol)
				if !indexed {
					l.table.Load().fsIx = nil
				}
				l.handle(notifFor(nrFor(t, tc.syscall), 42, argCWD, pathAddr, argCWD, path2Addr, tc.flags))
				if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response = %+v, want CONTINUE: Landlock decides it", got)
				}
				ev := sink.one(t)
				if ev.Verdict != tc.verdict || ev.Rule != tc.rule || ev.Reason != tc.reason {
					t.Errorf("verdict/rule/reason = %s/%s/%s, want %s/%s/%s", ev.Verdict, ev.Rule, ev.Reason, tc.verdict, tc.rule, tc.reason)
				}
			})
		}
	}
}

// TestMoveEndsAreLandedByTheirOwnWalk: each end of a rename or a link is decided where its own walk lands it, never
// where another end with the same cleaned spelling lands. With out/lk -> realbin/sub inside the write entry out/ and
// the exec.allow directory out/realbin/, the new name out/lk/../x cleans lexically to the source's own out/x, while
// the kernel walks out/realbin/sub/.. = out/realbin and refuses the move or the link EXDEV (it gains EXECUTE). The
// destination's landing was looked up by its cleaned spelling among the notification's walks, which found the
// source's (out/x), so the no-gain rule compared a directory with itself and the line said allow (a ledger lie at
// tier landlock). Real walks of a real tree, as a run makes them.
//
// Spec: docs/p0/supervisor.md R17.
func TestMoveEndsAreLandedByTheirOwnWalk(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	w, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"out/realbin/sub"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"out/x", "out/y"} {
		if err := os.WriteFile(filepath.Join(w, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("realbin/sub", filepath.Join(w, "out/lk")); err != nil {
		t.Fatal(err)
	}
	out := w + "/out"
	for _, tc := range []struct {
		name, syscall, from, to string
		verdict                 record.Verdict
		reason                  record.Reason
	}{
		{"a rename to a name that cleans to its own", "renameat", out + "/x", out + "/lk/../x", record.VerdictRefused, record.ReasonRenameOutsideContract},
		{"a link to a name that cleans to its own", "linkat", out + "/y", out + "/lk/../y", record.VerdictRefused, record.ReasonWriteOutsideContract},
		{"a rename through the link's parent to another name", "renameat", out + "/x", out + "/lk/../x2", record.VerdictRefused, record.ReasonRenameOutsideContract},
		{"a link to the real directory's own name", "linkat", out + "/y", out + "/realbin/sub/../y", record.VerdictRefused, record.ReasonWriteOutsideContract},
		{"a rename within the write entry", "renameat", out + "/x", out + "/./x2", record.VerdictAllow, ""},
	} {
		for _, indexed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/indexed=%v", tc.name, indexed), func(t *testing.T) {
				f := newFake()
				f.realWalks = true
				f.put(pathAddr, cstr(tc.from))
				f.put(path2Addr, cstr(tc.to))
				pol := testPolicy(nil, []agent.FSRule{{Path: out, Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet}}, nil)
				pol.Rules.Exec = []agent.ExecRule{{Raw: "./out/realbin/", Path: out + "/realbin", IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow}}
				pol.Rules.Contract = &agent.Contract{Name: "ends", Exec: &agent.ExecSection{Allow: []string{"./out/realbin/"}}}
				pol.Rules.Tier = backend.TierLandlock
				l, sink := newTestLoop(t, f, pol)
				if !indexed {
					l.table.Load().fsIx = nil
				}
				l.handle(notifFor(nrFor(t, tc.syscall), 42, argCWD, pathAddr, argCWD, path2Addr, 0))
				if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response = %+v, want CONTINUE: Landlock decides it", got)
				}
				ev := sink.one(t)
				if ev.Verdict != tc.verdict || ev.Rule != "fs.write[./out/]" || ev.Reason != tc.reason {
					t.Errorf("verdict/rule/reason = %s/%s/%s, want %s/fs.write[./out/]/%s", ev.Verdict, ev.Rule, ev.Reason, tc.verdict, tc.reason)
				}
			})
		}
	}
}

// TestLineInAReplacedWriteLinkNamesTheGrantingEntry: a write entry declared through a link, ./out/wp/wl/ with out/wp/wl
// -> ../xd, has its Landlock rule on xd's inode. Once the agent moves the link away and makes a real out/wp/wl, a mkdir,
// a create and an unlink inside it are granted by ./out/, and the line names ./out/; it named ./out/wp/wl/, matched by
// its declared spelling, though that entry grants nothing there. While the
// link is in place a write beneath it lands in out/xd and is the linked entry's.
//
// Spec: docs/p0/supervisor.md R15b.
func TestLineInAReplacedWriteLinkNamesTheGrantingEntry(t *testing.T) {
	const pathAddr = 0x10000
	w, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"out/wp/wl", "out/xd", "out/xd2", "out/wp2"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(w, "out/wp/wl/f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../xd2", filepath.Join(w, "out/wp2/wl")); err != nil {
		t.Fatal(err)
	}
	out := w + "/out"
	for _, tc := range []struct {
		name, syscall, p string
		flags            uint64
		rule             string
	}{
		{"a mkdir in the real directory at the link's name", "mkdirat", out + "/wp/wl/sub", 0o755, "fs.write[./out/]"},
		{"a create there", "openat", out + "/wp/wl/new", unix.O_WRONLY | unix.O_CREAT, "fs.write[./out/]"},
		{"an unlink there", "unlinkat", out + "/wp/wl/f", 0, "fs.write[./out/]"},
		{"a create beneath the link still in place", "openat", out + "/wp2/wl/new", unix.O_WRONLY | unix.O_CREAT, "fs.write[./out/wp2/wl/]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.realWalks = true
			f.put(pathAddr, cstr(tc.p))
			pol := testPolicy(nil, []agent.FSRule{
				{Path: out, Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet},
				{Path: out + "/wp/wl", Resolved: out + "/xd", Kind: agent.FSWrite, Raw: "./out/wp/wl/", Access: agent.AccessWriteSet},
				{Path: out + "/wp2/wl", Resolved: out + "/xd2", Kind: agent.FSWrite, Raw: "./out/wp2/wl/", Access: agent.AccessWriteSet},
			}, nil)
			pol.Rules.Tier = backend.TierLandlock
			pol.Record = agent.RecordFull
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, tc.syscall), 42, argCWD, pathAddr, tc.flags, 0o644))
			ev := sink.one(t)
			if ev.Verdict != record.VerdictAllow || ev.Rule != tc.rule {
				t.Errorf("verdict/rule = %s/%s, want allow/%s", ev.Verdict, ev.Rule, tc.rule)
			}
		})
	}
}

// heldExecTable is a write entry with an exec.allow directory and file inside it, images restricted, at tier landlock:
// the shape whose Landlock grants are bound to the inodes the builder held (enforce-landlock R5).
func heldExecTable() *Policy {
	pol := testPolicy(nil, []agent.FSRule{{Path: "/work/out", Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet}}, nil)
	pol.Rules.Exec = []agent.ExecRule{
		{Raw: "./out/bin/", Path: "/work/out/bin", IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
		{Raw: "./out/tool", Path: "/work/out/tool", Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
	}
	pol.Rules.Contract = &agent.Contract{Name: "held", Exec: &agent.ExecSection{Allow: []string{"./out/bin/", "./out/tool"}}}
	pol.Rules.Tier = backend.TierLandlock
	return pol
}

// movedExecDir has the fake filesystem in the state `mv out/bin out/old; mkdir out/bin` leaves, after the loop
// took its identities: the inode the Landlock builder granted EXECUTE to is out/old now, and out/bin is a new
// directory with no grant.
func movedExecDir(f *fakeKernel) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statIDs == nil {
		f.statIDs = map[string]fileID{}
	}
	f.statIDs["/work/out/old"] = fakeID("/work/out/bin")
	f.statIDs["/work/out/bin"] = fakeID("/work/out/bin (new)")
}

// TestReferLineFollowsTheHeldInode: Landlock binds an exec.allow grant to the inode the builder held at Prepare,
// and the rule moves with that inode. After `mv out/bin out/old` inside the write entry, and `mkdir out/bin`, a file
// renamed or linked into out/old gains EXECUTE and the kernel refuses it (EXDEV), while one moved out of out/old into
// the new out/bin, or linked there, gains nothing and is allowed. The line followed the declared names and said allow
// for the first two and refused for the last two (a ledger lie). The no-gain rule now asks the
// identity of each end's directories (decide.ExecGrants); the syscall is still Landlock's to answer.
//
// Spec: docs/p0/supervisor.md R17.
func TestReferLineFollowsTheHeldInode(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	for _, tc := range []struct {
		name, syscall, from, to string
		verdict                 record.Verdict
		reason                  record.Reason
	}{
		{"a rename into the moved exec directory", "renameat", "/work/out/a", "/work/out/old/a", record.VerdictRefused, record.ReasonRenameOutsideContract},
		{"a link into it", "linkat", "/work/out/b", "/work/out/old/b", record.VerdictRefused, record.ReasonWriteOutsideContract},
		{"a move out of it into the recreated name", "renameat", "/work/out/old/tool", "/work/out/bin/tool", record.VerdictAllow, ""},
		{"a link into the recreated name", "linkat", "/work/out/c", "/work/out/bin/c", record.VerdictAllow, ""},
		{"a hard link of the exec.allow file moved into another directory", "renameat", "/work/out/sub/tool-link", "/work/out/sub2/t", record.VerdictAllow, ""},
	} {
		for _, indexed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/indexed=%v", tc.name, indexed), func(t *testing.T) {
				f := newFake()
				f.put(pathAddr, cstr(tc.from))
				f.put(path2Addr, cstr(tc.to))
				l, sink := newTestLoop(t, f, heldExecTable())
				if !indexed {
					l.table.Load().fsIx = nil
				}
				movedExecDir(f)
				f.mu.Lock()
				f.statIDs["/work/out/sub/tool-link"] = fakeID("/work/out/tool") // the granted inode, by another name
				f.mu.Unlock()
				l.handle(notifFor(nrFor(t, tc.syscall), 42, argCWD, pathAddr, argCWD, path2Addr, 0))
				if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response = %+v, want CONTINUE: Landlock decides it", got)
				}
				ev := sink.one(t)
				if ev.Verdict != tc.verdict || ev.Rule != "fs.write[./out/]" || ev.Reason != tc.reason {
					t.Errorf("verdict/rule/reason = %s/%s/%s, want %s/fs.write[./out/]/%s", ev.Verdict, ev.Rule, ev.Reason, tc.verdict, tc.reason)
				}
			})
		}
	}
}

// TestExecLineFollowsTheHeldDirectory: an exec of a file under an exec.allow directory's declared name is granted
// only while that name still holds the inode the Landlock builder granted EXECUTE to. After `mv out/bin out/old;
// mkdir out/bin` the kernel refuses an exec of out/bin/tool (EACCES), which the line recorded allow under the
// directory entry; the loop now refuses it itself, never continued, as any exec no entry grants.
//
// Spec: docs/p0/supervisor.md R16.
func TestExecLineFollowsTheHeldDirectory(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	for _, moved := range []bool{false, true} {
		t.Run(fmt.Sprintf("moved=%v", moved), func(t *testing.T) {
			f := newFake()
			l, sink := newTestLoop(t, f, heldExecTable())
			if moved {
				movedExecDir(f)
			}
			f.put(pathAddr, cstr("/work/out/bin/tool"))
			execFixture(f, argvAddr, []string{"tool"})
			l.handle(notifFor(nrFor(t, "execve"), 42, pathAddr, argvAddr, 0))
			want, rule := record.VerdictAllow, "exec[./out/bin/]"
			if moved {
				want, rule = record.VerdictRefused, ruleUnmatched
			}
			wantExecAnswer(t, f, want)
			if ev := sink.one(t); ev.Verdict != want || ev.Rule != rule {
				t.Errorf("verdict/rule = %s/%s, want %s/%s", ev.Verdict, ev.Rule, want, rule)
			}
		})
	}
}

// TestTier2ExecUnderAListenerDenyReadIsRefused is R16b at tier 2: the fanotify listener refuses the exec's
// open of an image under a deny_read (an exec.allow directory inside one), so the continued exec's line says
// refused under that deny_read, not allow under the exec entry (ADR 0017's
// exec/exec-entry-directory-inside-deny-read at tier cgroup). Tier 1 lets it run.
//
// Spec: docs/p0/supervisor.md R16b.
func TestTier2ExecUnderAListenerDenyReadIsRefused(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	for _, tc := range []struct {
		tier    backend.Tier
		verdict record.Verdict
		rule    string
	}{
		{backend.TierCgroup, record.VerdictRefused, "fs.deny_read[./secrets/]"},
		{backend.TierLandlock, record.VerdictAllow, "exec[/work/secrets/bin/]"},
	} {
		t.Run(string(tc.tier), func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr("/work/secrets/bin/tool"))
			execFixture(f, argvAddr, []string{"tool"})
			pol := testPolicy(nil, []agent.FSRule{{Path: "/work/secrets", Kind: agent.FSDenyRead, Raw: "./secrets/"}}, nil)
			pol.Rules.Exec = []agent.ExecRule{{Path: "/work/secrets/bin/", IsDir: true, Source: agent.ExecSourceAllow}}
			pol.Rules.Tier = tc.tier
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, "execve"), 42, pathAddr, argvAddr, 0))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want CONTINUE: the refusal is the listener's", got)
			}
			ev := sink.one(t)
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule {
				t.Errorf("verdict/rule = %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.verdict, tc.rule)
			}
			// This line is the exec's one (R7a): the listener, asking about the refused open of the image by
			// this process, is told to write none, once; at tier 1 nothing refuses the open.
			id := fakeID("/work/secrets/bin/tool")
			if got := l.ExecLine(ev.TID, id.dev, id.ino); got != (tc.tier == backend.TierCgroup) {
				t.Errorf("ExecLine = %v at tier %s", got, tc.tier)
			}
			if l.ExecLine(ev.TID, id.dev, id.ino) || l.ExecLine(ev.TID+1, id.dev, id.ino) {
				t.Error("one exec answered for a second open, or for another process")
			}
		})
	}
}

// TestTier2ListenerRefusalIsTheListenersLine is R7a for an open at tier 2: an open the Landlock ruleset lets
// through and the fanotify listener refuses — a read under a deny_read nested in a write entry, a write-open
// there — is recorded by the listener, the mechanism that refused it, so this loop writes no line of its own
// and the open has one (ADR 0017's fs/read-deny-read-nested-in-write at tier cgroup held three). A refusal
// Landlock makes first never reaches the listener and keeps this loop's line, and at tier 1 every open keeps it.
//
// Spec: docs/p0/supervisor.md R7a.
func TestTier2ListenerRefusalIsTheListenersLine(t *testing.T) {
	fs := []agent.FSRule{
		{Path: "/work/out", Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet | agent.AccessReadSet},
		{Path: "/work/out/keys", Kind: agent.FSDenyRead, Raw: "./out/keys/", Unenforced: true},
		{Path: "/work/secrets", Kind: agent.FSDenyRead, Raw: "./secrets/"},
	}
	const pathAddr = 0x10000
	for _, tc := range []struct {
		name  string
		tier  backend.Tier
		path  string
		flags uint64
		lines int
	}{
		{"read under the nested deny_read", backend.TierCgroup, "/work/out/keys/k", 0, 0},
		{"write-open under it", backend.TierCgroup, "/work/out/keys/w", 0x241, 1},
		{"read Landlock refuses first", backend.TierCgroup, "/work/secrets/k", 0, 1},
		{"read under the nested deny_read at tier 1", backend.TierLandlock, "/work/out/keys/k", 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Record = agent.RecordFull
			pol.Rules.Tier = tc.tier
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, tc.flags))
			if got, _ := f.lastResp(); (got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0) != (tc.tier == backend.TierCgroup && tc.flags != 0) {
				t.Fatalf("response = %+v, expected only fallback write-open preemption", got)
			}
			if got := len(sink.all()); got != tc.lines {
				t.Errorf("%d lines from this loop, want %d: %+v", got, tc.lines, sink.all())
			}
		})
	}
}

// A mknod under a deny_read nested in a write entry is no open: tier 2's fanotify listener never sees it, and
// Landlock's union allows it under the write entry. So at tier 2 without the kernel recorder the loop writes
// the create's line itself, allowed under the write entry, never refused read-denied and never skipped as the
// listener's (R7a, R15).
func TestTier2MknodUnderNestedDenyReadKeepsItsLine(t *testing.T) {
	fs := []agent.FSRule{
		{Path: "/work/out", Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet | agent.AccessReadSet},
		{Path: "/work/out/keys", Kind: agent.FSDenyRead, Raw: "./out/keys/", Unenforced: true},
	}
	const pathAddr = 0x10000
	for _, tc := range []struct {
		name string
		args func(nr int32) *notif
	}{
		{"mknodat", func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.S_IFIFO|0o600, 0) }},
		{"mknod", func(nr int32) *notif { return notifFor(nr, 42, pathAddr, unix.S_IFIFO|0o600, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr("/work/out/keys/w"))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Record = agent.RecordFull
			pol.Rules.Tier = backend.TierCgroup
			l, sink := newTestLoop(t, f, pol)
			l.handle(tc.args(nrFor(t, tc.name)))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("response = %+v, want fallback refusal", got)
			}
			evs := sink.all()
			if len(evs) != 1 {
				t.Fatalf("%d lines, want 1: %+v", len(evs), evs)
			}
			if evs[0].Verdict != record.VerdictRefused || evs[0].Rule != "fs.deny_read[./out/keys/]" {
				t.Errorf("line = %+v, want refused under fs.deny_read[./out/keys/]", evs[0])
			}
		})
	}
}

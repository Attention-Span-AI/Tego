// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestFSLineNameIsTheDecisionsWalk: an end spelled with a ".." is named by the walk its verdict was taken on, never by
// a second walk. An agent can move a symlink between two walks of one notification, and a name walked apart from the
// decision then named a file the verdict and rule were never taken on: in an earlier build, an
// open of out/lk/../f decided where out/lk led at the decision's walk, and named where it led at a second walk, so a
// flip of out/lk between them wrote "allow b/f, rule fs.write[./out/]" for a file outside every write entry, and
// "refused out/a/f, write-outside-contract" for one inside it. Here the tree
// changes after every walk the loop makes (afterWalk), out/lk flipped between out/a/sub and ../b/sub, so a line named
// by any walk but the decision's names the other file. Each end a syscall follows is covered: an open, an attribute
// change, and a link's source with AT_SYMLINK_FOLLOW, from each side of the flip, and the kernel recorder's naming of a
// continued open. Real walks of a real tree, as a run makes them.
//
// Spec: docs/p0/supervisor.md R15b.
func TestFSLineNameIsTheDecisionsWalk(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	for _, tc := range []struct {
		name, syscall string
		args          func(a1, a2 uint64) []uint64
		to            string // a link's new name, relative to the test's directory
		op            string // the recorder's op, for the handover case
		// outside is the verdict on b/f, outside every write entry: a refusal, except for a mode change, which no
		// Landlock right governs at tier landlock.
		outside record.Verdict
	}{
		{name: "a write-open", syscall: "openat", op: record.FSOpen,
			args: func(a1, _ uint64) []uint64 { return []uint64{argCWD, a1, unix.O_WRONLY, 0} }},
		{name: "a mode change", syscall: "fchmodat", outside: record.VerdictAllow,
			args: func(a1, _ uint64) []uint64 { return []uint64{argCWD, a1, 0o600} }},
		{name: "a link's followed source", syscall: "linkat", to: "out/n",
			args: func(a1, a2 uint64) []uint64 { return []uint64{argCWD, a1, argCWD, a2, unix.AT_SYMLINK_FOLLOW} }},
	} {
		for _, start := range []struct {
			target, reached string
			verdict         record.Verdict
		}{
			{"a/sub", "out/a/f", record.VerdictAllow},
			{"../b/sub", "b/f", record.VerdictRefused},
		} {
			for _, handoff := range []bool{false, true} {
				if handoff && (tc.op == "" || start.verdict != record.VerdictAllow) {
					continue // only a continued open is the recorder's line
				}
				t.Run(fmt.Sprintf("%s/out-lk-to-%s/handoff=%v", tc.name, start.target, handoff), func(t *testing.T) {
					w, err := filepath.EvalSymlinks(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					for _, d := range []string{"out/a/sub", "b/sub"} {
						if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
							t.Fatal(err)
						}
					}
					for _, f := range []string{"out/a/f", "b/f"} {
						if err := os.WriteFile(filepath.Join(w, f), []byte("x"), 0o644); err != nil {
							t.Fatal(err)
						}
					}
					lk := filepath.Join(w, "out/lk")
					if err := os.Symlink(start.target, lk); err != nil {
						t.Fatal(err)
					}
					f := newFake()
					f.realWalks, f.goneOnSend = true, true
					target := start.target
					f.afterWalk = func() {
						target = map[string]string{"a/sub": "../b/sub", "../b/sub": "a/sub"}[target]
						if err := os.Remove(lk); err != nil {
							t.Error(err)
						}
						if err := os.Symlink(target, lk); err != nil {
							t.Error(err)
						}
					}
					f.put(pathAddr, cstr(w+"/out/lk/../f"))
					if tc.to != "" {
						f.put(path2Addr, cstr(filepath.Join(w, tc.to)))
					}
					out := w + "/out"
					pol := testPolicy(nil, []agent.FSRule{{Path: out, Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet}}, nil)
					pol.Rules.Tier = backend.TierLandlock
					if handoff {
						pol.Rules.Tier = backend.TierCgroup
					}
					pol.Record = agent.RecordFull
					l, sink := newTestLoop(t, f, pol)
					if handoff {
						l.kernelFS = func() bool { return true }
					}
					l.handle(notifFor(nrFor(t, tc.syscall), 42, tc.args(pathAddr, path2Addr)...))
					want, verdict := filepath.Join(w, start.reached), start.verdict
					if tc.outside != "" && start.verdict == record.VerdictRefused {
						verdict = tc.outside
					}
					if handoff {
						if got := len(sink.all()); got != 0 {
							t.Fatalf("%d lines from this loop, want none: the kernel recorder writes it", got)
						}
						n, ok := l.ContinuedFS(42, tc.op, "f", "", monotonicNS())
						if !ok || n.Path != want || n.Verdict != verdict {
							t.Errorf("ContinuedFS = %+v, %v; want %s of %q: the file the decision's walk reached", n, ok, verdict, want)
						}
						return
					}
					ev := sink.one(t)
					var p record.FSPayload
					if err := ev.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
					if ev.Verdict != verdict || p.Path != want {
						t.Errorf("line: %s of %q (rule %s, %s), want %s of %q: the file the decision's walk reached",
							ev.Verdict, p.Path, ev.Rule, ev.Reason, verdict, want)
					}
				})
			}
		}
	}
}

// TestTheWalkNamesADotDotSpelling: the walk that lands an end also names it, for a pathname with a ".." component
// (execWalk.named): where it landed the directory of the final component as spelled, joined with that component, never
// followed; where the whole walk lands for a final "." or "..", followed or not (a final "." or ".." is never a
// symlink); the name kept when the walk fails past that directory; and no name at
// all for a pathname with no ".." and no final ".", or for a final "." or ".." of a syscall that makes, removes or
// renames a name (pathQuery.parent), which it refuses before a lookup of its own. FSTarget and ExecImage both answer
// it, from their own walk. Real walks of a real tree, as this
// process.
//
// Spec: docs/p0/supervisor.md R15b, R16b.
func TestTheWalkNamesADotDotSpelling(t *testing.T) {
	w, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"out/realbin/sub", "out/realbin/d"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(w, "out/realbin/e"), []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"out/lk": "realbin/sub", "out/realbin/ln": "e", "out/realbin/dl": "planted", "out/realbin/loop": "loop"} {
		if err := os.Symlink(target, filepath.Join(w, link)); err != nil {
			t.Fatal(err)
		}
	}
	rb := w + "/out/realbin"
	for _, tc := range []struct {
		desc     string
		q        pathQuery
		at, name string
		err      error
	}{
		{"a followed final symlink is named, not followed", pathQuery{path: w + "/out/lk/../ln"}, rb + "/e", rb + "/ln", nil},
		{"an end not followed is named where it lands", pathQuery{path: w + "/out/lk/../e", nofollow: true}, rb + "/e", rb + "/e", nil},
		{"a trailing slash is not the name's", pathQuery{path: w + "/out/lk/../d/", nofollow: true}, rb + "/d", rb + "/d", nil},
		{"a final dot-dot is named where the whole walk lands", pathQuery{path: w + "/out/lk/.."}, rb, rb, nil},
		{"a final dot names the directory", pathQuery{path: w + "/out/lk/../."}, rb, rb, nil},
		{"an O_CREAT of a missing name", pathQuery{path: w + "/out/lk/../new", create: true}, rb + "/new", rb + "/new", nil},
		{"an O_CREAT through a dangling link names the link", pathQuery{path: w + "/out/lk/../dl", create: true}, rb + "/planted", rb + "/dl", nil},
		{"a walk that fails past the directory keeps its name", pathQuery{path: w + "/out/lk/../loop"}, "", rb + "/loop", unix.ELOOP},
		// A final ".." or "." is never a symlink, so a lookup that does not follow one resolves it as any other does
		// (path_lookupat): an attribute change with AT_SYMLINK_NOFOLLOW acts there.
		{"an unfollowed final dot-dot is named where the whole walk lands", pathQuery{path: w + "/out/lk/..", nofollow: true}, rb, rb, nil},
		{"an unfollowed final dot is named where the whole walk lands", pathQuery{path: w + "/out/lk/.", nofollow: true}, rb + "/sub", rb + "/sub", nil},
		{"a followed final dot is named where the whole walk lands", pathQuery{path: w + "/out/lk/."}, rb + "/sub", rb + "/sub", nil},
		{"a missing directory before a final dot-dot fails the lookup", pathQuery{path: w + "/out/none/..", nofollow: true}, "", "", unix.ENOENT},
		// The families that look up only the final component's directory (filename_parentat, filename_create) refuse a
		// final "." or ".." before a lookup of their own: no walk, so no name.
		{"a final dot-dot of a name-making syscall has no walk and no name", pathQuery{path: w + "/out/lk/..", nofollow: true, parent: true}, "", "", unix.EINVAL},
		{"a final dot of a name-making syscall has no walk and no name", pathQuery{path: w + "/out/lk/.", nofollow: true, parent: true}, "", "", unix.EINVAL},
		{"a file where the final component's directory is spelled names nothing", pathQuery{path: w + "/out/lk/../e/x"}, "", "", unix.ENOTDIR},
		{"control: no dot-dot, no name", pathQuery{path: w + "/out/lk/sub2", create: true}, rb + "/sub/sub2", "", nil},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			q := tc.q
			q.tid, q.dirfd = os.Getpid(), atFDCWD
			got, err := sysKernel{}.FSTarget(q)
			if !errors.Is(err, tc.err) || (tc.err == nil && err != nil) || got.at != tc.at || got.name != tc.name {
				t.Errorf("FSTarget = %+v, %v; want at %q name %q, %v", got, err, tc.at, tc.name, tc.err)
			}
		})
	}
	t.Run("ExecImage names the link it runs through", func(t *testing.T) {
		img, err := sysKernel{}.ExecImage(pathQuery{tid: os.Getpid(), dirfd: atFDCWD, path: w + "/out/lk/../ln"})
		if err != nil || img.link != rb+"/e" || img.name != rb+"/ln" {
			t.Errorf("ExecImage = link %q name %q, %v; want link %q name %q", img.link, img.name, err, rb+"/e", rb+"/ln")
		}
		img, err = sysKernel{}.ExecImage(pathQuery{tid: os.Getpid(), dirfd: atFDCWD, path: w + "/out/lk/../loop"})
		if !errors.Is(err, unix.ELOOP) || img.name != rb+"/loop" {
			t.Errorf("ExecImage of a loop = name %q, %v; want name %q, ELOOP", img.name, err, rb+"/loop")
		}
	})
}

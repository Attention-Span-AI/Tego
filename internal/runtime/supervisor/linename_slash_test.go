// SPDX-License-Identifier: Apache-2.0

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

// TestANameEndEndingInSlashIsDecidedOnTheName: an unlink, an rmdir, a mkdir, a rename's new name and a link's new name
// spelled with a trailing slash act on the name in its directory, never where a final symlink leads (filename_parentat
// strips the slash; lookup_one_qstr_excl looks the name up unfollowed), so the kernel answers ENOTDIR or EEXIST itself
// and Landlock's rmdir and rename hooks are asked at the symlink's own directory. FSTarget walked such an end whole, the
// final symlink followed, so with out/lk -> ../b/sub an rmdir or unlink of out/lk/ was decided on b/sub, outside every
// write entry: the loop refused it and the line read "refused out/lk, unmatched", a refusal no mechanism made, where
// the out/ write entry grants the name and the agent gets the kernel's ENOTDIR. With ro/lk -> ../out/sub, the
// verdict taken on out/sub read allow for an end Landlock refuses at
// ro (EACCES). A dangling out/dl, which the walk could not follow, was decided on the name already. Real walks of a
// real tree, as a run makes them.
//
// Spec: docs/p0/supervisor.md R15b.
func TestANameEndEndingInSlashIsDecidedOnTheName(t *testing.T) {
	const pathAddr, srcAddr = 0x10000, 0x20000
	for _, tc := range []struct {
		syscall string
		op      string
		dest    bool // the end is the syscall's second pathname (Path2)
		args    func(p uint64) []uint64
	}{
		{"unlinkat", record.FSUnlink, false, func(p uint64) []uint64 { return []uint64{argCWD, p, 0} }},
		{"unlinkat", record.FSUnlink, false, func(p uint64) []uint64 { return []uint64{argCWD, p, unix.AT_REMOVEDIR} }},
		{"mkdirat", record.FSMkdir, false, func(p uint64) []uint64 { return []uint64{argCWD, p, 0o755} }},
		{"renameat", record.FSRename, true, func(p uint64) []uint64 { return []uint64{argCWD, srcAddr, argCWD, p} }},
		{"linkat", record.FSLink, true, func(p uint64) []uint64 { return []uint64{argCWD, srcAddr, argCWD, p, 0} }},
	} {
		// ro/lk leads into the write entry from a directory none grants: Landlock's rmdir and rename hooks refuse it at
		// ro (EACCES), where a verdict taken on out/sub read allow.
		for _, end := range []struct {
			spelled, name string
			allow         bool
		}{{"out/lk/", "out/lk", true}, {"out/dl/", "out/dl", true}, {"out/sub/../lk/", "out/lk", true}, {"ro/lk/", "ro/lk", false}} {
			t.Run(fmt.Sprintf("%s/%s/%d", tc.syscall, end.spelled, tc.args(0)[len(tc.args(0))-1]), func(t *testing.T) {
				w, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				for _, d := range []string{"out/sub", "out/src", "b/sub", "ro"} {
					if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(w, "out/f"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
				for link, target := range map[string]string{"out/lk": "../b/sub", "out/dl": "../b/new", "ro/lk": "../out/sub"} {
					if err := os.Symlink(target, filepath.Join(w, link)); err != nil {
						t.Fatal(err)
					}
				}
				src := w + "/out/src" // a directory, so a rename onto a name ending in "/" is not refused before its hook
				if tc.syscall == "linkat" {
					src = w + "/out/f"
				}
				f := newFake()
				f.realWalks = true
				f.put(pathAddr, cstr(w+"/"+end.spelled))
				f.put(srcAddr, cstr(src))
				pol := testPolicy(nil, []agent.FSRule{{Path: w + "/out", Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet}}, nil)
				pol.Rules.Tier = backend.TierLandlock
				pol.Record = agent.RecordFull
				l, sink := newTestLoop(t, f, pol)
				l.handle(notifFor(nrFor(t, tc.syscall), 42, tc.args(pathAddr)...))
				got, _ := f.lastResp()
				refused := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0
				ev := sink.one(t)
				var p record.FSPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				name := filepath.Join(w, end.name)
				named := p.Path
				if tc.dest {
					named = p.Path2
				}
				if p.Op != tc.op || named != name {
					t.Errorf("line names %s %q (path2 %q), want %s with the end %q: the name the syscall acts on", p.Op, p.Path,
						p.Path2, tc.op, name)
				}
				if !end.allow {
					if ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched {
						t.Errorf("line %s rule %s; want refused, %s: Landlock refuses the name at a directory no entry grants",
							ev.Verdict, ev.Rule, ruleUnmatched)
					}
					return
				}
				if refused || ev.Verdict != record.VerdictAllow || ev.Rule != "fs.write[./out/]" {
					t.Errorf("refused %v, line %s rule %s; want a continued allow under fs.write[./out/], the entry that grants "+
						"the name, the kernel's own ENOTDIR or EEXIST to follow", refused, ev.Verdict, ev.Rule)
				}
			})
		}
	}
}

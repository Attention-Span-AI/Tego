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

// TestAnUnfollowedFinalDotIsWherePathLookupLands: an attribute change that does not follow a final symlink
// (AT_SYMLINK_NOFOLLOW, lchown, lsetxattr) and whose pathname ends in ".." or "." acts where path_lookupat lands it: a
// final ".." or "." is never a symlink, so the kernel resolves it physically, a symlink before it followed. With out/lk
// -> ../b/sub, a mode change of out/lk/.. changes b and one of out/lk/. changes b/sub. FSTarget answered EINVAL for
// such an end without a walk (as the rename, unlink, mkdir and link families refuse it, before a lookup of their own),
// so the verdict was the lexical clean's, and the line named out, "allow, rule fs.write[./out/]", for a change outside
// every write entry; with a plane deciding the run, R15c's refusal of a deny_write target reached so was skipped, and the
// loop's allow was the action's one line while the plane's hook refused it. Real walks of a real tree, as a run
// makes them.
//
// Spec: docs/p0/supervisor.md R15b, R15c.
func TestAnUnfollowedFinalDotIsWherePathLookupLands(t *testing.T) {
	const pathAddr, nameAddr = 0x10000, 0x20000
	nofollow := uint64(unix.AT_SYMLINK_NOFOLLOW)
	for _, tc := range []struct {
		syscall string
		op      string
		args    func(p uint64) []uint64
	}{
		{"fchmodat2", record.FSChmod, func(p uint64) []uint64 { return []uint64{argCWD, p, 0o711, nofollow} }},
		{"fchownat", record.FSChown, func(p uint64) []uint64 { return []uint64{argCWD, p, ^uint64(0), ^uint64(0), nofollow} }},
		{"lchown", record.FSChown, func(p uint64) []uint64 { return []uint64{p, ^uint64(0), ^uint64(0)} }},
		{"lsetxattr", record.FSXattr, func(p uint64) []uint64 { return []uint64{p, nameAddr, 0, 0, 0} }},
		{"setxattrat", record.FSXattr, func(p uint64) []uint64 { return []uint64{argCWD, p, nofollow, nameAddr, 0, 0} }},
		// The class: an O_NOFOLLOW open looks its final "." or ".." up as path_lookupat does, and opens that directory.
		{"openat", record.FSOpen, func(p uint64) []uint64 {
			return []uint64{argCWD, p, unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_DIRECTORY, 0}
		}},
	} {
		for _, end := range []struct{ spelled, reached string }{{"out/lk/..", "b"}, {"out/lk/.", "b/sub"}} {
			for _, plane := range []bool{false, true} {
				if plane && tc.op == record.FSOpen {
					continue // a read is no modification: no deny_write target refuses it
				}
				t.Run(fmt.Sprintf("%s/%s/plane=%v", tc.syscall, end.spelled, plane), func(t *testing.T) {
					nr := attrNR(t, tc.syscall) // skips a legacy form this architecture lacks
					w, err := filepath.EvalSymlinks(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					for _, d := range []string{"out", "b/sub"} {
						if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.Symlink("../b/sub", filepath.Join(w, "out/lk")); err != nil {
						t.Fatal(err)
					}
					f := newFake()
					f.realWalks = true
					f.put(pathAddr, cstr(w+"/"+end.spelled))
					f.put(nameAddr, cstr("user.x"))
					reached := filepath.Join(w, end.reached)
					pol := testPolicy(nil, []agent.FSRule{{Path: w + "/out", Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet}}, nil)
					pol.Rules.Tier = backend.TierLandlock
					if plane {
						// The plane's hooks refuse an attribute change beneath a deny_write target: here the place the
						// kernel reaches, which the lexical clean never names.
						pol.Rules.Tier = backend.TierCgroup
						pol.Rules.DenyWrite = []agent.FSRule{{Path: reached, Resolved: reached, Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true}}
					}
					pol.Record = agent.RecordFull
					l, sink := newTestLoop(t, f, pol)
					l.planeAttrs = plane
					l.handle(notifFor(nr, 42, tc.args(pathAddr)...))
					got, _ := f.lastResp()
					refused := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0
					ev := sink.one(t)
					var p record.FSPayload
					if err := ev.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
					if p.Path != reached || p.Op != tc.op {
						t.Errorf("line names %s %q (%s, rule %s), want %s %q: where the kernel's lookup lands", p.Op, p.Path,
							ev.Verdict, ev.Rule, tc.op, reached)
					}
					if plane {
						if !refused || ev.Verdict != record.VerdictRefused || ev.Rule != "fs.deny_write["+reached+"]" {
							t.Errorf("refused %v, line %s rule %s; want the loop's own refusal under fs.deny_write[%s]",
								refused, ev.Verdict, ev.Rule, reached)
						}
						return
					}
					if tc.op == record.FSOpen {
						// A read where no entry matches (this contract restricts no read), never under the write entry the
						// lexical clean names.
						if refused || ev.Rule != ruleUnmatched {
							t.Errorf("refused %v, line %s rule %s; want a continued open decided where it lands, rule %s",
								refused, ev.Verdict, ev.Rule, ruleUnmatched)
						}
						return
					}
					if refused || ev.Verdict != record.VerdictAllow || ev.Rule == "fs.write[./out/]" {
						t.Errorf("refused %v, line %s rule %s; want a continued allow decided where it lands, not under the write entry it never reached",
							refused, ev.Verdict, ev.Rule)
					}
				})
			}
		}
	}
}

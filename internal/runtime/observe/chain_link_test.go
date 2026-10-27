// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRecorderNamesTheLandlockLinkRefusal: at tier 2's plane modes and at tier 3 the kernel recorder writes a link's
// line from the chain's return, and the Landlock ruleset under the plane refuses a link path_link allows: a
// cross-directory link of a file-level write entry, whose directory has no REFER, and a link into an exec.allow
// directory, where the file would gain EXECUTE (hook_path_link, -EXDEV). The model explains that refusal, so the line
// says refused, write-outside-contract, under the name tier 1's line and compile --test give it, not observed by
// another mechanism (security F3 and F4). A link the ruleset allows keeps the old answer. A rename
// within one directory onto an exec.allow file entry is no REFER question (current_check_refer_path), so a refusal
// the chain returned for it is another mechanism's, not the ruleset's no-gain rule.
func TestRecorderNamesTheLandlockLinkRefusal(t *testing.T) {
	f := newFixture(t)
	addSyntheticParentIndex(f)
	bin := filepath.Join(f.out, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	f.rules.FS = append(f.rules.FS,
		agent.FSRule{Path: filepath.Join(f.dir, "a.txt"), Resolved: filepath.Join(f.dir, "a.txt"), Raw: "./a.txt", Kind: agent.FSWrite,
			Access: agent.AccessWriteSet, Regular: true},
		// A write entry of its own, so the directory index names out/bin as it names every declared directory.
		agent.FSRule{Path: bin, Resolved: bin, Raw: "./out/bin", Kind: agent.FSWrite, Access: agent.AccessWriteSet})
	f.rules.Exec = append(f.rules.Exec, agent.ExecRule{Raw: "./out/bin/", Path: bin, Resolved: bin, IsDir: true,
		Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
		agent.ExecRule{Raw: "./out/tool", Path: filepath.Join(f.out, "tool"), Resolved: filepath.Join(f.out, "tool"),
			Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
	f.rules.Tier = backend.TierBPFLSM
	top, ok1 := statDevIno(f.dir)
	out, ok2 := statDevIno(f.out)
	bi, ok3 := statDevIno(bin)
	if !ok1 || !ok2 || !ok3 {
		t.Fatal("could not stat the fixture's directories")
	}
	link := func(mono uint64, ret int32, from devIno, name string, to devIno, name2 string) []byte {
		h := sample{Kind: KindLink, PID: 50, TID: 50, MonoNS: mono, Ret: ret, RetOK: true}
		e := bpf.FSOpEvent{Hdr: h.header(FSOpSize), Dev: kernelDev(from.Dev), DirIno: from.Ino, Op: fsOpCode(KindLink),
			Ret: ret, RetOk: 1, NameOk: 1, Name2Ok: 1, Dev2: kernelDev(to.Dev), DirIno2: to.Ino}
		copy(e.Name[:], fixed(name, NameMax))
		copy(e.Name2[:], fixed(name2, NameMax))
		return wire(&e)
	}
	exdev := -int32(unix.EXDEV)
	rename := func(mono uint64, ret int32, from devIno, name string, to devIno, name2 string) []byte {
		h := sample{Kind: KindRename, PID: 50, TID: 50, MonoNS: mono, Ret: ret, RetOK: true}
		e := bpf.FSOpEvent{Hdr: h.header(FSOpSize), Dev: kernelDev(from.Dev), DirIno: from.Ino, Op: fsOpCode(KindRename),
			Ret: ret, RetOk: 1, NameOk: 1, Name2Ok: 1, Dev2: kernelDev(to.Dev), DirIno2: to.Ino}
		copy(e.Name[:], fixed(name, NameMax))
		copy(e.Name2[:], fixed(name2, NameMax))
		return wire(&e)
	}
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		link(1, exdev, top, "a.txt", out, "a2"),
		link(2, exdev, out, "x.txt", bi, "x2"),
		link(3, 0, bi, "t", out, "t2"),
		rename(4, exdev, out, "y.txt", bi, "y2"),
		rename(5, -int32(unix.EACCES), out, "tool.new", out, "tool"),
		// The file-level write entry's own rename and unlink: the plane's hooks allow both, the Landlock floor under
		// them refuses both, EACCES, for want of REFER or REMOVE_FILE on its directory.
		rename(6, -int32(unix.EACCES), top, "a.txt", out, "a3"),
		fsSample(sample{Kind: KindUnlink, PID: 50, TID: 50, MonoNS: 7, Ret: -int32(unix.EACCES), RetOK: true}, 0, uint32(top.Ino), top.Dev, "a.txt", ""),
	)
	fs := sink.byKind(record.KindFS)
	if len(fs) != 7 {
		t.Fatalf("%d fs lines, want 7: %+v", len(fs), fs)
	}
	aTxt := filepath.Join(f.dir, "a.txt")
	renameName, renameRefused := decide.LandlockRenameRefusal(f.rules, aTxt, filepath.Join(f.out, "a3"), true)
	deleteName, deleteRefused := decide.LandlockDeleteRefusal(f.rules, aTxt)
	if !renameRefused || !deleteRefused {
		t.Fatalf("the ruleset allows the file-level entry's own rename (%v) or unlink (%v)", !renameRefused, !deleteRefused)
	}
	for i, w := range map[int]struct {
		reason record.Reason
		rule   string
	}{5: {record.ReasonRenameOutsideContract, renameName}, 6: {record.ReasonDeleteOutsideContract, deleteName}} {
		if ev := fs[i]; ev.Verdict != record.VerdictRefused || ev.Reason != w.reason || ev.Rule != w.rule {
			t.Errorf("line %d, the file-level entry's own move: %s %s via %q by %q, want refused %s via the directory's %q", i, ev.Verdict,
				ev.Reason, ev.Rule, payload[record.FSPayload](t, ev).By, w.reason, w.rule)
		}
	}
	if ev := fs[4]; ev.Verdict != record.VerdictObserved || payload[record.FSPayload](t, ev).By != record.FSByOther {
		t.Errorf("the replace of the exec.allow file entry: %s %s by %q, want observed by another mechanism", ev.Verdict, ev.Reason,
			payload[record.FSPayload](t, ev).By)
	}
	// The rename into the exec.allow directory: REFER's no-gain rule (decide.RenameGains), named by its source.
	if ev := fs[3]; ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonRenameOutsideContract || ev.Rule != "fs.write[./out]" {
		t.Errorf("the rename into the exec directory: %s %s via %q, want refused rename-outside-contract via fs.write[./out]", ev.Verdict, ev.Reason, ev.Rule)
	}
	for i, w := range []struct {
		src, dst string
		verdict  record.Verdict
		reason   record.Reason
	}{
		{filepath.Join(f.dir, "a.txt"), filepath.Join(f.out, "a2"), record.VerdictRefused, record.ReasonWriteOutsideContract},
		{filepath.Join(f.out, "x.txt"), filepath.Join(bin, "x2"), record.VerdictRefused, record.ReasonWriteOutsideContract},
		{filepath.Join(bin, "t"), filepath.Join(f.out, "t2"), record.VerdictAllow, ""},
	} {
		ev := fs[i]
		p := payload[record.FSPayload](t, ev)
		if p.Path != w.src || p.Path2 != w.dst || ev.Verdict != w.verdict || ev.Reason != w.reason || p.By != "" {
			t.Errorf("line %d: %s %q -> %q (%s, by %q), want %s %q -> %q (%s)", i, ev.Verdict, p.Path, p.Path2, ev.Reason, p.By,
				w.verdict, w.src, w.dst, w.reason)
		}
		if w.verdict == record.VerdictRefused {
			if name, _ := decide.LandlockLinkRefusal(f.rules, w.src, w.dst); ev.Rule != name {
				t.Errorf("line %d: rule %q, want the ruleset's %q", i, ev.Rule, name)
			}
		}
	}
}

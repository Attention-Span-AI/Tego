// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSymlinkedProjectIsMatchedByItsCanonicalPath: a project reached through a symlink (the cwd a shell
// reports, a symlinked $HOME). compile keeps each entry's Path as declared and its
// Resolved canonical, and bpf_d_path reports the canonical path, so the index matched by Path alone missed every
// open: a read the kernel refused under the deny_read entry was recorded allow, and a write Landlock allowed
// in the write entry refused as outside the contract. The contract goes through the real agent.Compile.
func TestSymlinkedProjectIsMatchedByItsCanonicalPath(t *testing.T) {
	real, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(real, "proj")
	for _, d := range []string{"out", "secrets", "ledger"} {
		if err := os.MkdirAll(filepath.Join(proj, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(proj, "secrets", "key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(proj, link); err != nil {
		t.Fatal(err)
	}
	yaml := "version: 0\nname: sym\ncommand: [\"/bin/sh\", \"-c\", \"true\"]\n" +
		"fs:\n  write: [\"./out\"]\n  deny_read: [\"./secrets\"]\n" +
		"exec:\n  allow: [\"sh\"]\ntier: cgroup\n"
	contract := filepath.Join(link, "agent.yaml")
	if err := os.WriteFile(contract, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, ds, err := agent.LoadBytes(contract, []byte(yaml), nil)
	if err != nil {
		t.Fatalf("Load: %v %v", err, ds)
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(real, "ledger")
	rt, ds, err := agent.Compile(c, m, agent.WithPATH("/usr/bin:/bin"), agent.WithCwd(link), agent.WithHome(link),
		agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("Compile: %v %v", err, ds)
	}
	f := newFixture(t)
	f.rules = rt
	secret, report := filepath.Join(proj, "secrets", "key"), filepath.Join(proj, "out", "report")
	src, ok := statDevIno(filepath.Join(proj, "out"))
	if !ok {
		t.Fatal("stat out")
	}
	mk := fsSample(sample{Kind: KindMkdir, PID: 50, MonoNS: 3}, 0, 0, 0, "sub", "")
	e, err := bpf.Decode[bpf.FSOpEvent](mk)
	if err != nil {
		t.Fatal(err)
	}
	e.Dev, e.DirIno = kernelDev(src.Dev), src.Ino
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		// The kernel refuses this read (fanotify and Landlock match Resolved); d_path is canonical.
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 1}, 0, 1, 2049, secret, ""),
		// Landlock allows this write: the write entry's fd pins the target.
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 2}, uint32(os.O_WRONLY|os.O_CREATE), 2, 2049, report, ""),
		wire(&e))
	got := map[string]*record.Event{}
	for _, ev := range sink.byKind(record.KindFS) {
		got[payload[record.FSPayload](t, ev).Path] = ev
	}
	if ev := got[secret]; ev == nil || ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonReadDenied ||
		ev.Rule != "fs.deny_read[./secrets]" {
		t.Errorf("the refused read of the deny_read entry was recorded %+v", ev)
	}
	if ev := got[report]; ev == nil || ev.Verdict != record.VerdictAllow || ev.Rule != "fs.write[./out]" {
		t.Errorf("the allowed write in the write entry was recorded %+v", ev)
	}
	// An fs operation's path is rebuilt from the directory index, and spelled as an open's is: canonically.
	if ev := got[filepath.Join(proj, "out", "sub")]; ev == nil || ev.Verdict != record.VerdictAllow {
		t.Errorf("mkdir in the write entry was not recorded allow under its canonical path: %v", got)
	}
}

// TestRenameIsDecidedAtBothEnds: Landlock decides a rename on its destination too, and
// fentry/security_path_rename ran before Landlock did, so the recorder infers it. The verdict was the
// source's alone, and a rename out of the write entry, which Landlock refuses at the destination, was recorded
// allow. A destination the contract refuses is the refusal; one the index cannot name leaves it observed.
func TestRenameIsDecidedAtBothEnds(t *testing.T) {
	f := newFixture(t)
	addSyntheticParentIndex(f)
	out, ok1 := statDevIno(f.out)
	dir, ok2 := statDevIno(f.dir)
	if !ok1 || !ok2 {
		t.Fatal("stat")
	}
	rename := func(mono uint64, dst devIno) []byte {
		h := sample{Kind: KindRename, PID: 50, MonoNS: mono}
		e := bpf.FSOpEvent{Hdr: h.header(FSOpSize), Dev: kernelDev(out.Dev), DirIno: out.Ino,
			Dev2: kernelDev(dst.Dev), DirIno2: dst.Ino, NameOk: 1, Name2Ok: 1}
		copy(e.Name[:], "a.txt")
		copy(e.Name2[:], "b.txt")
		return wire(&e)
	}
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		rename(1, dir), // out of the write entry: refused at the destination
		rename(2, out), // within it: allowed at both ends
		rename(3, devIno{Dev: out.Dev, Ino: 4242})) // into a directory the index cannot name
	want := map[string]struct {
		verdict record.Verdict
		reason  record.Reason
	}{
		filepath.Join(f.dir, "b.txt"): {record.VerdictRefused, record.ReasonRenameOutsideContract},
		filepath.Join(f.out, "b.txt"): {record.VerdictAllow, ""},
		"":                            {record.VerdictObserved, ""},
	}
	evs := sink.byKind(record.KindFS)
	if len(evs) != 3 {
		t.Fatalf("%d fs events, want 3", len(evs))
	}
	for _, ev := range evs {
		p := payload[record.FSPayload](t, ev)
		key := p.Path2
		if strings.Contains(key, ":4242/") {
			key = ""
		}
		w, ok := want[key]
		if !ok || ev.Verdict != w.verdict || ev.Reason != w.reason {
			t.Errorf("rename %s -> %s recorded %s %s %s", p.Path, p.Path2, ev.Rule, ev.Verdict, ev.Reason)
		}
	}
}

// TestPathBytesAreMatchedRaw is enforce-cgroup-observe.md §6 E18: the kernel decided on a path's raw bytes, and the recorder matched after cstring had
// replaced a byte that is not UTF-8 with U+FFFD, so a read under a deny_read entry spelled with such a byte named
// no entry and was recorded allow. The line itself stays valid UTF-8.
func TestPathBytesAreMatchedRaw(t *testing.T) {
	f := newFixture(t)
	denied := filepath.Join(f.dir, "sec\xff")
	f.rules = ruleTable([]agent.FSRule{{Path: denied, Kind: agent.FSDenyRead, Raw: "./sec\xff"}}, nil, nil)
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 1}, 0, 1, 2049, denied+"/key", ""))
	evs := sink.byKind(record.KindFS)
	if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonReadDenied {
		t.Fatalf("a read under the deny_read entry recorded %+v", evs)
	}
	if !utf8.Valid(evs[0].Payload) {
		t.Errorf("the line is not valid UTF-8: %q", evs[0].Payload)
	}
}

// TestUnenforcedDenyReadOnAnUnmarkedMountIsObserved is enforce-cgroup-observe.md §6 E24's
// recorder half: a deny_read entry nested in a write entry is refused by tier 2's fanotify listener alone, which marks the mounts under it at Prepare. A mount the host makes beneath
// it later is on no mark, so a read there is made, and the line said refused (E24). The recorder compares the
// open's device with the devices of the mounts the listener marked. A read on a marked mount is the listener's
// refusal, whose own line is the one kept (supervisor R7a): the recorder writes none.
func TestUnenforcedDenyReadOnAnUnmarkedMountIsObserved(t *testing.T) {
	f := newFixture(t)
	di, ok := statDevIno(f.secrets)
	if !ok {
		t.Fatal("stat")
	}
	mountinfo := filepath.Join(t.TempDir(), "mountinfo")
	line := fmt.Sprintf("1 0 %d:%d / / rw - fs dev rw\n", unix.Major(di.Dev), unix.Minor(di.Dev))
	if err := os.WriteFile(mountinfo, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := ruleTable([]agent.FSRule{
		{Path: f.dir, Kind: agent.FSWrite, Raw: "."},
		{Path: f.secrets, Kind: agent.FSDenyRead, Raw: "./secrets", Unenforced: true},
	}, nil, nil)
	rt.Tier = backend.TierCgroup
	f.rules = rt
	later := unix.Mkdev(0, 4242)
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, mountinfo: mountinfo},
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 1}, 0, 1, di.Dev, filepath.Join(f.secrets, "a"), ""),
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 2}, 0, 2, later, filepath.Join(f.secrets, "late", "b"), ""))
	got := map[string]record.Verdict{}
	for _, ev := range sink.byKind(record.KindFS) {
		got[payload[record.FSPayload](t, ev).Path] = ev.Verdict
	}
	if v, ok := got[filepath.Join(f.secrets, "a")]; ok {
		t.Errorf("a read on the marked mount recorded %s, want no line: the listener's refusal is its line", v)
	}
	if v := got[filepath.Join(f.secrets, "late", "b")]; v != record.VerdictObserved {
		t.Errorf("a read on a mount made after Prepare recorded %s, want observed", v)
	}
}

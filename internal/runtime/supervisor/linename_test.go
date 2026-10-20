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

// TestFSLineNamesWhereADotDotSpellingLands: an fs line names the file its syscall reached. R6 cleans a joined spelling
// lexically, and a ".." after a symlink cleans onto another file: with out/lk -> realbin/sub, unlink("out/lk/../e")
// removes out/realbin/e, and its line named out/e, a file still there; RENAME_EXCHANGE of out/lk/../e and out/e read
// as an exchange of out/e with itself, and a rename of out/lk/../x named out/x for an object that was out/realbin/x.
// The verdicts were already the walk's; only the names were
// wrong. An end whose spelling holds a ".." is named where the physical walk of its directory lands, with its final
// component as spelled: a final symlink is never followed for the name, whatever the syscall does with it, so a ".."
// the clean resolves as the kernel does names what the spelling names (out/realbin/sub/../ln names out/realbin/ln,
// not the e it opens), and a refused rename's or link's new name, which no decision
// walked, is named where it lands too. Any other end keeps its spelling, and a symlink's target
// is never walked. The names are walked before the answer: the fake reads an answered notification gone, as the kernel
// does, so a walk made after it fails. Real walks of a real tree, as a run makes them.
//
// Spec: docs/p0/supervisor.md R15b.
func TestFSLineNamesWhereADotDotSpellingLands(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	w, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"out/realbin/sub", "ro"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"out/e", "out/realbin/e", "out/x", "out/realbin/x", "out/realbin/sub/f", "ro/src"} {
		if err := os.WriteFile(filepath.Join(w, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"out/lk": "realbin/sub", "out/realbin/ln": "e"} {
		if err := os.Symlink(target, filepath.Join(w, link)); err != nil {
			t.Fatal(err)
		}
	}
	out, ro := w+"/out", w+"/ro"
	open := func(a1, _ uint64) []uint64 { return []uint64{argCWD, a1, unix.O_RDONLY, 0} }
	for _, tc := range []struct {
		name, syscall, from, to string
		args                    func(a1, a2 uint64) []uint64
		path, path2             string
		verdict                 record.Verdict
	}{
		{"an unlink of a dot-dot after a symlink names the file it removes", "unlinkat", out + "/lk/../e", "",
			func(a1, _ uint64) []uint64 { return []uint64{argCWD, a1, 0} }, out + "/realbin/e", "", record.VerdictAllow},
		{"an exchange of it with out/e names both files", "renameat2", out + "/lk/../e", out + "/e",
			func(a1, a2 uint64) []uint64 { return []uint64{argCWD, a1, argCWD, a2, unix.RENAME_EXCHANGE} },
			out + "/realbin/e", out + "/e", record.VerdictRefused},
		{"a rename of it names the object it moves", "renameat", out + "/lk/../x", out + "/realbin/x2",
			func(a1, a2 uint64) []uint64 { return []uint64{argCWD, a1, argCWD, a2} }, out + "/realbin/x", out + "/realbin/x2", record.VerdictAllow},
		{"a link to a dot-dot new name names the new name it makes", "linkat", out + "/x", out + "/lk/../x3",
			func(a1, a2 uint64) []uint64 { return []uint64{argCWD, a1, argCWD, a2, 0} }, out + "/x", out + "/realbin/x3", record.VerdictRefused},
		{"a dot-dot through a real directory names the same file either way", "unlinkat", out + "/realbin/sub/../e", "",
			func(a1, _ uint64) []uint64 { return []uint64{argCWD, a1, 0} }, out + "/realbin/e", "", record.VerdictAllow},
		{"control: a spelling through the symlink with no dot-dot keeps its spelling", "unlinkat", out + "/lk/./f", "",
			func(a1, _ uint64) []uint64 { return []uint64{argCWD, a1, 0} }, out + "/lk/f", "", record.VerdictAllow},
		{"an open of a dot-dot whose final name is a symlink names the link, not the file it opens", "openat", out + "/realbin/sub/../ln", "",
			open, out + "/realbin/ln", "", record.VerdictAllow},
		{"so does one whose dot-dot follows a symlink", "openat", out + "/lk/../ln", "",
			open, out + "/realbin/ln", "", record.VerdictAllow},
		{"a refused rename names its dot-dot new name where its directory lands", "renameat", ro + "/src", out + "/lk/../moved",
			func(a1, a2 uint64) []uint64 { return []uint64{argCWD, a1, argCWD, a2} }, ro + "/src", out + "/realbin/moved", record.VerdictRefused},
		{"so does a refused link", "linkat", ro + "/src", out + "/lk/../linked",
			func(a1, a2 uint64) []uint64 { return []uint64{argCWD, a1, argCWD, a2, 0} }, ro + "/src", out + "/realbin/linked", record.VerdictRefused},
	} {
		for _, indexed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/indexed=%v", tc.name, indexed), func(t *testing.T) {
				f := newFake()
				f.realWalks, f.goneOnSend = true, true
				f.put(pathAddr, cstr(tc.from))
				if tc.to != "" {
					f.put(path2Addr, cstr(tc.to))
				}
				pol := testPolicy(nil, []agent.FSRule{{Path: out, Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet}}, nil)
				pol.Rules.Exec = []agent.ExecRule{{Raw: "./out/realbin/", Path: out + "/realbin", IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow}}
				pol.Rules.Contract = &agent.Contract{Name: "names", Exec: &agent.ExecSection{Allow: []string{"./out/realbin/"}}}
				pol.Rules.Tier = backend.TierLandlock
				pol.Record = agent.RecordFull
				l, sink := newTestLoop(t, f, pol)
				if !indexed {
					l.table.Load().fsIx = nil
				}
				l.handle(notifFor(nrFor(t, tc.syscall), 42, tc.args(pathAddr, path2Addr)...))
				if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response = %+v, want CONTINUE: Landlock decides it", got)
				}
				ev := sink.one(t)
				if ev.Verdict != tc.verdict {
					t.Errorf("verdict = %s (%s, %s), want %s", ev.Verdict, ev.Rule, ev.Reason, tc.verdict)
				}
				var p record.FSPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatalf("payload: %v", err)
				}
				if p.Path != tc.path || p.Path2 != tc.path2 {
					t.Errorf("line names path %q path2 %q, want %q and %q: the files the syscall reached", p.Path, p.Path2, tc.path, tc.path2)
				}
			})
		}
	}
}

// TestKernelRecorderNamingOfADotDotSpelling: at tier 2, where the kernel recorder writes a continued fs action's line
// with this loop's naming (R7a, ContinuedFS), an end spelled with a ".." after a symlink is named where its walk landed
// it, as this loop's own line names it: an unlink's path, and a rename's new name, its path2 (2c6-2).
//
// Spec: docs/p0/supervisor.md R7a, R15b.
func TestKernelRecorderNamingOfADotDotSpelling(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	w, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(w, "out/realbin/sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"out/e", "out/realbin/e", "out/x"} {
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
		args                    []uint64
		op, base, base2         string
		path, path2             string
	}{
		{"an unlink names the file it removes", "unlinkat", out + "/lk/../e", "", []uint64{argCWD, pathAddr, 0},
			record.FSUnlink, "e", "", out + "/realbin/e", ""},
		{"a rename names the new name it makes", "renameat", out + "/x", out + "/lk/../x5", []uint64{argCWD, pathAddr, argCWD, path2Addr},
			record.FSRename, "x", "x5", out + "/x", out + "/realbin/x5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.realWalks, f.goneOnSend = true, true
			f.put(pathAddr, cstr(tc.from))
			if tc.to != "" {
				f.put(path2Addr, cstr(tc.to))
			}
			pol := testPolicy(nil, []agent.FSRule{{Path: out, Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet}}, nil)
			pol.Rules.Tier = backend.TierCgroup
			pol.Rules.Record = agent.RecordFull
			l, sink := newTestLoop(t, f, pol)
			l.kernelFS = func() bool { return true }
			l.handle(notifFor(nrFor(t, tc.syscall), 42, tc.args...))
			if got := len(sink.all()); got != 0 {
				t.Fatalf("%d lines from this loop, want none: the kernel recorder writes it", got)
			}
			n, ok := l.ContinuedFS(42, tc.op, tc.base, tc.base2, monotonicNS())
			if !ok || n.Path != tc.path || n.Path2 != tc.path2 {
				t.Errorf("ContinuedFS = %+v, %v; want path %q path2 %q, the files the syscall reached", n, ok, tc.path, tc.path2)
			}
		})
	}
}

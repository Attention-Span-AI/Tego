// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"bytes"
	"context"
	"debug/elf"
	bin "encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// ldCache builds a loader cache naming each entry, name then path, in glibc's new format (dl-cache.h), after
// an old-format section of the same entries when withOld is set: the layout ldconfig wrote before glibc
// 2.32, in which the new header starts at the next 8-byte boundary after the old entries.
func ldCache(entries [][2]string, withOld bool) []byte {
	le := bin.NativeEndian
	var strs bytes.Buffer
	type entry struct{ key, value uint32 }
	newHeaderAndEntries := uint32(ldCacheNewHeader + len(entries)*ldCacheNewEntry)
	var es []entry
	for _, e := range entries {
		k := newHeaderAndEntries + uint32(strs.Len())
		strs.WriteString(e[0])
		strs.WriteByte(0)
		v := newHeaderAndEntries + uint32(strs.Len())
		strs.WriteString(e[1])
		strs.WriteByte(0)
		es = append(es, entry{k, v})
	}
	var out []byte
	if withOld {
		old := make([]byte, 16+len(entries)*ldCacheOldEntry)
		copy(old, ldCacheOldMagic)
		le.PutUint32(old[12:16], uint32(len(entries)))
		for len(old)%8 != 0 {
			old = append(old, 0)
		}
		out = append(out, old...)
	}
	hdr := make([]byte, ldCacheNewHeader)
	copy(hdr, ldCacheNewMagic)
	le.PutUint32(hdr[20:24], uint32(len(entries)))
	le.PutUint32(hdr[24:28], uint32(strs.Len()))
	out = append(out, hdr...)
	for _, e := range es {
		b := make([]byte, ldCacheNewEntry)
		le.PutUint32(b[0:4], 0x0303) // FLAG_ELF_LIBC6 | FLAG_X8664_LIB64
		le.PutUint32(b[4:8], e.key)
		le.PutUint32(b[8:12], e.value)
		out = append(out, b...)
	}
	return append(out, strs.Bytes()...)
}

// TestParseLdCache reads the libssl entries of a loader cache in both of the layouts glibc writes, in the
// cache's own order, and nothing else.
func TestParseLdCache(t *testing.T) {
	entries := [][2]string{
		{"libz.so.1", "/lib/x86_64-linux-gnu/libz.so.1"},
		{"libssl.so.3", "/opt/openssl/lib64/libssl.so.3"},
		{"libssl3.so", "/lib/x86_64-linux-gnu/libssl3.so"}, // NSS's, not OpenSSL's: R4's pattern leaves it out
		{"libssl.so.1.1", "/lib/x86_64-linux-gnu/libssl.so.1.1"},
		{"libssl.so", "relative/libssl.so"},
	}
	want := []string{"/opt/openssl/lib64/libssl.so.3", "/lib/x86_64-linux-gnu/libssl.so.1.1"}
	for _, withOld := range []bool{false, true} {
		got := parseLdCache(ldCache(entries, withOld))
		if !slices.Equal(got, want) {
			t.Errorf("old section %v: %q, want %q", withOld, got, want)
		}
	}
	for _, bad := range [][]byte{nil, []byte(ldCacheNewMagic), []byte(ldCacheOldMagic + "\x00\xff\xff\xff\xff"),
		ldCache(entries, false)[:ldCacheNewHeader+ldCacheNewEntry+3]} {
		_ = parseLdCache(bad) // must not panic; what it returns from a cut file is whatever it could read
	}
}

// TestParseLdCacheOfThisHost reads the loader cache this host really has: when the cache's bytes name a
// libssl, the parser must find at least one entry for it, or pre-attach would miss the library the host's
// processes load.
func TestParseLdCacheOfThisHost(t *testing.T) {
	data, err := os.ReadFile("/etc/ld.so.cache")
	if err != nil {
		t.Skipf("no loader cache: %v", err)
	}
	if !bytes.Contains(data, []byte("libssl.so.")) {
		t.Skip("this host's loader cache names no libssl")
	}
	got := parseLdCache(data)
	if len(got) == 0 {
		t.Fatalf("the loader cache names a libssl and parseLdCache found none")
	}
	t.Logf("libssl in the loader cache: %q; pre-attach would place probes on %q", got, systemLibraries("/", nil))
}

// FuzzParseLdCache: the cache is a root-owned file, but the parser still reads offsets out of it, so no
// input may panic, and every path it returns is absolute.
func FuzzParseLdCache(f *testing.F) {
	f.Add(ldCache([][2]string{{"libssl.so.3", "/usr/lib/libssl.so.3"}}, false))
	f.Add(ldCache([][2]string{{"libssl.so.3", "/usr/lib/libssl.so.3"}, {"libc.so.6", "/lib/libc.so.6"}}, true))
	f.Add([]byte(ldCacheOldMagic))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, p := range parseLdCache(data) {
			if !filepath.IsAbs(p) {
				t.Fatalf("relative path %q", p)
			}
		}
	})
}

// writeAt copies an ELF the test wrote into a fake root at path.
func writeAt(t *testing.T, root, path string, elfPath string) string {
	t.Helper()
	b, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

// TestSystemLibraries is what pre-attach finds on a host: the loader cache's libssl files first, including one
// in a directory no default search names, then the default directories', each file once whatever it is
// called, and never a file that is not an ELF for this build's machine or not named like a libssl.
func TestSystemLibraries(t *testing.T) {
	root := t.TempDir()
	syms := map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180}
	native := elfOptions{Dynamic: syms, Machine: nativeMachine()}
	private := writeAt(t, root, "/opt/ssl/lib/libssl.so.3", writeELF(t, withBuildID(native, 1)))
	system := writeAt(t, root, "/usr/lib64/libssl.so.3", writeELF(t, withBuildID(native, 2)))
	if err := os.Symlink("libssl.so.3", filepath.Join(root, "usr/lib64/libssl.so")); err != nil {
		t.Fatal(err)
	}
	foreign := native
	foreign.Machine = elf.EM_386
	if nativeMachine() == elf.EM_386 {
		foreign.Machine = elf.EM_X86_64
	}
	writeAt(t, root, "/usr/lib64/libssl.so.1.1", writeELF(t, withBuildID(foreign, 3)))
	if err := os.MkdirAll(filepath.Join(root, "usr/local/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/local/lib/libssl.so.10"), []byte("not an elf"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeAt(t, root, "/usr/lib64/libssl.so.3.bak", writeELF(t, withBuildID(native, 4)))
	cache := ldCache([][2]string{
		{"libssl.so.3", "/opt/ssl/lib/libssl.so.3"},
		{"libssl.so.3", "/usr/lib64/libssl.so.3"},
		{"libssl.so.3", "/missing/libssl.so.3"},
	}, false)
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/ld.so.cache"), cache, 0o644); err != nil {
		t.Fatal(err)
	}
	got := systemLibraries(root, nil)
	if want := []string{private, system}; !slices.Equal(got, want) {
		t.Fatalf("systemLibraries = %q, want %q", got, want)
	}
}

// withBuildID gives an ELF a distinct build id, so two files the test writes are two binaries (R7).
func withBuildID(o elfOptions, n byte) elfOptions {
	o.BuildID = []byte{0xb0, n}
	return o
}

// preattachTree is a process that maps no libssl at its exec and whose root holds, under the path its
// `import ssl` will open, the very file (one inode) a pre-attach placed probes on. It returns the host's path
// of that file and the path the process opens it by.
func preattachTree(t *testing.T, tree *procTree, pid int) (host, opened string) {
	t.Helper()
	lib := dlopenTree(t, tree, pid)
	inRoot := filepath.Join(tree.root, strconv.Itoa(pid), "root", lib)
	host = filepath.Join(t.TempDir(), "libssl.so.3")
	if err := os.Link(inRoot, host); err != nil {
		t.Fatal(err)
	}
	return host, lib
}

// TestPreattachPlacesProbesBeforeAnyProcess is R4's pre-attach: Start places the probes on the host's
// libssl before the run has a process at all, so a client whose first SSL_write comes straight after
// `import ssl` writes through probes that are already there, whatever the kernel record's drain and the
// attach at the open cost. The process's open of that same file then only takes its own reference: nothing
// is attached twice (I8), no verdict is held for it, and Stop gives back the pre-attach's reference with
// every other (I9).
func TestPreattachPlacesProbesBeforeAnyProcess(t *testing.T) {
	tree := newProcTree(t)
	host, opened := preattachTree(t, tree, 501)
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att,
		Preattach: func() []string { return []string{host} }})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := att.count(); got != 3 {
		t.Fatalf("%d probes placed at Start, want SSL_write and an SSL_read pair (3) before any process runs", got)
	}
	if !att.placedOn(t, 0, host) {
		t.Errorf("pre-attached at %s, want the host's path %s", att.paths[0], host)
	}
	u.OnExec(501, 41, "")
	u.OnOpen(501, 41, opened)
	if got := att.count(); got != 3 {
		t.Errorf("%d probes after the process opened the pre-attached file, want the same 3 (I8)", got)
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %v for a process whose libssl was pre-attached", gaps)
	}
	u.OnExit(501)
	if att.openLinks() != 3 {
		t.Errorf("%d links open after the process exited, want the run's 3 until Stop", att.openLinks())
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if att.openLinks() != 0 || u.cache.size() != 0 {
		t.Errorf("%d links open and %d binaries cached after Stop (I9)", att.openLinks(), u.cache.size())
	}
}

// TestPreattachFailureIsNoGapOfTheRun: a pre-attach the host refuses records nothing for the run, since no
// process has mapped anything, and the refusal stays the binary's one attempt (§7): a process that maps the
// library later gets the no-openssl gap it would have got at its open, without a second attempt.
func TestPreattachFailureIsNoGapOfTheRun(t *testing.T) {
	tree := newProcTree(t)
	host, opened := preattachTree(t, tree, 502)
	att := &fakeAttacher{err: errors.New("operation not permitted")}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att,
		Preattach: func() []string { return []string{host} }})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Fatalf("gaps = %v after a pre-attach failure, before any process", gaps)
	}
	u.OnExec(502, 41, "")
	u.OnOpen(502, 41, opened)
	u.OnExit(502)
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	if !hasGap(u.Gaps(), GapNoOpenSSL) {
		t.Errorf("gaps = %v, want the process's no-openssl gap for the library the host refused", u.Gaps())
	}
}

// TestSystemLibrariesStopsAtMaxPreattach: a host with more distinct libssl files than MaxPreattach gets the
// first MaxPreattach of them, in the list's order, and the rest are left to their open.
func TestSystemLibrariesStopsAtMaxPreattach(t *testing.T) {
	root := t.TempDir()
	native := elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180}, Machine: nativeMachine()}
	var want []string
	for i := 0; i < MaxPreattach+2; i++ {
		p := writeAt(t, root, "/usr/lib64/libssl.so."+strconv.Itoa(10+i), writeELF(t, withBuildID(native, byte(i))))
		if i < MaxPreattach {
			want = append(want, p)
		}
	}
	if got := systemLibraries(root, nil); !slices.Equal(got, want) {
		t.Fatalf("systemLibraries = %q, want the first %d: %q", got, MaxPreattach, want)
	}
}

// preattachLibs writes n distinct libssl files, each a binary of its own (R7), and returns their paths.
func preattachLibs(t *testing.T, n int) []string {
	t.Helper()
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, writeELF(t, withBuildID(elfOptions{Dynamic: map[string]uint64{
			SymWrite: 0x1100, SymWriteEx: 0x1140, SymRead: 0x1180, SymReadEx: 0x11c0}}, byte(0x40+i))))
	}
	return out
}

// TestPreattachPlacesEveryReadProbeFirst is probesFor's order as Start places it on a real ELF: SSL_read and
// SSL_read_ex, entry and return, before SSL_write and SSL_write_ex, one attach at a time.
func TestPreattachPlacesEveryReadProbeFirst(t *testing.T) {
	libs := preattachLibs(t, 1)
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Attacher: att, Preattach: func() []string { return libs }})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Stop() })
	var order []string
	for _, p := range att.probes {
		order = append(order, p.String())
	}
	if len(att.probes) != 6 {
		t.Fatalf("placed %q, want two reads with their returns and two writes", order)
	}
	for i, p := range att.probes {
		read := p.Symbol == SymRead || p.Symbol == SymReadEx
		if read != (i < 4) {
			t.Fatalf("placed %q: every read probe must come before any write probe", order)
		}
	}
}

// TestPreattachIsBounded: the agent waits on Start, so pre-attach stops once its budget is spent or the run's
// context is done, after the first library, which is always attempted. What it did not reach is left to be
// attached at its open, as it was before pre-attach.
func TestPreattachIsBounded(t *testing.T) {
	t.Run("budget", func(t *testing.T) {
		libs := preattachLibs(t, 3)
		att := &fakeAttacher{}
		var ticks atomic.Int64
		// Every look at the clock costs a second, so the budget is spent by the first check after the start.
		now := func() time.Time { return time.Unix(ticks.Add(1), 0) }
		u, sink := newTestUprobe(t, nil, Options{Attacher: att, Now: now, PreattachBudget: 500 * time.Millisecond,
			Preattach: func() []string { return libs }})
		if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = u.Stop() })
		if n := u.cache.size(); n != 1 {
			t.Errorf("%d libraries pre-attached past a spent budget, want the first alone", n)
		}
	})
	t.Run("context", func(t *testing.T) {
		libs := preattachLibs(t, 3)
		att := &fakeAttacher{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		u, sink := newTestUprobe(t, nil, Options{Attacher: att, Preattach: func() []string { return libs }})
		if err := u.Start(ctx, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = u.Stop() })
		if n := u.cache.size(); n != 1 {
			t.Errorf("%d libraries pre-attached for a run whose context is done, want the first alone", n)
		}
	})
	t.Run("within budget", func(t *testing.T) {
		libs := preattachLibs(t, 3)
		att := &fakeAttacher{}
		u, sink := newTestUprobe(t, nil, Options{Attacher: att, Preattach: func() []string { return libs }})
		if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = u.Stop() })
		if n := u.cache.size(); n != 3 {
			t.Errorf("%d libraries pre-attached, want all 3", n)
		}
	})
}

// TestSystemLibrariesStops: the listing's reads stop with the budget too, once it names one library.
func TestSystemLibrariesStops(t *testing.T) {
	root := t.TempDir()
	native := elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180}, Machine: nativeMachine()}
	first := writeAt(t, root, "/usr/lib64/libssl.so.3", writeELF(t, withBuildID(native, 1)))
	writeAt(t, root, "/usr/lib64/libssl.so.4", writeELF(t, withBuildID(native, 2)))
	if got := systemLibraries(root, func() bool { return true }); !slices.Equal(got, []string{first}) {
		t.Fatalf("systemLibraries = %q, want only %q once told to stop", got, first)
	}
}

// TestNoPreattachUnderRecordOff: under record: off the capture programs record nothing (tego_recording) and
// the kernel record carries no opens, so Start places no probe: pre-attached, the host's libssl would make
// every host process's SSL_read and SSL_write trap for the whole run and capture nothing (R4). That holds for
// the production list (Kernel with no Preattach: the host's own libssl) and for a given one. The same options
// under record: full do attach, so the zero is the rule's and not an empty list's.
func TestNoPreattachUnderRecordOff(t *testing.T) {
	libs := preattachLibs(t, 1)
	host := systemLibraries("/", nil)
	for _, tc := range []struct {
		name string
		opts Options
		want int // probes placed under record: full
	}{
		{"host libssl", Options{Kernel: true}, len(host)},
		{"given list", Options{Preattach: func() []string { return libs }}, 1},
	} {
		for _, mode := range []agent.RecordMode{agent.RecordOff, agent.RecordFull} {
			t.Run(tc.name+"/"+string(mode), func(t *testing.T) {
				att := &fakeAttacher{}
				opts := tc.opts
				opts.Attacher, opts.Rules = att, &agent.RuleTable{Record: mode}
				u, sink := newTestUprobe(t, nil, opts)
				if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = u.Stop() })
				switch {
				case mode == agent.RecordOff && att.count() != 0:
					t.Fatalf("%d probes placed at Start under record: off, want none", att.count())
				case mode == agent.RecordFull && tc.want > 0 && att.count() == 0:
					t.Fatalf("no probe placed at Start under record: full, want the %d libraries' probes", tc.want)
				case mode == agent.RecordFull && tc.want == 0:
					t.Logf("this host has no libssl for pre-attach to name, so only record: off's zero is shown")
				}
			})
		}
	}
}

// TestNothingAttachesUnderRecordOff: under record: off no probe is placed at an exec or at an open either, not
// only at Start. The kernel still emits exec and exit under off, and the recorder hands them on, so a process
// that maps a libssl at exec, or an executable with OpenSSL linked in, had its probes placed on the host's file
// there: every process on the host that calls into it paid the traps for the whole run, while the capture
// programs keep nothing of a record: off run's calls (tego_recording, R4). Nothing is recorded for such a
// process either: the run keeps no capture, so there is no coverage to report against it. Under record: full
// the same exec places the library's three probes, which is what shows the process is one a probe would go on.
func TestNothingAttachesUnderRecordOff(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordOff, agent.RecordFull} {
		t.Run(string(mode), func(t *testing.T) {
			tree := newProcTree(t)
			_, lib := sharedRootTree(t, tree, []int{601}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
			att := &fakeAttacher{}
			u, sink := newTestUprobe(t, nil, Options{
				Proc: proc.NewAt(tree.root), Attacher: att, Rules: &agent.RuleTable{Record: mode},
				Preattach: func() []string { return nil },
			})
			if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
				t.Fatal(err)
			}
			u.OnExec(601, 41, "")
			u.OnOpen(601, 41, lib)
			placed := att.count()
			if err := u.Stop(); err != nil {
				t.Fatal(err)
			}
			switch {
			case mode == agent.RecordFull && placed != 3:
				t.Fatalf("%d probes for a process mapping %s under record: full, want 3", placed, lib)
			case mode == agent.RecordOff && placed != 0:
				t.Fatalf("%d probes placed at an exec and an open under record: off, want none: the host pays "+
					"for them and the capture programs record nothing", placed)
			case mode == agent.RecordOff:
				// One gap, the mechanism's own, which is how run_start learns uprobe capture did not run;
				// no process's coverage, since nothing was captured to measure it against.
				gaps := u.Gaps()
				if len(gaps) != 1 || gaps[0].Why != GapMechanismUnavailable || gaps[0].Binary != Name {
					t.Fatalf("gaps %+v under record: off, want the mechanism-unavailable gap alone", gaps)
				}
			}
		})
	}
}

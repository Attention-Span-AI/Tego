// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/capture"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// debugLogger formats every operator line, so a log argument that races is evaluated and formatted rather
// than skipped with the line.
func debugLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestConcurrentOnExecAttachesOnce is the concurrent-onExec unit test §8 capture-derive.md I8 promises: many processes that
// map one libssl, exec'd at once, attach it exactly once, and once the source stops no link survives (capture-derive.md I9).
// Run it under -race: the already-attached path used to read the binary's reference count outside the
// cache's lock while another OnExec added a reference under it.
func TestConcurrentOnExecAttachesOnce(t *testing.T) {
	pids := []int{201, 202, 203, 204, 205, 206, 207, 208}
	tree := newProcTree(t)
	sharedRootTree(t, tree, pids, map[string]uint64{SymWrite: 0x1100, SymWriteEx2: 0x1140, SymRead: 0x1180, SymReadEx: 0x11c0})
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Logger: debugLogger()})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// One exec attaches; the rest race each other on the already-attached path.
	u.OnExec(pids[0], 41, "")
	var wg sync.WaitGroup
	for _, pid := range pids[1:] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u.OnExec(pid, 41, "")
		}()
	}
	wg.Wait()
	// SSL_write, SSL_write_ex2, and an entry and a return for each read (R1-R3), placed once.
	if got := att.count(); got != 6 {
		t.Fatalf("%d probes for %d processes on one libssl, want 6 (I8)", got, len(pids))
	}
	if got := u.cache.size(); got != 1 {
		t.Fatalf("attach cache holds %d binaries, want 1", got)
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %v for processes that were all captured", gaps)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := att.openLinks(); got != 0 {
		t.Errorf("%d links still open after Stop (I9)", got)
	}
	if got := u.cache.size(); got != 0 {
		t.Errorf("attach cache still holds %d binaries after Stop", got)
	}
}

// TestConcurrentOnExecAcrossTwoSourcesAttachesOnce is the same race across two runs sharing one attach cache
// (edge case #26), where the second source's references land on an entry the first one created.
func TestConcurrentOnExecAcrossTwoSourcesAttachesOnce(t *testing.T) {
	pids := []int{301, 302, 303, 304, 305, 306}
	tree := newProcTree(t)
	sharedRootTree(t, tree, pids, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	shared := newCache()
	att := &fakeAttacher{}
	one, sinkOne := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared, Logger: debugLogger()})
	two, sinkTwo := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared, Logger: debugLogger()})
	if err := one.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sinkOne); err != nil {
		t.Fatal(err)
	}
	if err := two.Start(context.Background(), source.RunRef{ID: "r-2", Agent: "b", CgroupID: 42}, sinkTwo); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i, pid := range pids {
		src, cg := one, uint64(41)
		if i%2 == 1 {
			src, cg = two, 42
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			src.OnExec(pid, cg, "")
		}()
	}
	wg.Wait()
	if got := att.count(); got != 3 {
		t.Fatalf("%d probes for two runs on one libssl, want 3 (I8)", got)
	}
	if err := one.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := two.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := att.openLinks(); got != 0 {
		t.Errorf("%d links still open after both runs stopped (I9)", got)
	}
}

// dlopenTree is a process whose exec shows no libssl — only its own executable, which exports no OpenSSL
// symbol — and whose root holds the libssl it will open later, the way CPython's `import ssl` loads _ssl and
// with it libssl.so.3. It returns the library's path as the process names it.
func dlopenTree(t *testing.T, tree *procTree, pid int) string {
	t.Helper()
	exe := writeELF(t, elfOptions{Dynamic: map[string]uint64{"PyRun_SimpleString": 0x1100}})
	exeBytes, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	so := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180}, BuildID: []byte{9, 9}})
	soBytes, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	python := tree.inRoot(t, pid, "usr/bin/python3.13", exeBytes)
	lib := tree.inRoot(t, pid, "usr/lib/x86_64-linux-gnu/libssl.so.3", soBytes)
	tree.process(t, pid, python, nil)
	// The exe candidate is /proc/<pid>/exe, which the fake tree links to the name, not to the file.
	exeLink := filepath.Join(tree.root, strconv.Itoa(pid), "exe")
	if err := os.Remove(exeLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(tree.root, strconv.Itoa(pid), "root", python), exeLink); err != nil {
		t.Fatal(err)
	}
	return lib
}

// TestOnOpenAttachesALibraryTheExecCouldNotSee is R4 for the library an exec cannot see: at the exec the
// process maps no libssl, so nothing is attached and a verdict is held; the open that loads the library
// attaches it, and the held verdict is withdrawn rather than left in the ledger as a static-tls-no-symbols
// gap for a process whose exchanges were all captured.
func TestOnOpenAttachesALibraryTheExecCouldNotSee(t *testing.T) {
	tree := newProcTree(t)
	lib := dlopenTree(t, tree, 401)
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(401, 41, "")
	if att.count() != 0 {
		t.Fatalf("attached %d probes at an exec that maps no libssl", att.count())
	}
	if !hasGap(u.Gaps(), GapStaticTLSNoSymbols) {
		t.Fatalf("gaps = %v, want the exec's held static-tls-no-symbols verdict", u.Gaps())
	}
	// An open of anything else is not a TLS library and attaches nothing.
	u.OnOpen(401, 41, "/usr/lib/x86_64-linux-gnu/libcrypto.so.3")
	u.OnOpen(401, 41, "/etc/ssl/openssl.cnf")
	if att.count() != 0 {
		t.Fatalf("attached %d probes on opens of files that are not a libssl", att.count())
	}
	u.OnOpen(401, 41, lib)
	if got := att.count(); got != 3 {
		t.Fatalf("%d probes after the libssl open, want SSL_write plus an SSL_read pair (3)", got)
	}
	if want := filepath.Join(tree.root, "401", "root", lib); !att.placedOn(t, 0, want) {
		t.Errorf("attached at %s, want the file of the process's own spelling %s (R39)", att.paths[0], want)
	}
	u.OnExit(401)
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %v for a process the open attached", gaps)
	}
	if att.openLinks() != 0 {
		t.Errorf("%d links open after the process exited (I9)", att.openLinks())
	}
}

// TestHookBeforeStartIsIgnored: the run starts the kernel record before this source (runtime.recorderFirst), so
// the recorder's drain can call a hook while the source has not started, or is still opening its kernel side.
// A Kernel-mode source has no attacher until Start makes one, and an attach tried then failed for want of it
// and recorded that failure in the attach cache, which keeps a binary's failure for good (§7's one attempt per
// binary): every later process of the run mapping that libssl would have gone uncaptured. Before Start, the
// only process the recorder can report is the launcher's own child stage, because the agent is released only
// once every source has started, so a hook call then is ignored.
func TestHookBeforeStartIsIgnored(t *testing.T) {
	tree := newProcTree(t)
	lib := dlopenTree(t, tree, 401)
	u, err := New(Options{Kernel: true, Proc: proc.NewAt(tree.root)})
	if err != nil {
		t.Fatal(err)
	}
	u.OnExec(401, 41, "/usr/bin/python3")
	u.OnOpen(401, 41, lib)
	id, err := candidateIdentity(filepath.Join(tree.root, "401", "root", lib))
	if err != nil {
		t.Fatal(err)
	}
	if ferr, failed := u.cache.failure(id); failed {
		t.Errorf("a hook before Start recorded a failure for %s in the attach cache: %v", lib, ferr)
	}
	if u.cache.size() != 0 {
		t.Errorf("a hook before Start attached %d binaries", u.cache.size())
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("a hook before Start held a verdict: %v", gaps)
	}
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
}

// TestAMappedNonELFIsNothingToAttachTo is the ld.so.cache case the KVM guest found: every dynamically linked
// process maps /etc/ld.so.cache, which is not an ELF, and reading it as one fails with a format error. That
// is the ordinary "nothing here" of R4's scan, not an attach the host refused. So `ls`, whose candidates all
// read and none exports R1-R3, is static-tls-no-symbols against its own executable, the reason R37 (as
// amended) gives every process whose readable candidates export nothing: without E71's signature scan a
// static TLS stack with no symbols (Bun, rustls, Go) cannot be told from no TLS stack at all. no-openssl is
// R37's for a discovery that could read nothing, which a format error on one mapping is not.
func TestAMappedNonELFIsNothingToAttachTo(t *testing.T) {
	tree := newProcTree(t)
	cache := tree.inRoot(t, 601, "etc/ld.so.cache", []byte("glibc-ld.so.cache1.1 not an elf at all"))
	so := writeELF(t, elfOptions{Dynamic: map[string]uint64{"malloc": 0x1100}})
	b, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	libc := tree.inRoot(t, 601, "usr/lib/libc.so.6", b)
	tree.process(t, 601, "/usr/bin/ls", []string{cache, libc})
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: &fakeAttacher{}})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(601, 41, "")
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if n := gapCount(u.Gaps(), GapNoOpenSSL); n != 0 {
		t.Errorf("gaps %+v: a mapped non-ELF file was reported as a failed attach", u.Gaps())
	}
	if n := gapCount(u.Gaps(), GapStaticTLSNoSymbols); n != 1 {
		t.Errorf("gaps %+v, want one static-tls-no-symbols", u.Gaps())
	}
	if _, err := readBinary(filepath.Join(tree.root, "601", "root", cache)); !errors.Is(err, ErrNotELF) {
		t.Errorf("readBinary(ld.so.cache) = %v, want ErrNotELF", err)
	}
}

// TestHeldVerdictBecomesOneGap pins when a held verdict turns into a gap, and that it is counted once: an
// exit settles it, a second exec record of the same image replaces it, and an exec of a new image settles
// the old image's.
func TestHeldVerdictBecomesOneGap(t *testing.T) {
	tree := newProcTree(t)
	so := writeELF(t, elfOptions{Dynamic: map[string]uint64{"malloc": 0x1100}})
	b, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	lib := tree.inRoot(t, 501, "usr/lib/libc.so.6", b)
	tree.process(t, 501, "/usr/bin/sh", []string{lib})
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: &fakeAttacher{}})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(501, 41, "")
	u.OnExec(501, 41, "") // the same image seen twice is one process, not two
	if got := gapCount(u.Gaps(), GapStaticTLSNoSymbols); got != 1 {
		t.Fatalf("static-tls-no-symbols count %d after two records of one exec, want 1", got)
	}
	u.OnExit(501)
	u.OnExit(501) // an exit is settled once
	if got := gapCount(u.Gaps(), GapStaticTLSNoSymbols); got != 1 {
		t.Fatalf("static-tls-no-symbols count %d after the exit, want 1", got)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := gapCount(u.Gaps(), GapStaticTLSNoSymbols); got != 1 {
		t.Fatalf("static-tls-no-symbols count %d after Stop, want 1", got)
	}
}

// TestHeldVerdictSurvivesStop is the other half: a process still running when the source stops was never
// captured, and its gap is in the report Stop leaves behind.
func TestHeldVerdictSurvivesStop(t *testing.T) {
	tree := newProcTree(t)
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: &fakeAttacher{}})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(999, 41, "") // no such process: R4 finds nothing
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := gapCount(u.Gaps(), GapNoOpenSSL); got != 1 {
		t.Fatalf("no-openssl count %d after Stop, want 1: %v", got, u.Gaps())
	}
	u.mu.Lock()
	held := len(u.uncaptured)
	u.mu.Unlock()
	if held != 0 {
		t.Errorf("%d verdicts still held after Stop", held)
	}
}

// TestKernelModeWithNothingToFollowIsOneGap covers a production source whose run never named a build: its
// tier's kernel record is not running, so no exec would ever reach OnExec. Start neither fails the run nor
// drains a ring nothing writes; it records mechanism-unavailable naming the mechanism, as capture.Select
// does for a factory that failed, and the source ignores every hook call after that.
func TestKernelModeWithNothingToFollowIsOneGap(t *testing.T) {
	att := &fakeAttacher{}
	u, err := New(Options{Kernel: true, Attacher: att})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, &fakeSink{}); err != nil {
		t.Fatalf("Start = %v; a capture mechanism that cannot run must never fail the run (§4)", err)
	}
	u.OnExec(os.Getpid(), 41, "")
	u.OnOpen(os.Getpid(), 41, "/usr/lib/x86_64-linux-gnu/libssl.so.3")
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	gaps := u.Gaps()
	if len(gaps) != 1 || gaps[0].Why != capture.GapMechanismUnavailable || gaps[0].Binary != Name || gaps[0].Count != 0 {
		t.Fatalf("gaps = %+v, want exactly one mechanism-unavailable binary=%s with no count", gaps, Name)
	}
	if att.count() != 0 {
		t.Errorf("an inert source attached %d probes", att.count())
	}
}

// TestKernelModeLoadFailureIsOneGap is the same when the build is named but its pins are not there (the
// load this binary cannot do, or a pin directory that vanished): the reason reaches the operator log, the
// ledger gets the gap.
func TestKernelModeLoadFailureIsOneGap(t *testing.T) {
	// The operator's log at its default level (info) must still say why: the gap cannot.
	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelInfo}))
	u, err := New(Options{Kernel: true, PinRoot: t.TempDir(), Logger: logger})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u.FollowKernel("0123456789abcdef")
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, &fakeSink{}); err != nil {
		t.Fatalf("Start = %v; a capture mechanism that cannot run must never fail the run (§4)", err)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !hasGapWhy(u.Gaps(), capture.GapMechanismUnavailable) {
		t.Fatalf("gaps = %+v, want mechanism-unavailable", u.Gaps())
	}
	if out := logged.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "capture unavailable") {
		t.Errorf("own log %q: want a warning naming why capture is unavailable", out)
	}
}

// hasGapWhy reports a gap of one reason whatever its count.
func hasGapWhy(gaps []source.Gap, why string) bool {
	for _, g := range gaps {
		if g.Why == why {
			return true
		}
	}
	return false
}

// TestLoadCollectionNeedsTheBuildsPinDirectory is LoadCollection refusing to invent a pin directory the
// tier-2 backend did not create, whose pins nothing would ever remove.
func TestLoadCollectionNeedsTheBuildsPinDirectory(t *testing.T) {
	if _, err := LoadCollection(t.TempDir(), "0123456789abcdef"); !errors.Is(err, ErrNoPinDir) {
		t.Fatalf("LoadCollection = %v, want ErrNoPinDir", err)
	}
}

// TestPinnedNamesAreTheELFNames is the reader half of the pin path the loaders compute: a collection loaded
// with MapOptions.PinPath pins each LIBBPF_PIN_BY_NAME map at PinPath/<ELF name>, and the ELF names are
// internal/bpf's constants. "capture_events" and "lost" were paths no loader creates.
func TestPinnedNamesAreTheELFNames(t *testing.T) {
	if CaptureEventsMapName != bpf.MapCaptureEvents {
		t.Errorf("capture ring opened as %q, pinned as %q", CaptureEventsMapName, bpf.MapCaptureEvents)
	}
	if LostMapName != bpf.MapCaptureLost {
		t.Errorf("lost counter opened as %q, pinned as %q", LostMapName, bpf.MapCaptureLost)
	}
	if got, want := filepath.Join(mapDir("", "h"), CaptureEventsMapName), "/sys/fs/bpf/tego/h/maps/tego_capture_events"; got != want {
		t.Errorf("capture ring path %s, want %s", got, want)
	}
}

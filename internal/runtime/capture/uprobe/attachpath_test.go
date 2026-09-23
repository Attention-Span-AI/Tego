// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// openingAttacher is fakeAttacher with the one behaviour the kernel actually has: a uprobe names its
// target by path and the path is resolved when the probe is placed, so a path that has stopped existing
// fails the attach exactly as link.OpenExecutable does. That is what makes a test over a fake /proc able
// to catch an attach aimed at an exited process's /proc entry.
//
// failFirst fails the first attach with the error the kernel's own lookup of the path gives, whatever the
// path. vanish, when set, is removed just before that failure, so the path the attach named really has
// stopped existing rather than merely being reported that way: that is the exec-then-exit race. A fake
// that only produced the errno would equally model a refusal the host owns, which reaches this package as
// ENOENT too (see errHostENOENT).
//
// failAll fails every attach with errHostENOENT instead, while the path stays where it is.
type openingAttacher struct {
	mu        sync.Mutex
	paths     []string
	links     []*fakeLink
	failFirst bool
	failAll   bool
	vanish    string
	calls     int
}

func (a *openingAttacher) Attach(path string, p Probe) (io.Closer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.failAll {
		return nil, errHostENOENT
	}
	if a.failFirst && a.calls == 1 {
		if a.vanish != "" {
			if err := os.RemoveAll(a.vanish); err != nil {
				return nil, err
			}
		}
		// perf_event_open on the uprobe PMU resolves the path with kern_path and answers ENOENT
		// when it is gone; cilium/ebpf wraps that errno unchanged.
		return nil, fmt.Errorf("creating perf_uprobe PMU: token %s:%#x: not found: %w", path, p.Offset, syscall.ENOENT)
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	a.paths = append(a.paths, path)
	l := &fakeLink{mu: &a.mu}
	a.links = append(a.links, l)
	return l, nil
}

// count is how many probes were actually placed.
func (a *openingAttacher) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.paths)
}

// errHostENOENT is the error every attach gets on a kernel built without CONFIG_UPROBE_EVENTS, which has no
// uprobe PMU: cilium/ebpf falls back to tracefs, and the uprobe_events file it opens there does not exist.
// It arrives as ENOENT and names a path, but not the candidate's, which is still there to be stat'ed.
var errHostENOENT = fmt.Errorf("creating trace event in tracefs: creating probe entry on tracefs: %w",
	&fs.PathError{Op: "open", Path: "/sys/kernel/tracing/uprobe_events", Err: syscall.ENOENT})

// attempts is how many times an attach was asked for at all, placed or refused. It is what §7's "one
// attempt per binary" is counted in: a probe that was never placed still spent the attempt.
func (a *openingAttacher) attempts() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// pathsFrom is every path attached from the nth placed probe onward.
func (a *openingAttacher) pathsFrom(n int) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.paths[n:]...)
}

// sharedRootTree builds a fake /proc in which every listed pid sees one shared filesystem through its own
// /proc/<pid>/root, which is how two processes on a host come to map the very same (device, inode) — the
// condition R7's attach cache is keyed on. It returns the shared root and the in-namespace library path.
func sharedRootTree(t *testing.T, tree *procTree, pids []int, symbols map[string]uint64) (string, string) {
	t.Helper()
	so := writeELF(t, elfOptions{Dynamic: symbols, BuildID: []byte{0xab, 0xcd}})
	b, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	const lib = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	if err := os.MkdirAll(filepath.Join(host, filepath.Dir(lib)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, lib), b, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, pid := range pids {
		tree.process(t, pid, "/nonexistent/python3", []string{lib})
		root := filepath.Join(tree.root, strconv.Itoa(pid), "root")
		if err := os.RemoveAll(root); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(host, root); err != nil {
			t.Fatal(err)
		}
	}
	return host, lib
}

// attachedPaths is the path every cached attachedBinary records.
func attachedPaths(c *cache) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, a := range c.byID {
		out = append(out, a.Path)
	}
	return out
}

// TestAttachUsesTheLivePathNotACachedProcEntry pins that the offset cache contributes offsets and a build
// id across processes (R7) but never a path: every candidate is spelled through the observed process's own
// /proc entry (capture-derive.md R39), which the kernel removes when that process exits. A second process mapping the same
// libssl must be attached through its own entry, not through the first process's vanished one.
func TestAttachUsesTheLivePathNotACachedProcEntry(t *testing.T) {
	tree := newProcTree(t)
	_, lib := sharedRootTree(t, tree, []int{51, 52}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	att := &openingAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(51, 41, "")
	// SSL_write is one probe and SSL_read needs an entry and a return (R1, R3).
	first := att.count()
	if first != 3 {
		t.Fatalf("%d probes for the first process, want 3 (%s)", first, lib)
	}

	// The process exits: R8 closes its links and drops the entry, while the parsed offsets stay
	// cached under (dev, ino) for the next process to reuse (R7).
	u.OnExit(51)
	if err := os.RemoveAll(filepath.Join(tree.root, "51")); err != nil {
		t.Fatal(err)
	}

	u.OnExec(52, 41, "")
	if att.count() != 2*first {
		t.Fatalf("%d probes after the second process, want %d: it was attached through pid 51's gone /proc entry",
			att.count(), 2*first)
	}
	stale := filepath.Join(tree.root, "51")
	for _, p := range att.pathsFrom(first) {
		if strings.HasPrefix(p, stale) {
			t.Errorf("attached through the exited process's /proc entry: %s", p)
		}
	}
	for _, p := range attachedPaths(u.cache) {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("the cached attachedBinary names a path that does not exist: %v", err)
		}
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %v, want none: the library is still there through pid 52's own root", gaps)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestVanishedPathDoesNotPoisonTheBinary pins the other half of §7's "one attempt per (dev,ino), no retry
// storm": the rule bites on what the binary and the host refuse, which no later process will refuse any
// differently. A file that went away under one process is not that, and caching it would answer every
// later process with a gap naming a libssl that is perfectly hookable.
func TestVanishedPathDoesNotPoisonTheBinary(t *testing.T) {
	tree := newProcTree(t)
	sharedRootTree(t, tree, []int{61, 62}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	// pid 61 is reaped mid-attach: the kernel takes its /proc entry, and with it the only spelling of
	// the library this attach had (R39). The library itself is untouched and pid 62 still reaches it
	// through its own entry.
	att := &openingAttacher{failFirst: true, vanish: filepath.Join(tree.root, "61")}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(61, 41, "")
	if att.count() != 0 {
		t.Fatalf("%d probes placed, want none: the first attach raced the file away", att.count())
	}
	if len(u.Gaps()) == 0 {
		t.Fatal("a process that could not be attached left no gap (I4)")
	}

	u.OnExec(62, 41, "")
	if att.count() != 3 {
		t.Fatalf("%d probes for the second process, want 3: the binary was poisoned by the first one's race",
			att.count())
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// refusedAttachSource starts a source over processes sharing one hookable libssl, against an attacher that
// refuses every probe with errHostENOENT while the candidate path stays perfectly readable: a host without
// CONFIG_UPROBE_EVENTS, which is a permanent property of this host and not a file that went away.
func refusedAttachSource(t *testing.T, pids []int) (*Uprobe, *openingAttacher) {
	t.Helper()
	tree := newProcTree(t)
	sharedRootTree(t, tree, pids, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	att := &openingAttacher{failAll: true}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := u.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	return u, att
}

// TestARefusalTheHostSpellsENOENTIsStillOneAttempt pins §7's "one attempt per (dev,ino), no retry storm"
// against the errno the refusal arrives under. The exemption for a candidate path that vanished with the
// process that mapped it (R39) has to be decided on whether the path is actually gone, because the error
// cannot decide it: on the uprobe PMU, perf_event_open's ENOENT is the kernel's lookup of that very path,
// while a host without CONFIG_UPROBE_EVENTS answers every attach with ENOENT from the tracefs file
// cilium/ebpf falls back to, a refusal it will repeat for every process that ever maps the binary.
// Exempting that spends an attach attempt on every exec of every process on the host, for the life of the
// run.
func TestARefusalTheHostSpellsENOENTIsStillOneAttempt(t *testing.T) {
	u, att := refusedAttachSource(t, []int{71, 72})
	u.OnExec(71, 41, "")
	first := att.attempts()
	if first != 1 {
		t.Fatalf("%d attach attempts for the first process, want 1: the rollback kept going", first)
	}
	u.OnExec(72, 41, "")
	if got := att.attempts(); got != first {
		t.Errorf("%d attach attempts after a second process, want %d: the refusal was not recorded and §7's one attempt per binary became a retry storm",
			got, first)
	}
	if att.count() != 0 {
		t.Errorf("%d probes placed against an attacher that refuses everything", att.count())
	}
}

// TestARefusedAttachIsANoOpenSSLGap pins which of R37's closed reasons an attach failure gets.
// static-tls-no-symbols means "a candidate exists but exports none of R1-R3's symbols" — Bun's BoringSSL,
// rustls. This candidate exports SSL_write and SSL_read and this package computed their offsets before it
// asked the kernel for anything, so that reason is simply false here, and §7's failure-modes table puts
// every attach() error under no-openssl with the cause in the run's own log instead.
func TestARefusedAttachIsANoOpenSSLGap(t *testing.T) {
	u, _ := refusedAttachSource(t, []int{73})
	u.OnExec(73, 41, "")
	gaps := u.Gaps()
	if hasGap(gaps, GapStaticTLSNoSymbols) {
		t.Errorf("a refused attach was reported as static-tls-no-symbols on a binary that exports SSL_write: %v", gaps)
	}
	if !hasGap(gaps, GapNoOpenSSL) {
		t.Errorf("gaps = %v, want no-openssl (§7's \"Uprobe attach fails\" row)", gaps)
	}
}

// TestAttacherHoldsOneExecutableHandle pins the bound on what the production attacher retains. Every path
// it is given is one process's own /proc entry (R39), so a handle keyed by path and never evicted would
// accumulate one dead entry per short-lived process the run execs. The reuse that is actually worth having
// spans one binary's consecutive probes (R1-R3), which one slot covers.
//
// link.OpenExecutable only reads the file, so this runs without privilege; placing a probe is the part
// behind the integration tag.
func TestAttacherHoldsOneExecutableHandle(t *testing.T) {
	first := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100}})
	second := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymRead: 0x1180}})
	a := &EBPFAttacher{}
	t.Cleanup(func() { _ = a.Close() })

	one, err := a.executable(first)
	if err != nil {
		t.Fatalf("executable(%s): %v", first, err)
	}
	again, err := a.executable(first)
	if err != nil {
		t.Fatalf("executable(%s) again: %v", first, err)
	}
	if again != one {
		t.Errorf("the next probe on the same binary reopened it")
	}
	if _, err := a.executable(second); err != nil {
		t.Fatalf("executable(%s): %v", second, err)
	}
	if back, err := a.executable(first); err != nil {
		t.Fatalf("executable(%s) after another binary: %v", first, err)
	} else if back == one {
		t.Errorf("the attacher still holds the handle of a path it has moved on from")
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if a.exec != nil {
		t.Errorf("Close left an executable handle behind")
	}
}

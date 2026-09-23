// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// rewriteInPlace gives one inode a different file's contents, which is what the attach cache has to
// survive. Writing through the existing name keeps (device, inode) and changes everything the file says
// about itself, so it reproduces on one filesystem what overlayfs and btrfs produce on a container host:
// a (device, inode) pair that no longer names the bytes it named before (ADR 0010,
// Documentation/filesystems/overlayfs.rst "Inode properties"). The pair is asserted unchanged, because a
// test that silently got a new inode would prove nothing.
func rewriteInPlace(t *testing.T, path, from string) {
	t.Helper()
	before, err := statIdentity(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatalf("read %s: %v", from, err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("rewrite %s: %v", path, err)
	}
	after, err := statIdentity(path)
	if err != nil {
		t.Fatalf("stat %s after the rewrite: %v", path, err)
	}
	if before != after {
		t.Fatalf("the rewrite moved the file to a new inode (%v -> %v): the test proves nothing", before, after)
	}
}

// recordedProbes is every probe the fake attacher was asked for, with its offset.
func recordedProbes(a *fakeAttacher) []Probe {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Probe(nil), a.probes...)
}

// TestInodeReuseDoesNotHandOnAnotherBinarysAttach pins R7's correctness key. The (device, inode) pair is
// the fast path and nothing more: the kernel's overlayfs documentation says both halves "can change over
// the lifetime of a non-directory object" when layers are not all on one filesystem and xino is off, and
// R39 puts every candidate on exactly that filesystem. A second binary reaching the pair the first one
// left behind must not be answered out of the first one's cache entry, because that answer is a process
// reported as captured with no probe anywhere in the library it actually maps — a silent absence, which
// I4 forbids.
func TestInodeReuseDoesNotHandOnAnotherBinarysAttach(t *testing.T) {
	tree := newProcTree(t)
	host, lib := sharedRootTree(t, tree, []int{81, 82}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(81, 41, "")
	// SSL_write is one probe and SSL_read needs an entry and a return (R1, R3).
	if got := att.count(); got != 3 {
		t.Fatalf("%d probes for the first binary, want 3", got)
	}

	// The inode now holds a different libssl: a different build id, and SSL_write somewhere else. The
	// first process is still alive, so its entry is still in the cache.
	replacement := writeELF(t, elfOptions{
		Dynamic: map[string]uint64{SymWrite: 0x1200, SymRead: 0x1280},
		BuildID: []byte{0x11, 0x22, 0x33},
	})
	rewriteInPlace(t, filepath.Join(host, lib), replacement)

	u.OnExec(82, 41, "")
	probes := recordedProbes(att)
	if len(probes) != 6 {
		t.Fatalf("%d probes after the inode changed hands, want 6: pid 82 was reported captured on pid 81's attach",
			len(probes))
	}
	if last := probes[5]; last.Symbol != SymWrite || last.Offset != 0x1200 {
		t.Errorf("probe = %s, want SSL_write at %#x, the offset in the file that is actually there", last, 0x1200)
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %v, want none: both processes map a hookable libssl", gaps)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestFailureDoesNotOutliveTheBinaryItWasRecordedFor pins the other half of the same key. §7 records one
// attempt per binary and never retries, so a failure keyed on a (device, inode) pair alone refuses every
// later file that reaches the pair for as long as the host is up — the cache is host-wide and outlives
// runs (ARCHITECTURE §9). The refusal is a no-openssl gap on a libssl that would have attached.
func TestFailureDoesNotOutliveTheBinaryItWasRecordedFor(t *testing.T) {
	tree := newProcTree(t)
	// A first binary exporting nothing of R1-R3: the static-tls-no-symbols case §7 records.
	host, lib := sharedRootTree(t, tree, []int{91, 92}, map[string]uint64{"EVP_CIPHER_do_all": 0x1100})
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(91, 41, "")
	if got := att.count(); got != 0 {
		t.Fatalf("%d probes on a binary exporting no OpenSSL symbols, want none", got)
	}
	if !hasGap(u.Gaps(), GapStaticTLSNoSymbols) {
		t.Fatalf("no static-tls-no-symbols gap for a binary with nothing to hook (I4): %v", u.Gaps())
	}

	replacement := writeELF(t, elfOptions{
		Dynamic: map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180},
		BuildID: []byte{0x44, 0x55},
	})
	rewriteInPlace(t, filepath.Join(host, lib), replacement)

	u.OnExec(92, 41, "")
	if got := att.count(); got != 3 {
		t.Fatalf("%d probes for the second process, want 3: a failure recorded for a file that is gone refused a hookable libssl",
			got)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestBinariesWithNoBuildIDStillShareOneAttach guards the sharing R7 asks for against the fix above. A
// stripped binary has no build id to key on, so the pair alone is all there is and two processes mapping
// it must still share one attach and one RefCount (R7, R8, edge case #26). This is the documented residual
// limitation stated as a behaviour: it is deliberate, not an oversight.
func TestBinariesWithNoBuildIDStillShareOneAttach(t *testing.T) {
	tree := newProcTree(t)
	host, lib := sharedRootTree(t, tree, []int{101, 102}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	stripped := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180}})
	rewriteInPlace(t, filepath.Join(host, lib), stripped)
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(101, 41, "")
	u.OnExec(102, 41, "")
	if got := att.count(); got != 3 {
		t.Errorf("%d probes for two processes mapping one stripped binary, want 3 (R7)", got)
	}
	if got := u.cache.size(); got != 1 {
		t.Errorf("attach cache holds %d binaries, want 1 (I8)", got)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

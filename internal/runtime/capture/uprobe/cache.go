// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"fmt"
	"io"
	"sync"
)

// Probe is one attachment: which program goes where in which binary.
type Probe struct {
	// Program is the BPF program's name in the capture object (internal/bpf's Prog* constants).
	Program string
	// Symbol is the OpenSSL entry point, for diagnostics; Offset is what the kernel actually uses.
	Symbol string
	// Offset is the symbol's file offset, from the per-binary offset cache.
	Offset uint64
	// Return is true for the uretprobe half of a read pair (R3).
	Return bool
}

// String renders a probe for the operator log.
func (p Probe) String() string {
	kind := "uprobe"
	if p.Return {
		kind = "uretprobe"
	}
	return fmt.Sprintf("%s %s@%#x -> %s", kind, p.Symbol, p.Offset, p.Program)
}

// Attacher places one uprobe on a binary and hands back the link that holds it. The production
// implementation is cilium/ebpf's link package over the loaded capture object; a test supplies one that
// records what it was asked for, which is what lets discovery, symbol choice, refcounting and detach be
// tested with no kernel at all.
type Attacher interface {
	Attach(path string, p Probe) (io.Closer, error)
}

// binaryAttacher is an Attacher that places a whole binary's probes at once and may share them beyond this
// process (sharedAttacher): the closers it returns are what the attach cache closes at refcount zero.
type binaryAttacher interface {
	AttachBinary(path string, id identity, probes []Probe) ([]io.Closer, error)
}

// attachedBinary is one binary this process has uprobes on, and the runs and processes that still want
// them. RefCount is len(refs): links close when it reaches zero and not before, so a libssl two runs share
// stays attached while either of them still has a process on it (R7, R8, edge case #26).
type attachedBinary struct {
	ID        identity
	Path      string
	Name      string
	BuildID   string
	WriteSyms []string
	ReadSyms  []string

	links []io.Closer
	refs  map[refKey]struct{}
}

// RefCount is how many references stand on this binary: one per source and process that mapped it.
func (a *attachedBinary) RefCount() int { return len(a.refs) }

// refKey names one reference: one source's hold on one process's mapping of a binary.
//
// A pid alone does not name it, because pids are reused and an exit event can be missed. Keyed by pid, a
// process run A attached and never saw exit and run B's live process that later drew the same pid onto the
// same binary were one reference: B's attach added nothing, and A's Stop gave back the only one and closed
// links B's process still maps. That is the detach R8 forbids while another run's contribution stands
// (edge case #26), and nothing would raise a gap for it (I4). Keyed by source as well, each run gives back
// exactly what it took, and an exit a source is told about can only drop that source's own reference.
type refKey struct {
	// owner is the Uprobe that took the reference, as New numbered it.
	owner uint64
	pid   int
}

// cache is the host-wide attach cache of §3: one entry per binary identity — the (device, inode) fast key
// and the build id R7 names as the correctness key beside it — the offsets parsed once per binary, and one
// attempt per binary so a verifier or permission failure never becomes a retry storm.
//
// It outlives a single run on purpose (§9 "resource lifetimes"): two concurrent runs sharing one system
// libssl share one attach, and the per-cgroup filter in the kernel still keeps their plaintext apart (R9,
// edge case #26).
type cache struct {
	mu      sync.Mutex
	byID    map[identity]*attachedBinary
	offsets map[identity]*binary
	failed  map[identity]error
	byRef   map[refKey][]identity
	// claims are the binaries an attach is in progress for, each with the channel its waiters block on
	// until that attempt has put its entry or its failure (see claim).
	claims map[identity]chan struct{}
}

// newCache returns an empty attach cache.
func newCache() *cache {
	return &cache{
		byID:    map[identity]*attachedBinary{},
		offsets: map[identity]*binary{},
		failed:  map[identity]error{},
		byRef:   map[refKey][]identity{},
		claims:  map[identity]chan struct{}{},
	}
}

// settled is the channel claim returns for a binary whose attempt has already finished: it is closed, so the
// caller reads the outcome from the cache at once, as a waiter would.
var settled = func() chan struct{} { ch := make(chan struct{}); close(ch); return ch }()

// claim makes the caller the one attempt in progress for a binary and returns nil, or, when another caller
// already holds that claim, returns the channel that closes when it lets go. A caller that gets nil must
// call unclaim once its entry or failure is in the cache. put still settles a race between two callers
// that each attached (which a claim prevents for one cache), so no (device, inode) keeps two sets of links.
//
// The caller asked ref and failure before claiming, each under its own hold of the lock, so another
// attempt can have put its entry or failure and let go of its claim in between. claim answers that from
// the cache under the lock it claims under, with a closed channel, so the caller goes back to ref and
// takes a reference; had it claimed, it would have attached the binary a second time, which I8 forbids
// and which a concurrent test caught as six probes for three (TestConcurrentOnExecAcrossTwoSourcesAttachesOnce).
func (c *cache) claim(id identity) <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.claims[id]; ok {
		return ch
	}
	if _, ok := c.byID[id]; ok {
		return settled
	}
	if _, ok := c.failed[id]; ok {
		return settled
	}
	c.claims[id] = make(chan struct{})
	return nil
}

// unclaim ends the caller's claim on a binary and wakes everyone waiting for it.
func (c *cache) unclaim(id identity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.claims[id]; ok {
		close(ch)
		delete(c.claims, id)
	}
}

// lookupOffsets returns the parsed ELF for a binary identity, or nil.
//
// The build id R7 names as the correctness key is checked by the map lookup itself, because identity
// carries it: an entry parsed from a different file cannot be reached through the (device, inode) pair it
// happens to share. This used to be a second argument compared after the hit, which every caller passed
// empty, so the check never ran; see identity for what a pair alone does not identify.
func (c *cache) lookupOffsets(id identity) *binary {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.offsets[id]
}

// putOffsets records a parsed ELF under its identity.
func (c *cache) putOffsets(id identity, b *binary) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offsets[id] = b
}

// failure returns the error a previous attempt on this binary recorded, if any. One attempt per binary is
// the whole of the "no retry storm" rule of §7: a verifier rejection or a permission failure is a property
// of the binary and the host, not of the process that happened to map it.
//
// "This binary" is identity, build id included: a failure recorded for one file must not outlive it and
// refuse a different file that reaches the same (device, inode) pair, because nothing ever retries and the
// refusal would be a no-openssl gap on a perfectly hookable libssl for the rest of the host's uptime.
func (c *cache) failure(id identity) (error, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	err, ok := c.failed[id]
	return err, ok
}

// fail records that attaching to a binary did not work.
func (c *cache) fail(id identity, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failed[id] = err
}

// ref adds a reference to an already attached binary and reports whether the binary was there, and how
// many references now stand on it. It is the fast path of I8: a second process mapping the same libssl
// never attaches a second time. The count is taken here, under the lock that guards refs, because a
// caller reading RefCount after the lock is released races every concurrent addRefLocked.
func (c *cache) ref(id identity, k refKey) (*attachedBinary, int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.byID[id]
	if !ok {
		return nil, 0, false
	}
	c.addRefLocked(a, k)
	return a, len(a.refs), true
}

// put records a freshly attached binary with its first reference. A concurrent caller that attached the
// same binary first wins: its entry stays, the loser's links are returned for the caller to close, so no
// (device, inode) is ever double-attached (I8).
func (c *cache) put(a *attachedBinary, k refKey) (*attachedBinary, []io.Closer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.byID[a.ID]; ok {
		c.addRefLocked(existing, k)
		return existing, a.links
	}
	c.byID[a.ID] = a
	c.addRefLocked(a, k)
	return a, nil
}

// addRefLocked records one reference on a binary. A reference already held is not counted twice: the
// same source seeing the same pid on the same binary again is one process to give back, not two.
func (c *cache) addRefLocked(a *attachedBinary, k refKey) {
	if a.refs == nil {
		a.refs = map[refKey]struct{}{}
	}
	if _, ok := a.refs[k]; ok {
		return
	}
	a.refs[k] = struct{}{}
	c.byRef[k] = append(c.byRef[k], a.ID)
}

// release drops one source's references for one process and returns the links of every binary that
// reached refcount zero, for the caller to close outside the lock (R8). A binary another source's
// reference still stands on keeps its links, whatever pid that reference carries.
func (c *cache) release(k refKey) []io.Closer {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := c.byRef[k]
	delete(c.byRef, k)
	var out []io.Closer
	for _, id := range ids {
		a, ok := c.byID[id]
		if !ok {
			continue
		}
		delete(a.refs, k)
		if len(a.refs) > 0 {
			continue
		}
		out = append(out, a.links...)
		delete(c.byID, id)
	}
	return out
}

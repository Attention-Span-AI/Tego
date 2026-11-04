// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"crypto/sha256"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// Bound attacker-chosen names/inodes as well as hash input (readExecBytes).
// The process-local cache holds no descriptors or executable bytes.
const maxNodeBuilds = 64

var nodeBuilds nodeBuildCache

// ctime cannot be restored with utimensat: rewriting the same inode, even with
// the same size and restored mtime, must not reuse its previous attestation.
type nodeBuildKey struct {
	id                fileID
	size              int64
	modified, changed unix.Timespec
}

func nodeKey(st unix.Stat_t) nodeBuildKey {
	return nodeBuildKey{fileID{st.Dev, st.Ino}, st.Size, st.Mtim, st.Ctim}
}

type nodeBuildResult struct {
	ready chan struct{}
	sum   [sha256.Size]byte
	ok    bool
}

// A single miss hashes outside the mutex; concurrent callers for that key wait
// on its result. FIFO eviction bounds entries, including pending ones. Evicting
// a pending entry can duplicate work under churn, never reuse another key.
type nodeBuildCache struct {
	mu      sync.Mutex
	entries map[nodeBuildKey]*nodeBuildResult
	order   []nodeBuildKey
}

func (c *nodeBuildCache) get(key nodeBuildKey, hash func() ([sha256.Size]byte, bool)) ([sha256.Size]byte, bool) {
	c.mu.Lock()
	if r := c.entries[key]; r != nil {
		c.mu.Unlock()
		<-r.ready
		return r.sum, r.ok
	}
	if c.entries == nil {
		c.entries = make(map[nodeBuildKey]*nodeBuildResult)
	}
	if len(c.order) == maxNodeBuilds {
		delete(c.entries, c.order[0])
		c.order = c.order[1:]
	}
	r := &nodeBuildResult{ready: make(chan struct{})}
	c.entries[key] = r
	c.order = append(c.order, key)
	c.mu.Unlock()

	r.sum, r.ok = hash()
	c.mu.Lock()
	if !r.ok && c.entries[key] == r {
		delete(c.entries, key)
		for i, k := range c.order {
			if k == key {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
	}
	close(r.ready)
	c.mu.Unlock()
	return r.sum, r.ok
}

func (c *nodeBuildCache) version(fd int, before unix.Stat_t) string {
	sum, ok := c.get(nodeKey(before), func() ([sha256.Size]byte, bool) {
		return hashNodeBuild(fd, before)
	})
	// Recheck this caller's own descriptor after a hit or wait too: a rewrite
	// while another worker was hashing must not receive its former build pin.
	if !ok || !nodeBuildUnchanged(fd, before) {
		return ""
	}
	return rows.NodeBuildVersion(sum)
}

func nodeBuildUnchanged(fd int, before unix.Stat_t) bool {
	var after unix.Stat_t
	return unix.Fstat(fd, &after) == nil && nodeKey(before) == nodeKey(after)
}

func hashNodeBuild(fd int, before unix.Stat_t) ([sha256.Size]byte, bool) {
	var sum [sha256.Size]byte
	h := sha256.New()
	block := make([]byte, 64<<10)
	for off := int64(0); off < before.Size; {
		n, err := unix.Pread(fd, block[:min(int64(len(block)), before.Size-off)], off)
		if err != nil || n <= 0 {
			return sum, false
		}
		_, _ = h.Write(block[:n]) // hash.Hash.Write cannot fail
		off += int64(n)
	}
	if !nodeBuildUnchanged(fd, before) {
		return sum, false
	}
	copy(sum[:], h.Sum(nil))
	return sum, true
}

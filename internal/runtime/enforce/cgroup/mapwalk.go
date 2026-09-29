// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// keyWalker is the part of *ebpf.Map a key walk uses; a test gives a map whose walk restarts.
type keyWalker interface {
	NextKey(key, nextKeyOut any) error
	MaxEntries() uint32
}

// walkStepsPerEntry bounds a key walk at this many NextKey steps per map entry. A walk that runs past it has
// restarted so often that it cannot finish, and fails rather than returning a partial key list.
const walkStepsPerEntry = 8

// mapKeys lists every key of a hash or LPM map that other launchers and the kernel may be deleting from while
// it walks. When the key under the cursor is deleted, the kernel's get_next_key restarts at the first key.
// cilium's MapIterator counts every step, restarts included, and aborts once the count passes max_entries, so
// on a shared map that is more than half full a concurrent Detach or cgroup_rmdir failed the caller's Prepare
// although its own rows were fine. This walk remembers the keys it has seen and steps past them after a
// restart, as internal/bpf ringIDs does. A key added during the walk may or may not be listed; a key present
// throughout is listed.
func mapKeys[K comparable](m keyWalker) ([]K, error) {
	var (
		keys  []K
		seen  = map[K]bool{}
		prev  any
		limit = walkStepsPerEntry * (int(m.MaxEntries()) + 1)
	)
	for range limit {
		var next K
		err := m.NextKey(prev, &next)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return keys, nil
		}
		if err != nil {
			return nil, err
		}
		k := next
		prev = &k
		if seen[k] {
			continue // a deletion restarted the walk at the first key: step past what was already listed
		}
		seen[k] = true
		keys = append(keys, k)
	}
	return nil, fmt.Errorf("%w: key walk restarted more than %d steps allow", ebpf.ErrIterationAborted, limit)
}

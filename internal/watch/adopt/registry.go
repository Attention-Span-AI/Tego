// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"sync"
)

// ErrAdopting is a process this registry already holds: an adoption of it is in progress or under way.
var ErrAdopting = errors.New("adopt: the process is already being adopted")

// ErrRegistryFull is a registry at its cap: the guard is adopting as many agents as it was told it may at once.
var ErrRegistryFull = errors.New("adopt: too many adoptions at once")

// Registry is the guard's record of the processes it is adopting, so it never adopts one twice: an identity is held
// from the moment an adoption of it begins until that adoption has ended. It is bounded (Max), safe for concurrent
// use, and in memory: across processes the run's cgroup says a process is governed (Check), and a host-wide lock per
// identity keeps two adopters apart (internal/runtime's adoption).
type Registry struct {
	mu   sync.Mutex
	max  int
	held map[Identity]string
}

// DefaultMaxAdoptions is how many adoptions one guard holds at once by default.
const DefaultMaxAdoptions = 32

// NewRegistry is a registry of at most max identities (DefaultMaxAdoptions when max <= 0).
func NewRegistry(max int) *Registry {
	if max <= 0 {
		max = DefaultMaxAdoptions
	}
	return &Registry{max: max, held: map[Identity]string{}}
}

// Claim holds id for owner. It returns ErrAdopting, with the holder's name, when id is held already, and
// ErrRegistryFull when the registry is at its cap.
func (r *Registry) Claim(id Identity, owner string) (holder string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.held[id]; ok {
		return h, ErrAdopting
	}
	if len(r.held) >= r.max {
		return "", ErrRegistryFull
	}
	r.held[id] = owner
	return "", nil
}

// Rename changes the name id is held under (a run id once the adoption has one).
func (r *Registry) Rename(id Identity, owner string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.held[id]; ok {
		r.held[id] = owner
	}
}

// Drop releases id.
func (r *Registry) Drop(id Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.held, id)
}

// Len is how many identities are held.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.held)
}

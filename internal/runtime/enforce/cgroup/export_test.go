// SPDX-License-Identifier: Apache-2.0

package cgroup

// acquire is acquireGen (whose doc is the contract) without the epoch.
func (s *slotTable) acquire(carriedOf func() (map[uint32]bool, error)) (uint32, error) {
	idx, _, err := s.acquireGen(carriedOf)
	return idx, err
}

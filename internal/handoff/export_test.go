// SPDX-License-Identifier: Apache-2.0

package handoff

import "sort"

// What this file exports, only this package's tests call.

// Codes lists the reason codes, sorted.
func Codes() []string {
	out := make([]string, 0, len(exits))
	for c := range exits {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// SHA256 is the hash of the sealed copy, lowercase hex: the pinned hash.
func (b *Binary) SHA256() string { return b.sum }

// Source is the path the copy was made from.
func (b *Binary) Source() string { return b.from }

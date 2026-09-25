// SPDX-License-Identifier: Apache-2.0

package observe

import "github.com/attention-span-ai/tego/pkg/spec/record"

// What this file exports, only this package's tests call.

// Decode decodes one sample into a fresh Record.
func Decode(raw []byte) (Record, error) {
	var r Record
	err := DecodeInto(&r, raw)
	return r, err
}

// IndexFor is ReasonFor's inverse, what the map-populating side of tier 2 stamps into
// struct tego_net_verdict. It returns 0, false for a code with no index.
func IndexFor(r record.Reason) (uint8, bool) {
	for i, code := range reasonByIndex {
		if code != "" && code == r {
			return uint8(i), true
		}
	}
	return 0, false
}

// len is the number of open buckets.
func (t *aggTable) len() int { return t.n }

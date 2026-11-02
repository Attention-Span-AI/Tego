// SPDX-License-Identifier: Apache-2.0

package execpin

// What this file exports, only this package's tests call.

// Sum64 is plain SipHash-2-4 of msg under k: the reference function the 64 published vectors check.
func Sum64(k Key, msg []byte) uint64 { return sum64(k, nil, msg) }

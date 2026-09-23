// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf && !(386 || amd64 || arm64)

package bpf

// withArchObjects adds nothing on an architecture uprobessl is not compiled for, so Load(ObjectUprobeSSL)
// reports ErrNotGenerated there and capture says it is unavailable, while the three tier-2 objects still load.
func withArchObjects(m map[Object]binding) map[Object]binding { return m }

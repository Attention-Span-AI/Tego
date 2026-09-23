// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf && (386 || amd64 || arm64)

package bpf

// withArchObjects adds the uprobe object on the architectures bpf2go compiled it for: the tags above are the
// union of the build constraints of uprobessl_x86_bpfel.go (386 || amd64) and uprobessl_arm64_bpfel.go.
func withArchObjects(m map[Object]binding) map[Object]binding {
	m[ObjectUprobeSSL] = binding{load: loadUprobessl, raw: _UprobesslBytes}
	return m
}

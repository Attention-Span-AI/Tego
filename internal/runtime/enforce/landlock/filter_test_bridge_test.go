// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package landlock

import "golang.org/x/net/bpf"

// Local unit tests use the same builder without exporting a harness wrapper in
// the ordinary production package. Integration builds supply their own bridge.
func BuildFilterMemfd(arch Arch, full bool, m MemfdArm) ([]bpf.Instruction, error) {
	return buildFilter(arch, filterOpts{full: full, abi: minTruncateABI, memfd: m, unixBinds: true}) // as the integration bridge
}

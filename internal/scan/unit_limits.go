// SPDX-License-Identifier: Apache-2.0

package scan

// These bounds are at least ten times the measured stock layout maxima in
// testdata/unit-layouts/README.md. The total includes overflow lookahead and
// a minimum slot per listing attempt. Missing directories consume no entries.
const (
	unitDirectoryEntries = 4096
	unitDirectoryCount   = 1024
	unitTotalEntries     = 4096
	unitAliasHops        = 16
	unitLineBytes        = 8192
	unitTokenLimit       = 4096
	unitExecLimit        = 128
	unitArgumentLimit    = 256
)

// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package scan

import "io/fs"

// dataless reports whether fi's contents aren't on disk. Only macOS evicts files to the cloud this way.
func dataless(fs.FileInfo) bool { return false }

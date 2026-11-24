// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package config

import "os"

// SetRulesFileFSForTest makes ReadRulesFile see the file system fs describes for each file (statfs magic, the mount
// row's type, point and super options), so a test of another package can put a rules file on WSL's Windows drive, a
// 9p share or a FAT disk without one. Only a test build has it. It returns the function that restores the real one.
func SetRulesFileFSForTest(fs func(f *os.File) (magic int64, fstype, point, super string, err error)) (restore func()) {
	prev := rulesFileFS
	rulesFileFS = fs
	return func() { rulesFileFS = prev }
}

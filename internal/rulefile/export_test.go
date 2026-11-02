// SPDX-License-Identifier: Apache-2.0

package rulefile

import "path/filepath"

// What this file exports, only this package's tests call.

// Check is Read's verdict alone: nil when the contract at path may be changed, else why not (ErrGuard and the
// reason, or the I/O error). A view says Writable or Why with it.
func Check(path string, g Guard) error {
	_, err := Read(path, g)
	return err
}

// Find is FindIn with DefaultGuard(filepath.Dir(dir)): the run directory's parent is its ledger root.
func Find(dir string, seq uint64) (*Found, error) {
	return FindIn(dir, seq, DefaultGuard(filepath.Dir(dir)))
}

// FindAt is FindAtIn with the guard Find uses.
func FindAt(dir string, seq uint64, h Hint) (*Found, error) {
	return FindAtIn(dir, seq, h, DefaultGuard(filepath.Dir(dir)))
}

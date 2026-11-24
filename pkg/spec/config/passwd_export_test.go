// SPDX-License-Identifier: Apache-2.0

//go:build (!cgo && !darwin) || osusergo

package config

import "testing"

// SetPasswdFileForTest lets external compiler tests use the real pure-Go lookup
// against a fixture without changing host passwd or process credentials.
func SetPasswdFileForTest(t *testing.T, path string) {
	t.Helper()
	saved := passwdFile
	t.Cleanup(func() { passwdFile = saved })
	passwdFile = path
}

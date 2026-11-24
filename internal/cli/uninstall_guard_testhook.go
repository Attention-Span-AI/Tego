// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import "errors"

// uninstallRealGuard refuses in a binary built with tegotesthooks: tego uninstall removes files in the invoking user's
// own home and stops that user's own units, which no TEGO_TEST_* setting isolates. A test runs runUninstall against an
// environment (uninstallEnv) of its own, made in a folder it created.
func uninstallRealGuard() error {
	return errors.New("this binary is built with tegotesthooks and must not remove the invoking user's own files or units; a test builds its own uninstallEnv")
}

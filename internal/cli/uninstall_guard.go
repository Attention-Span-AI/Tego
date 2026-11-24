// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package cli

// uninstallRealGuard is nil in a product build: tego uninstall works on the invoking user's own home and user
// services.
func uninstallRealGuard() error { return nil }

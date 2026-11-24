// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package cli

// scanDropBetweenSteps marks the points between dropScanPrivileges' all-thread changes. Only the integration build
// can hold the drop there (scan_dropstep_integration.go); every other build does nothing.
func scanDropBetweenSteps(string) {}

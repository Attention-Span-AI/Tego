// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"errors"
	"testing"
)

// TestTestBuildAnchorFailsClosed is identity-config.md R27: a binary built with tegotesthooks resolves the
// anchor it is told and, told none, resolves none, so a command that anchors refuses instead of writing the
// invoking user's own ~/.tego/chain.log.
func TestTestBuildAnchorFailsClosed(t *testing.T) {
	p, err := testAnchorResolver("/scratch/chain.log")(nil)
	if err != nil || p != "/scratch/chain.log" {
		t.Errorf("a set variable: %q, %v", p, err)
	}
	p, err = testAnchorResolver("")(nil)
	if !errors.Is(err, ErrTestAnchorUnset) || p != "" {
		t.Errorf("an unset variable: %q, %v", p, err)
	}
}

// TestTestBuildKeepsNoOwnLogWithoutAHome: R27's other half. An unset TEGO_TEST_OWN_LOG_HOME leaves the test build
// no home for tego.log, never the invoking user's.
func TestTestBuildKeepsNoOwnLogWithoutAHome(t *testing.T) {
	if got := testOwnLogHome("")(1000); got != "" {
		t.Errorf("an unset variable gave the home %q", got)
	}
	if got := testOwnLogHome("/scratch/home")(1000); got != "/scratch/home" {
		t.Errorf("a set variable gave %q", got)
	}
}

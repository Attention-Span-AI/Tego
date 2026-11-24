// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"errors"
	"testing"
)

// TestWSLRuleTestHook: the test build's switch for the rule on WSL is on for the exact value "on" alone, and never
// under AT_SECURE or when AT_SECURE cannot be read.
func TestWSLRuleTestHook(t *testing.T) {
	plain := func() (bool, error) { return false, nil }
	secure := func() (bool, error) { return true, nil }
	unknown := func() (bool, error) { return false, errors.New("no auxv") }
	for _, c := range []struct {
		value string
		at    func() (bool, error)
		want  bool
	}{
		{"on", plain, true}, {"", plain, false}, {"1", plain, false}, {"true", plain, false}, {"ON", plain, false},
		{"off", plain, false}, {"on ", plain, false}, {"on", secure, false}, {"on", unknown, false},
	} {
		if got := testWSLRule(c.value, c.at); got != c.want {
			t.Errorf("TEGO_TEST_WSL_RULE=%q: %v, want %v", c.value, got, c.want)
		}
	}
	if EnvTestWSLRule != "TEGO_TEST_WSL_RULE" || EnvTestNestedRule != "TEGO_TEST_NESTED_RULE" {
		t.Errorf("the variables are %q and %q", EnvTestWSLRule, EnvTestNestedRule)
	}
}

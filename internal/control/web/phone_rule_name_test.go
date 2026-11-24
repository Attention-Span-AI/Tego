// SPDX-License-Identifier: Apache-2.0

package web

import "testing"

// TestPhoneRuleNamesTellBuiltInRulesApart: each rule every contract carries has its own short phone name, so a
// phone list of them is not ten rows of the same words; none quotes a path.
func TestPhoneRuleNamesTellBuiltInRulesApart(t *testing.T) {
	seen := map[string]string{}
	for _, key := range []string{"built-in.deny_read[]", "builtin.host_ipc", "builtin.tego_surface", "builtin.other_tty",
		"built-in.own-records[]", "built-in.contract[]", "host-sockets", "route-query", "built-in.no-setuid[]", "record[]"} {
		name := phoneRuleName(ruleRow{Key: key})
		if name == "Access rule" || name == "" {
			t.Errorf("%s has the generic name %q", key, name)
		}
		if other, ok := seen[name]; ok {
			t.Errorf("%s and %s share the phone name %q", key, other, name)
		}
		seen[name] = key
	}
	if got := phoneRuleName(ruleRow{Key: "fs.deny_read[/home/u/.ssh/]"}); got != "File reads" {
		t.Errorf("a contract entry: %q", got)
	}
}

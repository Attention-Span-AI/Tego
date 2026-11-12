// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// TestSystemdRefusedNameFollowsTheRelaxedRules: the names systemd's relaxed rules (systemd.io/USER_NAMES) refuse, for
// which it starts no user manager (acceptance 3, 2026-11-11: the user 4242 on Ubuntu 24.04), and ordinary names it
// accepts, a few that only its strict rules would refuse among them.
func TestSystemdRefusedNameFollowsTheRelaxedRules(t *testing.T) {
	for name, refused := range map[string]bool{
		"svc": false, "tego": false, "a.b": false, "svc-agent": false, "_svc": false, "Svc1": false, "a b": false,
		"x$": false, "-x": false, "4242x": false, "0x1": false, "é": false,
		"": true, "4242": true, "0": true, "-1": true, "-": true, "-4242": true, ".": true, "..": true,
		"a:b": true, "a/b": true, "a\x01b": true, "a\x7fb": true, "\xff": true, " svc": true, "svc ": true, "svc\t": true,
	} {
		if why := SystemdRefusedName(name); (why != "") != refused {
			t.Errorf("%q: %q, want refused %v", name, why, refused)
		}
	}
}

// TestPlainUserName: a name a command reads as itself, never one it would read as an option or a uid ('#0' is uid 0
// to sudo -u; the review's S3).
func TestPlainUserName(t *testing.T) {
	for name, plain := range map[string]bool{
		"svc": true, "a b": true, "4242x": true, "x-1": true,
		"": false, "-x": false, "4242": false, "a\x00b": false, "a\u202eb": false, "#0": false, "#svc": false, "+x": false,
		"a#b": true, "x+": true,
	} {
		if got := PlainUserName(name); got != plain {
			t.Errorf("%q: %v, want %v", name, got, plain)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestNetworkingMirrored(t *testing.T) {
	mirrored := "[wsl2]\nmemory=4GB\nnetworkingMode = Mirrored # for VPNs\n"
	for _, tc := range []struct {
		name, wslinfo, config string
		want                  bool
	}{
		{"wsl says mirrored", "mirrored\n", "", true},
		{"wsl says mirrored, config says nat", "mirrored", "[wsl2]\nnetworkingMode=nat\n", true},
		{"wsl says nat, config not yet restarted", "nat\r\n", mirrored, false},
		{"wsl says none", "none\n", mirrored, false},
		{"wsl gave no answer: the config decides", "", mirrored, true},
		{"wsl gave an error text: the config decides", "bash: /usr/bin/wslinfo: No such file or directory", mirrored, true},
		{"no answer, default networking", "", "[wsl2]\nmemory=4GB\n", false},
		{"no answer, no config", "", "", false},
		{"no answer, mirrored outside [wsl2]", "", "[experimental]\nnetworkingMode=mirrored\n", false},
		{"no answer, commented out", "", "[wsl2]\n# networkingMode=mirrored\n;networkingMode=mirrored\n", false},
		{"no answer, byte order mark", "", "\ufeff[wsl2]\nnetworkingMode=mirrored\n", true},
		{"no answer, CRLF", "", "[wsl2]\r\nnetworkingMode=mirrored\r\n", true},
		{"no answer, mixed case", "", "[WSL2]\r\nNetworkingmode = MIRRORED\r\n", true},
		{"no answer, inline # comment", "", "[wsl2]\nnetworkingMode=mirrored # for VPNs\n", true},
		{"no answer, inline ; comment", "", "[wsl2]\r\nnetworkingMode = mirrored ; vpn\r\n", true},
		{"no answer, a comment that hides the value", "", "[wsl2]\nnetworkingMode= # mirrored\n", false},
		{"no answer, the same value twice", "", "[wsl2]\nnetworkingMode=mirrored\nmemory=4GB\nnetworkingMode=Mirrored\n", true},
		{"no answer, a duplicate that disagrees (first)", "", "[wsl2]\nnetworkingMode=mirrored\nnetworkingMode=nat\n", false},
		{"no answer, a duplicate that disagrees (last)", "", "[wsl2]\nnetworkingMode=nat\nnetworkingMode=mirrored\n", false},
		{"no answer, a duplicate in another section is not counted", "", "[wsl2]\nnetworkingMode=mirrored\n[experimental]\nnetworkingMode=nat\n", true},
	} {
		if got := networkingMirrored(tc.wslinfo, tc.config); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

// The mirrored verdict says the same thing on every path to it, in one line that names the one setting and the one
// command (R7), whether the port was measured reserved or the networking mode said so.
func TestMirroredWords(t *testing.T) {
	for _, w := range []string{mirroredWords(), portReservedWords(8484)} {
		if strings.Contains(w, "\n") || !strings.HasPrefix(w, "tego: ") || !strings.Contains(w, "mirrored networking") ||
			!strings.Contains(w, `networkingMode=nat in %USERPROFILE%\.wslconfig, then wsl --shutdown`) || !strings.HasSuffix(w, "run: tego session list") {
			t.Errorf("%q", w)
		}
	}
}

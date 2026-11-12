// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// SystemdRefusedName is why systemd refuses name as a user name, so that it starts no user manager for the account
// that has it and loginctl enable-linger changes nothing; "" when it accepts the name. The rules are systemd's relaxed
// ones (systemd.io/USER_NAMES, "Relaxed Mode"), which systemd-logind applies to names other programs registered: not
// empty, not digits only (read as a uid), not a '-' and digits only (read as a negative uid), valid UTF-8, no control
// character, no ':' or '/', not "." or "..", and no white space at either end. Measured for digits only on Ubuntu
// 24.04 (systemd 255, acceptance 3, 2026-11-11): loginctl enable-linger 1004 for the user 4242 exited 0 and wrote
// /var/lib/systemd/linger/4242, and user@1004.service failed with "Trying to run as user instance, but
// $XDG_RUNTIME_DIR is not set". The other rules are read from that page and systemd's code, not run. It is pure.
func SystemdRefusedName(name string) string {
	switch {
	case name == "":
		return "is empty"
	case digitsOnly(name):
		return "is digits only, which systemd reads as a uid"
	case name[0] == '-' && (len(name) == 1 || digitsOnly(name[1:])):
		return "is a '-' and digits only, which systemd reads as a negative uid"
	case !utf8.ValidString(name):
		return "is not valid UTF-8"
	case strings.IndexFunc(name, func(r rune) bool { return r < ' ' || r == 0x7f }) >= 0:
		return "holds a control character"
	case strings.ContainsAny(name, ":/"):
		return "holds a ':' or a '/'"
	case name == "." || name == "..":
		return "is . or .."
	case strings.ContainsRune(" \t\n\r", rune(name[0])) || strings.ContainsRune(" \t\n\r", rune(name[len(name)-1])):
		return "starts or ends with white space"
	}
	return ""
}

// PlainUserName reports whether a command that takes a user's name (loginctl enable-linger, sudo -u) reads name, as
// one shell word, as that name: not empty, every character printable, no leading '-', which it would read as an
// option, no leading '#', which sudo -u reads as a uid ('#0' is root; the review's S3: only an NSS source such as LDAP
// could supply such a name, since the files backend skips '#' lines), no leading '+', which marks a NIS compat entry
// in passwd, and not digits only, which it would read as a uid. A caller names the uid in its place otherwise.
func PlainUserName(name string) bool {
	if name == "" || strings.ContainsRune("-#+", rune(name[0])) ||
		strings.IndexFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return false
	}
	return !digitsOnly(name)
}

// digitsOnly reports whether s is not empty and holds only the ASCII digits.
func digitsOnly(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

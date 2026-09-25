// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"strings"
	"testing"
)

// escapeMount is the kernel's mangling of a mountinfo path (seq_path_root's " \t\n\\" as octal escapes).
func escapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case ' ', '\t', '\n', '\\':
			fmt.Fprintf(&b, "\\%03o", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// FuzzParseMountLine holds the mountinfo parser to its reading: a line it accepts has a filesystem type and a
// mount point, its mount point decodes the kernel's escapes exactly (a path escaped as the kernel escapes it
// comes back as it was), and decoding never lengthens a field.
func FuzzParseMountLine(f *testing.F) {
	f.Add("36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue", "/mnt/a b")
	f.Add("1 2 0:1 / /a\\040b rw - tmpfs t rw", "/tab\there")
	f.Add("1 2 0:1 / /a\\134 rw - tmpfs t rw", "/back\\slash\\")
	f.Add("1 2 0:1 / /a rw shared:1 master:2 - overlay overlay rw", "/new\nline")
	f.Add("1 2 0:1 / /a rw -", "")
	f.Fuzz(func(t *testing.T, line, point string) {
		m, ok := parseMountLine(line)
		if ok && (m.fstype == "" || m.point == "") {
			t.Fatalf("%q: accepted with fstype %q point %q", line, m.fstype, m.point)
		}
		if got := unescapeMount(line); len(got) > len(line) {
			t.Fatalf("%q decoded longer: %q", line, got)
		}
		if got := unescapeMount(escapeMount(point)); got != point {
			t.Fatalf("%q escaped as %q decodes to %q", point, escapeMount(point), got)
		}
		if point == "" || strings.ContainsAny(point, "\x00") {
			return
		}
		m, ok = parseMountLine("1 2 0:1 / " + escapeMount(point) + " rw - ext4 /dev/sda1 rw")
		if !ok || m.point != point || m.fstype != "ext4" {
			t.Fatalf("mount point %q: got %+v ok=%v", point, m, ok)
		}
	})
}

// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// mountOpensDevices reports whether a device node under path can be opened at all: the kernel refuses every open of a
// character or block device (EACCES, whatever the file's mode and the caller's uid, root's too) on a mount made nodev,
// and /tmp, /dev/shm and /run are mounted nodev on most distributions' images and in the KVM guests' own init, so a
// test that makes a device node there and expects a uid to open it by file mode proves nothing.
func mountOpensDevices(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	return uint64(st.Flags)&unix.ST_NODEV == 0, nil
}

// unescapeMountinfo undoes the octal escapes (\040 for a space) that /proc/self/mountinfo puts in a mount point.
func unescapeMountinfo(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, ok := octal3(s[i+1 : i+4]); ok {
				b.WriteByte(n)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func octal3(s string) (byte, bool) {
	if len(s) != 3 {
		return 0, false
	}
	v := 0
	for _, c := range []byte(s) {
		if c < '0' || c > '7' {
			return 0, false
		}
		v = v*8 + int(c-'0')
	}
	return byte(v), v < 256
}

func TestUnescapeMountinfo(t *testing.T) {
	for in, want := range map[string]string{
		`/mnt/a\040b`: "/mnt/a b", `/plain`: "/plain", `/x\134y`: `/x\y`, `/end\040`: "/end ", `/short\04`: `/short\04`, `\`: `\`,
	} {
		if got := unescapeMountinfo(in); got != want {
			t.Errorf("unescapeMountinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMountOpensDevicesAgreesWithMountinfo checks the helper against an independent reading of this machine's mounts:
// the per-mount option list in /proc/self/mountinfo says nodev exactly where statfs does.
func TestMountOpensDevicesAgreesWithMountinfo(t *testing.T) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Skipf("no /proc/self/mountinfo: %v", err)
	}
	// A mount point can hold several mounts, one over another (autofs under binfmt_misc); statfs answers for the one on
	// top, which mountinfo lists last.
	top := map[string]bool{}
	var points []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		point := unescapeMountinfo(f[4])
		if _, seen := top[point]; !seen {
			points = append(points, point)
		}
		top[point] = slices.Contains(strings.Split(f[5], ","), "nodev")
	}
	var sawNodev, sawDev bool
	for _, point := range points {
		wantNodev := top[point]
		got, err := mountOpensDevices(point)
		if err != nil {
			continue // a mount this user cannot reach, or one that went away
		}
		if got == wantNodev {
			t.Errorf("%s: mountOpensDevices = %v, but its top mount is nodev %v in mountinfo", point, got, wantNodev)
		}
		sawNodev, sawDev = sawNodev || wantNodev, sawDev || !wantNodev
	}
	if !sawDev {
		t.Errorf("no mount of this machine could be checked as one that opens devices (the root file system at least)")
	}
	t.Logf("checked against mountinfo: a nodev mount seen %v, a device-opening mount seen %v", sawNodev, sawDev)
	if _, err := mountOpensDevices("/no/such/path/at/all"); err == nil {
		t.Errorf("mountOpensDevices of a missing path: no error")
	}
}

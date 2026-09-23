// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// KernelVersion is a parsed uname release: major.minor.patch, with any suffix ("-41-generic", "-rc3") kept
// verbatim in Extra.
type KernelVersion struct {
	Major, Minor, Patch int
	Extra               string
}

// String renders the version as the kernel prints it: "6.17.0-41-generic".
func (v KernelVersion) String() string {
	return fmt.Sprintf("%d.%d.%d%s", v.Major, v.Minor, v.Patch, v.Extra)
}

// Kernel returns the running kernel's version (uname(2)).
func Kernel() (KernelVersion, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return KernelVersion{}, fmt.Errorf("uname: %w", err)
	}
	return ParseKernelRelease(unix.ByteSliceToString(u.Release[:]))
}

// ParseKernelRelease parses a uname release string: "6.17.0-41-generic", "5.14.0", "7.0-rc3", "6.1".
// Minor and patch default to 0; the first byte that is not part of "<n>.<n>.<n>" starts Extra.
func ParseKernelRelease(release string) (KernelVersion, error) {
	var v KernelVersion
	rest := release
	nums := [3]*int{&v.Major, &v.Minor, &v.Patch}
	for i := range nums {
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end == 0 {
			if i == 0 {
				return KernelVersion{}, fmt.Errorf("kernel release %q: no leading number", release)
			}
			break
		}
		n, err := strconv.Atoi(rest[:end])
		if err != nil {
			return KernelVersion{}, fmt.Errorf("kernel release %q: %w", release, err)
		}
		*nums[i] = n
		rest = rest[end:]
		if i < 2 && strings.HasPrefix(rest, ".") && len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9' {
			rest = rest[1:]
			continue
		}
		break
	}
	v.Extra = rest
	return v, nil
}

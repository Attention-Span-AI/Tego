// SPDX-License-Identifier: Apache-2.0

package sys

// AtLeast reports whether v is major.minor or newer, ignoring patch and suffix.
func (v KernelVersion) AtLeast(major, minor int) bool {
	return v.Major > major || (v.Major == major && v.Minor >= minor)
}

// leases is the count of leases out.
func (f *FD) leases() uint64 { return f.state.Load() & leaseMask }

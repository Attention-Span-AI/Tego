// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

// BuiltinStandardDevices is the immutable rule name a write to a standard data device carries when no entry of the
// contract granted it: the grant is the product's (ADR 0158), so a record never says the contract allowed it.
const BuiltinStandardDevices = "builtin.standard_devices"

// StandardDevice is one of the character devices a run with an fs: section may open for writing without naming it.
// It is granted by what the file is, not by its name: a file of the same name that is another device, a regular
// file, a link or a mount of something else holds no grant.
type StandardDevice struct {
	Path         string
	Major, Minor uint32
}

// standardDevices are the data sinks and sources of Linux's memory devices (devices.txt, major 1): what a shell
// redirect or a tool's scratch output opens, and what holds no file and no person's screen. /dev/tty and the
// pseudo-terminals are not here: a write to a terminal reaches a person's screen, and which terminal /dev/tty names
// depends on the process that opens it, not on a device number a check could fix (ADR 0158).
var standardDevices = [...]StandardDevice{
	{"/dev/null", 1, 3},
	{"/dev/zero", 1, 5},
	{"/dev/full", 1, 7},
	{"/dev/random", 1, 8},
	{"/dev/urandom", 1, 9},
}

// StandardDevices lists the devices, in the order a table holds their rows.
func StandardDevices() []StandardDevice { return standardDevices[:] }

// StandardDeviceAt reports whether a file with this mode and device number (st_mode, st_rdev) is the standard device
// named path: a character device with exactly its major and minor numbers. Every tier that can look at the object it
// grants asks this of the object, never of its name.
func StandardDeviceAt(path string, mode uint32, rdev uint64) bool {
	if mode&unix.S_IFMT != unix.S_IFCHR {
		return false
	}
	for _, d := range standardDevices {
		if d.Path == path {
			return unix.Major(rdev) == d.Major && unix.Minor(rdev) == d.Minor
		}
	}
	return false
}

// IsStandardDevice is true for a row compile added for a standard device (FSRule.StdDevice).
func (r FSRule) IsStandardDevice() bool { return r.StdDevice && r.Kind == FSWrite }

// lstatDevice is the look at a device's path compile takes; a test stands in the file a host could have there.
var lstatDevice = os.Lstat

// standardDeviceAccess is what a row grants: the writes and the ioctls a device accepts, never a create, a removal
// or a rename (those are rights on its directory, which no row here grants).
const standardDeviceAccess = AccessWriteFile | AccessTruncate | AccessIoctlDev

// standardDevices adds the rows of a contract with an fs: section, a write allow-list (SEMANTICS R6), which refuses a shell
// redirect to /dev/null. A contract with no fs: section is the one R6 gives no write entry at all and adds none (ADR 0158).
// The five devices hold no file, so a row each, keyed (at every tier) on the object the
// path names now. A device is left out when this host's file at its path is not the device (a look-alike, a link, a
// mount of something else: there is nothing to grant), and when an entry the contract wrote is at, over or beneath it
// (a write entry already decides it; a deny_write, deny_read, ask or watch entry, or a name entry that matches it,
// is the author's word, which a default never overrides).
func (b *fsBuilder) standardDevices() {
	for _, d := range standardDevices {
		fi, err := lstatDevice(d.Path)
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || !StandardDeviceAt(d.Path, st.Mode, uint64(st.Rdev)) { //nolint:unconvert // Rdev is uint64 on amd64 and arm64, not everywhere
			continue
		}
		if b.deviceNamed(d.Path, st) {
			continue
		}
		r := FSRule{Path: d.Path, Resolved: d.Path, Kind: FSWrite, Access: standardDeviceAccess, BuiltIn: true, StdDevice: true}
		b.meta(&r, fi, d.Path, Pos{})
		b.rules = append(b.rules, r)
	}
}

// deviceNamed reports whether an entry of the contract mentions the device p: any fs entry that covers it (the
// implicit ones are the product's), a deny_write entry, an fs.ask or fs.ask_read entry, or a name entry the contract declared that matches its name.
func (b *fsBuilder) deviceNamed(p string, st *syscall.Stat_t) bool {
	for _, r := range b.rules {
		if r.Kind == FSImplicit || r.StdDevice {
			continue
		}
		if r.BuiltIn && r.Kind == FSDenyRead && r.BuiltinRule == "" && r.Raw == "" {
			continue // the built-in credential list, which names no device
		}
		for _, s := range r.Spellings() {
			if Covers(s, p) {
				return true
			}
		}
		// Another name of the same file (a bind of the device, a hard link of it): the plane keys one row per inode, and the
		// entry already decides the file under every name the ruleset and the plane see.
		if r.Kind == FSWrite && b.sameInode(r.Canonical(), st) {
			return true
		}
	}
	for _, u := range b.userDW {
		for _, s := range []string{u.path, u.resolved, u.name} {
			if s != "" && Covers(s, p) {
				return true
			}
		}
	}
	// An fs.ask or fs.ask_read entry is a person's decision, and compiles after this (fsAsk): its declared entries are read here.
	for _, raw := range append(slices.Clone(b.k.c.FS.Ask), b.k.c.FS.AskRead...) {
		if abs := b.k.abs(raw); Covers(abs, p) || Covers(b.k.resolve(abs), p) {
			return true
		}
	}
	base := filepath.Base(p)
	for i := range b.declNames {
		if e := &b.declNames[i]; !e.BuiltIn && e.Matches(base) {
			return true
		}
	}
	return false
}

// sameInode reports whether the file at path is the one st describes: both device and inode number equal, links followed.
func (b *fsBuilder) sameInode(path string, st *syscall.Stat_t) bool {
	dev, ino, err := b.k.fileIdentity(path)
	return err == nil && dev == uint64(st.Dev) && ino == st.Ino //nolint:unconvert // Dev is a uint32 on some architectures
}

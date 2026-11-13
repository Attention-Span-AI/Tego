// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// MountSnapshot is the launcher's mount table as Prepare reads it once (agent.ReadMountSnapshot: bounded, strict,
// read twice and equal), and every question the listener's policy and the plane's holdability check ask of it: the
// mount points beneath a directory, the other places a deny_read tree is shown at, its parts mounted outside it, and
// the device of the mount a path reaches. One snapshot answers them all, so alias refusals, the listener's marks and the
// devices the recorder is told were marked (Handle.ListenerDevices) come from one table and never from a later look.
//
// Each alias or detached-part placement question is checked against the live system (live): the mount the table says the
// path's nearest existing directory reaches must be the one statx(2) reports for it. A table that disagrees with the
// system, one that could not be read, or one that holds no mount of the path answers an error, and the caller refuses
// the run rather than decide on a table that is not the system's (fix round 1, finding 2).
type MountSnapshot struct {
	mt  *agent.MountTable
	raw []byte
	err error
	// live is the mount id statx reports for a path that exists; nil skips the check (a test's table of its own).
	live func(path string) (int, error)
	// under answers the mount points beneath a directory from the parsed table's points.
	under func(dir string) ([]string, error)
}

// readMountSnapshot reads the table at path and checks it against the live system.
func readMountSnapshot(path string) *mountSnapshot {
	mt, raw, err := agent.ReadMountSnapshot(path)
	return newMountSnapshot(mt, raw, err, mountLive)
}

// mountLive is the live check readMountSnapshot uses: statxMountID. A test that points the package at a mount table
// of its own (mountInfoPath) sets it to nil, since that table is not the system's.
var mountLive = statxMountID

func newMountSnapshot(mt *agent.MountTable, raw []byte, err error, live func(string) (int, error)) *mountSnapshot {
	s := &mountSnapshot{mt: mt, raw: raw, err: err, live: live}
	s.under = mountPointsUnderFrom(s.Points)
	return s
}

// statxMountID is the mount id statx(2) reports for path (STATX_MNT_ID, the numbering mountinfo's first field uses).
func statxMountID(path string) (int, error) {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_MNT_ID, &stx); err != nil {
		return 0, err
	}
	if stx.Mask&unix.STATX_MNT_ID == 0 {
		return 0, errNoMountID
	}
	return int(stx.Mnt_id), nil
}

// errNoMountOf is a mount table that holds no mount of a path: a chroot's, which skips the mount above a root that
// is no mount point, or one whose mount tree cannot place it.
var errNoMountOf = errors.New("the mount table holds no mount of")

// errMountMismatch is a mount table whose mount for a path is not the one the system reports for it.
var errMountMismatch = errors.New("the mount table does not describe the mounts the system reports")

// check is the snapshot's error, or the disagreement between the table and the system at path's nearest existing
// directory.
func (s *mountSnapshot) check(path string) error {
	if s.err != nil {
		return s.err
	}
	path = mountSpelling(path)
	at := existingAncestor(path)
	want, ok := s.mt.MountID(at)
	if !ok {
		return fmt.Errorf("%w %s", errNoMountOf, path)
	}
	if s.live == nil {
		return nil
	}
	got, err := s.live(at)
	if err != nil {
		return fmt.Errorf("%w: statx %s: %w", errMountMismatch, at, err)
	}
	if got != want {
		return fmt.Errorf("%w: %s is on mount %d, the table says %d", errMountMismatch, at, got, want)
	}
	return nil
}

// aliases is the other places the table shows path's tree at (agent.MountTable.TreeAliases), each checked as path is.
func (s *mountSnapshot) aliases(path string) ([]string, error) {
	return s.places(path, (*agent.MountTable).TreeAliases)
}

// detached is the places outside path where a part of its tree is mounted (agent.MountTable.DetachedParts).
func (s *mountSnapshot) detached(path string) ([]string, error) {
	return s.places(path, (*agent.MountTable).DetachedParts)
}

func (s *mountSnapshot) places(path string, of func(*agent.MountTable, string) ([]string, bool)) ([]string, error) {
	path = mountSpelling(path)
	if err := s.check(path); err != nil {
		return nil, err
	}
	names, ok := of(s.mt, path)
	if !ok {
		return nil, fmt.Errorf("%w %s", errNoMountOf, path)
	}
	for _, n := range names {
		if err := s.check(n); err != nil {
			return nil, err
		}
	}
	return slices.Clip(names), nil
}

// device is the device of the filesystem path reaches, in the encoding the recorder's records carry, and whether the
// table places it.
func (s *mountSnapshot) device(path string) (uint64, bool) {
	if s.err != nil {
		return 0, false
	}
	ma, mi, ok := s.mt.Device(mountSpelling(path))
	if !ok {
		return 0, false
	}
	return unix.Mkdev(ma, mi), true
}

// mountSnapshot keeps package-local helpers using the same prepared facts.
type mountSnapshot = MountSnapshot

// ReadMounts acquires the bounded, strict snapshot shared by a root-tier Prepare.
func ReadMounts() *MountSnapshot { return acquireMountSnapshot(mountInfoPath) }

// acquireMountSnapshot is the acquisition boundary, replaced by a read-counter test.
var acquireMountSnapshot = readMountSnapshot

// Points returns the mounted roots from this snapshot for the plane's mount rows.
func (s *MountSnapshot) Points() ([]string, error) {
	if s.err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMountTable, s.err)
	}
	return s.mt.Points(), nil
}

// Table returns the immutable parsed facts for the recorder, including acquisition errors.
func (s *MountSnapshot) Table() (*agent.MountTable, error) { return s.mt, s.err }

// MountTable is the mount facts acquired during Prepare. No recorder rereads the table.
func (h *Handle) MountTable() (*agent.MountTable, error) {
	if h.run.Mounts == nil {
		return nil, ErrMountTable
	}
	return h.run.Mounts.Table()
}

// mountSpelling follows existing symlink ancestors before asking a textual mount table.
// statx follows them too. Missing tails retain their placement on that ancestor's mount.
func mountSpelling(path string) string {
	at := existingAncestor(path)
	resolved, err := filepath.EvalSymlinks(at)
	if err != nil {
		return path
	}
	return filepath.Clean(resolved + strings.TrimPrefix(path, at))
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// route says who answers a permission event and with what.
type route int

const (
	// routeSelf: the opener is this process (a worker's touch). The reader answers FAN_ALLOW at once. The
	// worker that made the open is waiting for this answer, so handing the event to a worker would deadlock the
	// listener on itself.
	routeSelf route = iota
	// routeDecide: a worker decides (allow-touch): it opens and reads the configured files, then the answer is
	// FAN_ALLOW.
	routeDecide
	// routeAllow: deny mode, not the target. The reader answers FAN_ALLOW at once.
	routeAllow
	// routeDeny: deny mode, the target. The reader answers FAN_DENY at once; the opener's open fails EPERM.
	routeDeny
)

func (r route) String() string {
	switch r {
	case routeSelf:
		return "self"
	case routeDecide:
		return "decide"
	case routeAllow:
		return "allow"
	case routeDeny:
		return "deny"
	}
	return "route(?)"
}

// response is the word an inline route writes. routeDecide has none of its own: its worker answers FAN_ALLOW.
func (r route) response() uint32 {
	if r == routeDeny {
		return unix.FAN_DENY
	}
	return unix.FAN_ALLOW
}

// route is the decision table. self is whether the opener is this process; target whether the opened file is
// the one deny mode refuses (never asked in allow-touch mode, which has none).
func (c config) route(self, target bool) route {
	switch {
	case self:
		return routeSelf
	case c.mode == modeDeny && target:
		return routeDeny
	case c.mode == modeDeny:
		return routeAllow
	default:
		return routeDecide
	}
}

// target is the file deny mode refuses, by name or by inode: "the file P" is whatever answers to P's name,
// which a re-created P does, and whatever is P's inode, which a hard link or a bind mount alias is. The inode is
// read once, when the listener starts; a P that does not exist yet is matched by name alone.
type target struct {
	path   string
	dev    uint64
	ino    uint64
	haveID bool
}

func newTarget(path string) (target, error) {
	if !filepath.IsAbs(path) {
		return target{}, fmt.Errorf("path %q is not absolute", path)
	}
	t := target{path: filepath.Clean(path)}
	var st unix.Stat_t
	if err := unix.Stat(t.path, &st); err == nil {
		t.dev, t.ino, t.haveID = uint64(st.Dev), uint64(st.Ino), true
	}
	return t, nil
}

// matches reports whether an opened file, named by the path /proc/self/fd/N reads back and by its device and
// inode, is the target. A file unlinked while open reads back with " (deleted)" after its name.
func (t target) matches(path string, dev, ino uint64) bool {
	path = strings.TrimSuffix(path, " (deleted)")
	return path == t.path || (t.haveID && dev == t.dev && ino == t.ino)
}

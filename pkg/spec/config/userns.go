// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strconv"
	"strings"
	"sync"
)

// uidMapPath is the process's own user-namespace uid map (user_namespaces(7)).
const uidMapPath = "/proc/self/uid_map"

// UserNamespace is what this process's uid map says of its user namespace. The zero value is
// UserNamespaceUnknown, so a fact never read is not taken for either answer.
type UserNamespace int

const (
	// UserNamespaceUnknown: the map could not be read (a chroot or minimal container with no /proc).
	UserNamespaceUnknown UserNamespace = iota
	// UserNamespaceInitial: the map was read and is the identity map of the whole uid range.
	UserNamespaceInitial
	// UserNamespaceChild: the map was read and is anything else, so the namespace is a child one.
	UserNamespaceChild
)

func (n UserNamespace) String() string {
	switch n {
	case UserNamespaceUnknown:
		return "unknown"
	case UserNamespaceInitial:
		return "initial"
	case UserNamespaceChild:
		return "child"
	}
	return "UserNamespace(" + strconv.Itoa(int(n)) + ")"
}

// CurrentUserNamespace reads this process's user namespace from /proc/self/uid_map: the initial one when the map is
// the identity map of the whole uid range, one line "0 0 4294967295", which only the initial namespace has; a child
// one when the map was read and is anything else (a child namespace's map is written once and covers at most what
// its creator mapped: `unshare -r` writes "0 <uid> 1", a rootless container "0 100000 65536"); unknown when the map
// cannot be read. Each caller decides what unknown means for it, and every one fails closed: the root gates
// (InitialUserNamespace, InitNSRoot, InvokingUID) take it as not the initial namespace, and ADR 0042 (3)(a)'s guard
// takes it as possibly the initial one and reads the capability sets as it does there.
// Read once per process: tego never changes its own user namespace.
func CurrentUserNamespace() UserNamespace { return currentUserNamespace() }

var currentUserNamespace = sync.OnceValue(func() UserNamespace { return readUserNamespace(uidMapPath) })

// readUserNamespace is CurrentUserNamespace over a given map file.
func readUserNamespace(path string) UserNamespace {
	data, err := os.ReadFile(path)
	switch {
	case err != nil:
		return UserNamespaceUnknown
	case identityUIDMap(data):
		return UserNamespaceInitial
	}
	return UserNamespaceChild
}

// InitialUserNamespace reports whether this process runs in the initial user namespace (CurrentUserNamespace is
// UserNamespaceInitial). A map that cannot be read is not the initial namespace's, so the answer fails closed.
func InitialUserNamespace() bool { return CurrentUserNamespace() == UserNamespaceInitial }

// identityUIDMap is CurrentUserNamespace's pure half: whether a map that was read is the initial namespace's.
func identityUIDMap(data []byte) bool {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 1 {
		return false
	}
	f := strings.Fields(lines[0])
	return len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295"
}

// InitNSRoot reports whether this process is root of the host: effective uid 0 in the initial user namespace
// (ADR 0042 (5)(d)); an unknown namespace (an unreadable uid map) is not root. Every "uid 0" gate of the root
// tiers asks this, never os.Geteuid() == 0 alone: under `unshare -r` the effective uid is 0 and every capability
// is held, but only over the new namespace, which owns neither the BPF subsystem, the cgroup2 root nor
// /run/tego, and SUDO_UID is whatever the caller set.
//
// It lives here, beside InvokingUID and DetectSecureExec, because InvokingUID applies it to SUDO_UID and pkg/spec
// imports nothing from internal (the depguard rule spec-is-pure); the launcher's gates call it from here.
func InitNSRoot() bool { return initNSRoot(os.Geteuid(), InitialUserNamespace()) }

// initNSRoot is InitNSRoot over explicit inputs.
func initNSRoot(euid int, initial bool) bool { return euid == 0 && initial }

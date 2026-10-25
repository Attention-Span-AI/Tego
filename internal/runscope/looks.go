// SPDX-License-Identifier: Apache-2.0

package runscope

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// LooksGoverned is the broad rule, for refusals only: whether a cgroup path is, or looks like, a run's. It is true
// for every path GovernedBy names a run in and for every look-alike of one, at any depth, in anyone's subtree:
//   - a tego.slice segment with, anywhere below it, a run-*.scope or an adopt-*.scope (any text between, a malformed
//     run id included) or an agent's slice, tego-*.slice (a run's, an adoption's or a Docker run's systemd parent,
//     tego-<agent>-<run slug>.slice, all live below one);
//   - the Docker cgroupfs parent, a tego segment with at least two segments below it (tego/<agent>/<run id>).
//
// The path is read segment by segment as the kernel printed it: nothing is cleaned away, so a ".." cannot hide a
// later name (an empty segment names nothing and is skipped). A run-*.scope with no tego.slice above it is not one:
// systemd-run names its transient scopes run-<x>.scope (app.slice/run-r3f2.scope is the person's own command).
// LooksGoverned never names a run: a caller that acts on a run reads GovernedBy.
func LooksGoverned(cgroup string) bool {
	var segs []string
	for s := range strings.SplitSeq(cgroup, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	underTop := false
	for i, s := range segs {
		if s == cgroupfsRoot && len(segs)-i > 2 {
			return true
		}
		if underTop && (looksLike(s, runPrefix, scopeSuffix) || looksLike(s, adoptPrefix, scopeSuffix) ||
			looksLike(s, agentPrefix, sliceSuffix)) {
			return true
		}
		if s == identity.TopSlice {
			underTop = true
		}
	}
	return false
}

// looksLike reports whether name is <prefix><anything><suffix>.
func looksLike(name, prefix, suffix string) bool {
	return len(name) >= len(prefix)+len(suffix) && strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix)
}

// ErrCgroupFile is a /proc/<pid>/cgroup file that does not name one cgroup v2 path: no "0::" line (a process on a
// v1-only hierarchy), more than one, a path that is not absolute, or a cgroup the kernel marks removed.
var ErrCgroupFile = errors.New("runscope: the cgroup file names no single cgroup v2 path")

// deletedSuffix is what the kernel appends to a cgroup v2 path whose cgroup was removed (proc_cgroup_show).
const deletedSuffix = " (deleted)"

// Unified is the cgroup v2 path a /proc/<pid>/cgroup file names: its one "0::" line, which must hold an absolute
// path. Anything else is ErrCgroupFile, never a guess: a reader that took the first of two such lines, or a relative
// path, would judge a path the kernel did not print. Pure and total (FuzzUnified).
func Unified(b []byte) (string, error) {
	found, n := "", 0
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		p, ok := bytes.CutPrefix(line, []byte("0::"))
		if !ok {
			continue
		}
		found, n = string(p), n+1
	}
	switch {
	case n == 0:
		return "", fmt.Errorf("%w: no 0:: line", ErrCgroupFile)
	case n > 1:
		return "", fmt.Errorf("%w: %d 0:: lines", ErrCgroupFile, n)
	case !strings.HasPrefix(found, "/"):
		return "", fmt.Errorf("%w: %q is not an absolute path", ErrCgroupFile, found)
	case strings.HasSuffix(found, deletedSuffix):
		return "", fmt.Errorf("%w: %q was removed", ErrCgroupFile, found)
	}
	return found, nil
}

// OutsideNamespace reports whether a path Unified read lies above the reader's cgroup namespace root: the kernel
// prints such a path relative to that root, as "/.." followed by more, so nothing below it can be judged.
func OutsideNamespace(cgroup string) bool {
	return cgroup == "/.." || strings.HasPrefix(cgroup, "/../")
}

// selfCgroup is this process's cgroup file, and selfCgroupNS its cgroup namespace's.
const (
	selfCgroup   = "/proc/self/cgroup"
	selfCgroupNS = "/proc/self/ns/cgroup"
)

// InitCgroupNS is the inode of the initial cgroup namespace, the one the kernel boots with (PROC_CGROUP_INIT_INO,
// include/linux/proc_ns.h). It is fixed: a namespace made later gets a dynamic inode, from 0xF0000000 up
// (PROC_DYNAMIC_FIRST), so no other namespace has it. Only a reader in this namespace is shown cgroup paths from the
// hierarchy's root.
const InitCgroupNS uint64 = 0xEFFFFFFB

// InRun reports whether this process is inside a run, or looks it: LooksGoverned of its own cgroup. It fails closed:
// when the file cannot be read, names no single cgroup v2 path, or names one above this process's own cgroup
// namespace root, it is true with the error. So it is when this process is not in the initial cgroup namespace, or
// its namespace cannot be read: the kernel prints the path relative to the namespace's root ("0::/" at the root
// itself), and nothing above that root, where a run's scope may be, shows in it. A process that unshares a cgroup
// namespace inside its run's scope reads "0::/", and so does every process of a cgroupns-private container; InRun
// cannot tell the two apart, so it refuses both (TestInRunInACgroupNamespace).
func InRun() (bool, error) {
	b, err := os.ReadFile(selfCgroup)
	ns, nsErr := cgroupNSInode(selfCgroupNS)
	return inRun(b, err, ns, nsErr)
}

// cgroupNSInode is the inode of the cgroup namespace file at path.
func cgroupNSInode(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat %s: no inode", path)
	}
	return st.Ino, nil
}

// inRun is InRun over what the reads returned: the cgroup file, and this process's cgroup namespace inode.
func inRun(b []byte, readErr error, ns uint64, nsErr error) (bool, error) {
	if readErr != nil {
		return true, fmt.Errorf("runscope: read %s: %w", selfCgroup, readErr)
	}
	if nsErr != nil {
		return true, fmt.Errorf("runscope: %s: %w", selfCgroupNS, nsErr)
	}
	if ns != InitCgroupNS {
		return true, fmt.Errorf("runscope: this process is in cgroup namespace %d, not the initial one (%d): its "+
			"cgroup path starts at that namespace's root, and a run's scope above the root would not show", ns, InitCgroupNS)
	}
	cg, err := Unified(b)
	if err != nil {
		return true, fmt.Errorf("runscope: %s: %w", selfCgroup, err)
	}
	if OutsideNamespace(cg) {
		return true, fmt.Errorf("runscope: %s: %q lies above this process's cgroup namespace root", selfCgroup, cg)
	}
	return LooksGoverned(cg), nil
}

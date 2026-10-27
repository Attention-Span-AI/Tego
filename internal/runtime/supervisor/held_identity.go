// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// planeKeyedIndex is the regular files a kernel decision plane keys an fs row at by their own inode, by identity
// (planeKeyedAt), built once per compiled table on first use.
type planeKeyedIndex struct {
	once sync.Once
	at   map[fileIdentity]string
}

// fileIdentity is a file's device and inode numbers.
type fileIdentity struct{ dev, ino uint64 }

// planeKeyedAt is the path a kernel decision plane keys the regular file st describes at, when it keys one: a
// deny_write target beneath a write entry, a linked file beneath a deny_write directory (RuleTable.DenyWriteLinked,
// ADR 0071 (6)) or an fs entry, as decide.CompilePlane keys them. The plane answers every name of such a file with
// that row, so an EACCES it returns for another name, a hard link made before the run, is explained by what the
// table says at the keyed path (heldKernelErrno; GAPS C38). Each path is stated following a final
// symlink, as the plane's shared-inode check states it; a file replaced since is the agent's to have been refused.
func (c *compiled) planeKeyedAt(st *unix.Stat_t) (string, bool) {
	if c.pol == nil || c.pol.Rules == nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", false
	}
	x := &c.planeKeyed
	x.once.Do(func() { x.at = planeKeyedFiles(c.pol.Rules) })
	p, ok := x.at[fileIdentity{dev: uint64(st.Dev), ino: st.Ino}] //nolint:unconvert // Dev is uint64 on amd64 and arm64 alike, not everywhere
	return p, ok
}

// planeKeyedFiles is planeKeyedIndex's map for rt: the deny_write targets first, then the linked files, then the fs
// entries, the first path keeping an identity.
func planeKeyedFiles(rt *agent.RuleTable) map[fileIdentity]string {
	out := map[fileIdentity]string{}
	add := func(p string) {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return
		}
		id := fileIdentity{dev: uint64(st.Dev), ino: st.Ino} //nolint:unconvert // Dev is uint64 on amd64 and arm64 alike, not everywhere
		if _, dup := out[id]; !dup {
			out[id] = p
		}
	}
	for i := range rt.DenyWrite {
		g := filepath.Clean(rt.DenyWrite[i].Governed())
		if slices.ContainsFunc(rt.FS, func(w agent.FSRule) bool { return w.Kind == agent.FSWrite && agent.Covers(w.Canonical(), g) }) {
			add(g)
		}
	}
	for _, p := range rt.DenyWriteLinked {
		add(filepath.Clean(p))
	}
	for i := range rt.FS {
		if rt.FS[i].Path != "" {
			add(rt.FS[i].Canonical())
		}
	}
	return out
}

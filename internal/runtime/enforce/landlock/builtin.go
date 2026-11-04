// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

// builtinDirectories retains O_PATH references until Handle.Close: a renamed
// directory keeps its refusal and its inode cannot be recycled during the run.
func (bd *builder) builtinDirectories() error {
	b := bd.rt.Builtins
	if b == nil {
		return nil
	}
	bd.builtinDirs = map[[2]uint64]string{}
	for _, roots := range []struct {
		paths []string
		rule  string
	}{
		{[]string{b.Ledger, b.LedgerResolved}, "ledger"}, {b.Runtime, agent.BuiltinHostIPC}, {b.IPCDirs, agent.BuiltinHostIPC}, {b.Nodes, agent.BuiltinHostIPC}, {b.TegoDirs, agent.BuiltinTegoSurface},
	} {
		for _, p := range roots.paths {
			if p == "" {
				continue
			}
			i, err := bd.hold(p, kindPlaneKey, 0)
			if roots.rule == agent.BuiltinHostIPC && builtinUnreachable(err) ||
				roots.rule != agent.BuiltinHostIPC && errors.Is(err, ErrPathVanished) {
				continue
			}
			if err != nil {
				return fmt.Errorf("landlock: pin %s directory %s: %w", roots.rule, p, err)
			}
			id := bd.fds.open[i].id
			bd.builtinDirs[[2]uint64{id.dev, id.ino}] = roots.rule
		}
	}
	return nil
}

// BuiltinSocketDirectories reports Prepare-pinned identities; callers must not
// mutate the map. The handle owns the references for its entire lifetime.
func (h *Handle) BuiltinSocketDirectories() map[[2]uint64]string { return h.builtinDirs }

// The agent has this launcher's uid and Landlock can only remove access. An
// absent or unsearchable host-server path contributes no reachable identity;
// its configured name refusal remains installed (ADR 0113).
func builtinUnreachable(err error) bool {
	var opened *pathOpenError
	return errors.As(err, &opened) && (errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EACCES))
}

// Resolve refusal parents at Prepare, not in the compiled table. Guarding the
// first missing component also covers an outside server creating it later.
// Exact peer/own-runtime exceptions must never expand to an ancestor.
func (bd *builder) planeProtectedParents() error {
	for i := range bd.run.Plane.Protected {
		r := &bd.run.Plane.Protected[i]
		if r.Rule&0x8000 == 0 {
			continue
		}
		for {
			_, err := bd.hold(r.Parent, kindPlaneKey, 0)
			if err == nil {
				break
			}
			if !builtinUnreachable(err) || r.Parent == "/" {
				return fmt.Errorf("landlock: pin immutable parent %s: %w", r.Parent, err)
			}
			r.Name, r.Parent = filepath.Base(r.Parent), filepath.Dir(r.Parent)
		}
	}
	return nil
}

// builtinOptionalKey identifies only immutable host-server paths, never an
// arbitrary contractual path that must be held successfully.
func (bd *builder) builtinOptionalKey(p string) bool {
	b := bd.rt.Builtins
	if b == nil {
		return false
	}
	for _, paths := range [][]string{b.Runtime, b.IPCDirs, b.Nodes} {
		for _, path := range paths {
			if p == path {
				return true
			}
		}
	}
	for _, n := range b.Names {
		if (p == n.Parent || p == filepath.Dir(n.Target)) && b.UnixRule(n.Target, false) == agent.BuiltinHostIPC {
			return true
		}
	}
	return false
}

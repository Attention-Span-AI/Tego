// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"fmt"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
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
			if errors.Is(err, ErrPathVanished) {
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

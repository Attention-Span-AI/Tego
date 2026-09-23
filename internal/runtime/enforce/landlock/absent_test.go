// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestNoFSSectionHandlesEveryWrite pins SEMANTICS §1's "no fs:" row as amended: the ruleset handles the
// whole write side (I4) and no rule grants any of it, so every write is refused exactly as under fs: {},
// while reads stay open. Leaving the write rights unhandled instead would also have left the implicit
// entries (the run directory, the contract file, /sys/fs/cgroup, /sys/fs/bpf) writable from inside the
// run, since Landlock cannot deny beneath an allow; that is why the unrestricted reading was not built.
//
// Spec: docs/p0/enforce-landlock.md I4.
func TestNoFSSectionHandlesEveryWrite(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "ledger/")
	rt := &agent.RuleTable{Contract: &agent.Contract{}, FS: []agent.FSRule{
		fsRule(agent.FSImplicit, root+"/ledger"),
	}}
	h, fake := prepare(t, 7, rt)
	writeSide := accessWriteFile | accessRemoveDir | accessRemoveFile | accessMakeChar | accessMakeDir |
		accessMakeReg | accessMakeSock | accessMakeFifo | accessMakeBlock | accessMakeSym | accessRefer | accessTruncate
	if got := accessFS(fake.created[0].Handled_access_fs); got&writeSide != writeSide {
		t.Errorf("handled fs = %#x, want every write-side right %#x handled", got, writeSide)
	}
	for _, p := range fake.paths {
		if accessFS(p.Access)&writeSide != 0 {
			t.Errorf("a rule grants %#x, which carries a write-side right under a contract with no fs: section", p.Access)
		}
	}
	// Reads, and exec with no exec: section, stay open at "/".
	if r, ok := h.entry("/"); !ok || r.Access != readSet|accessExecute {
		t.Errorf("root grant = %+v, want the read set with EXECUTE", r)
	}
}

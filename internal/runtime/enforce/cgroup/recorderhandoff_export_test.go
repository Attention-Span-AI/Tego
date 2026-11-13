// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// OrdinarySubmountHandoffFixture prepares and arms the real policy and listener against a modeled mount table,
// using the package's fake kernel. The denied entry is outside every compiled name scope. The tmpfs mount point
// stays absent on this host: statx therefore keeps its simulated mark distinct from the real temporary directory.
func OrdinarySubmountHandoffFixture(t *testing.T) (*Handle, *agent.RuleTable, string, Emitter, func() []*record.Event) {
	t.Helper()
	f := newFixture(t)
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.Mkdir(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range f.table.NameDeny {
		for _, scope := range n.Scopes {
			if agent.Covers(scope.Canonical, secret) {
				t.Fatalf("denied entry %s is inside a name scope %s", secret, scope.Canonical)
			}
		}
	}
	f.table.FS = []agent.FSRule{
		fsRule(agent.FSWrite, outside, "", "./outside/"),
		fsRule(agent.FSDenyRead, secret, "", "./outside/secret/"),
	}
	f.table.FS[1].Unenforced = true
	f.run.Mounts = mountSnapshotOf(fmt.Sprintf("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n30 22 0:77 / %s/tmp rw - tmpfs tmpfs rw\n", secret))
	h := f.prepareArmed(t)
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("close prepared handle: %v", err)
		}
	})
	path := filepath.Join(secret, "tmp", "x")
	h.fan.decide = func(fanEvent) (verdict, error) { return h.policy.decideOpen(path), nil }
	h.fan.threadGroup = func(pid int) int { return pid }
	h.fan.handle(fanEvent{FD: openFD(t), PID: int32(os.Getpid()), Mask: unix.FAN_OPEN_PERM})
	return h, f.table, path, f.events, f.events.all
}

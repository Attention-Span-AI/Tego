// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"testing"
)

// TestCompileRefusesWriteOverKernelImplicits holds R9 and SEMANTICS §2 ("/sys/fs/cgroup, /sys/fs/bpf are
// never writable from inside the run") against a write entry that is such a path, an ancestor of it or a
// directory beneath it. Landlock unions rules along the path and crosses mount points, so such an entry granted
// write on cgroup files; at tier 1 the run's own are owned by the agent's uid, and with fs.write: ["/sys"] the
// agent raised its own pids.max and memory.max and wrote another cgroup's cgroup.procs.
// These compiled with mount-point warnings only.
func TestCompileRefusesWriteOverKernelImplicits(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/sys/fs/cgroup", "/sys", "/sys/fs", "/sys/fs/bpf", "/sys/fs/cgroup/user.slice"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		t.Run(p, func(t *testing.T) {
			c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"" + p + "\"]\n")
			rt, ds, err := Compile(c, f.machine, f.opts()...)
			if !hasCode(ds, CodeContradiction) || !errors.Is(err, ErrContractOverlap) || rt != nil {
				t.Fatalf("fs.write %q: want contradiction, got err=%v codes=%v", p, err, codes(ds))
			}
		})
	}
}

// TestCompileWarnsOnAnICMPEntry is ADR 0018 (6): a port-0 entry admits ping sockets, whose sends only the
// supervisor decides, so compile says so.
func TestCompileWarnsOnAnICMPEntry(t *testing.T) {
	f := newFixture(t)
	_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nnet:\n  allow: [\"10.0.0.0/8:0\"]\n"))
	if !hasCode(ds, CodeUnenforced) {
		t.Errorf("no warning for an ICMP entry: %v", codes(ds))
	}
	_, ds = f.compile(f.load("version: 0\nname: a\ncommand: [python]\nnet:\n  allow: [\"10.0.0.0/8:443\"]\n"))
	if hasCode(ds, CodeUnenforced) {
		t.Errorf("a tcp entry warned: %v", codes(ds))
	}
}

// TestSetuidNeedsARootTier is ADR 0033 (2): setuid: true is a root tier's opt-out of no_new_privs, refused at
// tier landlock, where the flag is what lets the stage confine itself, and warned elsewhere.
func TestSetuidNeedsARootTier(t *testing.T) {
	f := newFixture(t)
	_, ds, err := Compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nsetuid: true\n"), f.machine, f.opts()...)
	if err == nil || !hasCode(ds, CodeSchema) {
		t.Errorf("setuid: true at tier landlock compiled (err %v): %v", err, codes(ds))
	}
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: cgroup\nsetuid: true\n"))
	if !hasCode(ds, CodeUnenforced) || !rt.Contract.Setuid {
		t.Errorf("setuid: true at tier cgroup: codes %v, setuid %v", codes(ds), rt.Contract.Setuid)
	}
}

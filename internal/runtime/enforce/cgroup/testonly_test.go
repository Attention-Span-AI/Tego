// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Helpers only the tests call. They live here, not in the package's own files, so the production binary carries
// nothing it never runs.

// marked returns the mounts this listener watches, sorted.
func (f *fanotifyListener) marked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.marks))
	for m := range f.marks {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// mark adds a mount-scoped mark for every permission event this listener answers. It is markFor with the
// whole of fanPermMask, which is what a caller that has no policy's per-mount masks asks for.
func (f *fanotifyListener) mark(mountRoot string) error { return f.markFor(mountRoot, fanPermMask) }

// stats reports what the listener counted. Only the tests read it: the ledger learns of each timeout from its
// GapFanotifyTimeout gap and of each refusal from its own event, not from these totals.
func (f *fanotifyListener) stats() (answered, refused, timeouts, dropped int64) {
	return f.answered.Load(), f.refused.Load(), f.timeouts.Load(), f.dropped.Load()
}

// pinState is the state directory of an in-process test whose build is pinned under the host's bpf filesystem
// (DefaultBPFFS): the host's own, hoststate.Path, verified and made as a root launcher makes it. A build's lock lives
// in the state directory, and for a build under DefaultBPFFS the one in hoststate.Path is the lock every tego
// process on the machine takes: a launcher's Prepare and its last-out removal, a reaper's build duties, the build's
// linger timer, gc's sweep. A test with a state directory of its own held a lock no other process saw while it
// shared their pins: on 2026-10-16 the linger timer an earlier end-to-end test's run had left (bpf.linger 5m) swept
// the build, idle by the only lock it read, while TestNetworkReservationRowsAreBoundedOnRealKernel's Prepare was
// pinning it, and the pin failed ENOENT. openState now refuses that pairing (TestHostPinsLockOnlyInTheHostStateDir).
// A test whose pins lie under another root (a temporary directory, a bpffs mount of its own) keeps a directory of
// its own.
func pinState(t testing.TB) string {
	t.Helper()
	d, err := hoststate.Open()
	if err != nil {
		t.Fatalf("the host state directory %s: %v", hoststate.Path, err)
	}
	_ = d.Close()
	return hoststate.Path
}

// acquireBuildLock takes the shared lock for a build hash. It never blocks forever: LOCK_SH contends with
// nothing but the brief exclusive attempt of a departing launcher, so a failure is ErrBuildLock and the
// caller retries the whole run (§4).
func acquireBuildLock(dir, hash string) (*buildLock, error) {
	d, err := hoststate.OpenAt(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuildLock, err)
	}
	defer func() { _ = d.Close() }()
	return acquireBuildLockIn(d, hash)
}

// openSlotTable prepares the table for one build hash under dir, creating the directory when it does not
// exist. The test owns its directory descriptor; explicit earlier close is also safe.
func openSlotTable(t testing.TB, dir, hash string) (*slotTable, error) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cgroup: create runtime directory %s: %w", dir, err)
	}
	d, err := hoststate.OpenAt(dir)
	if err != nil {
		return nil, err
	}
	s, err := openSlotTableIn(d, hash)
	if err != nil {
		return nil, err // openSlotTableIn owns d, including failure cleanup.
	}
	t.Cleanup(func() {
		if err := s.close(); err != nil {
			t.Errorf("close slot table: %v", err)
		}
	})
	return s, nil
}

// Reason exposes the live translation only to this package's tests.
func Reason(c bpf.ReasonCode) record.Reason { return kernelReason(c) }

// ReasonCode maps a ledger reason to the byte a map row or breadcrumb carries. A reason this tier cannot
// produce in-kernel — the ask and limit codes, which no kernel program decides — maps to ReasonNone, so a
// caller can never smuggle one into a map value.
func ReasonCode(r record.Reason) bpf.ReasonCode {
	return reasonToCode[r]
}

// distinctMountsBy reduces a list of ruled paths to one path per mount, with the mount lookup passed in, so a
// test can put two paths of one filesystem on two mounts without mount(2), which needs CAP_SYS_ADMIN.
func distinctMountsBy(paths []string, mountOfPath func(string) (mountKey, error)) []string {
	var out []string
	for _, g := range groupByMount(paths, mountOfPath) {
		out = append(out, g.path)
	}
	sort.Strings(out)
	return out
}

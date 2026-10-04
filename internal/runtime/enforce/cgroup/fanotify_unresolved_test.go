// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// openDeep creates a file whose canonical path is longer than PATH_MAX beneath dir, walking down by directory
// descriptors as an agent's openat would, and returns a descriptor on it that the caller owns. Its path cannot be
// read back through /proc/self/fd (ENAMETOOLONG), which is the listener's unresolved case.
func openDeep(t *testing.T, dir string) int {
	t.Helper()
	cur, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.Repeat("d", 200)
	for range 25 {
		if err := unix.Mkdirat(cur, name, 0o700); err != nil {
			t.Fatalf("mkdirat: %v", err)
		}
		next, err := unix.Openat(cur, name, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
		_ = unix.Close(cur)
		if err != nil {
			t.Fatalf("openat: %v", err)
		}
		cur = next
	}
	fd, err := unix.Openat(cur, "secret", unix.O_CREAT|unix.O_RDONLY|unix.O_CLOEXEC, 0o600)
	_ = unix.Close(cur)
	if err != nil {
		t.Fatalf("create the deep file: %v", err)
	}
	if _, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); !errors.Is(err, unix.ENAMETOOLONG) {
		_ = unix.Close(fd)
		t.Fatalf("readlink of a path over PATH_MAX = %v, want ENAMETOOLONG", err)
	}
	return fd
}

// TestDecideEventRefusesAnUnresolvedPathForTheRun is SEMANTICS §2's "a path that cannot be resolved is refused"
// at the listener (enforce-cgroup-observe.md §5 R8): a file beneath a deny_read entry whose canonical path is
// longer than PATH_MAX cannot be read back through its descriptor, and the run's own open of it was allowed with
// only a fanotify-path-unresolved gap. It is refused path-unresolved for the run's opener and one whose
// membership went unread, and allowed for an opener outside the run and where no entry could refuse the event.
func TestDecideEventRefusesAnUnresolvedPathForTheRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	deny := policyTable([]agent.FSRule{fsRule(agent.FSDenyRead, dir, "", "secrets/")}, nil)
	s := &sink{}
	l, pipe := testListener(t, s, nil, time.Second)
	l.run.CgroupPath = "/run.scope"
	l.policy = newPolicy(deny, "/run.scope")
	l.decide = l.decideEvent
	cgroup := "/run.scope/agent"
	l.cgroupOfPID = func(int) (string, error) { return cgroup, nil }

	fd := openDeep(t, dir)
	l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: int32(fd), PID: 4242})
	if _, resp := readResponse(t, pipe); resp != unix.FAN_DENY {
		t.Fatalf("response %#x, want FAN_DENY: the run read a deny_read file whose path is over PATH_MAX", resp)
	}
	var refusal *record.Event
	for _, e := range s.all() {
		if e.Kind == record.KindFS && e.Verdict == record.VerdictRefused {
			refusal = e
		}
	}
	if refusal == nil || refusal.Reason != record.ReasonPathUnresolved || refusal.Rule != agent.UnmatchedRule ||
		!hasGap(s.all(), GapFanotifyUnresolved) {
		t.Fatalf("events = %+v, want a path-unresolved refusal of the unmatched rule and a %s gap", s.all(),
			GapFanotifyUnresolved)
	}

	decideDeep := func(mask uint64) (verdict, error) {
		fd := openDeep(t, t.TempDir())
		t.Cleanup(func() { _ = unix.Close(fd) })
		return l.decideEvent(fanEvent{Mask: mask, FD: int32(fd), PID: 4242})
	}
	// The deny_read entry is dir alone; a deep file elsewhere is as unreadable, and is refused all the same.
	if v, err := decideDeep(unix.FAN_OPEN_PERM); v.allow || !errors.Is(err, errPathUnresolved) {
		t.Fatalf("decideEvent for the run's open = %+v, %v; want a refusal and errPathUnresolved", v, err)
	}

	cgroup = "/host.slice/ssh"
	if v, err := decideDeep(unix.FAN_OPEN_PERM); !v.allow || err != nil {
		t.Fatalf("decideEvent for an opener outside the run = %+v, %v; want an allow", v, err)
	}

	l.cgroupOfPID = func(int) (string, error) { return "", fmt.Errorf("read: %w", unix.EMFILE) }
	if v, err := decideDeep(unix.FAN_OPEN_PERM); v.allow || !errors.Is(err, errMembershipUnread) {
		t.Fatalf("decideEvent with membership unread = %+v, %v; want the refusal kept", v, err)
	}

	// An exec is refused under an exec list, which refuses by default, whatever the fs entries.
	l.cgroupOfPID = func(int) (string, error) { return "/run.scope", nil }
	l.policy = newPolicy(policyTable(nil, []agent.ExecRule{{Path: "/usr/bin/true", Raw: "true", Verdict: agent.VerdictAllow}}), "/run.scope")
	if v, err := decideDeep(unix.FAN_OPEN_EXEC_PERM); v.allow || v.reason != record.ReasonPathUnresolved {
		t.Fatalf("decideEvent for the run's exec = %+v, %v; want a path-unresolved refusal", v, err)
	}
	// No deny_read entry: no open could have been refused, so the unresolved open is allowed (with the gap).
	if v, err := decideDeep(unix.FAN_OPEN_PERM); !v.allow || !errors.Is(err, errPathUnresolved) {
		t.Fatalf("decideEvent for an open no entry could refuse = %+v, %v; want an allow and the error", v, err)
	}
}

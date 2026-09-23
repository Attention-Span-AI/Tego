// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// TestIsUnsupportedNamesOnlyTheAttachTypeGap pins §5 R7: the unix programs fall back to the inherited tier-1
// path only when the kernel genuinely lacks their attach types (below 6.7); attachCgroup's own call site uses
// this predicate to decide whether to swallow one program's attach failure and continue, or fail the whole of
// Prepare. Nothing else in this package tests it directly — every attachCgroup test goes through the fake
// kernel, which never calls the real predicate at all — so a change here that starts (or stops) swallowing the
// wrong errno would reach production silently: either a genuinely broken attach on a new-enough kernel gets
// misreported as "just missing unix support" (masking a real failure a launcher should have seen), or a kernel
// that really lacks the attach type fails Prepare outright instead of falling back per R7.
func TestIsUnsupportedNamesOnlyTheAttachTypeGap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"link package's own not-supported sentinel", link.ErrNotSupported, true},
		{"EINVAL: an older kernel rejects the attach type outright", unix.EINVAL, true},
		{"EOPNOTSUPP: the attach type is not implemented here", unix.EOPNOTSUPP, true},
		{"a wrapped EINVAL still matches, the way link.AttachCgroup's own error arrives", fmt.Errorf("attach cgroup: %w", unix.EINVAL), true},
		{"EPERM is a real permission failure, never a version gap", unix.EPERM, false},
		{"ENOENT (a vanished cgroup) must not be read as a version gap", unix.ENOENT, false},
		{"an unrelated error must not be swallowed", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUnsupported(tc.err); got != tc.want {
				t.Fatalf("isUnsupported(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestUnixProgramsAreDroppedBelowTheirKernel pins §5 R7 at the step where it can actually fail. The kernel
// validates a CGROUP_SOCK_ADDR program's expected attach type when the program is loaded
// (bpf_prog_load_check_attach), and answers EINVAL to the unix sockaddr attach types below 6.7. cgroup_net was
// loaded whole, so on every kernel from the 6.1 floor to 6.6 the object failed with connect_unix and tier 2 had
// no network programs at all; attachCgroup's fallback sat behind that load and was never reached. Both unix
// programs now leave the spec before the load when the kernel says it cannot have them, and only then:
// sendmsg_unix left behind would fail the object exactly as connect_unix did.
func TestUnixProgramsAreDroppedBelowTheirKernel(t *testing.T) {
	t.Parallel()
	newSpec := func() *ebpf.CollectionSpec {
		spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}}
		for _, name := range ebpfbindings.CgroupPrograms {
			spec.Programs[name] = &ebpf.ProgramSpec{Name: name}
		}
		return spec
	}

	below := newSpec()
	if err := dropUnixWhereUnsupported(below, func() (bool, error) { return false, nil }); err != nil {
		t.Fatalf("a kernel without the attach types: %v", err)
	}
	for _, name := range ebpfbindings.UnixPrograms {
		if _, ok := below.Programs[name]; ok {
			t.Fatalf("%s is still in the spec on a kernel below 6.7; loading it fails the whole object", name)
		}
	}
	if want := len(ebpfbindings.CgroupPrograms) - len(ebpfbindings.UnixPrograms); len(below.Programs) != want || want != 6 {
		t.Fatalf("%d programs left, want the other six", len(below.Programs))
	}

	at := newSpec()
	if err := dropUnixWhereUnsupported(at, func() (bool, error) { return true, nil }); err != nil {
		t.Fatalf("a kernel with the attach types: %v", err)
	}
	if len(at.Programs) != len(ebpfbindings.CgroupPrograms) {
		t.Fatalf("%d programs, want all %d on a kernel that has the attach types", len(at.Programs),
			len(ebpfbindings.CgroupPrograms))
	}

	// A probe that failed for another reason is not a version gap and must not be read as one.
	if err := dropUnixWhereUnsupported(newSpec(), func() (bool, error) { return false, unix.EPERM }); !errors.Is(err, ErrProgramLoad) {
		t.Fatalf("a failed probe = %v, want ErrProgramLoad", err)
	}
}

// TestOptionalTraceProgramsAreDroppedWhereTheKernelLacksThem covers ADR 0016 (3)'s security_file_truncate (6.2+),
// and io_bind and io_listen (6.11+, enforce-plane §2.20): the loader resolves an fexit program's target at load, so
// below those kernels the object would not load whole with them. It
// leaves the spec there, and only there, and the links the adopt check expects follow the spec, so an object
// loaded without it is still adopted by the next launcher.
func TestOptionalTraceProgramsAreDroppedWhereTheKernelLacksThem(t *testing.T) {
	t.Parallel()
	newSpec := func() *ebpf.CollectionSpec {
		spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}}
		for _, name := range ebpfbindings.TracePrograms {
			spec.Programs[name] = &ebpf.ProgramSpec{Name: name}
		}
		return spec
	}
	below := newSpec()
	var asked []string
	dropTraceWhereAbsent(below, func(fn string) bool { asked = append(asked, fn); return false })
	slices.Sort(asked)
	if !slices.Equal(asked, []string{"io_bind", "io_listen", "security_file_truncate"}) {
		t.Fatalf("asked the kernel about %v, want security_file_truncate, io_bind and io_listen", asked)
	}
	for name := range ebpfbindings.OptionalTracePrograms {
		if _, ok := below.Programs[name]; ok {
			t.Fatalf("%s is still in the spec on a kernel without %s", name, ebpfbindings.OptionalTracePrograms[name])
		}
	}
	if len(below.Programs) != len(ebpfbindings.TracePrograms)-len(ebpfbindings.OptionalTracePrograms) {
		t.Fatalf("%d programs left, want every other one", len(below.Programs))
	}
	links := sharedLinksOf(ebpfbindings.ObjectTraceProc, below)
	for _, l := range links {
		if l == ebpfbindings.ProgFileTruncate {
			t.Fatal("the adopt check expects a link for a program the load left out")
		}
	}
	if len(links) != len(ebpfbindings.TracePrograms)-len(ebpfbindings.OptionalTracePrograms)-len(ebpfbindings.ExecResultTracepoints) {
		t.Fatalf("%d links, want one per mandatory loaded program", len(links))
	}

	at := newSpec()
	dropTraceWhereAbsent(at, func(string) bool { return true })
	if len(at.Programs) != len(ebpfbindings.TracePrograms) {
		t.Fatalf("%d programs, want all %d on a kernel that has every function", len(at.Programs),
			len(ebpfbindings.TracePrograms))
	}
}

// TestAttachErrorNamesTheHierarchyConflict covers enforce-cgroup-observe.md §6 E36: the one cgroup-attach failure whose errno says
// nothing about its cause. kernel/bpf/cgroup.c's __cgroup_bpf_attach refuses with -EPERM when
// hierarchy_allows_attach() finds an ancestor cgroup already holding a program for the same attach type that
// was attached the legacy way with no flags — `bpftool cgroup attach /sys/fs/cgroup connect4 ...` is exactly
// that, bpftool passing no flags by default — and a bpf_link, being internally ALLOW_MULTI, is subject to the
// check like any other attachment. Wrapped as the generic load bucket it reached the operator as "bpf program
// load failed: ... operation not permitted", with no cause and nothing to act on, and §5 R1 covers only the
// other direction (that Tego's links cannot displace anyone else's).
func TestAttachErrorNamesTheHierarchyConflict(t *testing.T) {
	t.Parallel()
	const name, path = "tego_cg_connect4", "/sys/fs/cgroup/tego.slice/run-1.scope"

	// link.AttachCgroup wraps the raw errno, so the check has to be errors.Is, not equality.
	err := attachError(name, path, fmt.Errorf("attach cgroup: %w", unix.EPERM))
	if !errors.Is(err, ErrCgroupAttachConflict) {
		t.Fatalf("EPERM from a cgroup attach = %v, want ErrCgroupAttachConflict", err)
	}
	if errors.Is(err, ErrProgramLoad) {
		t.Fatalf("a host-side attach conflict must not arrive in the opaque verifier-rejection bucket: %v", err)
	}
	for _, want := range []string{name, path, "bpftool cgroup tree", "BPF_F_ALLOW_MULTI", "cap_bpf"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the message does not name %q, which the operator needs to act on it: %v", want, err)
		}
	}
	// doctor's D7 rows say the same words: one helper, so the two cannot drift.
	if !strings.Contains(err.Error(), AttachConflictHint(path)) {
		t.Fatalf("the message is not AttachConflictHint's: %v", err)
	}

	// Every other errno keeps its existing meaning: EINVAL on connect_unix is R7's version gap, and the
	// rest are genuine load failures.
	other := attachError(name, path, unix.EINVAL)
	if errors.Is(other, ErrCgroupAttachConflict) {
		t.Fatalf("EINVAL is a version or argument problem, never a hierarchy conflict: %v", other)
	}
	if !errors.Is(other, ErrProgramLoad) {
		t.Fatalf("a non-EPERM attach failure = %v, want ErrProgramLoad", other)
	}
}

// orderedLink is a shared link that records, when its descriptor is closed, whether its pin still existed.
type orderedLink struct {
	link.Link
	pin           string
	closed        bool
	pinWhenClosed bool
}

func (l *orderedLink) Close() error {
	_, err := os.Stat(l.pin)
	l.closed, l.pinWhenClosed = true, err == nil
	return nil
}

// Unpin removes the pin through the handle, which is what cilium/ebpf's link does.
func (l *orderedLink) Unpin() error { return os.Remove(l.pin) }

// TestUnpinRemovesEachSharedLinksPinBeforeClosingIt: the last launcher out of a build that does not linger removes
// a shared link's pin while its own descriptor still holds the link, and only then closes the descriptor, so its
// close(2) drops the last reference and the kernel detaches the link in this process before unpin returns
// (perf-cold C3). Closing first (the order of §9's 2026-09 change (4), amended 2026-10-19) left the last reference to
// the pin's removal, which 6.8 and later hand to a worker: the launcher left sooner, and the next run's load waited
// in bpf_trampoline_get for the detach it had left behind (enforce-plane §10.1, gate G-H2).
func TestUnpinRemovesEachSharedLinksPinBeforeClosingIt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pins, err := newPinLayout(dir, "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := pins.create(); err != nil {
		t.Fatal(err)
	}
	k := &bpfKernel{pins: pins, maps: map[string]*ebpf.Map{}, progs: map[string]*ebpf.Program{}}
	var links []*orderedLink
	for _, name := range []string{ebpfbindings.ProgFileOpen, ebpfbindings.ProgPathUnlink} {
		pin := filepath.Join(pins.Links, name)
		if err := os.WriteFile(pin, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		l := &orderedLink{pin: pin}
		links = append(links, l)
		k.shared = append(k.shared, sharedLink{Link: l, pin: pin})
	}
	if err := k.unpin(); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	for _, l := range links {
		if !l.closed || l.pinWhenClosed {
			t.Errorf("%s: closed %v with its pin present %v, want the descriptor closed once the pin was gone",
				filepath.Base(l.pin), l.closed, l.pinWhenClosed)
		}
		if _, err := os.Stat(l.pin); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: pin left after unpin (%v)", filepath.Base(l.pin), err)
		}
	}
	if len(k.shared) != 0 {
		t.Errorf("%d shared links still held after unpin; close would close them a second time", len(k.shared))
	}
	if _, err := os.Stat(pins.Root); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the build's pin directory is left after unpin (%v)", err)
	}
}

// stuckPlane makes build pins' plane directory in LSM mode one this (unprivileged) process cannot remove, as a
// removal that fails part way leaves it; the test's cleanup makes it removable again.
func stuckPlane(t *testing.T, pins pinLayout) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root removes a directory it cannot write to")
	}
	lay := newPlaneLayout(pins, filepath.Base(pins.Root), ebpfbindings.PlaneLSM)
	if err := lay.create(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lay.Links, "stand-in"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lay.Links, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lay.Links, 0o700) })
}

// TestPinsRemoveKeepsTheBuildUnderAPlaneItCannotRemove is enforce-plane R20: a plane directory the removal cannot
// take keeps the build's maps pinned. Unpinned under it, the next launcher re-creates the run set, and the pinned
// plane, adopted by its links, reads the dead one: it finds no run and allows everything.
func TestPinsRemoveKeepsTheBuildUnderAPlaneItCannotRemove(t *testing.T) {
	t.Parallel()
	pins, err := newPinLayout(t.TempDir(), "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := pins.create(); err != nil {
		t.Fatal(err)
	}
	runSet := filepath.Join(pins.Maps, ebpfbindings.MapRunSet)
	if err := os.WriteFile(runSet, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stuckPlane(t, pins)
	if err := pins.remove(); err == nil {
		t.Fatal("remove: nil error with a plane directory left")
	}
	if _, err := os.Stat(runSet); err != nil {
		t.Errorf("the build's run set was unpinned under a plane that could not be removed: %v", err)
	}
}

// TestUnpinKeepsTheBuildUnderAPlaneItCannotRemove is the same for the last launcher out, which unpins its own
// shared links and maps before pins.remove: they stay pinned when the plane cannot be removed.
func TestUnpinKeepsTheBuildUnderAPlaneItCannotRemove(t *testing.T) {
	t.Parallel()
	pins, err := newPinLayout(t.TempDir(), "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := pins.create(); err != nil {
		t.Fatal(err)
	}
	stuckPlane(t, pins)
	k := &bpfKernel{pins: pins, maps: map[string]*ebpf.Map{}, progs: map[string]*ebpf.Program{}}
	pin := filepath.Join(pins.Links, ebpfbindings.ProgFileOpen)
	if err := os.WriteFile(pin, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	l := &orderedLink{pin: pin}
	k.shared = append(k.shared, sharedLink{Link: l, pin: pin})
	if err := k.unpin(); err == nil {
		t.Fatal("unpin: nil error with a plane directory left")
	}
	if _, err := os.Stat(pin); err != nil {
		t.Errorf("a shared link was unpinned under a plane that could not be removed: %v", err)
	}
}

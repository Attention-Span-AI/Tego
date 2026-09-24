// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestDistinctMountsKeysByMountNotDevice is §5 R8's mark per mount: two bind mounts of one filesystem share
// st_dev but are two mounts, and FAN_MARK_MOUNT marks one mount, so each needs its own mark. The paths here are
// real files on one device; the lookup puts them on two mounts, which is what a bind mount does, without
// mount(2). Collapsing by device kept only the first, and a deny_read entry under the second mount was never
// decided. The lookup is injected, so this pins the collapse given a key, not which key distinctMountsBy takes:
// that is pinned by TestDistinctMountsSeparatesThisHostsMountsOfOneDevice where the host has two such mounts,
// and always by the root TestFanotifyMarksEveryBindMount.
func TestDistinctMountsKeysByMountNotDevice(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	for _, p := range []string{first, second} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var a, b unix.Stat_t
	if err := unix.Stat(first, &a); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(second, &b); err != nil {
		t.Fatal(err)
	}
	if a.Dev != b.Dev {
		t.Fatalf("the two paths must share a device for this test to mean anything: %d, %d", a.Dev, b.Dev)
	}
	bound := map[string]mountKey{first: {unique: true, id: 7}, second: {unique: true, id: 8}}
	lookup := func(p string) (mountKey, error) { return bound[p], nil }

	got := distinctMountsBy([]string{first, second}, lookup)
	if want := []string{first, second}; !slices.Equal(got, want) {
		t.Fatalf("marks = %v, want %v: one path per mount, whatever device the mounts share", got, want)
	}
	// One mount named by several paths is still one mark.
	bound[second] = bound[first]
	if got := distinctMountsBy([]string{first, second, first}, lookup); len(got) != 1 {
		t.Fatalf("marks = %v: two paths on one mount must collapse to one mark", got)
	}
}

// TestDistinctMountsKeepsUnknownByName asserts a path whose mount cannot be read is marked by its own name
// rather than dropped: the fail-closed side, since marking one mount twice is idempotent and leaving one
// unmarked is a refusal never made.
func TestDistinctMountsKeepsUnknownByName(t *testing.T) {
	t.Parallel()
	lookup := func(p string) (mountKey, error) {
		if p == "/known" {
			return mountKey{id: 1}, nil
		}
		return mountKey{}, errNoMountID
	}
	got := distinctMountsBy([]string{"/known", "/later", "/later", "", "/other"}, lookup)
	if want := []string{"/known", "/later", "/other"}; !slices.Equal(got, want) {
		t.Fatalf("marks = %v, want %v", got, want)
	}
}

// TestGroupByMountAsksOncePerPath: every deny_read entry names its mount through the same path (FSRule.Mount),
// and the built-in .env scan can write 50,000 of them, so a path already looked up is not handed to statx again.
// The groups are the ones asking each time would give.
func TestGroupByMountAsksOncePerPath(t *testing.T) {
	t.Parallel()
	asked := map[string]int{}
	lookup := func(p string) (mountKey, error) {
		asked[p]++
		switch p {
		case "/home", "/home/u/bin/tool":
			return mountKey{unique: true, id: 2}, nil
		case "/usr/bin/python3":
			return mountKey{unique: true, id: 1}, nil
		}
		return mountKey{}, errNoMountID
	}
	paths := []string{"/home/u/bin/tool", "/usr/bin/python3", "/later"}
	for range 5000 {
		paths = append(paths, "/home", "/later")
	}
	groups := groupByMount(paths, lookup)
	for p, n := range asked {
		if n != 1 {
			t.Errorf("statx asked about %s %d times, want once", p, n)
		}
	}
	if len(groups) != 3 || groups[0].path != "/home/u/bin/tool" || groups[1].path != "/usr/bin/python3" ||
		groups[2].path != "/later" {
		t.Fatalf("groups %+v, want /home/u/bin/tool (with /home), /usr/bin/python3 and /later", groups)
	}
	if n := len(groups[0].members); n != 5001 {
		t.Errorf("the /home mount holds %d of the paths, want 5001", n)
	}
	if n := len(groups[2].members); n != 5001 {
		t.Errorf("/later, which statx cannot name, holds %d of the paths, want 5001", n)
	}
}

// TestMountKeyOfNamesOneMount asserts the real lookup answers on this kernel and gives two files in one
// directory the same mount, and a path that does not exist an error (which distinctMountsBy keeps by name). A
// device number would pass this too; the tests that tell a mount from a device are named on
// TestDistinctMountsKeysByMountNotDevice.
func TestMountKeyOfNamesOneMount(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	one, two := filepath.Join(dir, "one"), filepath.Join(dir, "two")
	for _, p := range []string{one, two} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	k1, err := mountKeyOf(one)
	if err != nil {
		t.Fatalf("mountKeyOf(%s): %v", one, err)
	}
	k2, err := mountKeyOf(two)
	if err != nil {
		t.Fatalf("mountKeyOf(%s): %v", two, err)
	}
	if k1 != k2 || k1.id == 0 {
		t.Fatalf("keys %+v and %+v: two files of one directory must name one mount", k1, k2)
	}
	if _, err := mountKeyOf(filepath.Join(dir, "missing")); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("a missing path: %v, want ENOENT", err)
	}
}

// TestDistinctMountsSeparatesThisHostsMountsOfOneDevice is §5 R8's key, unprivileged: it looks in
// /proc/self/mountinfo for two mounts this process can reach that share an st_dev (a bind mount, as /run and
// /run/snapd/ns are on an Ubuntu host with snapd), and asserts distinctMountsBy, with the real lookup, keeps a
// path for each. A dedup keyed on the device would keep one. A mount point is used only when statx names that
// very mount for it, so one hidden under a later mount at the same place is not taken for it. A host with no
// such pair skips; TestFanotifyMarksEveryBindMount makes the pair itself, as root.
func TestDistinctMountsSeparatesThisHostsMountsOfOneDevice(t *testing.T) {
	t.Parallel()
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Skipf("no mountinfo: %v", err)
	}
	defer f.Close()
	byDev := map[uint64][]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// mountinfo escapes blanks and backslashes in a mount point as octal; such a point is skipped rather
		// than decoded, since any one pair is enough.
		if len(fields) < 5 || strings.Contains(fields[4], `\`) {
			continue
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		point := fields[4]
		var stx unix.Statx_t
		if unix.Statx(unix.AT_FDCWD, point, 0, unix.STATX_MNT_ID, &stx) != nil ||
			stx.Mask&unix.STATX_MNT_ID == 0 || stx.Mnt_id != id {
			continue
		}
		var st unix.Stat_t
		if unix.Stat(point, &st) != nil {
			continue
		}
		byDev[st.Dev] = append(byDev[st.Dev], point)
	}
	if err := sc.Err(); err != nil {
		t.Skipf("read mountinfo: %v", err)
	}
	var pair []string
	for _, points := range byDev {
		if len(points) >= 2 {
			pair = points[:2]
			break
		}
	}
	if pair == nil {
		t.Skip("this host shows no two reachable mounts of one device")
	}
	got := distinctMountsBy(pair, mountKeyOf)
	slices.Sort(pair)
	if !slices.Equal(got, pair) {
		t.Fatalf("marks = %v for two mounts of one device %v: each mount needs its own mark", got, pair)
	}
}

// TestMarkMasksAskOnlyForWhatCanBeRefused is §5 R8's mask per mount: a mark asks for FAN_OPEN_PERM only where
// a deny_read entry can refuse an open, and for FAN_OPEN_EXEC_PERM only while the exec check can refuse an
// exec. Every mark used to ask for both, so on a mount marked for an exec entry alone every open of every
// process was held for a decision that could only be an allow: the guest's root filesystem, where python3 lives,
// under kill test 4's contract, at 35–45 µs an open. The lookup is injected, so the paths need not exist.
func TestMarkMasksAskOnlyForWhatCanBeRefused(t *testing.T) {
	t.Parallel()
	mounts := map[string]mountKey{
		"/":                   {unique: true, id: 1},
		"/usr/bin/python3":    {unique: true, id: 1},
		"/home":               {unique: true, id: 2},
		"/home/u/bin/tool":    {unique: true, id: 2},
		"/opt/tools/bin/x":    {unique: true, id: 3},
		"/srv/data/bin/other": {unique: true, id: 4},
	}
	lookup := func(p string) (mountKey, error) {
		if k, ok := mounts[p]; ok {
			return k, nil
		}
		return mountKey{}, errNoMountID
	}
	deny := func(paths ...string) pathSet {
		var out []fsEntry
		for _, p := range paths {
			out = append(out, fsEntry{path: p, dir: true, rule: "fs.deny_read[" + p + "]"})
		}
		return newPathSet(out)
	}
	const open, exec = uint64(unix.FAN_OPEN_PERM), uint64(unix.FAN_OPEN_EXEC_PERM)
	for _, tc := range []struct {
		name  string
		paths []markPath
		deny  pathSet
		execs bool
		want  map[string]uint64
	}{
		{
			name:  "exec entries alone: no open event anywhere",
			paths: []markPath{{path: "/usr/bin/python3"}, {path: "/home/u/bin/tool"}},
			execs: true,
			want:  map[string]uint64{"/usr/bin/python3": exec, "/home/u/bin/tool": exec},
		},
		{
			name:  "a deny_read mount asks for opens, an exec-only mount does not",
			paths: []markPath{{path: "/home", open: true}, {path: "/usr/bin/python3"}},
			deny:  deny("/home/u/.ssh"),
			execs: true,
			want:  map[string]uint64{"/home": open | exec, "/usr/bin/python3": exec},
		},
		{
			name:  "one mount holding both asks for both",
			paths: []markPath{{path: "/", open: true}, {path: "/usr/bin/python3"}},
			deny:  deny("/root/.ssh"),
			execs: true,
			want:  map[string]uint64{"/": open | exec},
		},
		{
			name: "an exec path a deny_read entry covers keeps its mount's opens",
			// /opt/tools is a mount of its own under a denied /opt: an open there falls under the entry,
			// and it was refused while every mark asked for both events, so it still is.
			paths: []markPath{{path: "/", open: true}, {path: "/opt/tools/bin/x"}, {path: "/srv/data/bin/other"}},
			deny:  deny("/opt"),
			execs: true,
			want:  map[string]uint64{"/": open | exec, "/opt/tools/bin/x": open | exec, "/srv/data/bin/other": exec},
		},
		{
			name:  "no exec: section asks for no exec event",
			paths: []markPath{{path: "/home", open: true}},
			deny:  deny("/home/u/.ssh"),
			execs: false,
			want:  map[string]uint64{"/home": open},
		},
		{
			name:  "a path statx cannot name keeps its own mark and its rule's events",
			paths: []markPath{{path: "/later", open: true}, {path: "/usr/bin/python3"}},
			deny:  deny("/later"),
			execs: true,
			want:  map[string]uint64{"/later": open | exec, "/usr/bin/python3": exec},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotMounts, got := markMasks(tc.paths, tc.deny, tc.execs, lookup)
			if len(gotMounts) != len(tc.want) {
				t.Fatalf("mounts = %v, want the %d of %v", gotMounts, len(tc.want), tc.want)
			}
			for _, m := range gotMounts {
				if got[m] != tc.want[m] {
					t.Errorf("mask of %s = %#x, want %#x", m, got[m], tc.want[m])
				}
			}
		})
	}
}

// TestPrepareMarksEachMountForTheEventsItCanRefuse is the other half of the test above: Prepare's step 7 places
// each mark with the policy's own mask for that mount, not with every permission event. The fixture's table
// has a deny_read entry and no exec: section, so its one mark may ask for opens and never for execs.
func TestPrepareMarksEachMountForTheEventsItCanRefuse(t *testing.T) {
	t.Parallel()
	placed := map[string]uint64{}
	f := newFixture(t, func(o *Options) {
		next := o.newListener
		o.newListener = func(h *Handle) (*fanotifyListener, error) {
			l, err := next(h)
			if err != nil {
				return nil, err
			}
			l.markMount = func(m string, mask uint64) error { placed[m] = mask; return nil }
			return l, nil
		}
	})
	table := *f.table
	table.Contract = &agent.Contract{}
	h, err := f.backend.Prepare(context.Background(), &table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if len(placed) != 0 {
		t.Fatalf("Prepare placed marks %v: they are Arm's, after the stage's exec (ADR 0021 (2))", placed)
	}
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	// The mounts the table's deny_read entries are on, and those mounted beneath them: the fixture's own entry and,
	// where it exists, tego's host state (/run/tego, a built-in deny_read: as root in the KVM guest and on CI's
	// root job, not for a user on a dev box). One mark each, and no other; counting the fixture's entry alone
	// failed as root (amended 2026-10-05, v73 review R4).
	want := map[mountKey]string{}
	under := mountPointsUnderFrom(readMountinfo)
	for i := range table.FS {
		r := &table.FS[i]
		if r.Kind != agent.FSDenyRead {
			continue
		}
		var paths []string
		for _, p := range r.Spellings() {
			if r.Mount != "" {
				paths = append(paths, r.Mount)
			} else {
				paths = append(paths, p)
			}
			mps, err := under(p)
			if err != nil {
				t.Fatalf("mount points beneath %s: %v", p, err)
			}
			paths = append(paths, mps...)
		}
		for _, p := range paths {
			key, err := mountKeyOf(p)
			if err != nil {
				t.Fatalf("mount of deny_read %s: %v", p, err)
			}
			want[key] = p
		}
	}
	got := map[mountKey]string{}
	for m := range placed {
		key, err := mountKeyOf(m)
		if err != nil {
			t.Fatalf("mount of mark %s: %v", m, err)
		}
		got[key] = m
	}
	secret, err := mountKeyOf(filepath.Join(f.dir, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, secretMarked := got[secret]; len(placed) != len(want) || len(got) != len(want) || !secretMarked {
		t.Fatalf("marks %v, want one on each mount of the table's deny_read entries %v, the fixture's secret among them",
			placed, want)
	}
	for key, p := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("no mark on the mount of deny_read %s", p)
		}
	}
	for m, mask := range placed {
		if mask != unix.FAN_OPEN_PERM {
			t.Errorf("mark on %s asks for %#x, want FAN_OPEN_PERM (%#x) alone: nothing refuses an exec under a "+
				"contract with no exec: section", m, mask, unix.FAN_OPEN_PERM)
		}
	}
}

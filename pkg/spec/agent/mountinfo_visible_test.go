// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A mount beneath a covered parent can remain in mountinfo without being reached
// by its printed path. Same-point stacks and a chroot's omitted parents differ.
func TestMountVisibility(t *testing.T) {
	const root = "1 0 8:1 / / rw - ext4 disk rw\n"
	for _, tc := range []struct {
		name, rows, path, wantPoint, wantType string
		visible                               []string
		unknown                               bool
	}{
		{
			name: "same-point stacks retain their top",
			rows: root + "2 1 8:2 / /vol rw - ext4 disk rw\n" +
				"3 2 0:3 / /vol rw - tmpfs none rw\n" +
				"4 3 0:4 / /vol rw - overlay none rw,lowerdir=/missing\n",
			path: "/vol/sub", wantPoint: "/vol", wantType: "overlay",
			visible: []string{"1", "4"},
		},
		{
			name: "child of a hidden parent stays hidden",
			rows: root + "2 1 8:2 / /vol rw - ext4 disk rw\n" +
				"3 2 8:3 / /vol/sub rw - ext4 disk rw\n" +
				"4 2 0:4 / /vol rw - tmpfs none rw\n" +
				"5 4 8:5 / /vol/live rw - ext4 disk rw\n",
			path: "/vol/sub/file", wantPoint: "/vol", wantType: "tmpfs",
			visible: []string{"1", "4", "5"},
		},
		{
			name: "a new ancestor hides an older child of root",
			rows: root + "2 1 8:2 / /vol/sub rw - ext4 disk rw\n" +
				"3 1 0:3 / /vol rw - tmpfs none rw\n",
			path: "/vol/sub/file", wantPoint: "/vol", wantType: "tmpfs",
			visible: []string{"1", "3"},
		},
		{
			name: "stale child does not hide a reachable child at the same point",
			rows: root + "2 1 8:2 / /vol rw - ext4 disk rw\n" +
				"4 2 0:4 / /vol rw - tmpfs none rw\n" +
				"5 4 8:5 / /vol/sub rw - ext4 disk rw\n" +
				"3 2 8:3 / /vol/sub rw - ext4 disk rw\n",
			path: "/vol/sub/file", wantPoint: "/vol/sub", wantType: "ext4",
			visible: []string{"1", "4", "5"},
		},
		{
			name: "a partial chroot omits its parent",
			rows: "10 9 8:10 /data /vol rw - ext4 disk rw\n",
			path: "/vol/file", wantPoint: "/vol", wantType: "ext4",
			visible: []string{"10"},
		},
		{
			name: "a partial chroot still hides an older child",
			rows: "10 9 8:10 /old /vol/sub rw - ext4 disk rw\n" +
				"20 9 8:20 /new /vol rw - ext4 disk rw\n",
			path: "/vol/sub/file", wantPoint: "/vol", wantType: "ext4",
			visible: []string{"20"},
		},
		{
			name:    "same-point parent cycle is unknown",
			unknown: true,
			rows: root + "2 3 8:2 / /vol rw - ext4 disk rw\n" +
				"3 2 8:3 / /vol rw - ext4 disk rw\n",
			path: "/vol/file", wantPoint: "/", wantType: "ext4",
			visible: []string{"1"},
		},
		{
			name: "self-parented namespace root is visible",
			rows: "1 1 8:1 / / rw - ext4 disk rw\n",
			path: "/file", wantPoint: "/", wantType: "ext4",
			visible: []string{"1"},
		},
		{
			name:    "self-parented child is unknown",
			unknown: true,
			rows:    root + "2 2 8:2 / /vol rw - ext4 disk rw\n",
			path:    "/vol/file", wantPoint: "/", wantType: "ext4",
			visible: []string{"1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := visibleMountFixture(t, tc.rows)
			for _, m := range table.mounts {
				want := slices.Contains(tc.visible, m.id)
				if table.visible(m) != want {
					t.Errorf("mount %s visibility = %v, want %v", m.id, table.visible(m), want)
				}
			}
			m, point, ok := table.lookup(tc.path)
			if tc.unknown {
				if ok {
					t.Fatalf("ambiguous mount acquired identity: %+v", m)
				}
				return
			}
			if !ok || point || m.point != tc.wantPoint || m.fstype != tc.wantType {
				t.Fatalf("lookup(%s) = %+v, point=%v, ok=%v; want %s (%s)", tc.path, m, point, ok, tc.wantPoint, tc.wantType)
			}
		})
	}
}

func TestMountLookupVerifiesLiveIdentity(t *testing.T) {
	p := t.TempDir()
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, p, unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &st); err != nil || st.Mask&unix.STATX_MNT_ID == 0 {
		t.Logf("kernel exposes no statx mount identity: %v", err)
		return
	}
	table, err := loadMountTable("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p, p + "/missing/child"} {
		m, _, ok := table.lookup(path)
		if !ok || m.id != fmt.Sprint(st.Mnt_id) {
			t.Fatalf("lookup(%s) = %+v, held=%v; kernel mount %d", path, m, ok, st.Mnt_id)
		}
	}
	// A changed live topology must not reuse the old table's inferred identity.
	i, _ := table.visibleIndex(p)
	table.mounts[i].id = "not-the-kernels-mount"
	if m, _, ok := table.lookup(p); ok {
		t.Fatalf("stale mount identity accepted: %+v", m)
	}
}

func TestMountAmbiguousSiblingsRemainUnknown(t *testing.T) {
	const rows = "1 0 8:1 / / rw - ext4 d1 rw\n" +
		"2 1 8:2 / /q rw - ext4 d2 rw\n" +
		"3 1 8:3 / /q rw - ext4 d3 rw\n"
	for _, live := range []bool{false, true} {
		t.Run(fmt.Sprintf("live=%v", live), func(t *testing.T) {
			old := statLiveMount
			t.Cleanup(func() { statLiveMount = old })
			var siblingChecks int
			statLiveMount = func(_ int, path string, _, _ int, st *unix.Statx_t) error {
				st.Mask, st.Mnt_id = unix.STATX_MNT_ID, 1
				if path == "/q" || strings.HasPrefix(path, "/q/") {
					st.Mnt_id = 3
					siblingChecks++
				}
				return nil
			}
			mt, err := parseMountSnapshot([]byte(rows), "ambiguous siblings", live)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/q", "/q/secret", "/q/secret/deeper"} {
				if id, ok := mt.MountID(path); ok {
					t.Errorf("MountID(%s) = %d; ambiguous siblings must stay unknown", path, id)
				}
				if names, ok := mt.TreeAliases(path); ok {
					t.Errorf("TreeAliases(%s) = %v; listener admission must retain uncertainty", path, names)
				}
			}
			if id, ok := mt.MountID("/unrelated"); !ok || id != 1 {
				t.Errorf("unrelated path = %d, %v; want root mount 1", id, ok)
			}
			if why := mt.t.uncertaintyAt("/q/secret"); !strings.Contains(why, "one visible top") {
				t.Errorf("sibling uncertainty lost: %q", why)
			}
			if siblingChecks != 0 {
				t.Errorf("live selection checked ambiguous siblings %d times; refuse before live selection", siblingChecks)
			}
		})
	}
}

func TestMountVisibleLookupHandlesDeepSamePointStacks(t *testing.T) {
	var rows strings.Builder
	rows.WriteString("1 0 8:1 / / rw - ext4 disk rw\n")
	const depth = 2048
	for id := 2; id <= depth; id++ {
		fmt.Fprintf(&rows, "%d %d 8:%d / /vol rw - ext4 disk rw\n", id, id-1, id)
	}
	table := visibleMountFixture(t, rows.String())
	m, point, ok := table.lookup("/vol")
	if !ok || !point || m.id != fmt.Sprint(depth) {
		t.Fatalf("deep stack's top = %+v, point=%v, ok=%v", m, point, ok)
	}
	if _, _, ok := table.lookup("relative/path"); ok {
		t.Fatal("a relative path acquired a mount identity")
	}
}

func visibleMountFixture(t *testing.T, rows string) *mountTable {
	t.Helper()
	table := &mountTable{probed: true}
	for line := range strings.SplitSeq(rows, "\n") {
		if line == "" {
			continue
		}
		m, ok := parseMountLine(line)
		if !ok {
			t.Fatalf("invalid fixture mount row: %s", line)
		}
		table.mounts = append(table.mounts, m)
	}
	table.order()
	return table
}

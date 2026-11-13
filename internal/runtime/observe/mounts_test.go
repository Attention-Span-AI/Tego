// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func writeMountinfo(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadMounts(t *testing.T) {
	p := writeMountinfo(t, ""+
		"1 0 0:1 / / rw - rootfs rootfs rw\n"+
		"20 1 8:2 / /mnt/a\\040b rw,noatime shared:1 master:2 - ext4 /dev/sda2 rw\n"+ // spaces and optional fields
		"21 1 8:3 / /mnt/nb sp\vx\r rw - ext4 /dev/sda3 rw\n")
	want := []mountRow{
		{id: 1, dev: unix.Mkdev(0, 1), point: "/"},
		{id: 20, dev: unix.Mkdev(8, 2), point: "/mnt/a b"},
		{id: 21, dev: unix.Mkdev(8, 3), point: "/mnt/nb sp\vx\r"},
	}
	got := readMounts(p)
	if len(got) != len(want) {
		t.Fatalf("rows %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	malformed := writeMountinfo(t, "1 0 0:1 / / rw - rootfs rootfs rw\ngarbage\n")
	if rows := readMounts(malformed); rows != nil {
		t.Errorf("partial facts accepted: %+v", rows)
	}
	if rows := readMounts(filepath.Join(t.TempDir(), "missing")); rows != nil {
		t.Errorf("an unreadable table has rows: %+v", rows)
	}
}

// TestMarkedDevicesWithAnEscapedAndAnOddMountPoint: a mount point holding a space (escaped) or a byte Fields
// splits on still names its device.
func TestMarkedDevicesWithAnEscapedAndAnOddMountPoint(t *testing.T) {
	for _, tc := range []struct {
		name, field, root string
	}{
		{"space", `/no\040such`, "/no such/secrets"},
		{"no-break space", "/no such", "/no such/secrets"},
		{"carriage return", "/no\rsuch", "/no\rsuch/secrets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mi := writeMountinfo(t, "1 0 0:1 / / rw - rootfs rootfs rw\n"+
				"30 1 7:8 / "+tc.field+" rw - ext4 /dev/x rw\n")
			rt := &agent.RuleTable{Tier: backend.TierCgroup, FS: []agent.FSRule{
				{Path: tc.root, Kind: agent.FSDenyRead, Raw: tc.root, Unenforced: true},
			}}
			got := markedDevices(rt, mi)
			if _, ok := got[unix.Mkdev(7, 8)]; !ok || len(got) != 1 {
				t.Errorf("marked %v, want only device 7:8", got)
			}
		})
	}
}

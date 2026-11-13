// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Missing host layer names do not refuse grants. Warn for each grant that can
// reach a separate storage mount, naming both the grant and the visible mount.
func TestCompileWarnsAboutUnplacedOverlayBacking(t *testing.T) {
	f := newFixture(t)
	bin := filepath.Join(f.root, "image", "bin")
	out := filepath.Join(f.project, "out")
	volume := filepath.Join(out, "volume")
	sub := filepath.Join(volume, "sub")
	for _, d := range []string{bin, sub} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(bin, "tego")
	f.file(exe, "tego", 0o755)
	overlay := "1 0 0:40 / / rw - overlay overlay rw,lowerdir=/absent-host-layers/lower,upperdir=/absent-host-layers/upper,workdir=/absent-host-layers/work"
	for _, tc := range []struct {
		name, body, mount string
		want              int
	}{
		{"merged write", writeSection(out), "", 0},
		{"read only", "version: 0\nname: a\ncommand: [python]\n", "2 1 8:9 /data " + volume + " rw - ext4 /dev/sdb1 rw", 0},
		{"unrelated volume", writeSection(bin + "-other"), "2 1 8:9 /data " + volume + " rw - ext4 /dev/sdb1 rw", 0},
		{"over volume", writeSection(out), "2 1 8:9 /data " + volume + " rw - ext4 /dev/sdb1 rw", 1},
		{"at volume", writeSection(volume), "2 1 8:9 /data " + volume + " rw - ext4 /dev/sdb1 rw", 1},
		{"inside volume", writeSection(sub), "2 1 8:9 /data " + volume + " rw - ext4 /dev/sdb1 rw", 1},
		{"other overlay", writeSection(sub), "2 1 0:41 / " + volume + " rw - overlay overlay rw,lowerdir=/some/other/lower", 1},
		{"same overlay device", writeSection(sub), "2 1 0:40 /unrelated " + volume + " rw - overlay overlay rw,lowerdir=/absent-host-layers/lower", 0},
		{"ask", "version: 0\nname: a\ncommand: [python]\nfs: {ask: [" + sub + "]}\n", "2 1 8:9 /data " + volume + " rw - ext4 /dev/sdb1 rw", 1},
		{"write and ask each warn", writeSection(out) + "  ask: [" + sub + "]\n", "2 1 8:9 /data " + volume + " rw - ext4 /dev/sdb1 rw", 2},
		{"multiple grants each warn", writeSection(out, sub), "2 1 8:9 /data " + volume + " rw - ext4 /dev/sdb1 rw", 2},
		{"covered volume", writeSection(sub), "2 1 8:9 /data " + volume + " rw - ext4 /dev/sdb1 rw\n3 2 0:99 / " + volume + " rw - tmpfs tmpfs rw", 0},
		{"hidden child volume", writeSection(out), "2 1 0:90 / " + volume + " rw - tmpfs tmpfs rw\n3 2 8:9 /data " + sub + " rw - ext4 /dev/sdb1 rw\n4 2 0:91 / " + volume + " rw - tmpfs tmpfs rw", 0},
		{"grant under hidden child", writeSection(sub), "2 1 0:90 / " + volume + " rw - tmpfs tmpfs rw\n3 2 8:9 /data " + sub + " rw - ext4 /dev/sdb1 rw\n4 2 0:91 / " + volume + " rw - tmpfs tmpfs rw", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ds, err := Compile(f.load(tc.body), f.machine, f.opts(WithOwnBinaries(exe), fakeMountInfo(f, overlay, tc.mount), withInstallDirs())...)
			if err != nil {
				t.Fatalf("unexpected refusal: %v\n%s", err, render(ds))
			}
			var warnings []Diagnostic
			for _, d := range ds {
				if d.Code == "overlay-backing-unknown" {
					warnings = append(warnings, d)
				}
			}
			want := tc.want
			if len(warnings) != want {
				t.Fatalf("got %d backing warnings, want %d:\n%s", len(warnings), want, render(ds))
			}
			if want == 2 {
				secondField := "write"
				if tc.name == "write and ask each warn" {
					secondField = "ask"
				}
				if warnings[0].Message != runtimeBackingWarning("write", out, volume, "") || warnings[1].Message != runtimeBackingWarning(secondField, sub, volume, "") {
					t.Errorf("per-entry warning text = %+v", warnings)
				}
			}
			if want == 1 {
				d := warnings[0]
				if d.Severity != SeverityWarning || !strings.Contains(d.Message, volume) || !strings.Contains(d.Message, "fs."+map[bool]string{true: "ask", false: "write"}[tc.name == "ask"]+" ") || !strings.Contains(d.Message, "cannot tell whether") || !strings.Contains(d.Message, "runtime's storage") || !strings.Contains(d.Message, "whole host filesystem") {
					t.Errorf("warning must name grant, mount, uncertainty and host action: %+v", d)
				}
				grant := out
				switch tc.name {
				case "at volume":
					grant = volume
				case "inside volume", "other overlay", "ask":
					grant = sub
				}
				if !strings.Contains(d.Message, `"`+grant+`"`) {
					t.Errorf("warning does not name actual grant %q: %s", grant, d.Message)
				}
			}
		})
	}
	for _, fs := range []string{"tmpfs", "ramfs", "hugetlbfs", "devtmpfs", "devpts", "proc", "sysfs", "cgroup2"} {
		t.Run("no storage warning on "+fs, func(t *testing.T) {
			_, ds, _ := Compile(f.load(writeSection(sub)), f.machine, f.opts(WithOwnBinaries(exe), fakeMountInfo(f, overlay, "2 1 0:99 / "+volume+" rw - "+fs+" none rw"), withInstallDirs())...)
			for _, d := range ds {
				if d.Code == "overlay-backing-unknown" {
					t.Errorf("kernel or memory filesystem got storage warning: %s", render(ds))
				}
			}
		})
	}
	t.Run("placeable layers need no storage warning", func(t *testing.T) {
		layer := filepath.Join(f.root, "layer")
		if err := os.MkdirAll(layer, 0o755); err != nil {
			t.Fatal(err)
		}
		mi := fakeMountInfo(f, "2 1 0:40 / "+filepath.Dir(bin)+" rw - overlay overlay rw,lowerdir="+layer,
			"3 1 8:9 /data "+volume+" rw - ext4 /dev/sdb1 rw")
		_, ds, err := Compile(f.load(writeSection(sub)), f.machine, f.opts(WithOwnBinaries(exe), mi, withInstallDirs())...)
		if err != nil {
			t.Fatalf("unexpected refusal: %v\n%s", err, render(ds))
		}
		for _, d := range ds {
			if d.Code == "overlay-backing-unknown" {
				t.Errorf("placeable layer got warning: %s", render(ds))
			}
		}
	})

	t.Run("every binary overlay device is excluded", func(t *testing.T) {
		other := filepath.Join(volume, "bin")
		if err := os.MkdirAll(other, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(other, "tego"), "tego", 0o755)
		mi := fakeMountInfo(f, overlay, "2 1 0:41 / "+volume+" rw - overlay overlay rw,lowerdir=/absent-other-layers/lower")
		_, ds, err := Compile(f.load(writeSection(sub)), f.machine, f.opts(WithOwnBinaries(exe), WithPATH(f.bin+":"+other), mi, withInstallDirs())...)
		if err != nil {
			t.Fatalf("unexpected refusal: %v\n%s", err, render(ds))
		}
		for _, d := range ds {
			if d.Code == "overlay-backing-unknown" {
				t.Errorf("binary overlay got storage warning: %s", render(ds))
			}
		}
	})
}

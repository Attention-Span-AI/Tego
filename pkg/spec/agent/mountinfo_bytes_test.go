// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMountSnapshotPreservesPathBytes(t *testing.T) {
	for _, tc := range []struct {
		name, option, want string
	}{
		{"carriage return", "lowerdir=/data/lower\r", "/data/lower\r"},
		{"carriage return plus", "lowerdir+=/data/lower\r", "/data/lower\r"},
		{"escaped bytes", `lowerdir=/data/a\040b\011c\012d\054e\075f`, "/data/a b\tc\nd,e=f"},
		{"literal octal plus", `lowerdir+=/data/\134040`, `/data/\040`},
		{"literal octal list", `lowerdir=/data/\134\134040`, `/data/\040`},
		{"colon list", `lowerdir=/data/a\134:b`, "/data/a:b"},
		{"other whitespace", "lowerdir=/data/a\v\u00a0b", "/data/a\v\u00a0b"},
		{"non-UTF8 bytes", "lowerdir=/data/\xff\xfe", "/data/\xff\xfe"},
		{"case and unicode", "lowerdir=/data/A-é-e\u0301", "/data/A-é-e\u0301"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, end := range []string{"\n", ""} {
				// root, point and source have mountinfo escaping; super options
				// retain their escaping until their values have been separated.
				point := "/merged\r\v\u00a0é-e\u0301"
				root := "/root \\040\t\n\r"
				source := "/source \\012\r"
				alias := "/alias \n\r\\012"
				rows := "1 0 8:1 / / rw - ext4 disk rw\n3 1 0:2 " + escapeMount(root) + " " + escapeMount(alias) + " rw - ext4 disk rw\n2 1 0:2 " + escapeMount(root) + " " + escapeMount(point) + " rw - overlay " + escapeMount(source) + " rw," + tc.option + end
				file := filepath.Join(t.TempDir(), "mountinfo")
				if err := os.WriteFile(file, []byte(rows), 0o600); err != nil {
					t.Fatal(err)
				}
				table, err := loadMountTable(file)
				if err != nil {
					t.Fatal(err)
				}
				m, _, ok := table.lookup(point)
				if !ok || m.root != root || m.point != point || m.source != source || m.super != "rw,"+tc.option {
					t.Errorf("compile reader changed bytes (ending %q): %+v", end, m)
				}
				for reader, fm := range map[string]FileMount{
					"compile": table.fileMount(point),
					"MountOf": MountOf([]byte(rows), point),
				} {
					if !fm.Held || fm.Source != source || !slices.Equal(fm.Aliases, []string{alias}) || fm.Unmapped != "" || !slices.Equal(fm.Layers, []string{tc.want}) {
						t.Errorf("%s changed bytes (ending %q): %+v, want layer %q source %q", reader, end, fm, tc.want, source)
					}
				}
			}
		})
	}
}

func TestMountSnapshotCountsInputBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  int
		end   string
		valid bool
	}{
		{"at bound", maxMountTableBytes, "\r\n", true},
		{"at bound without newline", maxMountTableBytes, "\r", true},
		{"past bound", maxMountTableBytes + 1, "\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rows strings.Builder
			for i := range 16 {
				point, parent := fmt.Sprintf("/m%d", i), 1
				if i == 0 {
					point, parent = "/", 0
				}
				prefix := fmt.Sprintf("%d %d 8:1 / %s rw - ext4 disk rw,x=", i+1, parent, point)
				end := "\r\n"
				if i == 15 {
					end = tc.end
				}
				size := tc.size / 16
				if i == 15 {
					size += tc.size % 16
				}
				rows.WriteString(prefix + strings.Repeat("x", size-len(prefix)-len(end)) + end)
			}
			if rows.Len() != tc.size {
				t.Fatalf("fixture bytes = %d, want %d", rows.Len(), tc.size)
			}
			table, err := readMountSnapshot(strings.NewReader(rows.String()), "fixture", false)
			if tc.valid {
				if err != nil || len(table.mounts) != 16 {
					t.Fatalf("exact bound refused: %v", err)
				}
			} else if err == nil || table.err == nil || len(table.mounts) != 0 || !strings.Contains(err.Error(), "larger than") {
				t.Fatalf("oversized input not refused whole: mounts=%d err=%v", len(table.mounts), err)
			}
			if fm := MountOf([]byte(rows.String()), "/"); fm.Held != tc.valid {
				t.Errorf("MountOf held=%v, want %v", fm.Held, tc.valid)
			}
		})
	}
}

func TestCompileRefusesCarriageReturnLayerAlias(t *testing.T) {
	f := newFixture(t)
	merged := filepath.Join(f.root, "merged")
	decoy := filepath.Join(f.root, "data", "lower")
	layer := decoy + "\r"
	alias := filepath.Join(f.project, "out", "storage")
	for _, dir := range []string{merged, decoy, layer, alias} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(merged, "tego")
	f.file(exe, "tego", 0o755)
	// Both layer names exist. Only the CR-suffixed tree is exposed at the
	// grant, so dropping CR would establish a false negative comparison.
	mi := fakeMountInfo(f,
		"2 1 0:40 / "+merged+" rw - overlay overlay rw,lowerdir="+decoy+":"+layer,
		"3 1 8:1 "+escapeMount(layer)+" "+alias+" rw - ext4 disk rw")
	for _, field := range []string{"write", "ask"} {
		t.Run(field, func(t *testing.T) {
			c := f.load(strings.Replace(writeSection(alias), "write:", field+":", 1))
			wantRefused(t, f, c, "a layer of the overlay holding tego's binaries", mi, WithOwnBinaries(exe), withInstallDirs())
		})
	}
}

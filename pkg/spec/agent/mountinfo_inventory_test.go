// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCapturedMountTablesHaveNoAmbiguousSiblings measures the restored refusal's
// reach over every raw table, including partial captures that lack a root row.
func TestCapturedMountTablesHaveNoAmbiguousSiblings(t *testing.T) {
	tables, unlinked := 0, 0
	err := filepath.WalkDir("testdata", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".mountinfo") {
			return nil
		}
		tables++
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// Only the labelled model fixtures have comment headers and path
			// placeholders. Do not repair or graph-validate partial captures.
			data = []byte(strings.NewReplacer("@HOME@", "/fixture/home", "@HOST@", "/fixture/host",
				"{{ROOT}}", "/fixture").Replace(string(data)))
			var rows []string
			for _, row := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
				if !strings.HasPrefix(row, "#") {
					rows = append(rows, row)
				}
			}
			checkNoMountSiblings(t, path, rows)
			for _, row := range rows {
				m, ok := parseMountRecord(row)
				if !ok {
					t.Fatalf("invalid raw record: %s", row)
				}
				if !m.unlinkedRoot() {
					continue
				}
				unlinked++
				// These two nspawn captures document temporary FILE binds.
				// A new marker row needs its captured type reviewed first.
				if (path != "testdata/chroot-mountinfo/nspawn.mountinfo" && path != "testdata/additional-mountinfo/nspawn-selfbind.mountinfo") ||
					(m.point != "/proc/sys/kernel/random/boot_id" && m.point != "/proc/kmsg") {
					t.Fatalf("unclassified captured unlinked root; stop compatibility review: %s: %s", path, row)
				}
				t.Logf("documented nspawn temporary-file bind: %s", row)
			}
			t.Logf("%d rows; 0 ambiguous sibling groups", len(rows))
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if tables == 0 {
		t.Fatal("no mount-table fixtures measured")
	}
	if tables != 51 || unlinked != 6 {
		t.Fatalf("inventory changed: %d raw tables, %d unlinked rows", tables, unlinked)
	}
	t.Logf("%d raw tables measured; %d documented unlinked file rows; no unclassified unlinked roots", tables, unlinked)
}

// checkNoMountSiblings checks raw records, independently of the visibility index,
// so neither live selection nor a whole-table refusal can conceal sibling rows.
func checkNoMountSiblings(t *testing.T, name string, rows []string) {
	t.Helper()
	type position struct{ parent, point string }
	groups := map[position][]string{}
	for _, row := range rows {
		m, ok := parseMountRecord(row)
		if !ok {
			t.Fatalf("%s: invalid inventory row %q", name, row)
		}
		key := position{m.parent, m.point}
		groups[key] = append(groups[key], m.id)
	}
	for key, ids := range groups {
		if len(ids) > 1 {
			t.Fatalf("%s: parent %s at %s has ambiguous siblings %v; compatibility needs review", name, key.parent, key.point, ids)
		}
	}
}

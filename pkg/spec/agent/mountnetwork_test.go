// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// A repeated source does not establish filesystem identity. Keep it a warning, and pin the limit that a second
// superblock is outside the alias search even when its network source has exactly the same spelling.
func TestCompileWarnsForRepeatedNetworkSourceSeparateFilesystems(t *testing.T) {
	for _, tc := range []struct {
		name, fs, dev, source string
		warn                  bool
	}{
		{"nfs", "nfs", "0:43", "server:/export", true},
		{"nfs4", "nfs4", "0:43", "server:/export", true},
		{"cifs", "cifs", "0:43", "//server/share", true},
		{"same filesystem", "nfs", "0:42", "server:/export", false},
		{"other source", "nfs", "0:43", "server:/other", false},
		{"local source string is not evidence", "ext4", "0:43", "server:/export", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			a, b := f.project, filepath.Join(f.root, "other")
			firstSource := tc.source
			if tc.name == "other source" {
				firstSource = "server:/export"
			}
			mounts := fmt.Sprintf("1 0 8:1 / / rw - ext4 /dev/root rw\n"+
				"2 1 0:42 / %s rw - %s %s rw\n"+
				"3 1 %s / %s rw - %s %s rw\n", a, tc.fs, firstSource, tc.dev, b, tc.fs, tc.source)
			mt, err := ParseMountTableStrict([]byte(mounts))
			if err != nil {
				t.Fatal(err)
			}
			for _, query := range []func(string) ([]string, bool){mt.TreeAliases, mt.DetachedParts} {
				aliases, held := query(filepath.Join(a, "secrets"))
				if !held || tc.dev != "0:42" && len(aliases) != 0 {
					t.Fatalf("aliases = %v, held %v; separate filesystems must not be identified by source", aliases, held)
				}
			}
			path := filepath.Join(f.root, "mountinfo")
			f.file(path, mounts, 0o600)
			rt, ds := f.compile(f.load("version: 0\nname: network-source-limit\ncommand: [static-tool]\n"), WithMountInfo(path))
			if rt == nil {
				t.Fatalf("repeated network source refused compilation: %v", ds)
			}
			var warnings []Diagnostic
			for _, d := range ds {
				if d.Code == CodeMountWarning && strings.Contains(d.Message, "same network source string") {
					warnings = append(warnings, d)
				}
			}
			if (len(warnings) != 0) != tc.warn {
				t.Fatalf("warnings = %v, want warning %v", warnings, tc.warn)
			}
			if !tc.warn {
				return
			}
			if len(warnings) != 1 || warnings[0].Severity != SeverityWarning || warnings[0].Informational() {
				t.Fatalf("want one visible warning, got %+v", warnings)
			}
			for _, want := range []string{a, b, tc.source, "different filesystem instances", "not recognised", "deny the other path too"} {
				if !strings.Contains(warnings[0].Message+warnings[0].Fix, want) {
					t.Errorf("warning omitted %q: %+v", want, warnings[0])
				}
			}
		})
	}
}

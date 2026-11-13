// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Hidden mount rows must supply neither side of an R10 identity comparison.
func TestCompileHoldsProfilesWithHiddenMountRows(t *testing.T) {
	for _, side := range []string{"protected", "granted"} {
		t.Run(side, func(t *testing.T) {
			f := newFixture(t)
			srv := filepath.Join(f.root, "srv")
			work := filepath.Join(f.root, "work")
			data := filepath.Join(f.root, "data")
			profiles := filepath.Join(srv, "profiles")
			alias := filepath.Join(work, "profiles")
			var rows []string
			if side == "protected" {
				rows = []string{
					"2 1 0:2 / " + srv + " rw - tmpfs none rw",
					"3 2 0:3 / " + profiles + " rw - tmpfs none rw",
					"4 2 8:1 " + data + " " + srv + " rw - ext4 disk rw",
					"5 1 8:1 " + filepath.Join(data, "profiles") + " " + alias + " rw - ext4 disk rw",
				}
			} else {
				profiles = filepath.Join(data, "profiles")
				rows = []string{
					"2 1 0:2 / " + work + " rw - tmpfs none rw",
					"3 2 0:3 / " + alias + " rw - tmpfs none rw",
					"4 2 8:1 " + data + " " + work + " rw - ext4 disk rw",
				}
			}
			entry := filepath.Join(alias, "base")
			for _, p := range []string{profiles, entry} {
				if err := os.MkdirAll(p, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			machine := *f.machine
			machine.Profiles = config.Setting[string]{Value: profiles}
			for _, kind := range []string{"write", "ask"} {
				t.Run(kind, func(t *testing.T) {
					c := f.load(strings.Replace(writeSection(entry), "write:", kind+":", 1))
					_, ds, err := Compile(c, &machine, f.opts(fakeMountInfo(f, rows...))...)
					if err == nil || !strings.Contains(render(ds), "the profiles directory "+profiles+", through another mount of it") {
						t.Fatalf("hidden %s row lost profiles protection for %s:\n%s", side, kind, render(ds))
					}
				})
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// A chroot below a mountpoint can hide its root's mountinfo row while exposing
// binds of both a binary and protected data. Missing identity proves no separation: a table whose rows do not
// connect to one root at / is refused whole, and every write and ask grant with it, naming why and the remedy.
func TestCompileRefusesUnplacedProtectedIdentity(t *testing.T) {
	for _, held := range []bool{false, true} {
		name := "protected target"
		if held {
			name = "walk directory"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			bin := ownInstall(f)
			profiles := filepath.Join(f.root, "srv", "profiles")
			entry := filepath.Join(f.project, "out", "p")
			for _, d := range []string{profiles, entry} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			rows := "2 99 8:1 /host/bin " + bin + " rw - ext4 disk rw\n" +
				"3 99 8:1 /host/srv/profiles " + entry + " rw - ext4 disk rw\n"
			want := "Tego is running inside a root that is not a mount point, so the kernel does not show the filesystem under it"
			if held {
				rows += "4 99 8:2 /profiles " + profiles + " rw - ext4 other rw\n"
			}
			mi := filepath.Join(f.root, "partial-mountinfo")
			if err := os.WriteFile(mi, []byte(rows), 0o600); err != nil {
				t.Fatal(err)
			}
			machine := *f.machine
			machine.Profiles = config.Setting[string]{Value: profiles}
			for _, kind := range []string{"write", "ask"} {
				t.Run(kind, func(t *testing.T) {
					c := f.load(strings.Replace(writeSection(entry), "write:", kind+":", 1))
					_, ds, err := Compile(c, &machine, f.opts(WithMountInfo(mi), WithOwnBinaries(filepath.Join(bin, "tego")), withInstallDirs())...)
					if err == nil || !strings.Contains(render(ds), want) || !strings.Contains(render(ds), "root is a mount point") {
						t.Fatalf("unplaced %s admitted %s grant, or lost actionable uncertainty (want %q):\n%s", name, kind, want, render(ds))
					}
				})
			}
		})
	}
}

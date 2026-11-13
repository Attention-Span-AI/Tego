// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Mount identity cannot identify a FUSE mirror as the same data. A visible FUSE
// mount gets a warning, rather than a guessed refusal or a protection claim.
func TestCompileWarnsAboutVisibleFUSEMounts(t *testing.T) {
	f := newFixture(t)
	profiles := filepath.Join(f.root, "profiles")
	mirror := filepath.Join(f.project, "out", "mirror")
	for _, d := range []string{profiles, filepath.Join(mirror, "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	m := *f.machine
	m.Profiles = config.Setting[string]{Value: profiles}
	for _, fs := range []string{"fuse", "fuse.sshfs", "fuseblk"} {
		t.Run(fs, func(t *testing.T) {
			mi := fakeMountInfo(f, "5 1 0:99 / "+mirror+" rw - "+fs+" mirror rw")
			for _, entry := range []string{filepath.Dir(mirror), mirror, filepath.Join(mirror, "sub")} {
				for _, field := range []string{"write", "ask"} {
					body := "version: 0\nname: a\ncommand: [python]\nfs: {" + field + ": [" + entry + "]}\n"
					_, ds, err := Compile(f.load(body), &m, f.opts(mi)...)
					if err != nil || !strings.Contains(render(ds), "reaches FUSE mount "+mirror) {
						t.Errorf("fs.%s %s: want successful compile and a warning naming the mirror; err=%v\n%s", field, entry, err, render(ds))
					}
				}
			}
		})
	}
}

// The binary layer closure does not follow backing trees of arbitrary policy
// directories. Keep this limit explicit alongside the FUSE warning regression.
func TestCompileMountIdentityDoesNotTracePolicyOverlayLayers(t *testing.T) {
	f := newFixture(t)
	profiles := filepath.Join(f.root, "profiles")
	layer := filepath.Join(f.project, "policy-layer")
	for _, d := range []string{profiles, layer} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	m := *f.machine
	m.Profiles.Value = profiles
	mi := fakeMountInfo(f, "5 1 0:99 / "+profiles+" rw - overlay overlay rw,lowerdir="+layer)
	_, ds, err := Compile(f.load(writeSection(layer)), &m, f.opts(mi)...)
	if err != nil {
		t.Fatalf("documented different-filesystem limit changed: %v\n%s", err, render(ds))
	}
}

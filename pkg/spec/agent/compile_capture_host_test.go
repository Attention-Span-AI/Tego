// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A CI host can run containers beside Tego. Storage of an unrelated container
// is not backing of a Tego binary on the host's disk.
func TestCompileContainerHostMountTables(t *testing.T) {
	for _, tc := range []struct {
		name, storage string
		rootless      bool
	}{
		{"docker-small", "/var/lib/docker", false},
		{"docker-containerd-store", "/var/lib/containerd", false},
		{"containerd-ctr", "/var/lib/containerd", false},
		{"podman-rootless-native", "/home/runner/.local/share/containers/storage", true},
		{"podman-fuse-overlayfs", "/data/fuse-storage/graph", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			storage := filepath.Join(f.root, "host", strings.TrimPrefix(tc.storage, "/"))
			if err := os.MkdirAll(storage, 0o755); err != nil {
				t.Fatal(err)
			}
			input, err := containerMountFixtures.ReadFile("testdata/container-mountinfo/" + tc.name + ".hostfull.mountinfo")
			if err != nil {
				t.Fatal(err)
			}
			line, err := containerMountFixtures.ReadFile("testdata/container-mountinfo/" + tc.name + ".host.mountinfo")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(input), string(line)) == tc.rootless {
				t.Fatal("host versus rootless user-namespace capture confused")
			}
			// Keep all captured ancestry, devices and mount options. Relocate
			// storage only, so the test never touches an installed runtime.
			table := strings.ReplaceAll(string(input), tc.storage, storage)
			storageDevice := "253:1"
			if tc.name == "podman-fuse-overlayfs" {
				// This store is on the capture guest's second disk. Move its
				// /data mount with it, retaining that holding filesystem.
				table = strings.ReplaceAll(string(input), "/data", filepath.Join(f.root, "host", "data"))
				storageDevice = "253:16"
			}
			mi := filepath.Join(f.root, "host-mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			fm := MountOf([]byte(table), exe)
			if !fm.Held || fm.Device != "253:1" || len(fm.Layers) != 0 || fm.Unmapped != "" {
				t.Fatalf("Tego must be on host disk: %+v", fm)
			}
			if held := MountOf([]byte(table), storage); !held.Held || held.Device != storageDevice {
				t.Fatalf("runtime storage moved off its captured disk: %+v", held)
			}
			for _, entry := range []string{storage, filepath.Join(f.project, "out")} {
				_, ds, err := Compile(f.load(writeSection(entry+"/")), f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
				if err != nil {
					t.Fatalf("unrelated container storage/project refused: %v\n%s", err, render(ds))
				}
				for _, d := range ds {
					if d.Code == CodeOverlayBackingUnknown || d.Code == CodeMountWarning {
						t.Errorf("unrelated host storage got mount warning: %+v", d)
					}
				}
			}
			// Moving a protected binary into that same storage folder changes
			// the answer for a reason unrelated to its container ownership.
			storedExe := filepath.Join(storage, "tego")
			f.file(storedExe, "not run", 0o755)
			wantRefused(t, f, f.load(writeSection(storage+"/")), "the tego binary", WithOwnBinaries(storedExe), WithMountInfo(mi))
		})
	}
}

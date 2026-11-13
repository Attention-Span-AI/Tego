// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileCapturedHostFileBinds(t *testing.T) {
	for _, name := range []string{"docker-small", "docker-many-layers", "docker-containerd-store-many-layers", "podman-rootless-native", "podman-fuse-overlayfs"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			etc := filepath.Join(f.project, "etc")
			if err := os.Mkdir(etc, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{"resolv.conf", "hosts", "hostname"} {
				f.file(filepath.Join(etc, file), "container config", 0o644)
			}
			table := runtimeMountFixture(t, name, f.home, filepath.Join(f.root, "absent-host"))
			table = strings.ReplaceAll(table, " /etc/", " "+etc+"/")
			replayBackingMountIDs(t, table)
			mi := filepath.Join(f.root, "mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				for _, grant := range []string{etc + "/", filepath.Join(etc, "hosts"), filepath.Join(etc, "resolv.conf"), filepath.Join(etc, "hostname")} {
					body := strings.Replace(writeSection(grant), "write:", field+":", 1)
					_, ds, err := Compile(f.load(body), f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
					if err != nil {
						t.Fatalf("ordinary config-file grant refused: %v\n%s", err, render(ds))
					}
					want := 0
					if name == "podman-fuse-overlayfs" {
						want = 1
					}
					if backingCount(ds) != want {
						t.Errorf("captured file bind warnings=%d want=%d\n%s", backingCount(ds), want, render(ds))
					}
				}
				// A normal CLI protects the fixed system config path even if
				// absent and even when TEGO_CONFIG points elsewhere. The builtin
				// machine above isolated file-bind warning behavior; keep the
				// normal /etc ancestor refusal as a separate assertion.
				layers := f.machine.Layers
				f.machine.Layers = append([]string{filepath.Join(etc, "tego", "config.yaml")}, layers...)
				wantRefused(t, f, f.load(strings.Replace(writeSection(etc+"/"), "write:", field+":", 1)), "the machine config", WithOwnBinaries(exe), WithMountInfo(mi))
				f.machine.Layers = layers
				// Bind one protected file at the ordinary hosts name. Warning
				// filtering must never bypass the independent identity refusal.
				var rows []string
				for row := range strings.SplitSeq(strings.TrimSuffix(table, "\n"), "\n") {
					m, _ := parseMountLine(row)
					if m.point != filepath.Join(etc, "hosts") {
						rows = append(rows, row)
					}
				}
				root, _ := parseMountLine(rows[0])
				for _, protected := range []struct{ path, why string }{
					{exe, "the tego binary"},
					{filepath.Join(f.project, "agent.yaml"), "the contract file"},
				} {
					alias := strings.Join(rows, "\n") + fmt.Sprintf("\n9000 %s %s %s %s rw - %s %s %s\n", root.id, root.dev, protected.path, filepath.Join(etc, "hosts"), root.fstype, root.source, root.super)
					if err := os.WriteFile(mi, []byte(alias), 0o600); err != nil {
						t.Fatal(err)
					}
					for _, grant := range []string{etc + "/", filepath.Join(etc, "hosts")} {
						wantRefused(t, f, f.load(strings.Replace(writeSection(grant), "write:", field+":", 1)), protected.why, WithOwnBinaries(exe), WithMountInfo(mi))
					}
				}
				if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCompileBackingMountFileTypeMustBeKnown(t *testing.T) {
	for _, kind := range []string{"directory", "missing", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			out := filepath.Join(f.project, "out")
			point := filepath.Join(out, "hosts")
			switch kind {
			case "directory":
				if err := os.Mkdir(point, 0o755); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				// A symlink loop gives a deterministic identity-read failure,
				// including when the test runner has root's DAC override.
				if err := os.Symlink("hosts", point); err != nil {
					t.Fatal(err)
				}
			}
			table := runtimeMountFixture(t, "docker-small", f.home, filepath.Join(f.root, "absent-host"))
			root, _ := parseMountLine(strings.SplitN(table, "\n", 2)[0])
			table += fmt.Sprintf("9000 %s 253:1 /host/hosts %s rw - ext4 /dev/vda1 rw\n", root.id, point)
			mi := filepath.Join(f.root, "mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				_, ds, err := Compile(f.load(strings.Replace(writeSection(out+"/"), "write:", field+":", 1)), f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
				if err != nil {
					t.Fatalf("ordinary output refused: %v\n%s", err, render(ds))
				}
				count := 0
				for _, d := range ds {
					if d.Code == CodeOverlayBackingUnknown {
						count++
					}
				}
				if count != 1 {
					t.Errorf("%s mount warnings=%d want exactly 1\n%s", kind, count, render(ds))
				}
			}
		})
	}
}

// This is synthetic: no captured runtime used a storage root with a space.
func TestCompileSyntheticEscapedStorage(t *testing.T) {
	f := newFixture(t)
	exe := filepath.Join(ownInstall(f), "tego")
	layer := filepath.Join(f.root, "containerd data", "fs")
	if err := os.MkdirAll(layer, 0o755); err != nil {
		t.Fatal(err)
	}
	mi := fakeMountInfo(f, "2 1 0:45 / "+filepath.Dir(exe)+" rw - overlay overlay rw,lowerdir="+escapeMount(layer)+",uuid=on,nouserxattr")
	// The option parser must decode mountinfo's octal space once, rather
	// than splitting the layer or treating it as absent host backing.
	layers, why := stackLayers("overlay", "rw,lowerdir="+escapeMount(layer)+",uuid=on,nouserxattr")
	if len(layers) != 1 || layers[0] != layer || why != "" {
		t.Fatalf("escaped layer lost: %q %q", layers, why)
	}
	for _, field := range []string{"write", "ask"} {
		wantRefused(t, f, f.load(strings.Replace(writeSection(layer+"/"), "write:", field+":", 1)), "a layer of the overlay holding tego's binaries", mi, WithOwnBinaries(exe))
	}
}

func TestCompileCapturedMixedLayersRemainProtected(t *testing.T) {
	for _, name := range []string{"containerd-ctr-many-layers", "docker-containerd-store-many-layers"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			host := filepath.Join(f.root, "host")
			alias := filepath.Join(f.project, "out", "storage")
			table := runtimeMountFixture(t, name, f.home, host)
			root, _ := parseMountLine(strings.SplitN(table, "\n", 2)[0])
			fm := MountOf([]byte(table), exe)
			if len(fm.Layers) != 2 || fm.Unmapped != relativeOverlayLayers {
				t.Fatalf("not the captured mixed layout: %+v", fm)
			}
			for _, layer := range fm.Layers {
				if err := os.MkdirAll(layer, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(alias, 0o755); err != nil {
				t.Fatal(err)
			}
			// Expose the absolute backing paths on a separate disk and bind
			// the captured upper layer beneath an ordinary output name.
			table += fmt.Sprintf("9000 %s 253:1 / %s rw - ext4 /dev/vda1 rw\n9001 %s 253:1 %s %s rw - ext4 /dev/vda1 rw\n", root.id, host, root.id, strings.TrimPrefix(fm.Layers[0], host), alias)
			mi := filepath.Join(f.root, "mixed-mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				for _, grant := range append(fm.Layers, alias) {
					wantRefused(t, f, f.load(strings.Replace(writeSection(grant+"/"), "write:", field+":", 1)), "a layer of the overlay holding tego's binaries", WithOwnBinaries(exe), WithMountInfo(mi))
				}
			}
		})
	}
}

func TestCompileCapturedLayerFileBindStillRefuses(t *testing.T) {
	for _, name := range []string{"docker-small", "docker-containerd-store-many-layers", "containerd-ctr-many-layers", "podman-rootless-native"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			alias := filepath.Join(f.project, "out", "binary-file")
			f.file(alias, "not run", 0o755)
			table := runtimeMountFixture(t, name, f.home, filepath.Join(f.root, "absent-host"))
			root, _ := parseMountLine(strings.SplitN(table, "\n", 2)[0])
			fm := MountOf([]byte(table), exe)
			if len(fm.Layers) == 0 {
				t.Fatal("capture must name an absolute layer")
			}
			// The host spelling is absent, but a bind of one file beneath it
			// still correlates with that layer. It remains a protected place
			// even though a regular-file mount gets no backing warning.
			table += fmt.Sprintf("9000 %s 253:1 %s %s rw - ext4 /dev/vda1 rw\n", root.id, filepath.Join(fm.Layers[0], "usr/bin/tego"), alias)
			mi := filepath.Join(f.root, "layer-file-mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				for _, grant := range []string{alias, filepath.Dir(alias) + "/"} {
					wantRefused(t, f, f.load(strings.Replace(writeSection(grant), "write:", field+":", 1)), "a layer of the overlay holding tego's binaries", WithOwnBinaries(exe), WithMountInfo(mi))
				}
			}
		})
	}
}

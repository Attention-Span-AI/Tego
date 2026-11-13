// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileCiphertextFileBindKeepsWarning(t *testing.T) {
	for _, fs := range []string{"fuse.gocryptfs", "fuse", "fuseblk", "ecryptfs"} {
		t.Run(fs, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(f.home, ".local/bin/tego")
			if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
				t.Fatal(err)
			}
			f.file(exe, "plaintext binary", 0o755)
			point := filepath.Join(f.project, "out", "ciphertext")
			f.file(point, "encrypted bytes!", 0o600)
			table := fmt.Sprintf("1 0 8:1 / / rw - ext4 disk rw\n2 1 0:80 / %s rw - %s vault rw\n3 1 8:1 /cipher/file %s rw - ext4 disk rw\n", f.home, fs, point)
			replayBackingMountIDs(t, table)
			mi := filepath.Join(f.root, "mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				c := f.load(strings.Replace(writeSection(point), "write:", field+":", 1))
				_, ds, err := Compile(c, f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi), withInstallDirs())...)
				if err != nil || backingCount(ds) != 1 {
					t.Fatalf("ciphertext bind: err=%v backing=%d want 1\n%s", err, backingCount(ds), render(ds))
				}
			}
			// Preserve the existing conservative refusal of nonempty identical bytes.
			f.file(point, "plaintext binary", 0o600)
			wantRefused(t, f, f.load(writeSection(point)), "byte-identical alias", WithOwnBinaries(exe), WithMountInfo(mi), withInstallDirs())
		})
	}
}

func TestCompileEmptyPodmanFileBindKeepsWarning(t *testing.T) {
	for _, layout := range []string{"docker-many-layers", "podman-fuse-overlayfs"} {
		for _, content := range []string{"", "nonempty"} {
			t.Run(fmt.Sprintf("%s/protected=%q", layout, content), func(t *testing.T) {
				f := newFixture(t)
				exe := filepath.Join(ownInstall(f), "tego")
				policy := filepath.Join(f.root, "empty-config.yaml")
				f.file(policy, content, 0o600)
				f.machine.Layers = append(f.machine.Layers, policy)
				point := filepath.Join(f.project, "run", ".containerenv")
				if err := os.MkdirAll(filepath.Dir(point), 0o755); err != nil {
					t.Fatal(err)
				}
				f.file(point, "", 0o600)
				table := runtimeMountFixture(t, layout, f.home, filepath.Join(f.root, "absent-host"))
				root, _ := parseMountLine(strings.SplitN(table, "\n", 2)[0])
				podman := runtimeMountFixture(t, "podman-fuse-overlayfs", f.home, filepath.Join(f.root, "absent-host"))
				for row := range strings.SplitSeq(podman, "\n") {
					m, ok := parseMountLine(row)
					if ok && m.point == "/run/.containerenv" {
						row = strings.Replace(row, "445 438 ", "9000 "+root.id+" ", 1)
						table += strings.Replace(row, " /run/.containerenv ", " "+point+" ", 1) + "\n"
					}
				}
				replayBackingMountIDs(t, table)
				mi := filepath.Join(f.root, "mountinfo")
				if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"write", "ask"} {
					for _, grant := range []string{point, filepath.Dir(point) + "/"} {
						_, ds, err := Compile(f.load(strings.Replace(writeSection(grant), "write:", field+":", 1)), f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
						want := 0
						if content == "" || layout == "podman-fuse-overlayfs" {
							want = 1
						}
						if err != nil || backingCount(ds) != want {
							t.Fatalf("empty Podman bind: err=%v backing=%d want %d\n%s", err, backingCount(ds), want, render(ds))
						}
					}
				}
				if content != "" {
					f.file(point, content, 0o600)
					for _, field := range []string{"write", "ask"} {
						wantRefused(t, f, f.load(strings.Replace(writeSection(point), "write:", field+":", 1)), "byte-identical alias of the machine config", WithOwnBinaries(exe), WithMountInfo(mi))
					}
				}
			})
		}
	}
}

func TestCompileBackingWarningNamesProtectedFile(t *testing.T) {
	for _, kind := range []string{"contract file", "machine config", "tego binary"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			protected := filepath.Join(f.project, "agent.yaml")
			switch kind {
			case "machine config":
				protected = filepath.Join(f.root, "policy", "config.yaml")
				if err := os.MkdirAll(filepath.Dir(protected), 0o755); err != nil {
					t.Fatal(err)
				}
				f.file(protected, "config", 0o600)
				f.machine.Layers = []string{protected}
			case "tego binary":
				protected = exe
			}
			// Mount just the protected file's containing tree on sshfs; the
			// output grant remains on ext4, so this target alone causes the warning.
			mi := fakeMountInfo(f, "2 1 0:80 / "+filepath.Dir(protected)+" rw - fuse.sshfs user@server:/p rw")
			out := filepath.Join(f.root, "plain-output")
			if err := os.Mkdir(out, 0o700); err != nil {
				t.Fatal(err)
			}
			_, ds, err := Compile(f.load(writeSection(out)), f.machine, f.opts(WithOwnBinaries(exe), mi)...)
			if err != nil || backingCount(ds) != 1 {
				t.Fatalf("sshfs target: err=%v backing=%d\n%s", err, backingCount(ds), render(ds))
			}
			for _, d := range ds {
				if d.Code == CodeOverlayBackingUnknown && (!strings.Contains(d.Message, "the "+kind+" "+protected+" lies on fuse.sshfs") || !strings.Contains(d.Message, "cannot tell")) {
					t.Errorf("warning omits protected target: %s", d.Message)
				}
			}
		})
	}
}

func TestCompilePodmanOrdinaryGrantReachesNoFileBind(t *testing.T) {
	f := newFixture(t)
	exe := filepath.Join(ownInstall(f), "tego")
	table := runtimeMountFixture(t, "podman-fuse-overlayfs", f.home, filepath.Join(f.root, "absent-host"))
	out := filepath.Join(f.project, "out")
	mt, err := readMountSnapshot(strings.NewReader(table), "captured podman", false)
	if err != nil {
		t.Fatal(err)
	}
	held, _, ok := mt.lookup(out)
	if !ok || held.fstype != "fuse.fuse-overlayfs" {
		t.Fatalf("ordinary grant not on root: %+v", held)
	}
	binds := 0
	for _, m := range mt.mounts {
		if m.dev == "0:44" {
			binds++
			if isAncestorOrSelf(out, m.point) || isAncestorOrSelf(m.point, out) {
				t.Fatalf("ordinary grant reaches file bind %s", m.point)
			}
		}
	}
	if binds != 4 {
		t.Fatalf("captured file binds=%d want 4", binds)
	}
	mi := filepath.Join(f.root, "mountinfo")
	if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	_, ds, err := Compile(f.load(writeSection(out)), f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
	if err != nil || backingCount(ds) != 0 {
		t.Fatalf("ordinary Podman grant: %v\n%s", err, render(ds))
	}
}

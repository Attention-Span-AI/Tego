// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Captures and the explicitly labelled synthetic cases are embedded so overlays
// can verify fixture coverage without modifying the checked-in snapshots.
//
//go:embed testdata/container-mountinfo/*.mountinfo
var containerMountFixtures embed.FS

const relativeBackingReason = "layers named relative to a folder the mount table does not record"

type containerRuntimeCase struct {
	name           string
	layers, lowers int
	unmapped, tail string
}

var capturedRuntimeCases = []containerRuntimeCase{
	{"docker-small", 4, 2, "", "nouserxattr"},
	{"docker-small-volume", 4, 2, "", "nouserxattr"},
	{"docker-many-layers-70", 0, 72, relativeBackingReason, "nouserxattr"},
	{"docker-many-layers", 0, 122, relativeBackingReason, "nouserxattr"},
	{"docker-many-layers-volume", 0, 122, relativeBackingReason, "nouserxattr"},
	{"docker-containerd-store", 4, 2, "", "nouserxattr"},
	{"docker-containerd-store-volume", 4, 2, "", "nouserxattr"},
	{"docker-containerd-store-many-layers", 2, 122, relativeBackingReason, "nouserxattr"},
	{"docker-containerd-store-many-layers-volume", 2, 122, relativeBackingReason, "nouserxattr"},
	{"containerd-ctr", 3, 1, "", "uuid=on,nouserxattr"},
	{"containerd-ctr-volume", 3, 1, "", "uuid=on,nouserxattr"},
	{"containerd-ctr-many-layers", 2, 121, relativeBackingReason, "uuid=on,nouserxattr"},
	{"containerd-ctr-many-layers-volume", 2, 121, relativeBackingReason, "uuid=on,nouserxattr"},
	{"podman-rootless-native", 3, 1, "", "redirect_dir=nofollow,uuid=on,userxattr"},
	{"podman-rootless-native-volume", 3, 1, "", "redirect_dir=nofollow,uuid=on,userxattr"},
	{"podman-rootless-native-rm", 3, 1, "", "redirect_dir=nofollow,uuid=on,fsync=volatile,userxattr"},
	{"podman-fuse-overlayfs", 0, 0, "fuse.fuse-overlayfs", "user_id=0,group_id=0,default_permissions,allow_other"},
	{"podman-fuse-overlayfs-volume", 0, 0, "fuse.fuse-overlayfs", "user_id=0,group_id=0,default_permissions,allow_other"},
}

func TestCompileContainerRuntimeMountTables(t *testing.T) {
	cases := append(slices.Clone(capturedRuntimeCases), containerRuntimeCase{name: "synthetic-fuse-overlayfs", unmapped: "fuse.overlayfs"})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			out := filepath.Join(f.project, "out")
			alias := filepath.Join(f.project, "protected-alias")
			if err := os.Mkdir(alias, 0o755); err != nil {
				t.Fatal(err)
			}
			data := runtimeMountFixture(t, tc.name, f.home, filepath.Join(f.root, "absent-host"))
			data = strings.ReplaceAll(data, " /work/out ", " "+out+" ")
			root, ok := parseMountLine(strings.SplitN(data, "\n", 2)[0])
			if !ok {
				t.Fatal("missing root mount")
			}
			fm := MountOf([]byte(data), exe)
			if !fm.Held || len(fm.Layers) != tc.layers || (tc.unmapped == "" && fm.Unmapped != "") || (tc.unmapped != "" && !strings.Contains(fm.Unmapped, tc.unmapped)) {
				t.Fatalf("runtime layer placement: held=%v layers=%d unmapped=%q; want %d / %q", fm.Held, len(fm.Layers), fm.Unmapped, tc.layers, tc.unmapped)
			}
			for _, layer := range fm.Layers {
				if _, err := os.Stat(layer); !os.IsNotExist(err) {
					t.Fatalf("host layer %q must be absent: %v", layer, err)
				}
			}
			mi := filepath.Join(f.root, "runtime-mountinfo")
			if err := os.WriteFile(mi, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				t.Run(field, func(t *testing.T) {
					body := "version: 0\nname: container\ncommand: [python]\nfs: {" + field + ": [\"" + out + "/\"]}\n"
					_, ds, err := Compile(f.load(body), f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
					if err != nil {
						t.Fatalf("ordinary container grant refused: %v\n%s", err, render(ds))
					}
					var got, want []string
					mountWarnings := 0
					for _, d := range ds {
						if d.Code == CodeMountWarning {
							mountWarnings++
						}
						if d.Code == CodeOverlayBackingUnknown {
							if d.Severity != SeverityWarning {
								t.Errorf("backing diagnostic is not a warning: %+v", d)
							}
							got = append(got, backingWarningSummary(d.Message))
						}
					}
					if strings.HasSuffix(tc.name, "-volume") {
						want = []string{runtimeBackingWarning(field, out+"/", out, tc.unmapped)}
					}
					if !slices.Equal(got, want) {
						t.Errorf("backing warnings = %q; want exactly %q", got, want)
					}
					// Docker overlay emits one advisory on the merged tree and one
					// on a volume mount point; neither is a backing warning.
					wantMount := 1
					if strings.HasPrefix(tc.unmapped, "fuse.") {
						wantMount = 2
					}

					if mountWarnings != wantMount {
						t.Errorf("mount advisories=%d want=%d\n%s", mountWarnings, wantMount, render(ds))
					}
					wantRefused(t, f, f.load(strings.Replace(body, out+"/", filepath.Dir(exe)+"/", 1)), "the tego binary", WithOwnBinaries(exe), WithMountInfo(mi))
					// Real mount IDs are not 1; attach synthetic aliases to the
					// captured root rather than creating an unrelated lineage.
					aliasTable := data + fmt.Sprintf("9000 %s %s %s %s rw,relatime - %s %s %s\n", root.id, root.dev, filepath.Dir(exe), alias, root.fstype, root.source, root.super)
					if err := os.WriteFile(mi, []byte(aliasTable), 0o600); err != nil {
						t.Fatal(err)
					}
					wantRefused(t, f, f.load(strings.Replace(body, out+"/", alias+"/", 1)), "the tego binary", WithOwnBinaries(exe), WithMountInfo(mi))
					if err := os.WriteFile(mi, []byte(data), 0o600); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestCapturedMountTableDetails(t *testing.T) {
	for _, tc := range capturedRuntimeCases {
		t.Run(tc.name, func(t *testing.T) {
			input, err := containerMountFixtures.ReadFile("testdata/container-mountinfo/" + tc.name + ".mountinfo")
			if err != nil {
				t.Fatal(err)
			}
			data := string(input)
			mt, err := readMountSnapshot(strings.NewReader(data), tc.name, false)
			if err != nil {
				t.Fatal(err)
			}
			root, _, ok := mt.lookup("/usr/local/bin/tego")
			if !ok || root.point != "/" || root.id == "1" || root.parent == "0" {
				t.Fatalf("captured root ancestry not accepted: %+v", root)
			}
			if !strings.HasSuffix(root.super, tc.tail) || strings.Contains(root.super, "index=off") {
				t.Fatalf("lost real option tail: %s", root.super)
			}
			lowers := 0
			for opt := range strings.SplitSeq(root.super, ",") {
				if val, ok := strings.CutPrefix(opt, "lowerdir="); ok {
					lowers = len(splitLowerdir(val))
				}
			}
			if lowers != tc.lowers {
				t.Fatalf("lowers=%d want=%d", lowers, tc.lowers)
			}
			for _, path := range []string{"/proc/kcore", "/proc/acpi", "/sys/firmware"} {
				m, point, held := mt.lookup(path)
				if !held || !point || m.fstype != "tmpfs" && m.fstype != "devtmpfs" {
					t.Errorf("masked path not preserved: %s %+v", path, m)
				}
				if why := mt.controlFS(path); why != "" {
					t.Errorf("mask incorrectly treated as the covered kernel filesystem: %s", why)
				}
			}
			for _, path := range []string{"/proc", "/proc/sys", "/sys"} {
				if mt.controlFS(path) == "" {
					t.Errorf("unmasked kernel interface lost its refusal: %s", path)
				}
			}
			if strings.HasSuffix(tc.name, "-volume") {
				m, point, held := mt.lookup("/work/out")
				if !held || !point || m.dev != "253:1" || m.fstype != "ext4" || !strings.HasSuffix(m.root, "work-out-host") {
					t.Fatalf("captured bind volume lost: %+v", m)
				}
				if (strings.HasPrefix(tc.name, "docker-") || strings.HasPrefix(tc.name, "containerd-")) && !strings.Contains(data, " master:1 - ") {
					t.Error("capture lost its optional propagation field")
				}
			}
		})
	}
}

// The expected warning and advice are independent of the product formatter.
// TestCompileBackingWarningNamesProtectedFile pins the additional target words.
func backingWarningSummary(message string) string {
	summary, _, _ := strings.Cut(message, "; protected files: ")
	return summary
}

// The expected text is independent of the formatter in product code.
func runtimeBackingWarning(field, raw, mount, unplaced string) string {
	reason := ""
	if strings.HasPrefix(unplaced, "layers named relative") {
		reason = ", because the layers are named relative to a folder the mount table does not record"
	} else if unplaced != "" {
		reason = ", because " + unplaced + " does not establish which folder holds the files it shows"
	}
	advice := "do not mount the runtime's storage or the whole host filesystem at a place a contract may write"
	if unplaced != "" && !strings.HasPrefix(unplaced, "layers named relative") {
		advice = "keep the folder that stores the encrypted or mirrored files out of every write grant"
	}
	return fmt.Sprintf("fs.%s %q reaches mount %s and Tego cannot tell whether that mount shows the folders holding its protected files%s; %s", field, raw, mount, reason, advice)
}

func runtimeMountFixture(t *testing.T, name, home, host string) string {
	t.Helper()
	input, err := containerMountFixtures.ReadFile("testdata/container-mountinfo/" + name + ".mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, row := range strings.Split(strings.TrimSuffix(string(input), "\n"), "\n") {
		if !strings.HasPrefix(row, "#") {
			rows = append(rows, row)
		}
	}
	return strings.NewReplacer("@HOME@", home, "@HOST@", host,
		"/var/lib/docker", host+"/docker", "/var/lib/containerd", host+"/containerd",
		"/home/runner/.local/share/containers/storage", host+"/podman").Replace(strings.Join(rows, "\n") + "\n")
}

func TestCompileEncryptedHomeMountTables(t *testing.T) {
	for _, name := range []string{"home-gocryptfs", "home-ecryptfs"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			bin := filepath.Join(f.home, ".local", "bin")
			exe := filepath.Join(bin, "tego")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			f.file(exe, "tego", 0o755)
			table := runtimeMountFixture(t, name, f.home, filepath.Join(f.root, "absent-host"))
			fm := MountOf([]byte(table), exe)
			if !fm.Held || fm.Unmapped != map[string]string{"home-gocryptfs": "fuse.gocryptfs", "home-ecryptfs": "ecryptfs"}[name] {
				t.Fatalf("encrypted binary not on intended mount: %+v", fm)
			}
			if err := os.MkdirAll(fm.Source, 0o755); err != nil {
				t.Fatal(err)
			}
			disk := filepath.Join(f.project, "out")
			table += "40 1 8:2 /tenant-output " + disk + " rw - ext4 disk rw\n"
			mi := filepath.Join(f.root, "encrypted-mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				for _, entry := range []string{filepath.Join(f.home, "work"), disk, bin, filepath.Dir(bin), fm.Source} {
					if err := os.MkdirAll(entry, 0o755); err != nil {
						t.Fatal(err)
					}
					body := "version: 0\nname: enc\ncommand: [python]\nfs: {" + field + ": [\"" + entry + "/\"]}\n"
					opts := []CompileOption{WithOwnBinaries(exe), WithMountInfo(mi), withInstallDirs()}
					if entry == fm.Source {
						wantRefused(t, f, f.load(body), "backing folder", opts...)
						continue
					}
					if entry == bin || entry == filepath.Dir(bin) {
						wantRefused(t, f, f.load(body), "the tego binary", opts...)
						continue
					}
					_, ds, err := Compile(f.load(body), f.machine, f.opts(opts...)...)
					if err != nil {
						t.Fatalf("ordinary %s %s refused: %v\n%s", field, entry, err, render(ds))
					}
					var got, want []string
					for _, d := range ds {
						if d.Code == CodeOverlayBackingUnknown {
							if d.Severity != SeverityWarning {
								t.Errorf("backing diagnostic is not a warning: %+v", d)
							}
							got = append(got, backingWarningSummary(d.Message))
						}
					}
					if entry == disk {
						want = []string{runtimeBackingWarning(field, entry+"/", disk, fm.Unmapped)}
					}
					if !slices.Equal(got, want) {
						t.Errorf("%s %s warnings=%q want=%q", field, entry, got, want)
					}
				}
			}
		})
	}
}

func TestCompileMixedRelativeLayers(t *testing.T) {
	for _, option := range []string{
		"lowerdir=relative/lower:@HOST@/visible",
		"lowerdir=@HOST@/visible:relative/lower",
		"lowerdir+=relative/lower,lowerdir+=@HOST@/visible",
		"lowerdir=relative/lower,upperdir=@HOST@/visible,workdir=relative/work",
	} {
		t.Run(option, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			layer := filepath.Join(f.root, "layers", "visible")
			alias := filepath.Join(f.project, "out", "storage")
			for _, d := range []string{layer, alias} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			table := runtimeMountFixture(t, "overlay-mixed-relative", f.home, filepath.Dir(layer))
			first := strings.SplitN(table, "\n", 2)[0]
			table = strings.Replace(table, first, "1 0 0:73 / / rw - overlay overlay rw,"+strings.ReplaceAll(option, "@HOST@", strings.ReplaceAll(escapeMount(filepath.Dir(layer)), ",", `\054`)), 1)
			// A different-device disk holds the absolute layer. A bind exposes it
			// beneath an ordinary output name; neither relative ordering may hide it.
			table += fmt.Sprintf("40 1 8:2 / %s rw - ext4 disk rw\n41 1 8:2 /visible %s rw - ext4 disk rw\n", filepath.Dir(layer), alias)
			mi := filepath.Join(f.root, "mixed-mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			fm := MountOf([]byte(table), exe)
			if !slices.Contains(fm.Layers, layer) {
				t.Errorf("absolute layer disappeared: %+v", fm)
			}
			for _, field := range []string{"write", "ask"} {
				for _, entry := range []string{layer, alias} {
					c := f.load(strings.Replace(writeSection(entry), "write:", field+":", 1))
					wantRefused(t, f, c, "a layer of the overlay holding tego's binaries", WithMountInfo(mi), WithOwnBinaries(exe))
				}
			}
		})
	}
}

func TestCompileRelativeLayersKeepMalformedRefusals(t *testing.T) {
	for _, option := range []string{
		"lowerdir=relative/lower:../escape",
		"lowerdir=relative/lower:/data/link/../lower",
		"lowerdir+=relative/lower,datadir+=../escape",
		`lowerdir=relative/lower,upperdir=/data/up\134per`,
		`lowerdir=relative/lower,workdir=relative/work\134dir`,
		"lowerdir=relative/lower,upperdir=../upper",
		"lowerdir=relative/lower,workdir=../work",
		"lowerdir+=",
		"lowerdir=relative/lower,upperdir=",
	} {
		t.Run(option, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			mi := fakeMountInfo(f, "1 0 0:73 / / rw - overlay overlay rw,"+option)
			why := "parent path component"
			if strings.HasSuffix(option, "=") {
				why = "empty layer path"
			}
			if strings.Contains(option, `\134`) {
				why = "ambiguous overlay quoting"
			}
			for _, field := range []string{"write", "ask"} {
				c := f.load(strings.Replace(writeSection(filepath.Join(f.project, "out")), "write:", field+":", 1))
				wantRefused(t, f, c, why, mi, WithOwnBinaries(exe))
			}
		})
	}
}

func TestCompileUnplacedBackingOnAnotherBinaryFilesystem(t *testing.T) {
	for _, fs := range []string{"fuse.bindfs", "fuse.gocryptfs", "ecryptfs", "overlay"} {
		t.Run(fs, func(t *testing.T) {
			f := newFixture(t)
			rootExe := filepath.Join(ownInstall(f), "tego")
			homeBin := filepath.Join(f.home, ".local", "bin")
			if err := os.MkdirAll(homeBin, 0o755); err != nil {
				t.Fatal(err)
			}
			f.file(filepath.Join(homeBin, "tego"), "second", 0o755)
			opts := "rw"
			if fs == "overlay" {
				opts = "rw,lowerdir=relative/lower,upperdir=relative/upper,workdir=relative/work"
			}
			table := "1 0 0:73 / / rw - overlay overlay rw,lowerdir=/absent-root/lower\n" +
				"2 1 0:80 / " + f.home + " rw - " + fs + " opaque " + opts + "\n"
			mi := filepath.Join(f.root, "multiple-mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				entry := filepath.Join(f.project, "out")
				c := f.load(strings.Replace(writeSection(entry), "write:", field+":", 1))
				_, ds, err := Compile(c, f.machine, f.opts(WithOwnBinaries(rootExe), WithPATH(f.bin+":"+homeBin), WithMountInfo(mi), withInstallDirs())...)
				if err != nil {
					t.Fatalf("ordinary grant refused: %v\n%s", err, render(ds))
				}
				var got []string
				for _, d := range ds {
					if d.Code == CodeOverlayBackingUnknown {
						if d.Severity != SeverityWarning {
							t.Errorf("backing diagnostic is not a warning: %+v", d)
						}
						got = append(got, backingWarningSummary(d.Message))
					}
				}
				reason := fs
				if fs == "overlay" {
					reason = "layers named relative to a folder the mount table does not record"
				}
				want := []string{runtimeBackingWarning(field, entry, "/", reason)}
				if !slices.Equal(got, want) {
					t.Errorf("another binary's filesystem hid unplaced backing: got=%q want=%q", got, want)
				}
			}
		})
	}
}

func TestCompileNestedUnplacedBacking(t *testing.T) {
	for _, fs := range []string{"overlay", "fuse", "fuseblk", "fuse.sshfs", "fuse.gocryptfs", "ecryptfs", "aufs", "shiftfs"} {
		t.Run(fs, func(t *testing.T) {
			f := newFixture(t)
			bin := ownInstall(f)
			layer := filepath.Join(f.root, "layer")
			if err := os.MkdirAll(layer, 0o755); err != nil {
				t.Fatal(err)
			}
			options := "rw"
			reason := fs
			if fs == "overlay" {
				options = "rw,lowerdir=relative/lower,upperdir=relative/upper,workdir=relative/work"
				reason = "layers named relative to a folder the mount table does not record"
			}
			mi := fakeMountInfo(f,
				"2 1 0:73 / "+bin+" rw - overlay overlay rw,lowerdir="+layer,
				"3 1 0:80 / "+layer+" rw - "+fs+" opaque "+options)
			for _, field := range []string{"write", "ask"} {
				entry := filepath.Join(f.project, "out")
				c := f.load(strings.Replace(writeSection(entry), "write:", field+":", 1))
				_, ds, err := Compile(c, f.machine, f.opts(mi, WithOwnBinaries(filepath.Join(bin, "tego")), withInstallDirs())...)
				if err != nil {
					t.Fatalf("ordinary nested backing grant refused: %v\n%s", err, render(ds))
				}
				var got []string
				for _, d := range ds {
					if d.Code == CodeOverlayBackingUnknown {
						if d.Severity != SeverityWarning {
							t.Errorf("backing diagnostic is not a warning: %+v", d)
						}
						got = append(got, backingWarningSummary(d.Message))
					}
				}
				want := []string{runtimeBackingWarning(field, entry, "/", reason)}
				if !slices.Equal(got, want) {
					t.Errorf("nested backing warnings=%q want=%q", got, want)
				}
				wantRefused(t, f, f.load(strings.Replace(writeSection(layer), "write:", field+":", 1)), "a layer of the overlay holding tego's binaries", mi, WithOwnBinaries(filepath.Join(bin, "tego")), withInstallDirs())
			}
		})
	}
}

func TestCompileUnplacedBackingOnMemoryFilesystem(t *testing.T) {
	for _, name := range []string{"docker-many-layers", "podman-fuse-overlayfs"} {
		for _, memory := range []string{"tmpfs", "ramfs", "hugetlbfs", "devtmpfs"} {
			t.Run(name+"/"+memory, func(t *testing.T) {
				f := newFixture(t)
				exe := filepath.Join(ownInstall(f), "tego")
				out := filepath.Join(f.project, "out")
				table := runtimeMountFixture(t, name, f.home, filepath.Join(f.root, "absent-host"))
				root := strings.SplitN(table, "\n", 2)[0]
				rootMount, _ := parseMountLine(root)
				table = root + "\n40 " + rootMount.id + " 0:90 / " + out + " rw - " + memory + " memory rw\n"
				mi := filepath.Join(f.root, "memory-mountinfo")
				if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
					t.Fatal(err)
				}

				for _, field := range []string{"write", "ask"} {
					c := f.load(strings.Replace(writeSection(out), "write:", field+":", 1))
					_, ds, err := Compile(c, f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi), withInstallDirs())...)
					if err != nil {
						t.Fatalf("ordinary memory-backed output refused: %v\n%s", err, render(ds))
					}
					var got []string
					for _, d := range ds {
						if d.Code == CodeOverlayBackingUnknown {
							if d.Severity != SeverityWarning {
								t.Errorf("backing diagnostic is not a warning: %+v", d)
							}
							got = append(got, backingWarningSummary(d.Message))
						}
					}
					if len(got) != 0 {
						t.Errorf("C65 memory limit: got=%q want zero backing warnings", got)
					}
				}
			})
		}
	}
}

func TestCompileUnplacedBackingDoesNotWarnForNullDevice(t *testing.T) {
	for _, name := range []string{"docker-many-layers", "podman-fuse-overlayfs"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			table := runtimeMountFixture(t, name, f.home, filepath.Join(f.root, "absent-host"))
			mi := filepath.Join(f.root, "null-mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				c := f.load(strings.Replace(writeSection("/dev/null"), "write:", field+":", 1))
				_, ds, err := Compile(c, f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
				if err != nil {
					t.Fatalf("null-device grant refused: %v\n%s", err, render(ds))
				}
				for _, d := range ds {
					if d.Code == CodeOverlayBackingUnknown {
						t.Errorf("character device got backing warning: %v", d)
					}
				}
			}
		})
	}
}

func TestEncryptedHomeSourceFixtures(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"home-ecryptfs", "/host/ecryptfs/.Private"},
		{"home-gocryptfs", "/host/gocryptfs/cipher"},
		{"home-fuse-nonpath", "user@server:/home"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := runtimeMountFixture(t, tc.name, "/home/fixture", "/host")
			fm := MountOf([]byte(data), "/home/fixture/.local/bin/tego")
			if !fm.Held || fm.Source != tc.source || unplacedBacking(fm.Unmapped) == "" {
				t.Fatalf("source fixture: %+v want %s", fm, tc.source)
			}
		})
	}
}

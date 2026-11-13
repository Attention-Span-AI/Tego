// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMountUnlinkedRootSpelling(t *testing.T) {
	for _, root := range []string{"/gone//deleted", "/gone\\040name//deleted", "/deleted", "/has/deleted/name", "/has//deleted/name", "/has//deleted//deleted", "//deleted", "/gone/../name//deleted", "/gone///deleted", "/gone//deleted/", "relative//deleted"} {
		t.Run(root, func(t *testing.T) {
			want := root == "/gone//deleted" || root == "/gone\\040name//deleted" || root == "/deleted" || root == "/has/deleted/name"
			_, ok := parseMountRecord("2 1 8:1 " + root + " /bound rw - ext4 disk rw")
			if ok != want {
				t.Fatalf("root %q accepted=%v want=%v", root, ok, want)
			}
		})
	}
	valid := "1 0 8:1 / / rw - ext4 disk rw\n2 1 8:1 /gone//deleted /bound rw - ext4 disk rw\n"
	for _, bad := range []string{"3 1 8:1 / /else rw - ext4 disk", "2 1 8:1 / /else rw - ext4 disk rw", "3 99 8:1 / /else rw - ext4 disk rw", "3 1 08:1 / /else rw - ext4 disk rw", "3 1 8:1 /dirty/../root /else rw - ext4 disk rw"} {
		if mt, err := ParseMountTableStrict([]byte(valid + bad + "\n")); err == nil || mt != nil {
			t.Errorf("unlinked root excused other malformed row %q: %v", bad, err)
		}
	}
}

func TestCompileUnlinkedFileIdentity(t *testing.T) {
	for _, content := range []string{"", "protected bytes"} {
		for _, same := range []bool{true, false} {
			t.Run(fmt.Sprintf("empty=%v/same-inode=%v", content == "", same), func(t *testing.T) {
				f := newFixture(t)
				protected := filepath.Join(f.root, "protected.yaml")
				f.file(protected, content, 0o600)
				f.machine.Layers = []string{protected}
				point := filepath.Join(f.project, "out", "bound")
				oldName := filepath.Join(f.root, "unlinked-name")
				if same {
					if err := os.Link(protected, oldName); err != nil {
						t.Fatal(err)
					}
				} else {
					f.file(oldName, content, 0o600) // Same bytes alone are not identity on a placed filesystem.
				}
				if err := os.Link(oldName, point); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(oldName); err != nil {
					t.Fatal(err)
				}
				table := fmt.Sprintf("1 0 8:1 / / rw - ext4 disk rw\n2 1 8:1 %s//deleted %s rw - ext4 disk rw\n", oldName, point)
				replayBackingMountIDs(t, table)
				mi := filepath.Join(f.root, "mountinfo")
				if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"write", "ask"} {
					for _, grant := range []string{point, filepath.Dir(point) + "/"} {
						_, ds, err := Compile(f.load(strings.Replace(writeSection(grant), "write:", field+":", 1)), f.machine, f.opts(WithMountInfo(mi))...)
						if same {
							if err == nil || !strings.Contains(render(ds), "same device and inode") || !strings.Contains(render(ds), protected) {
								t.Errorf("hard-link alias admitted or wrong reason: %v\n%s", err, render(ds))
							}
						} else if err != nil || backingCount(ds) != 0 {
							t.Errorf("different inode refused/warned: %v\n%s", err, render(ds))
						}
					}
				}
			})
		}
	}
}

func TestCompileUnlinkedDirectoryAndUnknownType(t *testing.T) {
	for _, kind := range []string{"directory", "regular", "wrong mount", "missing type", "missing inode", "missing mount id", "stat failure", "symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			point := filepath.Join(f.project, "out", "bound")
			switch kind {
			case "directory":
				if err := os.Mkdir(point, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(f.home, point); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(point, 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				f.file(point, "ordinary", 0o600)
			}
			// The former directory name lies below a protected tree. It is no longer a tree alias.
			table := fmt.Sprintf("1 0 8:1 / / rw - ext4 disk rw\n2 1 8:1 %s/gone//deleted %s rw - ext4 disk rw\n", filepath.Join(f.home, ".tego"), point)
			replayBackingMountIDs(t, table)
			old := statBackingFile
			statBackingFile = func(fd int, p string, flags, mask int, st *unix.Statx_t) error {
				err := old(fd, p, flags, mask, st)
				if p == point {
					switch kind {
					case "wrong mount":
						st.Mnt_id++
					case "missing type":
						st.Mask &^= unix.STATX_TYPE
					case "missing inode":
						st.Mask &^= unix.STATX_INO
					case "missing mount id":
						st.Mask &^= unix.STATX_MNT_ID
					case "stat failure":
						return unix.EACCES
					}
				}
				return err
			}
			mi := filepath.Join(f.root, "mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				_, ds, err := Compile(f.load(strings.Replace(writeSection(filepath.Dir(point)), "write:", field+":", 1)), f.machine, f.opts(WithMountInfo(mi))...)
				if kind == "regular" {
					if err != nil || backingCount(ds) != 0 {
						t.Errorf("ordinary unlinked %s refused: %v\n%s", kind, err, render(ds))
					}
				} else if err == nil || !strings.Contains(render(ds), "cannot classify the unlinked-root mount") {
					t.Errorf("unknown unlinked content admitted: %v\n%s", err, render(ds))
				}
			}
			mt, err := ParseMountTableStrict([]byte(table))
			if err != nil {
				t.Fatal(err)
			}
			fm := mt.Of(filepath.Join(f.home, ".tego"))
			if len(fm.Aliases) != 0 || len(fm.Beneath) != 0 {
				t.Errorf("unlinked name used as tree alias: %+v", fm)
			}
		})
	}
}

func TestCompileUnlinkedProtectedBackingWarns(t *testing.T) {
	for _, dev := range []string{"8:1", "8:2"} {
		for _, fs := range []string{"ext4", "tmpfs", "ramfs"} {
			t.Run(dev+"/"+fs, func(t *testing.T) {
				f := newFixture(t)
				policy := filepath.Join(f.root, "protected.yaml")
				f.file(policy, "protected bytes", 0o600)
				f.machine.Layers = []string{policy}
				out := filepath.Join(f.project, "out")
				mi := fakeMountInfo(f, "2 1 "+dev+" /gone//deleted "+policy+" rw - ext4 disk rw",
					"3 1 0:99 /output "+out+" rw - "+fs+" storage rw")
				// The plain-root grant also checks that the protected file's own
				// filesystem cannot hide the unknown surviving name.
				for _, grant := range []string{out, filepath.Join(f.project, "work")} {
					for _, field := range []string{"write", "ask"} {
						_, ds, err := Compile(f.load(strings.Replace(writeSection(grant), "write:", field+":", 1)), f.machine, f.opts(mi)...)
						if err != nil || backingCount(ds) != 1 || !strings.Contains(render(ds), "unlinked root") || !strings.Contains(render(ds), policy) {
							t.Errorf("unplaced protected backing lost warning: %v\n%s", err, render(ds))
						}
					}
				}
			})
		}
	}
}

func TestCompileCapturedNspawnProtectedGrants(t *testing.T) {
	f := newFixture(t)
	exe := filepath.Join(ownInstall(f), "tego")
	data, err := os.ReadFile("testdata/chroot-mountinfo/nspawn.mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(f.project, "out", "alias")
	if err := os.Mkdir(alias, 0o700); err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte(fmt.Sprintf("9000 344 253:1 /srv/d%s %s rw - ext4 disk rw\n", filepath.Dir(exe), alias))...)
	mi := filepath.Join(f.root, "mountinfo")
	if err := os.WriteFile(mi, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"write", "ask"} {
		for _, grant := range []string{filepath.Dir(exe), alias} {
			wantRefused(t, f, f.load(strings.Replace(writeSection(grant), "write:", field+":", 1)), "the tego binary", WithOwnBinaries(exe), WithMountInfo(mi))
		}
	}
	data = append(data, []byte("9001 344 8:1 /malformed/../root /else rw - ext4 disk rw\n")...)
	if err := os.WriteFile(mi, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"write", "ask"} {
		wantRefused(t, f, f.load(strings.Replace(writeSection(filepath.Join(f.project, "out")), "write:", field+":", 1)), "mount table cannot be read whole", WithMountInfo(mi))
	}
}

func TestCompileUnlinkedFileOnUnplacedBacking(t *testing.T) {
	for _, fs := range []string{"overlay", "fuse.gocryptfs", "ecryptfs"} {
		for _, content := range []string{"identical", "different", "empty", "both empty"} {
			t.Run(fs+"/"+content, func(t *testing.T) {
				f := newFixture(t)
				exe := filepath.Join(ownInstall(f), "tego")
				point := filepath.Join(f.project, "out", "bound")
				data := "tego"
				if content == "different" {
					data = "different"
				}
				if content == "empty" || content == "both empty" {
					data = ""
				}
				if content == "both empty" {
					f.file(exe, "", 0o755)
				}
				f.file(point, data, 0o600)
				root := "1 0 0:73 / / rw - overlay overlay rw,lowerdir=relative/lower\n"
				if fs != "overlay" {
					root = fmt.Sprintf("1 0 8:1 / / rw - ext4 disk rw\n3 1 0:73 / %s rw - %s opaque rw\n", filepath.Dir(exe), fs)
				}
				table := root + fmt.Sprintf("2 1 8:2 /gone//deleted %s rw - ext4 disk rw\n", point)
				replayBackingMountIDs(t, table)
				mi := filepath.Join(f.root, "mountinfo")
				if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"write", "ask"} {
					_, ds, err := Compile(f.load(strings.Replace(writeSection(point), "write:", field+":", 1)), f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
					if content == "identical" {
						if err == nil || !strings.Contains(render(ds), "byte-identical alias") {
							t.Errorf("unplaced alias admitted: %v\n%s", err, render(ds))
						}
						continue
					}
					want := 1
					if fs == "overlay" && content != "both empty" {
						want = 0
					}
					if err != nil || backingCount(ds) != want {
						t.Errorf("unplaced %s: err=%v warnings=%d want=%d\n%s", content, err, backingCount(ds), want, render(ds))
					}
				}
			})
		}
	}
}

// The populated directory models a retained FUSE directory after its original
// dentry is unhashed. No emptiness or link-count inference is valid here.
func TestCompileUnlinkedPopulatedDirectory(t *testing.T) {
	f := newFixture(t)
	point := filepath.Join(f.project, "out", "bound")
	if err := os.Mkdir(point, 0o700); err != nil {
		t.Fatal(err)
	}
	content := filepath.Join(point, "protected.yaml")
	f.file(content, "protected bytes", 0o600)
	protected := filepath.Join(f.root, "protected.yaml")
	if err := os.Link(content, protected); err != nil {
		t.Fatal(err)
	}
	f.machine.Layers = []string{protected}
	table := fmt.Sprintf("1 0 8:1 / / rw - ext4 disk rw\n2 1 8:1 /gone//deleted %s rw - ext4 disk rw\n3 1 8:1 /retained/protected.yaml %s rw - ext4 disk rw\n", point, protected)
	replayBackingMountIDs(t, table)
	mi := filepath.Join(f.root, "mountinfo")
	if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"write", "ask"} {
		for _, grant := range []string{point, filepath.Dir(point), filepath.Join(point, "new-file")} {
			_, ds, err := Compile(f.load(strings.Replace(writeSection(grant), "write:", field+":", 1)), f.machine, f.opts(WithMountInfo(mi))...)
			if err == nil || !strings.Contains(render(ds), "cannot classify the unlinked-root mount") {
				t.Errorf("%s %s admitted populated unlinked directory: %v\n%s", field, grant, err, render(ds))
			}
		}
		// The uncertainty is local to grants reaching the directory.
		_, ds, err := Compile(f.load(strings.Replace(writeSection(filepath.Join(f.project, "work")), "write:", field+":", 1)), f.machine, f.opts(WithMountInfo(mi))...)
		if err != nil {
			t.Errorf("unrelated grant refused: %v\n%s", err, render(ds))
		}
	}
}

func TestUnlinkedProtectedIdentity(t *testing.T) {
	for _, fault := range []string{"EIO", "mount mismatch", "missing mount id", "missing type", "missing inode", "lookup failure", "absent", "not directory", "directory", "different inode", "same inode"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			protected := filepath.Join(f.root, "protected.yaml")
			point := filepath.Join(f.project, "out", "bound")
			if fault == "directory" {
				if err := os.Mkdir(protected, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				f.file(protected, "protected bytes", 0o600)
			}
			if fault == "same inode" {
				if err := os.Link(protected, point); err != nil {
					t.Fatal(err)
				}
			} else {
				f.file(point, "ordinary", 0o600)
			}
			table := fmt.Sprintf("1 0 8:1 / / rw - ext4 disk rw\n2 1 8:1 /gone//deleted %s rw - ext4 disk rw\n", point)
			replayBackingMountIDs(t, table)
			mt, err := ParseMountTableStrict([]byte(table))
			if err != nil {
				t.Fatal(err)
			}
			if fault == "lookup failure" {
				mt.t.uncertainPoints[protected] = "injected lookup failure after earlier placement"
			}
			old := statBackingFile
			protectedReads := 0
			statBackingFile = func(fd int, p string, flags, mask int, st *unix.Statx_t) error {
				err := old(fd, p, flags, mask, st)
				if p != protected {
					return err
				}
				protectedReads++
				if flags&unix.AT_SYMLINK_NOFOLLOW == 0 {
					t.Error("protected statx follows symlinks")
				}
				switch fault {
				case "EIO":
					return unix.EIO
				case "absent":
					return unix.ENOENT
				case "not directory":
					return unix.ENOTDIR
				case "mount mismatch":
					st.Mnt_id++
				case "missing mount id":
					st.Mask &^= unix.STATX_MNT_ID
				case "missing type":
					st.Mask &^= unix.STATX_TYPE
				case "missing inode":
					st.Mask &^= unix.STATX_INO
				}
				return err
			}
			for _, grant := range []string{point, filepath.Dir(point)} {
				k := compiler{}
				k.checkUnlinkedMounts(&mt.t, []writeTarget{{name: "the protected config", path: protected, placed: true}}, Pos{}, grant, grant)
				text := render(k.ds.list)
				switch fault {
				case "absent", "not directory", "directory", "different inode":
					if len(k.ds.list) != 0 {
						t.Errorf("established non-alias refused: %s", text)
					}
				case "same inode":
					if !strings.Contains(text, "same device and inode") {
						t.Errorf("alias not refused: %s", text)
					}
				default:
					if !strings.Contains(text, "cannot establish the protected file identity") || !strings.Contains(text, protected) {
						t.Errorf("protected identity uncertainty skipped: %s", text)
					}
				}
			}
			if fault != "lookup failure" && protectedReads == 0 {
				t.Error("protected identity was not read under its snapshot mount id")
			}
		})
	}
}

func TestMountUnlinkedDirectoryUncertainty(t *testing.T) {
	for _, kind := range []string{"directory", "regular", "unknown", "different device"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			point := filepath.Join(f.project, "out", "bound")
			dev := "8:1"
			if kind == "regular" {
				f.file(point, "ordinary", 0o600)
			} else if err := os.Mkdir(point, 0o700); err != nil {
				t.Fatal(err)
			}
			if kind == "different device" {
				dev = "8:2"
			}
			table := fmt.Sprintf("1 0 8:1 / / rw - ext4 disk rw\n2 1 %s /gone//deleted %s rw - ext4 disk rw\n", dev, point)
			replayBackingMountIDs(t, table)
			if kind == "unknown" {
				old := statBackingFile
				statBackingFile = func(fd int, p string, flags, mask int, st *unix.Statx_t) error {
					if p == point {
						return unix.EIO
					}
					return old(fd, p, flags, mask, st)
				}
			}
			mt, err := ParseMountTableStrict([]byte(table))
			if err != nil {
				t.Fatal(err)
			}
			wantKnown := kind == "regular" || kind == "different device"
			for _, query := range []func(string) ([]string, bool){mt.TreeAliases, mt.DetachedParts} {
				if names, ok := query(f.home); ok != wantKnown {
					t.Errorf("alias certainty=%v names=%v want=%v", ok, names, wantKnown)
				}
			}
			_, _, reason := mt.AliasDetails(f.home)
			if (reason == "") != wantKnown || (!wantKnown && !strings.Contains(reason, point)) {
				t.Errorf("alias uncertainty reason=%q wantKnown=%v mount=%q", reason, wantKnown, point)
			}
			if !mt.t.bindExposed(f.home) && !wantKnown {
				t.Error("unplaced directory discarded from scope exposure")
			}
			if points := mt.t.pointsOf(f.home); kind == "directory" && len(points) != 2 {
				t.Errorf("hard-link candidates discard directory: %v", points)
			}
		})
	}
}

func TestUnlinkedDirectoryBackingWarning(t *testing.T) {
	f := newFixture(t)
	point := filepath.Join(f.project, "out", "bound")
	if err := os.Mkdir(point, 0o700); err != nil {
		t.Fatal(err)
	}
	table := fmt.Sprintf("1 0 8:1 / / rw - ext4 disk rw\n2 1 8:2 /gone//deleted %s rw - ext4 disk rw\n", point)
	replayBackingMountIDs(t, table)
	mt, err := ParseMountTableStrict([]byte(table))
	if err != nil {
		t.Fatal(err)
	}
	k := compiler{}
	k.warnOverlayBacking(&mt.t, ownNames{absent: []string{"/unseen/layer"}}, Pos{}, point, point)
	if backingCount(k.ds.list) != 1 {
		t.Fatalf("unplaced directory lost backing uncertainty: %s", render(k.ds.list))
	}
}

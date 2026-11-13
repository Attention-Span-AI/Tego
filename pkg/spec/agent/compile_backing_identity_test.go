// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func backingCount(ds []Diagnostic) int {
	n := 0
	for _, d := range ds {
		if d.Code == CodeOverlayBackingUnknown {
			n++
		}
	}
	return n
}

// Replay snapshot IDs while reading real type, size and bytes. Product statx
// always checks the kernel's live mount ID; these fixtures need no mount syscall.
func replayBackingMountIDs(t *testing.T, table string) {
	t.Helper()
	ids := map[string]uint64{}
	for row := range strings.SplitSeq(strings.TrimSuffix(table, "\n"), "\n") {
		m, ok := parseMountLine(row)
		if ok {
			id, _ := strconv.ParseUint(m.id, 10, 64)
			ids[m.point] = id
		}
	}
	oldOpen := openBackingMountID
	t.Cleanup(func() { openBackingMountID = oldOpen })
	openBackingMountID = func(f *os.File, st *unix.Statx_t) error {
		if err := oldOpen(f, st); err != nil {
			return err
		}
		if id, ok := ids[f.Name()]; ok {
			st.Mnt_id = id
			st.Mask |= unix.STATX_MNT_ID
		}
		return nil
	}
	old := statBackingFile
	t.Cleanup(func() { statBackingFile = old })
	statBackingFile = func(fd int, p string, flags, mask int, st *unix.Statx_t) error {
		if err := unix.Statx(fd, p, flags, mask, st); err != nil {
			return err
		}
		if p == "" {
			var err error
			p, err = os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
			if err != nil {
				return err
			}
		}
		// Replay the holding mount for protected paths as well as mount roots.
		for at := filepath.Clean(p); ; at = filepath.Dir(at) {
			if id, ok := ids[at]; ok {
				st.Mnt_id = id
				st.Mask |= unix.STATX_MNT_ID
				break
			}
			if at == "/" || at == "." {
				break
			}
		}
		return nil
	}
}

func TestCompileAbsentPlusFuseBinaryGrantOnFuse(t *testing.T) {
	for _, fs := range []string{"ext4", "fuse.bindfs", "fuse.gocryptfs", "ecryptfs"} {
		t.Run(fs, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			bin, work := filepath.Join(f.home, ".local/bin"), filepath.Join(f.home, "work")
			for _, p := range []string{bin, work} {
				if err := os.MkdirAll(p, 0755); err != nil {
					t.Fatal(err)
				}
			}
			f.file(filepath.Join(bin, "tego"), "second", 0755)
			mi := fakeMountInfo(f, "1 0 0:73 / / rw - overlay overlay rw,lowerdir=/absent-root/lower", "2 1 0:80 / "+f.home+" rw - "+fs+" opaque rw")
			for _, field := range []string{"write", "ask"} {
				_, ds, err := Compile(f.load(strings.Replace(writeSection(work), "write:", field+":", 1)), f.machine, f.opts(WithOwnBinaries(exe), WithPATH(f.bin+":"+bin), mi, withInstallDirs())...)
				if err != nil || backingCount(ds) != 1 {
					t.Errorf("%s: err=%v backing=%d want 1\n%s", field, err, backingCount(ds), render(ds))
				}
			}
		})
	}
}

func TestCompileRelativeLayerFileBind(t *testing.T) {
	for _, protected := range []string{"binary", "non-executable target"} {
		for _, content := range []string{"identical", "one byte different", "last byte different", "size different"} {
			t.Run(protected+"/"+content, func(t *testing.T) {
				f := newFixture(t)
				exe := filepath.Join(ownInstall(f), "tego")
				target, why := exe, "the tego binary"
				mode := os.FileMode(0755)
				if protected != "binary" {
					target = filepath.Join(f.root, "policy.yaml")
					why = "the machine config"
					mode = 0644
					f.machine.Layers = []string{target}
				}
				bytes := strings.Repeat("protected bytes", 5000)
				f.file(target, bytes, mode)
				point := filepath.Join(f.project, "out", "binary-file")
				data := bytes
				if content == "one byte different" {
					data = "P" + bytes[1:]
				}
				if content == "last byte different" {
					data = bytes[:len(bytes)-1] + "!"
				}
				if content == "size different" {
					data = "different size"
				}
				f.file(point, data, mode)
				table := runtimeMountFixture(t, "docker-many-layers", f.home, filepath.Join(f.root, "absent-host"))
				root, _ := parseMountLine(strings.SplitN(table, "\n", 2)[0])
				table += fmt.Sprintf("9000 %s 253:1 /var/lib/docker/overlay2/278259b2aaaa/diff/usr/local/bin/tego %s rw - ext4 /dev/vda1 rw\n", root.id, point)
				replayBackingMountIDs(t, table)
				mi := filepath.Join(f.root, "file-mountinfo")
				if err := os.WriteFile(mi, []byte(table), 0600); err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"write", "ask"} {
					for _, grant := range []string{point, filepath.Dir(point) + "/"} {
						c := f.load(strings.Replace(writeSection(grant), "write:", field+":", 1))
						if content == "identical" {
							_, ds, err := Compile(c, f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
							found := false
							for _, d := range ds {
								found = found || d.Code == CodeContradiction && strings.Contains(d.Message, why) && strings.Contains(d.Message, target) && strings.Contains(d.Message, point)
							}
							if err == nil || !found {
								t.Errorf("identical file must refuse and name file %s and mount %s: %v\n%s", target, point, err, render(ds))
							}
							continue
						}
						_, ds, err := Compile(c, f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
						if err != nil || backingCount(ds) != 0 {
							t.Errorf("different file: err=%v backing=%d\n%s", err, backingCount(ds), render(ds))
						}
					}
				}
			})
		}
	}
}

func TestCompileProtectsEncryptedBackingSource(t *testing.T) {
	for _, fs := range []string{"fuse.gocryptfs", "fuse.bindfs", "ecryptfs"} {
		for _, kind := range []string{"directory", "absent", "file", "relative"} {
			t.Run(fs+"/"+kind, func(t *testing.T) {
				f := newFixture(t)
				bin := filepath.Join(f.home, ".local/bin")
				exe := filepath.Join(bin, "tego")
				homeWork := filepath.Join(f.home, "work")
				cipher := filepath.Join(f.root, "cipher")
				alias := filepath.Join(f.project, "out", "cipher-alias")
				for _, p := range []string{bin, homeWork, alias} {
					if err := os.MkdirAll(p, 0755); err != nil {
						t.Fatal(err)
					}
				}
				f.file(exe, "tego", 0755)
				source := cipher
				switch kind {
				case "directory":
					if err := os.MkdirAll(filepath.Join(cipher, "sub"), 0755); err != nil {
						t.Fatal(err)
					}
				case "file":
					f.file(cipher, "file", 0644)
				case "relative":
					source = "relative/cipher"
				}
				mi := fakeMountInfo(f, "2 1 0:80 / "+f.home+" rw - "+fs+" "+source+" rw", "3 1 8:1 "+cipher+" "+alias+" rw - ext4 disk rw")
				for _, field := range []string{"write", "ask"} {
					opts := []CompileOption{WithOwnBinaries(exe), mi, withInstallDirs()}
					body := func(p string) *Contract { return f.load(strings.Replace(writeSection(p), "write:", field+":", 1)) }
					_, ds, err := Compile(body(homeWork), f.machine, f.opts(opts...)...)
					if err != nil || backingCount(ds) != 0 {
						t.Fatalf("home grant refused/warned: %v\n%s", err, render(ds))
					}
					if kind == "directory" {
						for _, grant := range []string{cipher, filepath.Join(cipher, "sub"), alias} {
							wantRefused(t, f, body(grant), "backing folder", opts...)
						}
						continue
					}
					_, ds, err = Compile(body(filepath.Join(f.project, "out")), f.machine, f.opts(opts...)...)
					if err != nil || backingCount(ds) != 1 {
						t.Errorf("stale source trusted: err=%v backing=%d\n%s", err, backingCount(ds), render(ds))
					}
					for _, d := range ds {
						if d.Code == CodeOverlayBackingUnknown && (!strings.Contains(d.Message, "keep the folder that stores the encrypted or mirrored files out of every write grant") || strings.Contains(d.Message, "runtime's storage")) {
							t.Errorf("wrong unnamed-backing advice: %s", d.Message)
						}
					}
				}
			})
		}
	}
}

// C65: runtime storage on memory backing, also bound under a writable place,
// receives no backing warning. This is a stated limit, for both backing classes.
func TestCompileAbsentLayersStorageOnTmpfs(t *testing.T) {
	for _, name := range []string{"docker-small", "docker-many-layers", "podman-fuse-overlayfs"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			out := filepath.Join(f.project, "out")
			table := runtimeMountFixture(t, name, f.home, filepath.Join(f.root, "absent-host"))
			root, _ := parseMountLine(strings.SplitN(table, "\n", 2)[0])
			table += fmt.Sprintf("9000 %s 0:90 /docker %s rw - tmpfs tmpfs rw\n", root.id, out)
			mi := filepath.Join(f.root, "memory-mountinfo")
			if err := os.WriteFile(mi, []byte(table), 0600); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				_, ds, err := Compile(f.load(strings.Replace(writeSection(out), "write:", field+":", 1)), f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
				if err != nil || backingCount(ds) != 0 {
					t.Errorf("C65 memory limit: err=%v backing=%d\n%s", err, backingCount(ds), render(ds))
				}
			}
		})
	}
}

// The printed mountpoint can name something else after the snapshot. A regular
// file there exempts nothing unless the live nofollow identity/type/size agrees.
func TestCompileBackingFileSnapshotIdentity(t *testing.T) {
	for _, kind := range []string{"regular", "directory after snapshot", "symlink", "wrong mount", "no id", "no type", "no size", "read failure"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			out := filepath.Join(f.project, "out")
			point := filepath.Join(out, "bound")
			f.file(point, "ordinary", 0644)
			m := mount{id: "9000", parent: "1", dev: "8:2", root: "/storage", point: point, fstype: "ext4"}
			mt := &mountTable{probed: true, mounts: []mount{m, {id: "1", parent: "0", dev: "0:73", root: "/", point: "/", fstype: "overlay"}}}
			mt.order()
			mt.live = true
			old := statBackingFile
			t.Cleanup(func() { statBackingFile = old })
			statBackingFile = func(fd int, p string, flags, mask int, st *unix.Statx_t) error {
				if p != point || flags != unix.AT_SYMLINK_NOFOLLOW || mask != unix.STATX_MNT_ID|unix.STATX_TYPE|unix.STATX_SIZE {
					t.Fatalf("wrong snapshot probe %q flags=%x mask=%x", p, flags, mask)
				}
				*st = unix.Statx_t{Mask: unix.STATX_MNT_ID | unix.STATX_TYPE | unix.STATX_SIZE, Mode: unix.S_IFREG, Size: 8, Mnt_id: 9000}
				switch kind {
				case "directory after snapshot":
					st.Mode = unix.S_IFDIR
				case "symlink":
					st.Mode = unix.S_IFLNK
				case "wrong mount":
					st.Mnt_id++
				case "no id":
					st.Mask &^= unix.STATX_MNT_ID
				case "no type":
					st.Mask &^= unix.STATX_TYPE
				case "no size":
					st.Mask &^= unix.STATX_SIZE
				case "read failure":
					return errors.New("unreadable")
				}
				return nil
			}
			var k compiler
			k.warnOverlayBacking(mt, ownNames{absent: []string{"/absent/lower"}}, Pos{}, out, out)
			want := 1
			if kind == "regular" {
				want = 0
			}
			if got := backingCount(k.ds.list); got != want {
				t.Errorf("snapshot %s backing=%d want=%d: %s", kind, got, want, render(k.ds.list))
			}
		})
	}
}

func TestCompileProtectsNonExecutableBackingSource(t *testing.T) {
	for _, fs := range []string{"ecryptfs", "fuse.gocryptfs"} {
		t.Run(fs, func(t *testing.T) {
			f := newFixture(t)
			policy := filepath.Join(f.home, "config.yaml")
			source := filepath.Join(f.root, "cipher")
			f.file(policy, "protected policy", 0644)
			f.machine.Layers = []string{policy}
			if err := os.Mkdir(source, 0755); err != nil {
				t.Fatal(err)
			}
			mi := fakeMountInfo(f, "2 1 0:80 / "+f.home+" rw - "+fs+" "+source+" rw")
			for _, field := range []string{"write", "ask"} {
				wantRefused(t, f, f.load(strings.Replace(writeSection(source), "write:", field+":", 1)), "backing folder", mi)
			}
		})
	}
}

func TestCompileBackingFileComparisonStaysBounded(t *testing.T) {
	for _, replacement := range []string{"symlink", "FIFO", "directory"} {
		t.Run(replacement, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			point := filepath.Join(f.project, "out", "file")
			f.file(point, "tego", 0644)
			table := runtimeMountFixture(t, "docker-many-layers", f.home, filepath.Join(f.root, "absent-host"))
			root, _ := parseMountLine(strings.SplitN(table, "\n", 2)[0])
			table += fmt.Sprintf("9000 %s 8:2 /storage/file %s rw - ext4 disk rw\n", root.id, point)
			replayBackingMountIDs(t, table)
			previous := statBackingFile
			statBackingFile = func(fd int, p string, flags, mask int, st *unix.Statx_t) error {
				err := previous(fd, p, flags, mask, st)
				if err == nil && p == point {
					if err := os.Remove(point); err != nil {
						t.Fatal(err)
					}
					switch replacement {
					case "symlink":
						err = os.Symlink(exe, point)
					case "FIFO":
						err = unix.Mkfifo(point, 0644)
					case "directory":
						err = os.Mkdir(point, 0755)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				return err
			}
			mi := filepath.Join(f.root, "mounts")
			if err := os.WriteFile(mi, []byte(table), 0600); err != nil {
				t.Fatal(err)
			}
			_, ds, err := Compile(f.load(writeSection(filepath.Dir(point))), f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(mi))...)
			if err != nil || backingCount(ds) != 1 {
				t.Errorf("uncertain replacement: err=%v backing=%d\n%s", err, backingCount(ds), render(ds))
			}
		})
	}
}

func TestCompileRelativeFileAliasAfterWarning(t *testing.T) {
	f := newFixture(t)
	exe := filepath.Join(ownInstall(f), "tego")
	out := filepath.Join(f.project, "out")
	point := filepath.Join(out, "binary-file")
	f.file(point, "tego", 0755)
	mi := fakeMountInfo(f, "1 0 0:73 / / rw - overlay overlay rw,lowerdir=relative/lower", "2 1 8:2 /workspace "+out+" rw - ext4 disk rw", "3 2 8:3 /storage/tego "+point+" rw - ext4 disk rw")
	// Reading a different holding mount can warn before the nested file is seen.
	// That warning must not short-circuit a later protected-file alias refusal.
	data, err := os.ReadFile(filepath.Join(f.root, "mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	replayBackingMountIDs(t, string(data))
	for _, field := range []string{"write", "ask"} {
		wantRefused(t, f, f.load(strings.Replace(writeSection(out), "write:", field+":", 1)), "the tego binary", WithOwnBinaries(exe), mi)
	}
}

func TestCompileOrdinaryMemoryGrantsStayQuiet(t *testing.T) {
	for _, fs := range []string{"overlay", "fuse.gocryptfs", "ecryptfs"} {
		t.Run(fs, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			binaryMount := "1 0 0:73 / / rw - overlay overlay rw,lowerdir=relative/lower"
			if fs != "overlay" {
				binaryMount = "2 1 0:80 / " + filepath.Dir(exe) + " rw - " + fs + " opaque rw"
			}
			mi := fakeMountInfo(f, binaryMount, "3 1 0:90 / /tmp rw - tmpfs tmpfs rw", "4 1 0:91 / /dev/shm rw - tmpfs tmpfs rw", "5 1 0:92 / /run rw - tmpfs tmpfs rw")
			for _, p := range []string{"/tmp", "/dev/shm", "/run"} {
				for _, field := range []string{"write", "ask"} {
					_, ds, err := Compile(f.load(strings.Replace(writeSection(p), "write:", field+":", 1)), f.machine, f.opts(WithOwnBinaries(exe), mi)...)
					// /run still refuses its protected /run/tego host state; this test
					// isolates the shared memory-filesystem backing-warning rule (C65).
					if backingCount(ds) != 0 || p != "/run" && err != nil {
						t.Errorf("memory grant %s: err=%v backing=%d\n%s", p, err, backingCount(ds), render(ds))
					}
				}
			}
		})
	}
}

func TestCompileNestedUnplacedFileAlias(t *testing.T) {
	for _, fs := range []string{"fuse.bindfs", "overlay"} {
		t.Run(fs, func(t *testing.T) {
			f := newFixture(t)
			exe := filepath.Join(ownInstall(f), "tego")
			layer := filepath.Join(f.root, "visible-layer")
			out := filepath.Join(f.project, "out")
			point := filepath.Join(out, "binary-file")
			if err := os.Mkdir(layer, 0755); err != nil {
				t.Fatal(err)
			}
			f.file(point, "tego", 0755)
			opts := "rw"
			if fs == "overlay" {
				opts = "rw,lowerdir=relative/lower"
			}
			mi := fakeMountInfo(f, "2 1 0:73 / "+filepath.Dir(exe)+" rw - overlay overlay rw,lowerdir="+layer, "3 1 0:80 / "+layer+" rw - "+fs+" opaque "+opts, "4 1 8:2 /unrelated-host-spelling/tego "+point+" rw - ext4 disk rw")
			data, err := os.ReadFile(filepath.Join(f.root, "mountinfo"))
			if err != nil {
				t.Fatal(err)
			}
			replayBackingMountIDs(t, string(data))
			for _, field := range []string{"write", "ask"} {
				wantRefused(t, f, f.load(strings.Replace(writeSection(out), "write:", field+":", 1)), "the tego binary", WithOwnBinaries(exe), mi)
			}
		})
	}
}

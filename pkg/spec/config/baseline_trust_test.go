// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestBaselineSystemTrustWalk(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(*testing.T, string)
		bad    bool
		absent bool
	}{
		{"present good", nil, false, false},
		{"present empty", func(t *testing.T, root string) { writeFile(t, root+"/etc/tego", "config.yaml", "", 0o644) }, false, false},
		{"absent", func(t *testing.T, root string) {
			if err := os.Remove(root + "/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
		}, false, true},
		{"unreadable by users", func(t *testing.T, root string) {
			if err := os.Chmod(root+"/etc/tego/config.yaml", 0o600); err != nil {
				t.Fatal(err)
			}
		}, true, false},
		{"writable file", func(t *testing.T, root string) {
			if err := os.Chmod(root+"/etc/tego/config.yaml", 0o664); err != nil {
				t.Fatal(err)
			}
		}, true, false},
		{"writable parent", func(t *testing.T, root string) {
			if err := os.Chmod(root+"/etc/tego", 0o777); err != nil {
				t.Fatal(err)
			}
		}, true, false},
		{"writable ancestor", func(t *testing.T, root string) {
			if err := os.Chmod(root+"/etc", 0o775); err != nil {
				t.Fatal(err)
			}
		}, true, false},
		{"directory", func(t *testing.T, root string) {
			if err := os.Remove(root + "/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root+"/etc/tego/config.yaml", 0o755); err != nil {
				t.Fatal(err)
			}
		}, true, false},
		{"fifo", func(t *testing.T, root string) {
			if err := os.Remove(root + "/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(root+"/etc/tego/config.yaml", 0o644); err != nil {
				t.Fatal(err)
			}
		}, true, false},
		{"safe link", func(t *testing.T, root string) {
			if err := os.Rename(root+"/etc/tego/config.yaml", root+"/etc/tego/real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real", root+"/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
		}, false, false},
		{"safe absolute link", func(t *testing.T, root string) {
			if err := os.Rename(root+"/etc/tego/config.yaml", root+"/etc/tego/real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/tego/real", root+"/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
		}, false, false},
		{"link target before dotdot", func(t *testing.T, root string) {
			if err := os.Rename(root+"/etc/tego/config.yaml", root+"/etc/tego/real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/", root+"/etc/tego/top"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("top/../etc/tego/real", root+"/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
		}, false, false},
		{"link through writable placement", func(t *testing.T, root string) {
			if err := os.Mkdir(root+"/writable", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(root+"/etc/tego/config.yaml", root+"/writable/real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root+"/writable", 0o777); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/writable/real", root+"/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
		}, true, false},
		{"dangling link", func(t *testing.T, root string) {
			if err := os.Remove(root + "/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("missing", root+"/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
		}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := trustedDir(t)
			if err := os.Chmod(root, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(root+"/etc/tego", 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, root+"/etc/tego", "config.yaml", "baseline: {env: {deny: [TOKEN]}}", 0o644)
			if tc.setup != nil {
				tc.setup(t, root)
			}
			// Exercise the descriptor form against the same ordinary, special-file,
			// symlink, dot-dot, absence and writable-placement fixtures.
			verified, placementErr := OpenSystemFileAt(root, "/etc/tego/config.yaml", os.Getuid())
			var pinnedData []byte
			if verified != nil {
				var readErr error
				pinnedData, readErr = io.ReadAll(verified.File)
				closeErr := verified.Close()
				if readErr != nil || closeErr != nil {
					t.Fatalf("pinned read/close: %v / %v", readErr, closeErr)
				}
			}
			if (placementErr != nil) != (tc.bad || tc.absent) {
				t.Fatalf("descriptor placement bad=%v absent=%v: %v", tc.bad, tc.absent, placementErr)
			}
			data, absent, err := readSystemTrustedAt(root, "/etc/tego/config.yaml", os.Getuid(), os.Getuid(), MaxLayerSize)
			if tc.bad {
				if err == nil || absent {
					t.Fatalf("bad layer became valid/absent: %q %v %v", data, absent, err)
				}
				return
			}
			if err != nil || absent != tc.absent {
				t.Fatalf("%q %v %v", data, absent, err)
			}
			if string(pinnedData) != string(data) {
				t.Fatal("verified descriptor and config reader disagree on bytes")
			}

		})
	}
	// Policy checks on fstat facts, including root-owned empty baselines. No chown/root needed.
	for _, tc := range []struct {
		owner, mode uint32
		bad         bool
	}{{0, 0o644, false}, {1000, 0o644, true}, {0, 0o664, true}, {0, 0o646, true}} {
		if got := systemModeReason(&syscall.Stat_t{Uid: tc.owner, Mode: syscall.S_IFREG | tc.mode}, 0); (got != "") != tc.bad {
			t.Fatalf("%+v: %s", tc, got)
		}
	}
}

func TestBaselineSystemLinkOwnership(t *testing.T) {
	for _, owner := range []uint32{0, 1000} {
		st := &syscall.Stat_t{Uid: owner, Mode: syscall.S_IFLNK | 0o777}
		if got := systemOwnerReason(st, 0); (got != "") != (owner != 0) {
			t.Fatalf("link uid=%d: %s", owner, got)
		}
	}
}

func TestBaselineProductionSystemTrustAndDanglingLayers(t *testing.T) {
	path := writeFile(t, trustedDir(t), "system", "baseline: {}", 0o644)
	// Production checks the whole actual walk. The fixture is deliberately in a user-owned home.
	for _, mode := range []TrustMode{TrustAbort, TrustWarn} {
		m, ds, err := LoadSources(Sources{Etc: path}, "", os.Getuid(), mode)
		if mode == TrustWarn {
			if err != nil || m == nil || m.BaselineKnown() || m.baseline.Empty() || countCode(ds, CodeBaselineUnknown) != 1 {
				t.Fatalf("%v %v %v", m, ds, err)
			}
			continue
		}
		var ue *UntrustedError
		if !errors.As(err, &ue) || !strings.Contains(ue.Fix(), "root-owned") || strings.Contains(ue.Fix(), "root or you") {
			t.Fatalf("wrong system repair: %v", err)
		}
		if m != nil || !errors.Is(err, ErrUntrusted) || len(ds) != 0 {
			t.Fatalf("%v %v %v", m, ds, err)
		}
	}
	for _, layer := range []Layer{LayerUser, LayerEnvFile} {
		dir := trustedDir(t)
		link := filepath.Join(dir, "link")
		if err := os.Symlink("missing", link); err != nil {
			t.Fatal(err)
		}
		src := Sources{}
		if layer == LayerUser {
			src.User = link
		} else {
			src.EnvFile = link
		}
		if m, _, err := LoadSources(src, "", os.Getuid(), TrustAbort); err == nil || m != nil {
			t.Fatal("dangling layer became absent", err)
		}
	}
}

func TestBaselineDanglingAncestorIsNotAbsent(t *testing.T) {
	dir := trustedDir(t)
	if err := os.Symlink("missing", dir+"/parent"); err != nil {
		t.Fatal(err)
	}
	for _, layer := range []Layer{LayerUser, LayerEnvFile} {
		src := Sources{}
		if layer == LayerUser {
			src.User = dir + "/parent/config.yaml"
		} else {
			src.EnvFile = dir + "/parent/config.yaml"
		}
		if m, _, err := LoadSources(src, "", os.Getuid(), TrustAbort); err == nil || m != nil {
			t.Fatal("dangling ancestor became absence", err)
		}
	}
}

// Metadata checks exclude ancestor opens (I10). Their saved identity and authority must still
// describe the path after the layer is opened; a changed name is uncertainty, never a safe layer.
func TestBaselineSystemWalkRechecksPlacement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"ancestor mode", func(t *testing.T, root string) {
			if err := os.Chmod(root+"/etc", 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{"file mode", func(t *testing.T, root string) {
			if err := os.Chmod(root+"/etc/tego/config.yaml", 0o666); err != nil {
				t.Fatal(err)
			}
		}},
		{"ancestor name", func(t *testing.T, root string) {
			if err := os.Rename(root+"/etc/tego", root+"/moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root+"/etc/tego", 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, root+"/etc/tego", "config.yaml", "different", 0o644)
		}},
		{"file name", func(t *testing.T, root string) {
			writeFile(t, root+"/etc/tego", "replacement", "different", 0o644)
			if err := os.Rename(root+"/etc/tego/replacement", root+"/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
		}},
		{"link name", func(t *testing.T, root string) {
			if err := os.Symlink("other", root+"/etc/tego/replacement"); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(root+"/etc/tego/replacement", root+"/etc/tego/config.yaml"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := trustedSystemRoot(t)
			if tc.name == "link name" {
				if err := os.Rename(root+"/etc/tego/config.yaml", root+"/etc/tego/real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("real", root+"/etc/tego/config.yaml"); err != nil {
					t.Fatal(err)
				}
			}
			walk, absent, err := inspectSystemLayer(root, "/etc/tego/config.yaml", os.Getuid())
			if err != nil || absent {
				t.Fatalf("inspect: absent=%v, err=%v", absent, err)
			}
			tc.mutate(t, root)
			if err := walk.recheck(); !errors.Is(err, ErrUntrusted) {
				t.Fatalf("changed placement recheck = %v, want ErrUntrusted", err)
			}
		})
	}
}

func TestBaselineSystemWalkRechecksAbsence(t *testing.T) {
	root := trustedSystemRoot(t)
	if err := os.Remove(root + "/etc/tego/config.yaml"); err != nil {
		t.Fatal(err)
	}
	walk, absent, err := inspectSystemLayer(root, "/etc/tego/config.yaml", os.Getuid())
	if err != nil || !absent {
		t.Fatalf("inspect: absent=%v, err=%v", absent, err)
	}
	writeFile(t, root+"/etc/tego", "config.yaml", "appeared", 0o644)
	if err := walk.recheck(); err == nil || !strings.Contains(err.Error(), "name appeared") {
		t.Fatalf("appeared layer recheck = %v, want an absence error", err)
	}
}

func trustedSystemRoot(t *testing.T) string {
	t.Helper()
	root := trustedDir(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root+"/etc/tego", 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root+"/etc/tego", "config.yaml", "baseline: {env: {deny: [TOKEN]}}", 0o644)
	return root
}

// These descriptor-stat fixtures model ownership without chown or root tests.
func TestSystemAccountOwnership(t *testing.T) {
	for _, path := range []string{"/etc/group", "/etc/target", "/etc", "/"} {
		t.Run(path, func(t *testing.T) {
			st := &syscall.Stat_t{Uid: 1000, Mode: syscall.S_IFREG | 0644}
			if why := systemModeReason(st, 0); !strings.Contains(why, "not root-owned") {
				t.Fatalf("%s accepted non-root owner: %q", path, why)
			}
			st.Uid = 0
			if why := systemModeReason(st, 0); why != "" {
				t.Fatal(why)
			}
		})
	}
}

func TestSystemFilePinnedRecheck(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root+"/etc", 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root+"/etc", "group", "test\n", 0644)
	f, err := OpenSystemFileAt(root, "/etc/group", os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Chmod(root+"/etc", 0775); err != nil {
		t.Fatal(err)
	}
	if err := f.Recheck(); err == nil {
		t.Fatal("accepted changed pinned ancestor")
	}
}

// Real file/link layout with controlled uid facts avoids chown and root tests.
func TestSystemAccountForeignOwnerFixtures(t *testing.T) {
	for _, linked := range []bool{false, true} {
		t.Run(fmt.Sprintf("symlink=%v", linked), func(t *testing.T) {
			root := trustedSystemRoot(t)
			target := root + "/etc/tego/config.yaml"
			account := "/etc/tego/config.yaml"
			if linked {
				target = root + "/etc/tego/user-owned"
				if err := os.Rename(root+account, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("user-owned", root+account); err != nil {
					t.Fatal(err)
				}
			}
			observed := false
			f, err := openSystemFileAt(root, account, os.Getuid(), func(path string, st *syscall.Stat_t) *syscall.Stat_t {
				copy := *st
				if path == target {
					observed = true
					copy.Uid = uint32(os.Getuid() + 1)
				}
				return &copy
			})
			if f != nil {
				if e := f.Close(); e != nil {
					t.Error(e)
				}
			}
			if !observed || err == nil || !strings.Contains(err.Error(), target) || !strings.Contains(err.Error(), "not root-owned") {
				t.Fatalf("accepted foreign-owned account target: observed=%v err=%v", observed, err)
			}
		})
	}
}

func TestSystemAccountLinkInputBound(t *testing.T) {
	for _, long := range []bool{false, true} {
		t.Run(fmt.Sprintf("long=%v", long), func(t *testing.T) {
			root := trustedSystemRoot(t)
			for i := 0; i < 40; i++ {
				target := fmt.Sprint(i + 1)
				if i == 39 {
					target = "config.yaml"
				}
				if long {
					target = strings.Repeat("./", 1800) + target
				}
				if err := os.Symlink(target, fmt.Sprintf("%s/etc/tego/%d", root, i)); err != nil {
					t.Fatal(err)
				}
			}
			f, err := OpenSystemFileAt(root, "/etc/tego/0", os.Getuid())
			if f != nil {
				if e := f.Close(); e != nil {
					t.Error(e)
				}
			}
			if long {
				if err == nil || !strings.Contains(err.Error(), "input limit reached") {
					t.Fatalf("unbounded symlink input accepted: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSystemAccountPlacementDepthBound(t *testing.T) {
	root := trustedSystemRoot(t)
	path := root
	for i := 0; i < 513; i++ {
		path = filepath.Join(path, "d")
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(path, "account"), []byte("test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenSystemFileAt(root, strings.TrimPrefix(path, root)+"/account", os.Getuid())
	if f != nil {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "component limit reached") {
		t.Fatalf("unbounded placement depth: %v", err)
	}
}

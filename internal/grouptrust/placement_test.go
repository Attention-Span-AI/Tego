// SPDX-License-Identifier: Apache-2.0

package grouptrust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestAccountPlacement(t *testing.T) {
	for _, tc := range []struct {
		name            string
		mode            os.FileMode
		link, badTarget bool
		badParent       bool
		sticky          bool
		refuse          bool
	}{
		{name: "ordinary"},
		{name: "group-writable-group", mode: 0664, refuse: true},
		{name: "other-writable-group", mode: 0646, refuse: true},
		{name: "writable-parent", badParent: true, refuse: true},
		{name: "sticky-writable-parent", badParent: true, sticky: true, refuse: true},
		{name: "verified-root-link", link: true},
		{name: "link-to-unverified-file", link: true, badTarget: true, refuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, "etc"), 0755); err != nil {
				t.Fatal(err)
			}
			paths := [3]string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"}
			for i, p := range paths {
				if err := os.WriteFile(filepath.Join(root, p), []byte(privateAccountData[i]), 0644); err != nil {
					t.Fatal(err)
				}
			}
			group := filepath.Join(root, paths[1])
			if tc.mode != 0 {
				if err := os.Chmod(group, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			if tc.badParent {
				mode := os.FileMode(0775)
				if tc.sticky {
					mode = os.ModeSticky | 0777
				}
				if err := os.Chmod(filepath.Join(root, "etc"), mode); err != nil {
					t.Fatal(err)
				}
			}
			if tc.link {
				target := filepath.Join(root, "etc", "target")
				if err := os.Rename(group, target); err != nil {
					t.Fatal(err)
				}
				if tc.badTarget {
					if err := os.Chmod(target, 0664); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink("target", group); err != nil {
					t.Fatal(err)
				}
			}
			opens := 0
			data, err := collectAccountFilesWith(paths, func(p string) (*config.SystemFile, error) {
				opens++
				// The fixture owner models uid 0. Production supplies literal / and 0.
				return config.OpenSystemFileAt(root, p, os.Getuid())
			})
			policy := accountPolicy(1000, data, err)
			decision := policy.Check(0664, 1000, 1000)
			if tc.refuse {
				requireCollectionRefusal(t, policy)
				var mode *ModeError
				if !errors.As(decision, &mode) || !strings.Contains(mode.AccountRepair, "/etc/") || !strings.Contains(mode.AccountRepair, "writable") {
					t.Fatalf("missing named placement repair: %v / %+v", err, mode)
				}
			} else {
				if err != nil || decision != nil {
					t.Fatalf("collection %v, decision %v", err, decision)
				}
				if opens != 6 {
					t.Fatalf("got %d opens, want both passes", opens)
				}
			}
		})
	}
}

func TestAccountPlacementBothPasses(t *testing.T) {
	for _, index := range []int{0, 1, 2, 3, 4, 5} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0755); err != nil {
				t.Fatal(err)
			}
			paths := [3]string{"/passwd", "/group", "/nsswitch.conf"}
			for i, p := range paths {
				if err := os.WriteFile(filepath.Join(root, p), []byte(privateAccountData[i]), 0644); err != nil {
					t.Fatal(err)
				}
			}
			opens := 0
			data, err := collectAccountFilesWith(paths, func(p string) (*config.SystemFile, error) {
				if opens == index {
					if err := os.Chmod(filepath.Join(root, p), 0664); err != nil {
						t.Fatal(err)
					}
				}
				opens++
				return config.OpenSystemFileAt(root, p, os.Getuid())
			})
			requireCollectionRefusal(t, accountPolicy(1000, data, err))
		})
	}
}

func TestAccountPlacementLongRepair(t *testing.T) {
	err := fmt.Errorf("account evidence /etc/group: %s: group or other writable", strings.Repeat("x", 4000))
	policy := accountPolicy(1000, [3][]byte{}, err)
	var mode *ModeError
	if e := policy.Check(0664, 1000, 1000); !errors.As(e, &mode) {
		t.Fatal(e)
	}
	if len(mode.AccountRepair) > 2048 || !strings.Contains(mode.AccountRepair, "/etc/group") || !strings.Contains(mode.AccountRepair, "group or other writable") {
		t.Fatalf("bounded repair lost file or cause: %s", mode.AccountRepair)
	}
}

// The single-file caller read retains exactly the same pinned two-pass policy.
func TestSingleAccountReadPinsBothPasses(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root+"/etc", 0755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"first", "second"} {
				if err := os.WriteFile(root+"/etc/"+name, []byte("same bytes\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink("first", root+"/etc/passwd"); err != nil {
				t.Fatal(err)
			}
			opens := 0
			data, err := collectAccountFilesCount([3]string{"/etc/passwd"}, func(path string) (*config.SystemFile, error) {
				opens++
				if opens == 2 && changed {
					if err := os.Remove(root + path); err != nil {
						return nil, err
					}
					if err := os.Symlink("second", root+path); err != nil {
						return nil, err
					}
				}
				return config.OpenSystemFileAt(root, path, os.Getuid())
			}, 1)
			if opens != 2 {
				t.Fatalf("%d opens, want one fresh open per pass", opens)
			}
			if changed {
				if err == nil || !strings.Contains(AccountRepair(err), "run the scan again") {
					t.Fatalf("changed link accepted or repair omitted: %v", err)
				}
			} else if err != nil || string(data[0]) != "same bytes\n" {
				t.Fatalf("stable verified link: %q %v", data[0], err)
			}
		})
	}
}

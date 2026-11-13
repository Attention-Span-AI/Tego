// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestDoctorExplainsPlainFolderChroot replays the captured chroot tables before any contract is compiled. A
// missing root row keeps refusing the table, but doctor must name the situation and an actionable remedy. A
// self-bound root and a root on its own filesystem have the row and receive no such warning.
func TestDoctorExplainsPlainFolderChroot(t *testing.T) {
	const diagnosis = "Tego is running inside a root that is not a mount point, so the kernel does not show the filesystem under it; " +
		"make the root a mount point, for example bind the folder onto itself before entering it, or run Tego outside that root"
	for _, tc := range []struct {
		name    string
		missing bool
	}{
		{"chroot-dir", true}, {"chroot-dir-proc-only", true}, {"chroot-selfbind", false}, {"chroot-own-fs", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join("../../pkg/spec/agent/testdata/chroot-mountinfo", tc.name+".mountinfo")
			mt, _, err := agent.ReadMountSnapshot(path)
			if tc.missing {
				if mt != nil || !errors.Is(err, agent.ErrMountSnapshot) {
					t.Fatalf("plain-folder chroot table = %v, %v; want no table and ErrMountSnapshot", mt, err)
				}
			} else if err != nil {
				t.Fatalf("root at a mount point: %v", err)
			}
			got := runDoctorMountFixture(t, path, t.TempDir())
			want := "WARNING: mount alias check unavailable: "
			if tc.missing {
				if !strings.Contains(got, want) || !strings.Contains(got, diagnosis) {
					t.Errorf("doctor did not explain the plain-folder chroot and its remedy:\n%s", got)
				}
			} else if strings.Contains(got, want) || strings.Contains(got, diagnosis) {
				t.Errorf("doctor warned about a root row present in the table:\n%s", got)
			}
		})
	}
}

// Run must acquire these facts at check time, rather than repeat the generic fallback clause or read a run-probe
// cache. These are the previous round's modeled fixtures, not observations of installed distributions.
func TestDoctorDiagnosesHomeAliases(t *testing.T) {
	for _, tc := range []struct{ name, home, alias string }{
		{"atomic", "/var/home/alice", "/sysroot/ostree/deploy/fedora/var/home/alice"},
		{"toolbox", "/home/alice", "/run/host/var/home/alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, tc.home)
			if err := os.MkdirAll(home, 0o700); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join("../../pkg/spec/agent/testdata/mountcompat", tc.name+".mountinfo"))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "mountinfo")
			if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(data), "{{ROOT}}", root)), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.name == "atomic" {
				link := filepath.Join(root, "home/alice")
				if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(home, link); err != nil {
					t.Fatal(err)
				}
				home = link // doctor's passwd spelling must follow the host's /home link too.
			}
			got := runDoctorMountFixture(t, path, home)
			for _, want := range []string{"WARNING", "this host shows your home", filepath.Join(root, tc.home),
				filepath.Join(root, tc.alias), "cgroup without a decision plane refuses", "cgroup and bpflsm with a decision plane can hold", "remaining contract"} {
				if !strings.Contains(got, want) {
					t.Errorf("doctor omitted %q: %s", want, got)
				}
			}
			// A later check must see current facts, even when the capability probes return the same answers.
			if err := os.WriteFile(path, []byte("1 0 8:1 / / rw - ext4 /dev/root rw\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if next := runDoctorMountFixture(t, path, home); strings.Contains(next, "this host shows your home") {
				t.Errorf("doctor retained an earlier mount warning: %s", next)
			}
		})
	}
}

func TestDoctorNamesDetachedProtectedTargetAndRepeatedNetworkSource(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh/keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "mountinfo")
	data := fmt.Sprintf("1 0 8:1 / / rw - ext4 /dev/root rw\n"+
		"2 1 8:1 %s %s rw - ext4 /dev/root rw\n"+
		"3 1 0:42 / %s rw - nfs server:/export rw\n"+
		"4 1 0:43 / %s rw - nfs server:/export rw\n", filepath.Join(home, ".ssh/keys"),
		filepath.Join(root, "other-keys"), filepath.Join(root, "a"), filepath.Join(root, "b"))
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runDoctorMountFixture(t, path, home)
	for _, want := range []string{filepath.Join(home, ".ssh"), filepath.Join(root, "other-keys"),
		"cgroup and bpflsm refuse", "detached part", "same network source string", "not recognised", "deny the other path too"} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor omitted %q: %s", want, got)
		}
	}
}

// The same-device unlinked directory makes both alias queries uncertain even when
// the snapshot also establishes a detached part or a whole-tree alias.
func TestDoctorUncertainMountAliases(t *testing.T) {
	for _, tc := range []struct {
		name, aliasRoot, device      string
		makeRoot, regular, uncertain bool
	}{
		{"detached-directory", ".ssh/keys", "8:1", true, false, true},
		{"whole-tree-directory", ".ssh", "8:1", true, false, true},
		{"home-directory", "", "8:1", true, false, true},
		{"unreadable-root", ".ssh/keys", "8:1", false, false, true},
		{"other-device", ".ssh/keys", "8:2", true, false, false},
		{"regular-root", ".ssh/keys", "8:1", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			if err := os.MkdirAll(filepath.Join(home, ".ssh/keys"), 0o700); err != nil {
				t.Fatal(err)
			}
			unlinked := filepath.Join(root, "unlinked")
			if tc.makeRoot {
				if tc.regular {
					if err := os.WriteFile(unlinked, []byte("ordinary file"), 0o600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Mkdir(unlinked, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			id := uint64(3)
			if tc.makeRoot {
				var st unix.Statx_t
				if err := unix.Statx(unix.AT_FDCWD, unlinked, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st); err != nil {
					t.Fatal(err)
				}
				if st.Mask&unix.STATX_MNT_ID == 0 || st.Mnt_id <= 2 {
					t.Fatal("fixture needs a distinct mount ID")
				}
				id = st.Mnt_id
			}
			path := filepath.Join(root, "mountinfo")
			data := fmt.Sprintf("1 0 8:1 / / rw - ext4 /dev/root rw\n"+
				"2 1 8:1 %s %s rw - ext4 /dev/root rw\n"+
				"%d 1 %s /former//deleted %s rw - ext4 /dev/root rw\n",
				filepath.Join(home, tc.aliasRoot), filepath.Join(root, "other-keys"), id, tc.device, unlinked)
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			got := runDoctorMountFixture(t, path, home)
			if strings.Contains(got, "cannot tell whether folder") != tc.uncertain {
				t.Errorf("uncertainty warning = %t, want %t:\n%s", !tc.uncertain, tc.uncertain, got)
			}
			if !strings.Contains(got, filepath.Join(root, "other-keys")) {
				t.Errorf("lost the established alias warning:\n%s", got)
			}
			if tc.uncertain && (!strings.Contains(got, unlinked) || strings.Contains(got, "can hold whole-tree aliases")) {
				t.Errorf("uncertainty omitted its mount or retained reassurance:\n%s", got)
			}
			if tc.name == "detached-directory" {
				_, warning, ok := strings.Cut(got, "; WARNING: ")
				if !ok {
					t.Fatalf("no mount warning:\n%s", got)
				}
				warning, _, _ = strings.Cut(warning, "\n")
				checkGolden(t, "mount-alias-uncertain.txt.golden", strings.ReplaceAll(warning, root, "{{ROOT}}")+"\n")
			}
		})
	}
}

func runDoctorMountFixture(t *testing.T, path, home string) string {
	t.Helper()
	oldChecks, oldMountInfo, oldHome := machineChecks, doctorMountInfo, doctorPasswdHome
	t.Cleanup(func() { machineChecks, doctorMountInfo, doctorPasswdHome = oldChecks, oldMountInfo, oldHome })
	machineChecks = passingChecks(&calls{})
	doctorMountInfo = path
	doctorPasswdHome = func(int) (string, error) { return home, nil }
	r, err := Run(context.Background(), &config.Machine{}, "")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

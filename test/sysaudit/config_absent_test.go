// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sysaudit

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Audit both an absent layer in a present folder and an absent layer folder.
// The system shape depends on the host; each case reports that shape explicitly.
func TestConfigAbsentLayerAccesses(t *testing.T) {
	if testutil.InSysTraceChild() {
		testutil.MarkBegin()
		_, _, err := config.LoadSources(config.Sources{Etc: os.Getenv(envEtc), User: os.Getenv(envUser)}, os.Getenv(envHome), os.Getuid(), config.TrustAbort)
		testutil.MarkEnd()
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, shape := range []string{"present", "absent-file", "absent-folder"} {
		t.Run(shape, func(t *testing.T) {
			home := t.TempDir()
			user := filepath.Join(home, ".tego", "config.yaml")
			if shape != "absent-folder" {
				if err := os.Mkdir(filepath.Dir(user), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if shape == "present" {
				if err := os.WriteFile(user, []byte("version: 0\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			systemShape := "present-folder"
			if _, err := os.Lstat(filepath.Dir(config.EtcPath)); os.IsNotExist(err) {
				systemShape = "absent-folder"
			} else if err != nil {
				t.Fatal(err)
			}
			t.Logf("exercised shapes: user=%s (constructed); system=%s (host-dependent %s)", shape, systemShape, filepath.Dir(config.EtcPath))
			if systemShape != "absent-folder" {
				t.Log("absent system folder shape not exercised: /etc/tego exists on this machine; all constructed user shapes still run")
			}
			layers := []string{config.EtcPath, user}
			calls := testutil.SysTrace(t, t.Name(), envEtc+"="+config.EtcPath, envUser+"="+user, envHome+"="+home)
			for _, c := range calls {
				switch c.Nr {
				case 0, 3, 5, 17:
					t.Logf("descriptor syscall nr=%d fd=%d", c.Nr, c.Args[0])
				}
				if c.Written() {
					t.Errorf("configuration wrote: %v", c)
				}
				for _, p := range c.Paths {
					t.Logf("trace %s: %v at_symlink_nofollow=%t", p, c, c.Name == "lstat" || c.Name == "newfstatat" && c.Args[3]&unix.AT_SYMLINK_NOFOLLOW != 0)
					if throughALink(p) {
						t.Errorf("noncanonical path: %v", c)
						continue
					}
					if strings.HasPrefix(p, "/proc/self/fd/") || strings.HasPrefix(p, "/proc/"+strconv.Itoa(c.TID)+"/fd/") {
						continue
					}
					allowed := false
					for _, l := range layers {
						allowed = allowed || p == l || p == filepath.Dir(l)
					}
					if !allowed && !walkLook(c, p, layers...) {
						t.Errorf("outside I10: %v", c)
					}
				}
			}
		})
	}
}

// A statfs passes the audit only as the look at a layer's ancestor that config.ThroughProc makes (GAPS C250's pending
// exception): not of a sibling folder, not of an unrelated path, and no other call that follows links.
func TestWalkLookTakesStatfsOnlyOfALayersAncestors(t *testing.T) {
	layer := "/home/u/.tego/config.yaml"
	statfs := testutil.Syscall{Name: "statfs", Nr: unix.SYS_STATFS}
	for p, want := range map[string]bool{"/": true, "/home": true, "/home/u/.tego": true, "/home/other": false, "/opt/catalog": false, layer: false} {
		if got := walkLook(statfs, p, layer); got != want {
			t.Errorf("statfs of %s: %t, want %t", p, got, want)
		}
	}
	if walkLook(testutil.Syscall{Name: "stat"}, "/home", layer) {
		t.Error("a stat that follows links passed as a look at an ancestor")
	}
}

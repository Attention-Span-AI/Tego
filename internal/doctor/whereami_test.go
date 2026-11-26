// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/whereami"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// This package's tests describe a host unless a test says where it is: a run of them inside a container must not
// change what they read.
func init() { whereami.Here = func() whereami.Kind { return whereami.Host } }

// inPlace makes this test run as if in k.
func inPlace(t *testing.T, k whereami.Kind) {
	t.Helper()
	was := whereami.Here
	whereami.Here = func() whereami.Kind { return k }
	t.Cleanup(func() { whereami.Here = was })
}

// hostCure is what a host (and WSL) printed before the places were told apart, written out so a change to it fails
// here: the output of an ordinary host is byte for byte what it was.
const hostCure = "enable systemd user delegation: Delegate=cpu memory pids in /etc/systemd/system/user@.service.d/delegate.conf, then systemctl daemon-reload and re-login"

var places = []struct {
	name string
	kind whereami.Kind
	want string
}{
	{"host", whereami.Host, hostCure},
	{"WSL", whereami.WSL, hostCure},
	{"container", whereami.Container, whereami.ContainerCgroupCure},
}

// TestCgroupCureByPlace: D3's cure as root (the root cgroup.procs is not writable, as on a read-only /sys/fs/cgroup) and as
// a user (a refusal Detect did not build), in each place.
func TestCgroupCureByPlace(t *testing.T) {
	for _, p := range places {
		t.Run(p.name, func(t *testing.T) {
			inPlace(t, p.kind)
			fs, err := cgroup.NewAt(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := probeDelegatedCgroup(fs, nil)
			if root.OK || root.ID != CheckCgroupV2 || !strings.Contains(root.Detail, "not writable") {
				t.Fatalf("root: %+v", root)
			}
			user := probeCgroupWith(1000, nil, func(int) (*cgroup.FS, error) {
				return nil, errors.New("cgroup: no delegated cgroup v2 subtree for uid 1000: statfs: no such file or directory")
			})
			if user.OK {
				t.Fatalf("user: %+v", user)
			}
			for who, fix := range map[string]string{"root": root.Fix, "user": user.Fix} {
				if fix != p.want {
					t.Errorf("%s: fix %q, want %q", who, fix, p.want)
				}
			}
			for _, line := range []string{root.Detail + "; fix: " + root.Fix, user.Detail + "; fix: " + user.Fix} {
				if strings.Contains(line, "Delegate=") == (p.kind == whereami.Container) {
					t.Errorf("the line %q has the wrong place's cure", line)
				}
			}
		})
	}
}

// TestAHostPrintsWhatItPrintedBefore holds the host's cgroup cure to the words of v0.2.0-rc.1 (hostCure is a literal copy
// of what that build recorded), and a whole host report to what it printed: the cure on the cgroupv2 line and again on the fix: line.
func TestAHostPrintsWhatItPrintedBefore(t *testing.T) {
	if delegateFix != hostCure {
		t.Errorf("delegateFix changed: %q", delegateFix)
	}
	text, refusal := reportFor(t, true, "/sys/fs/cgroup/cgroup.procs not writable: read-only file system", hostCure)
	for _, want := range []string{
		"FAIL cgroupv2: /sys/fs/cgroup/cgroup.procs not writable: read-only file system; fix: " + hostCure + "\n",
		"\nfix: " + hostCure + "\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the host report lost %q:\n%s", want, text)
		}
	}
	if want := "missing for landlock: cgroupv2: /sys/fs/cgroup/cgroup.procs not writable: read-only file system; fix: " + hostCure; refusal != want {
		t.Errorf("the host's run refusal is %q, want %q", refusal, want)
	}
}

// reportFor is the text report and the run's refusal of a machine whose cgroup check failed with fix, as root or as a user.
func reportFor(t *testing.T, root bool, detail, fix string) (text, refusal string) {
	t.Helper()
	st := state(func(st *probeState) {
		st.root = root
		fail(st, CheckCgroupV2, detail, fix)
	})
	rep := st.report(config.Builtin(), "")
	var b bytes.Buffer
	if err := rep.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	return b.String(), rep.WhyNot(backend.TierLandlock)
}

// TestTheContainerCureIsPrintedOnce: doctor and machine check (the same report) print the cure on the cgroupv2 line and
// point to it from the one-line fix, and the run's refusal carries it once; a host prints its cure twice in doctor, as it always did.
func TestTheContainerCureIsPrintedOnce(t *testing.T) {
	for _, root := range []bool{true, false} {
		for _, p := range places {
			t.Run(p.name, func(t *testing.T) {
				inPlace(t, p.kind)
				fs, _ := cgroup.NewAt(t.TempDir())
				r := probeDelegatedCgroup(fs, nil)
				if !root {
					r = probeCgroupWith(1000, nil, func(int) (*cgroup.FS, error) { return nil, errors.New("cgroup: no delegated cgroup v2 subtree") })
				}
				text, refusal := reportFor(t, root, r.Detail, r.Fix)
				want := 1
				if p.kind != whereami.Container {
					want = 2 // the cgroupv2 line and the fix: line, as before
				}
				if n := strings.Count(text, p.want); n != want {
					t.Errorf("the cure appears %d times in doctor, want %d:\n%s", n, want, text)
				}
				if n := strings.Count(refusal, p.want); n != 1 {
					t.Errorf("the run's refusal carries the cure %d times, want once: %q", n, refusal)
				}
				if p.kind == whereami.Container {
					if !strings.Contains(text, "\nfix: what the cgroupv2 line above says the container needs\n") {
						t.Errorf("the fix: line does not point at the cgroupv2 line:\n%s", text)
					}
					if strings.Contains(text+refusal, "systemd user delegation") || strings.Contains(text+refusal, "wsl.conf") {
						t.Errorf("a container is told the host's cure:\n%s\n%s", text, refusal)
					}
				}
			})
		}
	}
}

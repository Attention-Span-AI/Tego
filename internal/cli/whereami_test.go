// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/whereami"
	"github.com/attention-span-ai/tego/internal/runscope"
)

// This package's tests describe a host unless a test says where it is.
func init() { whereami.Here = func() whereami.Kind { return whereami.Host } }

var kindNames = map[whereami.Kind]string{whereami.Host: "host", whereami.WSL: "WSL", whereami.Container: "container"}

func inPlace(t *testing.T, k whereami.Kind) {
	t.Helper()
	was := whereami.Here
	whereami.Here = func() whereami.Kind { return k }
	t.Cleanup(func() { whereami.Here = was })
}

// hostNotAtTop is the refusal of tego setup as v0.2.0-rc.1 printed it on a host or on WSL, a cgroup namespace of its own
// with no service manager at the top of the tree (the message a cgroup-namespaced guest printed).
const hostNotAtTop = "tego setup: the service manager (systemd) is not at the top of this cgroup tree: process 1 is not in " +
	"/init.scope; on WSL, turn systemd on ([boot] systemd=true in /etc/wsl.conf), update WSL (wsl --update) and start the " +
	"distribution again; until then tego cannot show that this process is outside every tego run, so the machine was not " +
	"checked; nothing was written"

func notAtTop(t *testing.T) {
	t.Helper()
	was := selfAnswer
	selfAnswer = func() runscope.Answer { return runscope.Unproven(runscope.CauseInitNotAtRoot, nil) }
	t.Cleanup(func() { selfAnswer = was })
}

// TestStartAndSetupRefusalByPlace: the refusal names the command the person typed, says the WSL and host words
// byte for byte as before, and in a container says what a container needs and sends the command to the machine's own terminal.
func TestStartAndSetupRefusalByPlace(t *testing.T) {
	notAtTop(t)
	for _, name := range []string{"start", "setup"} {
		for _, k := range []whereami.Kind{whereami.Host, whereami.WSL, whereami.Container} {
			t.Run(name+" "+kindNames[k], func(t *testing.T) {
				inPlace(t, k)
				var b bytes.Buffer
				if !refuseSetup(name, &b) {
					t.Fatal("no refusal: the answer is not outside")
				}
				got := b.String()
				if !strings.HasPrefix(got, "tego "+name+": ") {
					t.Errorf("the refusal does not name the command %q: %q", name, got)
				}
				if other := map[string]string{"start": "setup", "setup": "start"}[name]; strings.Contains(got, "tego "+other) {
					t.Errorf("the refusal names %q too: %q", other, got)
				}
				if k != whereami.Container {
					want := strings.Replace(hostNotAtTop, "tego setup:", "tego "+name+":", 1)
					if !strings.HasPrefix(got, want) {
						t.Errorf("a %s's refusal changed:\n got %q\nwant %q", kindNames[k], got, want)
					}
					return
				}
				for _, want := range []string{"this is a container", "examples/container/compose.yaml", "docs/user/container.md",
					"SYS_ADMIN", "apparmor=unconfined", "/run/tego-lsm/lsm-list", "tego run",
					"outside any tego run and any container"} {
					if !strings.Contains(got, want) {
						t.Errorf("the container's refusal lacks %q: %q", want, got)
					}
				}
				for _, bad := range []string{"WSL", "wsl", "systemd=true", "Delegate=", "privileged", "until then"} {
					if strings.Contains(got, bad) {
						t.Errorf("the container's refusal carries %q: %q", bad, got)
					}
				}
			})
		}
	}
}

// TestScopeRefusalByPlace: the refusal a command prints when no user scope was tried says the container's words in a
// container, and the table's elsewhere.
func TestScopeRefusalByPlace(t *testing.T) {
	a := runscope.Unproven(runscope.CauseInitNotAtRoot, nil)
	e := &scopeNotOutside{answer: a}
	inPlace(t, whereami.Host)
	if got := e.Error(); !strings.Contains(got, "on WSL, turn systemd on") {
		t.Errorf("a host's words changed: %q", got)
	}
	inPlace(t, whereami.Container)
	if got := e.Error(); strings.Contains(got, "WSL") || !strings.Contains(got, "examples/container") {
		t.Errorf("a container's words: %q", got)
	}
	got := notOutside("doctor", a, "", "nothing was started", "")
	if !strings.HasPrefix(got, "tego doctor: nothing was started: this process cannot be shown to be outside every tego run: this is a container") {
		t.Errorf("the container refusal of another command: %q", got)
	}
}

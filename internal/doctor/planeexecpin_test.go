// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// TestPlanePinImagesRun is the exec pin cell's machinery without a plane (ADR 0048 (7)): the gate says ready, waits
// for its go-ahead and execs its descriptor 4 with its argv[1:]; the probe writes its byte to descriptor 3 and ends
// once its stdin does; a #! script whose interpreter is /proc/self/fd/5 runs the probe; an exec the kernel refuses
// ends the gate with the errno as its status; and a gate doctor traces with PTRACE_SEIZE execs as an untraced one
// does when nothing refuses it. Outside every run each of these execs passes, so the cell's outcomes in a plane's
// run are the plane's.
func TestPlanePinImagesRun(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("the cell's images are x86-64 code; this is %s", runtime.GOARCH)
	}
	var fds []*sys.FD
	t.Cleanup(func() {
		for _, fd := range fds {
			_ = fd.Close()
		}
	})
	memfd := func(name string, b []byte) *sys.FD {
		fd, err := planePinMemfd(name, b)
		if err != nil {
			t.Fatal(err)
		}
		fds = append(fds, fd)
		return fd
	}
	gate := memfd(planePinGateName, planePinGateImage())
	probe := memfd(planePinProbeName, planePinProbeImage())
	script := memfd(planePinScriptName, []byte("#!"+planePinInterp+"\n"))
	junk := memfd("tego-pin-junk", []byte("not an image\n"))
	c := &planePinCell{}
	for _, tc := range []struct {
		name   string
		target *sys.FD
		try    planePinTry
		want   string
	}{
		{"probe", probe, planePinTry{argv: []string{planePinProbeName, "a"}}, planePinRan},
		{"long vector", probe, planePinTry{argv: planePinLongVector()}, planePinRan},
		{"script", script, planePinTry{argv: []string{planePinScriptName}}, planePinRan},
		{"traced", probe, planePinTry{argv: []string{"git-status"}, trace: true}, planePinRan},
		{"not an image", junk, planePinTry{argv: []string{"junk"}}, "status 0x800, "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := startPinGate(nil, gate, tc.target, probe, tc.try.argv)
			if err != nil {
				t.Fatal(err)
			}
			defer g.stop()
			got, err := c.try(tc.try, g)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(got, tc.want) || tc.want == planePinRan && got != planePinRan {
				t.Errorf("outcome %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPlanePinGateWaitWithoutAReapIsAnError: a Wait that fails before it reaps the gate leaves no ProcessState,
// and wait returns that error, where it read the status from a nil ProcessState and panicked.
func TestPlanePinGateWaitWithoutAReapIsAnError(t *testing.T) {
	g := &planePinGate{cmd: proc.Command("true"), done: make(chan struct{}), waitErr: errors.New("exec: Wait was already called")}
	close(g.done)
	if _, err := g.wait(); err == nil || !strings.Contains(err.Error(), "Wait was already called") {
		t.Fatalf("wait = %v, want the error of the Wait that did not reap the gate", err)
	}
	if !g.ended {
		t.Fatal("wait did not mark the gate ended")
	}
}

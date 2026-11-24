// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runscope"
)

// The facts of the hosts the gate tells apart.
var (
	notWSL     = func() (string, error) { return "6.17.0-41-generic", nil }
	wslKernel  = func() (string, error) { return "6.18.58.1-microsoft-standard-WSL2", nil }
	noMarks    = func(string) bool { return false }
	wslRunMark = func(p string) bool { return p == "/run/WSL" }
	// wslMarksOf is a WSL 2 distribution's files: the launcher's folder and the interop binfmt_misc entry.
	wslMarksOf = func(p string) bool { return p == "/run/WSL" || p == "/proc/sys/fs/binfmt_misc/WSLInterop" }
	wslBinfmt  = func(p string) bool { return p == "/proc/sys/fs/binfmt_misc/WSLInterop" }
)

// gateHost is this machine's reads with the gate's facts injected: the kernel release and which marks are there.
func gateHost(release func() (string, error), exists func(string) bool) selfHost {
	h := machine
	h.release, h.exists = release, exists
	return h
}

// TestWSLDetection: WSL is told by facts and never by an environment variable, by three independent marks (the
// kernel release names Microsoft or WSL; WSL's launcher folder is there; one of its binfmt_misc entries is there), and
// the detection is asymmetric (ADR 0100, amended 2026-11-19, round 5): any ONE mark holds (wslHolds), two are what the
// rule's relaxation on WSL needs. A release that cannot be read counts as its mark, and so does a mark that cannot be
// looked at; a distribution with interop off shows its release alone, one mark, and is held.
func TestWSLDetection(t *testing.T) {
	refusedLook := func(p string) bool { return p == "/run/WSL" } // what pathExists says of an EACCES on /run/WSL
	for _, c := range []struct {
		name    string
		release func() (string, error)
		exists  func(string) bool
		marks   int
	}{
		{"an ordinary kernel", notWSL, noMarks, 0},
		{"WSL 2: its kernel, its launcher folder and its binfmt entry", wslKernel, wslMarksOf, 2},
		{"WSL 2's kernel and its launcher folder", wslKernel, wslRunMark, 2},
		{"WSL 2's kernel and its binfmt entry", wslKernel, wslBinfmt, 2},
		{"a WSL kernel in capitals, with the folder", func() (string, error) { return "5.15.0-MICROSOFT", nil }, wslRunMark, 2},
		{"a custom kernel named for WSL, with the folder", func() (string, error) { return "6.6.0-wsl-custom", nil }, wslRunMark, 2},
		{"a custom kernel with WSL's folder and its binfmt entry", notWSL, wslMarksOf, 2},
		{"a custom kernel with the folder and the late binfmt entry", notWSL,
			func(p string) bool { return p == "/run/WSL" || p == "/proc/sys/fs/binfmt_misc/WSLInterop-late" }, 2},
		{"a release that cannot be read, with the folder", func() (string, error) { return "", unix.EFAULT }, wslRunMark, 2},
		// One mark alone: held, never relaxed.
		{"one mark: WSL 2's kernel alone", wslKernel, noMarks, 1},
		{"one mark: a kernel named for WSL alone", func() (string, error) { return "6.6.0-wsl-custom", nil }, noMarks, 1},
		{"one mark: an ordinary kernel whose /run/WSL a security module refuses to show", notWSL, refusedLook, 1},
		{"one mark: an ordinary kernel with WSL's binfmt entry alone", notWSL, wslBinfmt, 1},
		{"one mark: both binfmt entries are one mark", notWSL,
			func(p string) bool { return strings.HasPrefix(p, "/proc/sys/fs/binfmt_misc/WSLInterop") }, 1},
		{"one mark: a release that cannot be read alone", func() (string, error) { return "", unix.EFAULT }, noMarks, 1},
		{"one mark: WSL with interop off shows its kernel alone", wslKernel, noMarks, 1},
	} {
		h := gateHost(c.release, c.exists)
		if got := h.wslMarks(); got < c.marks || c.marks < 2 && got != c.marks {
			t.Errorf("%s: %d marks; want %d", c.name, got, c.marks)
		}
		// Any one mark holds; two lift the hold only where this build's WSL switch is on (an ordinary build's state).
		wantHold := c.marks >= 1 && !(c.marks >= 2 && wslRuleOn())
		if got := h.wslHolds(); got != wantHold {
			t.Errorf("%s: wslHolds = %v; want %v (any one mark holds; two only while this build's switch is off)", c.name, got, wantHold)
		}
	}
	// The same marks as pkg/spec/agent's compile check of WSL's launcher (TestWSLLauncherCannotBeGiven pins them too).
	if !slices.Equal(wslMarks, []string{"/run/WSL", "/proc/sys/fs/binfmt_misc/WSLInterop", "/proc/sys/fs/binfmt_misc/WSLInterop-late"}) {
		t.Errorf("wslMarks = %v", wslMarks)
	}
	t.Setenv("WSL_DISTRO_NAME", "Ubuntu")
	t.Setenv("WSL_INTEROP", "/run/WSL/1_interop")
	if gateHost(notWSL, noMarks).wslMarks() != 0 {
		t.Error("WSL's environment variables made a machine with none of WSL's marks count as WSL")
	}
	if pathExists(filepath.Join(t.TempDir(), "missing")) || !pathExists(t.TempDir()) {
		t.Error("pathExists is wrong about a missing path or a present one")
	}
	if os.Geteuid() != 0 {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(dir, 0o700) }()
		if !pathExists(filepath.Join(dir, "x")) {
			t.Error("a path that cannot be looked at must count as there (the gate fails closed)")
		}
	}
}

// TestGateInThisBuild drives the real gate (selfHost.withheld) through the real rule (runscope.Decide) and the real
// peer check (refuse) with the WSL facts injected, in the build these tests run in. A process every fact holds for is:
// on WSL with two marks, outside in both branches where the build's WSL switch is on (an ordinary build's state since
// the switch-on commit, ADR 0100) and otherwise (a test build's starting state) unknown with the gate's cause
// wsl-launcher-unproven, the kernel's first cgroup namespace included (where a distribution with
// isolateDistroCgroup=false sits), and no peer is served there; on WSL with one mark, unknown with that cause in every
// build (round 5); outside WSL, unknown with cause system-unproven beyond the first namespace (the answer before the
// rule), and outside in it (ordinary Linux).
func TestGateInThisBuild(t *testing.T) {
	if nestedRuleOn() {
		t.Fatal("the nested switch of the gate is on at the start of the test: an ordinary build has none, and a test build's starts off")
	}
	const other = uint64(4026532208)
	for _, c := range []struct {
		name    string
		release func() (string, error)
		exists  func(string) bool
		ino     uint64
		cause   runscope.Cause // "" means outside
	}{
		{"WSL, the distribution's own cgroup namespace", wslKernel, wslMarksOf, other, runscope.CauseWSLLauncherUnproven},
		{"WSL by its folder and binfmt entry, own namespace", notWSL, wslMarksOf, other, runscope.CauseWSLLauncherUnproven},
		{"WSL with isolateDistroCgroup=false, the first namespace", wslKernel, wslMarksOf, runscope.InitCgroupNS, runscope.CauseWSLLauncherUnproven},
		{"WSL by its folder and binfmt entry, the first namespace", notWSL, wslMarksOf, runscope.InitCgroupNS, runscope.CauseWSLLauncherUnproven},
		{"a container or nested system, not WSL", notWSL, noMarks, other, runscope.CauseSystemUnproven},
		{"ordinary Linux, the first namespace", notWSL, noMarks, runscope.InitCgroupNS, ""},
		// One mark holds (ADR 0100, amended 2026-11-19, round 5): the careful side of the asymmetric detection.
		{"a machine whose /run/WSL cannot be looked at, the first namespace", notWSL, wslRunMark, runscope.InitCgroupNS, runscope.CauseWSLLauncherUnproven},
		{"a WSL release alone (interop off), the first namespace", wslKernel, noMarks, runscope.InitCgroupNS, runscope.CauseWSLLauncherUnproven},
		{"a WSL release alone (interop off), its own namespace", wslKernel, noMarks, other, runscope.CauseWSLLauncherUnproven},
	} {
		v, _ := testProver()
		host := gateHost(c.release, c.exists)
		want := c.cause
		if want == runscope.CauseWSLLauncherUnproven && wslRuleOn() && host.wslMarks() >= 2 {
			want = "" // two marks and this build's switch: the rule's relaxation on WSL
		}
		g := &gated{selfReads: &selfReads{host: host, prover: v}, path: []byte("0::/non-systemd\n"), ino: c.ino}
		a := runscope.Decide(g)
		d := runscope.Describe(a)
		switch {
		case want == "" && !a.Outside():
			t.Errorf("%s: %s; want outside", c.name, d)
		case want != "" && (d.Verdict != runscope.Unknown || d.Cause != want):
			t.Errorf("%s: %s; want unknown, %s", c.name, d, want)
		}
		if want == runscope.CauseWSLLauncherUnproven && !strings.Contains(runscope.Why(a), "not proven yet") {
			t.Errorf("%s: the words %q do not say the launcher's refusal is not proven yet", c.name, runscope.Why(a))
		}
		if c.ino != runscope.InitCgroupNS {
			continue
		}
		p := Peer{UID: 1000, PID: 42, Cgroup: "/non-systemd", CgroupNS: c.ino, StartBootNS: 1}
		err := refuse(p, 1000, c.ino, nil, neverAsked(t, c.name), func() (runscope.Cause, bool) { return host.withheld(true) })
		if served := err == nil; served != (want == "") || err != nil && codeOf(err) != CodeCgroupNS {
			t.Errorf("%s: a peer at the namespace root: refuse = %v; want served only outside WSL", c.name, err)
		}
	}
}

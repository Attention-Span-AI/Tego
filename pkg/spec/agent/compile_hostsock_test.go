// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// mkSocket makes a unix socket node at root+p, as a daemon's bind would.
func mkSocket(t *testing.T, root, p string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mknod(full, syscall.S_IFSOCK|0o600, 0); err != nil {
		t.Fatal(err)
	}
}

// TestHostSocketsWarning is R19 as ADR 0070 amends it: a contract with no net: section that sets host_sockets: true
// warns naming the well-known host daemon sockets that exist (docker.sock as root-equivalent) and the abstract-socket
// condition, once, at the key, with a fix that names a net: section's unix: entry; a net: section, even an empty one,
// silences it because it decides unix destinations by its own entries; without the opt-out the run refuses them
// (host-sockets), so nothing is warned; and a machine with none of those sockets still warns the opt-out, saying so.
// A socket-named file that is not a socket is not reported.
func TestHostSocketsWarning(t *testing.T) {
	f := newFixture(t)
	mkSocket(t, f.root, "/run/user/4242/bus")
	mkSocket(t, f.root, "/var/run/docker.sock")
	mkSocket(t, f.root, "/tmp/.X11-unix/X0")
	f.file(filepath.Join(f.root, "run", "user", "4242", "openssh_agent"), "not a socket", 0o600)

	c := f.load("version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\n")
	_, ds := f.compile(c)
	var got []Diagnostic
	for _, d := range ds {
		if d.Code == CodeHostSockets {
			got = append(got, d)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want one %s warning, got %d:\n%s", CodeHostSockets, len(got), render(ds))
	}
	d := got[0]
	for _, want := range []string{"host_sockets: true", "/run/user/4242/bus: the D-Bus session bus", "/var/run/docker.sock: the Docker daemon, root-equivalent", "/tmp/.X11-unix/X0: the X server", "Landlock ABI 6"} {
		if !strings.Contains(d.Message, want) {
			t.Errorf("message lacks %q: %s", want, d.Message)
		}
	}
	if strings.Contains(d.Message, "openssh_agent") {
		t.Errorf("a regular file was reported as a socket: %s", d.Message)
	}
	if d.Severity != SeverityWarning || !strings.Contains(d.Fix, "net:") || !strings.Contains(d.Fix, "unix:") || d.Line != 4 {
		t.Errorf("want a warning at the key whose fix is a net: section with a unix: entry: %+v", d)
	}
	if _, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\n")); hasCode(ds, CodeHostSockets) {
		t.Errorf("without host_sockets: true the run refuses the daemon sockets, so nothing is warned:\n%s", render(ds))
	}

	for _, contract := range []string{
		"version: 0\nname: t\ncommand: [\"python\"]\nnet: {}\nhost_sockets: true\n",
		"version: 0\nname: t\ncommand: [\"python\"]\nnet:\n  allow: [\"127.0.0.1:8080\"]\n",
	} {
		if _, ds := f.compile(f.load(contract)); hasCode(ds, CodeHostSockets) {
			t.Errorf("a net: section refuses what it does not name, so it must not warn:\n%s\n%s", contract, render(ds))
		}
	}

	quiet := newFixture(t)
	if _, ds := quiet.compile(quiet.load("version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\n")); !strings.Contains(render(ds), "none of the well-known daemon sockets exists") {
		t.Errorf("no daemon socket exists: the opt-out is still warned, saying none was found:\n%s", render(ds))
	}
}

// TestHostSocketsX11Planted: /tmp is writable by every user, so what stands at /tmp/.X11-unix can be anyone's.
// A FIFO there must not block the compile of a contract with no net: section, and a link to a directory of
// sockets is not followed: the X server makes the directory itself, and os.ReadDir followed the link and
// reported the linked directory's sockets as this host's X servers.
func TestHostSocketsX11Planted(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.root, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(f.root, x11Dir), 0o644); err != nil {
		t.Fatal(err)
	}
	mkSocket(t, f.root, "/run/user/4242/bus")
	compileWithin(t, f, f.load("version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\n"), 10*time.Second)

	g := newFixture(t)
	mkSocket(t, g.root, "/elsewhere/X0")
	if err := os.MkdirAll(filepath.Join(g.root, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(g.root, "elsewhere"), filepath.Join(g.root, x11Dir)); err != nil {
		t.Fatal(err)
	}
	mkSocket(t, g.root, "/run/user/4242/bus")
	if _, ds := g.compile(g.load("version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\n")); strings.Contains(render(ds), "X0: the X server") {
		t.Errorf("a link at /tmp/.X11-unix must not be followed:\n%s", render(ds))
	}
}

// TestHostSocketsX11ManyNames: /tmp/.X11-unix is mode 1777, so any local user, or the agent in an earlier
// run, can create names there. A bounded listing returned the first names in the file system's order, which
// on tmpfs (the usual /tmp) puts names created after X0 first, so a hundred names made after the X server's
// socket pushed X0 out of the warning. Each display's name is looked up instead: X0 and an Xvfb display
// (:99) are named whatever else the directory holds, and a planted name that is not a socket is not. The
// directory is placed on tmpfs (/dev/shm) when this machine has one there.
func TestHostSocketsX11ManyNames(t *testing.T) {
	f := newFixture(t)
	tmp := t.TempDir()
	var sfs syscall.Statfs_t
	if syscall.Statfs("/dev/shm", &sfs) == nil && sfs.Type == 0x01021994 { // TMPFS_MAGIC
		if d, err := os.MkdirTemp("/dev/shm", "tego-x11-"); err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(d) })
			tmp = d
		}
	}
	if err := os.Symlink(tmp, filepath.Join(f.root, "tmp")); err != nil {
		t.Fatal(err)
	}
	mkSocket(t, f.root, "/tmp/.X11-unix/X0")
	for i := 0; i < 100; i++ {
		f.file(filepath.Join(tmp, ".X11-unix", "planted"+strconv.Itoa(i)), "", 0o644)
	}
	f.file(filepath.Join(tmp, ".X11-unix", "X5"), "not a socket", 0o644)
	mkSocket(t, f.root, "/tmp/.X11-unix/X99")
	_, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\n"))
	msg := render(ds)
	for _, want := range []string{"/tmp/.X11-unix/X0: the X server", "/tmp/.X11-unix/X99: the X server"} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "X5") || strings.Contains(msg, "planted") {
		t.Errorf("a name that is not an X server's socket was reported:\n%s", msg)
	}
}

// TestHostSocketsUnixOnlyState is ADR 0070's compile half: a contract with no net: section is in the unix-only state
// (HostSocketsRefused) and its IP destinations stay unrestricted (NetUnrestricted); host_sockets: true lifts it
// (HostSocketsOpened); a net: section is in neither, whatever host_sockets says; and a profile cannot lift it for the
// contract that extends it (stricter false > true: profile-cannot-loosen at the profile's line). A table with no
// Contract, or none at all, is in neither.
func TestHostSocketsUnixOnlyState(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		yaml            string
		refused, opened bool
	}{
		{"version: 0\nname: t\ncommand: [\"python\"]\n", true, false},
		{"version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: false\n", true, false},
		{"version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\n", false, true},
		{"version: 0\nname: t\ncommand: [\"python\"]\nnet: {}\n", false, false},
		{"version: 0\nname: t\ncommand: [\"python\"]\nnet: {}\nhost_sockets: true\n", false, false},
	} {
		rt, _ := f.compile(f.load(tc.yaml))
		if rt.HostSocketsRefused() != tc.refused || rt.HostSocketsOpened() != tc.opened {
			t.Errorf("%q: refused %v opened %v, want %v %v", tc.yaml, rt.HostSocketsRefused(), rt.HostSocketsOpened(), tc.refused, tc.opened)
		}
		if rt.NetUnrestricted() != (rt.Contract.Net == nil) {
			t.Errorf("%q: the unix-only state changed NetUnrestricted, which every IP decision asks", tc.yaml)
		}
	}
	var none *RuleTable
	if none.HostSocketsRefused() || none.HostSocketsOpened() || (&RuleTable{}).HostSocketsRefused() || (&RuleTable{}).HostSocketsOpened() {
		t.Error("a table with no Contract must be in neither state")
	}

	src := writeProfile(t, f, "opens-sockets", "host_sockets: true\n")
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: a\nextends: opens-sockets\ncommand: [python]\n", 0o644)
	c, ds, err := Load(path, src)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	if c.HostSockets || !hasCode(ds, CodeProfileCannotLoosen) {
		t.Fatalf("a profile's host_sockets: true must be ignored and warned, got %v:\n%s", c.HostSockets, render(ds))
	}
	if rt, _ := f.compile(c); !rt.HostSocketsRefused() {
		t.Error("the contract extending the profile must stay in the unix-only state")
	}
	f.file(path, "version: 0\nname: a\nextends: opens-sockets\ncommand: [python]\nhost_sockets: true\n", 0o644)
	if c, ds, err = Load(path, src); err != nil || !c.HostSockets {
		t.Fatalf("the top-level contract's own host_sockets: true opens them: %v %v\n%s", c != nil && c.HostSockets, err, render(ds))
	}
}

// TestHostSocketsRootTierBestEffort is acceptance (5): the root tiers are not changed by ADR 0070, so where a run in the
// unix-only state may land at tier cgroup or bpflsm, compile says the restriction is best effort there until
// those tiers carry a kernel program for it, and run_start's best_effort lists host_sockets/root-tier at those tiers alone. Tier landlock
// lists nothing, and neither does a contract that opted out or has a net: section.
func TestHostSocketsRootTierBestEffort(t *testing.T) {
	f := newFixture(t)
	roots := WithTiers(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	const msg = "best effort at the root tiers for aliases and unsupported datagrams"
	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\ntier: cgroup\n"), roots)
	if !strings.Contains(render(ds), msg) || !hasCode(ds, CodeUnenforced) {
		t.Errorf("a run that may land at tier cgroup must be told %q:\n%s", msg, render(ds))
	}
	// What it rests on there, as the KVM conformance rows show (the plane leaves connect and sendmsg notified, and the
	// supervisor refuses at every plane axis): the relay and Landlock, as at tier landlock, with the datagram residual.
	for _, part := range []string{"the supervisor's relay and Landlock", "as at tier landlock", "a send the supervisor continues"} {
		if !strings.Contains(render(ds), part) {
			t.Errorf("the root-tier note must say %q:\n%s", part, render(ds))
		}
	}
	if strings.Contains(render(ds), "notifications the decision plane leaves it") {
		t.Errorf("no decision plane decides a connect in place of its notification (enforce-plane R22):\n%s", render(ds))
	}
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		if !slices.Contains(rt.BestEffortCellsAt(tier, ""), BestEffortHostSocketsRoot) {
			t.Errorf("tier %s: best_effort %v lacks %s", tier, rt.BestEffortCellsAt(tier, ""), BestEffortHostSocketsRoot)
		}
	}
	if slices.Contains(rt.BestEffortCellsAt(backend.TierLandlock, ""), BestEffortHostSocketsRoot) {
		t.Error("tier landlock relays every connect and addressed send: no best-effort cell")
	}
	connect := Action{Kind: ActionNetConnect, Path: "/run/docker.sock"}
	if got := rt.BestEffortCellsFor(connect, EvalResult{Verdict: VerdictRefused, Rule: HostSocketsRule}, backend.TierCgroup); !slices.Contains(got, BestEffortHostSocketsRoot) {
		t.Errorf("compile --test's cgroup column for a unix connect: %v lacks %s", got, BestEffortHostSocketsRoot)
	}
	if got := rt.BestEffortCellsFor(connect, EvalResult{Verdict: VerdictRefused, Rule: HostSocketsRule}, backend.TierLandlock); slices.Contains(got, BestEffortHostSocketsRoot) {
		t.Errorf("compile --test's landlock column: %v", got)
	}
	if _, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\ntier: landlock\n"), roots); strings.Contains(render(ds), msg) {
		t.Errorf("a run held at tier landlock is told of the root tiers:\n%s", render(ds))
	}
	// An --observe run refuses nothing (tego watch's generic contract has no net: section), so it is told of no refusal:
	// as root the note sat under watch's "No rule refuses anything" (internal/cli TestWatchSpeaksAsWatch).
	const auto = "version: 0\nname: t\ncommand: [\"python\"]\n"
	if _, ds := f.compile(f.load(auto), roots); !strings.Contains(render(ds), msg) {
		t.Errorf("an auto run that may land at a root tier must be told %q:\n%s", msg, render(ds))
	}
	if _, ds := f.compile(f.load(auto), roots, WithObserve()); strings.Contains(render(ds), msg) {
		t.Errorf("an --observe run is told of a host-sockets refusal it never makes:\n%s", render(ds))
	}
	for _, yaml := range []string{
		"version: 0\nname: t\ncommand: [\"python\"]\ntier: cgroup\nhost_sockets: true\n",
		"version: 0\nname: t\ncommand: [\"python\"]\ntier: cgroup\nnet: {}\n",
	} {
		rt, ds := f.compile(f.load(yaml), roots)
		if strings.Contains(render(ds), msg) || slices.Contains(rt.BestEffortCellsAt(backend.TierCgroup, ""), BestEffortHostSocketsRoot) {
			t.Errorf("%q is not in the unix-only state at a root tier:\n%s", yaml, render(ds))
		}
	}
}

// TestHostSocketWhat names what a well-known daemon socket gives, for the refused line of a unix destination: the
// R19 list's text with %U as the user's runtime directory, an X server's socket, and "" for a socket it does not name.
func TestHostSocketWhat(t *testing.T) {
	for p, want := range map[string]string{
		"/var/run/docker.sock":         "the Docker daemon, root-equivalent",
		"/run/user/1000/bus":           "the D-Bus session bus, through which systemd-run --user starts a command outside the run",
		"/run/user/1000/openssh_agent": "the SSH agent",
		"/tmp/.X11-unix/X0":            "the X server, which takes keystrokes into every other window",
		"/run/user/1001/bus":           "",
		"/home/u/project/app.sock":     "",
	} {
		if got := HostSocketWhat(p, "/run/user/1000"); got != want {
			t.Errorf("HostSocketWhat(%q) = %q, want %q", p, got, want)
		}
	}
}

// TestHostSocketsDatagramBestEffort: tier landlock's unix-only state lists host_sockets/datagram, the datagrams the
// supervisor continues rather than relays (ADR 0070), in run_start's best_effort and in compile --test's column for a
// datagram it admits; a refused datagram, a connect, the opt-out and a net: section rest on no such cell.
func TestHostSocketsDatagramBestEffort(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\n"), WithTiers(backend.TierLandlock))
	if !slices.Contains(rt.BestEffortCellsAt(backend.TierLandlock, ""), BestEffortHostSocketsDatagram) {
		t.Errorf("tier landlock: best_effort %v lacks %s", rt.BestEffortCellsAt(backend.TierLandlock, ""), BestEffortHostSocketsDatagram)
	}
	if slices.Contains(rt.BestEffortCellsAt(backend.TierCgroup, ""), BestEffortHostSocketsDatagram) {
		t.Error("tier cgroup's unix-only state is host_sockets/root-tier, not the landlock datagram cell")
	}
	send := Action{Kind: ActionNetSend, Proto: ProtoUDP, Host: "203.0.113.9", Port: 53}
	if got := rt.BestEffortCellsFor(send, EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}, backend.TierLandlock); !slices.Contains(got, BestEffortHostSocketsDatagram) {
		t.Errorf("an admitted datagram's landlock column: %v lacks %s", got, BestEffortHostSocketsDatagram)
	}
	journal := Action{Kind: ActionNetSend, Path: "/run/systemd/journal/socket"}
	if got := rt.BestEffortCellsFor(journal, EvalResult{Verdict: VerdictRefused, Rule: HostSocketsRule}, backend.TierLandlock); slices.Contains(got, BestEffortHostSocketsDatagram) {
		t.Errorf("a refused datagram is exact: %v", got)
	}
	connect := Action{Kind: ActionNetConnect, Proto: ProtoTCP, Host: "203.0.113.9", Port: 443}
	if got := rt.BestEffortCellsFor(connect, EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}, backend.TierLandlock); len(got) != 0 {
		t.Errorf("every connect is relayed: %v", got)
	}
	for _, yaml := range []string{
		"version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\n",
		"version: 0\nname: t\ncommand: [\"python\"]\nnet: {}\n",
	} {
		rt, _ := f.compile(f.load(yaml), WithTiers(backend.TierLandlock))
		if slices.Contains(rt.BestEffortCellsAt(backend.TierLandlock, ""), BestEffortHostSocketsDatagram) {
			t.Errorf("%q is not in the unix-only state", yaml)
		}
	}
}

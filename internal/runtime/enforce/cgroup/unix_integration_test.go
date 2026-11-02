// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// unixHelperEnv selects the child half of TestUnixVerdictOnRealKernel.
const unixHelperEnv = "TEGO_UNIX_HELPER"

// unixFixture is the names the unix kernel cells decide: listening stream sockets, datagram sockets that nothing
// reads, and the table whose unix: and fs entries admit some of them (§5 R7).
type unixFixture struct {
	base, work, secret, tag                      string
	listed, unlisted, listedDgram, unlistedDgram string
	workDgram, secretDgram                       string
	absListed, absUnlisted                       string
	absListedDgram, absUnlistedDgram             string
	tooLong                                      string
}

// newUnixFixture makes the names under a new directory and serves each until the test ends; tag keeps its abstract
// names apart from another test's.
func newUnixFixture(t *testing.T, tag string) *unixFixture {
	t.Helper()
	base, err := os.MkdirTemp("", "eyu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	u := &unixFixture{base: base, work: filepath.Join(base, "work"), tag: tag + "-" + strconv.Itoa(os.Getpid())}
	u.secret = filepath.Join(u.work, "secret")
	if err := os.MkdirAll(u.secret, 0o755); err != nil {
		t.Fatal(err)
	}
	u.listed, u.unlisted = filepath.Join(base, "listed.sock"), filepath.Join(base, "unlisted.sock")
	u.listedDgram, u.unlistedDgram = filepath.Join(base, "listed.dg"), filepath.Join(base, "unlisted.dg")
	u.workDgram, u.secretDgram = filepath.Join(u.work, "ok.dg"), filepath.Join(u.secret, "no.dg")
	u.absListed, u.absUnlisted = "@tego-it-listed-"+u.tag, "@tego-it-unlisted-"+u.tag
	u.absListedDgram, u.absUnlistedDgram = "@tego-it-listed-dg-"+u.tag, "@tego-it-unlisted-dg-"+u.tag
	// tooLong is a unix: entry a contract can hold (the parser checks sun_path's length before ~/ expands) that
	// no row can: it is skipped, and the run still prepares and attaches on every kernel (SkipUnixLong).
	u.tooLong = filepath.Join(base, strings.Repeat("l", 120)+".sock")
	for _, p := range []string{u.listed, u.unlisted, u.absListed, u.absUnlisted} {
		acceptUnix(t, p)
	}
	for _, p := range []string{u.listedDgram, u.unlistedDgram, u.workDgram, u.secretDgram, u.absListedDgram, u.absUnlistedDgram} {
		receiveUnixgram(t, p)
	}
	return u
}

// table is the run's rules: unix: entries for the listed names, a write entry over work/ and a deny_read over
// work/secret/.
func (u *unixFixture) table() *agent.RuleTable {
	entry := func(name string) agent.NetRule {
		r := agent.NetRule{Raw: "unix:" + name, Proto: agent.ProtoUnix, Verdict: agent.VerdictAllow, Static: true}
		if strings.HasPrefix(name, "@") {
			r.Abstract, r.UnixPath = true, name[1:]
		} else {
			r.UnixPath = name
		}
		return r
	}
	return &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull,
		Net: []agent.NetRule{entry(u.listed), entry(u.listedDgram), entry(u.absListed), entry(u.absListedDgram),
			entry(u.tooLong)},
		FS: []agent.FSRule{
			{Path: u.work, Kind: agent.FSWrite, Resolved: u.work},
			{Path: u.secret, Kind: agent.FSDenyRead, Resolved: u.secret},
		}}
}

// TestUnixVerdictOnRealKernel runs connect_unix and sendmsg_unix in the running kernel (§5 R7): from inside the
// run, the agent's own connects and datagrams, and from the launcher's cgroup, the supervisor's relay, which
// connects a duplicate of the agent's socket to the inode it resolved, named /proc/self/fd/<n>
// (supervisor.md R11). Every refusal it asserts is one the kernel made before the path lookup: before these
// programs, every unix destination below was reachable at tier 2 whatever the contract said, and an
// addressed datagram, which the supervisor records and continues (supervisor.md R13b), left for an unlisted
// socket. Below 6.7 the programs are not loaded, and a run of tier cgroup without a plane mode decides no unix
// name in the kernel: the test asserts that, and skips. With a plane mode the plane decides them there
// (enforce-plane R14), which TestPlaneUnixVerdictOnRealKernel holds to these same cells.
func TestUnixVerdictOnRealKernel(t *testing.T) {
	u := newUnixFixture(t, "cg")
	h, dir, _ := realRun(t, "unix", u.table())
	if s := h.Rules().Skipped; len(s) != 1 || s[0].Raw != "unix:"+u.tooLong || s[0].Why != SkipUnixLong {
		t.Fatalf("skipped %+v, want only the entry longer than sun_path", s)
	}
	kern := h.kern.(*bpfKernel)
	_, connectUnix := kern.progs[ebpfbindings.ProgConnectUnix]
	_, sendmsgUnix := kern.progs[ebpfbindings.ProgSendmsgUnix]
	if connectUnix != sendmsgUnix {
		t.Fatalf("connect_unix loaded %v, sendmsg_unix loaded %v: the two arrive together in 6.7", connectUnix, sendmsgUnix)
	}
	if !connectUnix {
		// Below 6.7, and with no plane mode, the kernel decides nothing about unix sockets for the run; tier 1
		// does (§6 E1).
		got := runUnixHelper(t, dir, u.base, []string{"connect " + u.unlisted, "sendto " + u.unlistedDgram})
		if got[0] != nil || got[1] != nil {
			t.Fatalf("below the unix hooks' kernel the run's unix connect and datagram were refused: %v, %v", got[0], got[1])
		}
		t.Skip("this kernel predates the unix sockaddr hooks (6.7); the programs are not loaded and, with no " +
			"plane mode, tier 1 decides")
	}
	unixKernelCells(t, dir, u, unix.EPERM)

	slot := h.Slot()
	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	names := kern.maps[ebpfbindings.MapUnixNames]
	var key ebpfbindings.UnixKey
	var val ebpfbindings.NetVerdict
	for it := names.Iterate(); it.Next(&key, &val); {
		if key.RunIdx == slot {
			t.Fatalf("a unix name row of slot %d survived Detach: %q", slot, key.Name[:])
		}
	}
}

// unixKernelCells are the unix names' cells for the run in the cgroup dir names, whichever program decides them:
// connect_unix and sendmsg_unix refuse with EPERM (6.7+), the plane's socket_connect and socket_sendmsg with EACCES
// (below 6.7, enforce-plane R14).
func unixKernelCells(t *testing.T, dir *os.File, u *unixFixture, refused syscall.Errno) {
	t.Run("the agent's own connects and datagrams", func(t *testing.T) {
		cases := []struct {
			op   string
			want error
		}{
			{"connect " + u.listed, nil},
			{"connect " + u.unlisted, refused},
			{"connect " + filepath.Join(u.base, "missing.sock"), refused}, // decided before the lookup
			{"connect " + u.absListed, nil},
			{"connect " + u.absUnlisted, refused},
			{"connect listed.sock", refused}, // relative: never the supervisor's relay (§5 R7)
			{"dgram-connect " + u.listedDgram, nil},
			{"dgram-connect " + u.unlistedDgram, refused},
			{"sendto " + u.listedDgram, nil},
			{"sendto " + u.unlistedDgram, refused},
			{"sendto " + u.workDgram, nil},       // beneath a write entry: the run's own (SEMANTICS §5)
			{"sendto " + u.secretDgram, refused}, // beneath a deny_read inside it
			{"sendto " + u.absListedDgram, nil},
			{"sendto " + u.absUnlistedDgram, refused},
			{"sendto unlisted.dg", nil}, // relative: left to tier 1, which records it
			{"sendto " + u.work + "/../unlisted.dg", refused},
			{"sendto " + u.work + "/./ok.dg", refused}, // not spelled canonically: refused, fail-closed
			{"sendto " + u.base + "//listed.dg", refused},
			{"procfd " + u.unlisted, refused}, // the relay's name shape, from inside the run
		}
		ops := make([]string, len(cases))
		for i, c := range cases {
			ops[i] = c.op
		}
		got := runUnixHelper(t, dir, u.base, ops)
		for i, c := range cases {
			if !errors.Is(got[i], c.want) && !(c.want == nil && got[i] == nil) {
				t.Errorf("%s from inside the run: %v, want %v", c.op, got[i], c.want)
				continue
			}
			t.Logf("%s from inside the run: %v", c.op, got[i])
		}
	})

	t.Run("the supervisor's relay from the launcher's cgroup", func(t *testing.T) {
		relay := func(name string, via bool) error {
			t.Helper()
			pid, fd, done := holdUnix(t, dir)
			defer done()
			pidfd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				t.Fatalf("pidfd_open(%d): %v", pid, err)
			}
			defer unix.Close(pidfd)
			dup, err := unix.PidfdGetfd(pidfd, fd, 0)
			if err != nil {
				t.Fatalf("pidfd_getfd(%d, %d): %v", pid, fd, err)
			}
			defer unix.Close(dup)
			if !via {
				return unix.Connect(dup, &unix.SockaddrUnix{Name: name})
			}
			pfd, err := unix.Open(name, unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatalf("open %s O_PATH: %v", name, err)
			}
			defer unix.Close(pfd)
			return unix.Connect(dup, &unix.SockaddrUnix{Name: "/proc/self/fd/" + strconv.Itoa(pfd)})
		}
		// The relay admitted the socket it resolved, whatever its name (supervisor.md R11); the kernel admits
		// the name it relays under from this cgroup, and only that name.
		if err := relay(u.unlisted, true); err != nil {
			t.Errorf("relayed connect through /proc/self/fd from the launcher's cgroup: %v, want success", err)
		}
		if err := relay(u.unlisted, false); !errors.Is(err, refused) {
			t.Errorf("relayed connect naming an unlisted socket directly: %v, want %v", err, refused)
		}
		if err := relay(u.absListed, false); err != nil {
			t.Errorf("relayed connect to a listed abstract name: %v, want success", err)
		}
		if err := relay(u.absUnlisted, false); !errors.Is(err, refused) {
			t.Errorf("relayed connect to an unlisted abstract name: %v, want %v", err, refused)
		}
	})

	t.Run("the relay's name from any other cgroup", func(t *testing.T) {
		other := filepath.Join("/sys/fs/cgroup", "tego-it-unix-other-"+u.tag)
		if err := os.Mkdir(other, 0o755); err != nil {
			t.Skipf("cannot create a second cgroup at %s: %v", other, err)
		}
		defer os.Remove(other)
		odir, err := os.Open(other)
		if err != nil {
			t.Fatal(err)
		}
		defer odir.Close()
		pid, fd, done := holdUnix(t, dir)
		defer done()
		got := runUnixHelper(t, odir, u.base, []string{fmt.Sprintf("relay %d %d %s", pid, fd, u.unlisted)})
		if !errors.Is(got[0], refused) {
			t.Fatalf("/proc/self/fd relay from a cgroup that is not the launcher's: %v, want %v", got[0], refused)
		}
	})
}

// TestUnixHelper is the child half of TestUnixVerdictOnRealKernel. It does nothing in a normal run.
func TestUnixHelper(t *testing.T) {
	mode := os.Getenv(unixHelperEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	out := os.NewFile(3, "report")
	switch mode {
	case "ops":
		for _, op := range strings.Split(os.Getenv("TEGO_UNIX_OPS"), "\n") {
			fmt.Fprintf(out, "%d\n", errnoOf(unixOp(op)))
		}
	case "hold":
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintf(out, "ERR %v\n", err)
			return
		}
		fmt.Fprintf(out, "FD %d\n", fd)
		_ = out.Close()
		_, _ = io.Copy(io.Discard, os.Stdin)
	}
}

// unixOp performs one operation of the helper's list and returns its error.
func unixOp(op string) error {
	verb, arg, _ := strings.Cut(op, " ")
	typ := unix.SOCK_STREAM
	if verb == "sendto" || verb == "dgram-connect" {
		typ = unix.SOCK_DGRAM
	}
	fd, err := unix.Socket(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	switch verb {
	case "connect", "dgram-connect":
		return unix.Connect(fd, &unix.SockaddrUnix{Name: arg})
	case "sendto":
		return unix.Sendto(fd, []byte("x"), 0, &unix.SockaddrUnix{Name: arg})
	case "procfd":
		pfd, err := unix.Open(arg, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(pfd)
		return unix.Connect(fd, &unix.SockaddrUnix{Name: "/proc/self/fd/" + strconv.Itoa(pfd)})
	case "relay":
		var pid, tfd int
		var path string
		if _, err := fmt.Sscanf(arg, "%d %d %s", &pid, &tfd, &path); err != nil {
			return err
		}
		pidfd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			return err
		}
		defer unix.Close(pidfd)
		dup, err := unix.PidfdGetfd(pidfd, tfd, 0)
		if err != nil {
			return err
		}
		defer unix.Close(dup)
		pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(pfd)
		return unix.Connect(dup, &unix.SockaddrUnix{Name: "/proc/self/fd/" + strconv.Itoa(pfd)})
	default:
		return fmt.Errorf("unknown op %q", op)
	}
}

// errnoOf is the helper's report of one result: 0, the errno, or -1 for an error without one.
func errnoOf(err error) int {
	var en syscall.Errno
	switch {
	case err == nil:
		return 0
	case errors.As(err, &en):
		return int(en)
	default:
		return -1
	}
}

// unixHelperCommand re-executes this test binary as TestUnixHelper in the cgroup dir names, from cwd.
func unixHelperCommand(dir *os.File, cwd, mode string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestUnixHelper$")
	cmd.Env = append(os.Environ(), unixHelperEnv+"="+mode)
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	cmd.Stderr = os.Stderr
	return cmd
}

// runUnixHelper runs ops in a helper inside the cgroup dir names and returns one result per op.
func runUnixHelper(t *testing.T, dir *os.File, cwd string, ops []string) []error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cmd := unixHelperCommand(dir, cwd, "ops")
	cmd.Env = append(cmd.Env, "TEGO_UNIX_OPS="+strings.Join(ops, "\n"))
	cmd.ExtraFiles = []*os.File{w}
	startHelper(t, cmd)
	w.Close()
	var out []error
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		n, err := strconv.Atoi(strings.TrimSpace(sc.Text()))
		switch {
		case err != nil || n < 0:
			out = append(out, fmt.Errorf("helper: %q", sc.Text()))
		case n == 0:
			out = append(out, nil)
		default:
			out = append(out, syscall.Errno(n))
		}
	}
	r.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v", err)
	}
	if len(out) != len(ops) {
		t.Fatalf("helper reported %d results for %d operations", len(out), len(ops))
	}
	return out
}

// holdUnix starts a helper in the run's cgroup that creates an AF_UNIX stream socket, the socket the
// supervisor would duplicate, and keeps it until the returned function runs.
func holdUnix(t *testing.T, dir *os.File) (int, int, func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cmd := unixHelperCommand(dir, "/", "hold")
	cmd.ExtraFiles = []*os.File{w}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	startHelper(t, cmd)
	w.Close()
	fd := helperFD(t, cmd, r)
	return cmd.Process.Pid, fd, func() {
		stdin.Close()
		_ = cmd.Wait()
	}
}

// acceptUnix listens on a unix stream socket, a pathname or an @abstract name, and accepts and closes every
// connection until the test ends.
func acceptUnix(t *testing.T, name string) {
	t.Helper()
	l, err := net.Listen("unix", name)
	if err != nil {
		t.Fatalf("listen unix %s: %v", name, err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
}

// receiveUnixgram binds a unix datagram socket that nothing reads; a send to it succeeds while its queue has
// room, which a handful of datagrams never fills.
func receiveUnixgram(t *testing.T, name string) {
	t.Helper()
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen unixgram %s: %v", name, err)
	}
	t.Cleanup(func() { c.Close() })
}

// TestUnixRowsPurgedOnRealMaps is §5 R12 for the unix name trie on the kernel's own LPM map: a slot reclaimed
// from a launcher that died with rows pinned is scrubbed of its unix rows too, or the next run on the slot
// inherits a dead run's admitted socket names (§8 I5).
func TestUnixRowsPurgedOnRealMaps(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull,
		Net: []agent.NetRule{{Raw: "unix:/run/tego-it.sock", Proto: agent.ProtoUnix, UnixPath: "/run/tego-it.sock",
			Verdict: agent.VerdictAllow, Static: true}}}
	h, _, _ := realRun(t, "unixpurge", rt)
	kern := h.kern.(*bpfKernel)
	names := kern.maps[ebpfbindings.MapUnixNames]
	stale, err := ebpfbindings.UnixPathKey(h.Slot(), "/stale-from-a-dead-run.sock", false)
	if err != nil {
		t.Fatal(err)
	}
	allow := ebpfbindings.NetVerdict{Verdict: uint8(ebpfbindings.VerdictAllow)}
	if err := names.Update(&stale, &allow, 0); err != nil {
		t.Fatalf("write a stale row: %v", err)
	}
	if err := kern.purgeSlot(h.Slot()); err != nil {
		t.Fatalf("purgeSlot: %v", err)
	}
	var got ebpfbindings.NetVerdict
	if err := names.Lookup(&stale, &got); err == nil {
		t.Fatalf("a unix name row of slot %d survived purgeSlot", h.Slot())
	}
}

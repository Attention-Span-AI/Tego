// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// reapMainEnv makes this test binary, started as the reaper's command (`<binary> __reap <spec>`), run ReapMain
// itself from TestMain, before the testing package opens anything: the production sweep and inheritance as the
// tego binary's first descriptor operations. "run" runs it as it is; "sealed" makes an owner first, so the sweep
// is refused (sys.ErrSealed) as one after any other descriptor operation is. In both, the reaper's hold (reached
// once its launcher is gone, before it acts) prints "hold", its session and every descriptor it then holds, and
// exits 0: what ReapMain did before acting is then on stdout, and a reaper that fails closed never prints "hold".
const reapMainEnv = "TEGO_TEST_REAP_MAIN"

// reapMainHelper is reapMainEnv's dispatch; it returns when this binary was not started so.
func reapMainHelper() {
	mode := os.Getenv(reapMainEnv)
	if mode == "" || len(os.Args) < 2 || os.Args[1] != ReapCommand {
		return
	}
	if mode == "sealed" {
		if _, err := sys.Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)); err != nil {
			fmt.Fprintf(os.Stderr, "seal: %v\n", err)
			os.Exit(9)
		}
	}
	reapHold = func() {
		sid, _ := unix.Getsid(0)
		fmt.Printf("hold\nsid %d\n", sid)
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			fmt.Fprintf(os.Stderr, "list descriptors: %v\n", err)
			os.Exit(9)
		}
		for _, e := range entries {
			link, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
			if err != nil || link == "anon_inode:[eventpoll]" || link == "anon_inode:[eventfd]" {
				continue // the listing's own descriptor, closed by now, and the Go runtime's poller
			}
			if strings.HasPrefix(link, "/proc/") && strings.HasSuffix(link, "/fd") {
				continue // the listing's own descriptor
			}
			fmt.Printf("fd %s %s\n", e.Name(), link)
		}
		os.Exit(0)
	}
	os.Exit(ReapMain(os.Args[2:]))
}

// reapMainResult is what a ReapMain helper did: its exit code, whether it reached its hold, its session and
// descriptors there, and its standard error.
type reapMainResult struct {
	code   int
	hold   bool
	sid    string
	fds    map[int]string
	stderr string
}

// runReapMain runs cmd, a reaper command whose executable is this test binary, as ReapMain in mode
// (reapMainEnv).
func runReapMain(t *testing.T, cmd *proc.Cmd, mode string) reapMainResult {
	t.Helper()
	if cmd.Path != os.Args[0] || len(cmd.Args) < 2 || cmd.Args[1] != ReapCommand {
		t.Fatalf("not a reaper command of this binary: %q", cmd.Args)
	}
	cmd.Env = append(cmd.Env, reapMainEnv+"="+mode)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	r := reapMainResult{fds: map[int]string{}}
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	default:
		t.Fatalf("reaper helper: %v", err)
	}
	r.stderr = errb.String()
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		line := sc.Text()
		if line == "hold" {
			r.hold = true
		}
		if v, ok := strings.CutPrefix(line, "sid "); ok {
			r.sid = v
		}
		if rest, ok := strings.CutPrefix(line, "fd "); ok {
			num, link, _ := strings.Cut(rest, " ")
			n, err := strconv.Atoi(num)
			if err != nil {
				t.Fatalf("helper line %q", line)
			}
			r.fds[n] = link
		}
	}
	return r
}

// numbers is the sorted set of descriptor numbers in fds.
func (r reapMainResult) numbers() []int {
	var got []int
	for n := range r.fds {
		got = append(got, n)
	}
	slices.Sort(got)
	return got
}

// deadLauncherPidfd is a pidfd of a process that has exited and been reaped, as the reaper's launcher's is once
// it is gone: a reaper given it waits for nothing.
func deadLauncherPidfd(t *testing.T) *os.File {
	t.Helper()
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	fd, err := sys.PidfdOpenProcessFD(cmd.Process.Pid) // a zombie until Wait, so the pid is still this child
	if werr := cmd.Wait(); err == nil && werr != nil {
		err = werr
	}
	if err != nil {
		t.Skipf("pidfd of an exited child: %v", err)
	}
	f, err := fd.Release("launcher-pidfd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestTheReaperFailsClosedOnItsInheritedDescriptors is ADR 0023 C9's reaper as ReapMain runs it: it sweeps every
// number above what its launcher passed and then owns each passed number through sys.Inherited with the kind it
// must be, and a number that is open but not that kind (a stray file where the pidfd, the run directory, a DNS
// directory or the handoff pipe should be), or a sweep sys refuses, ends it with exit 125 and one line naming the
// number, before it waits on, reads, sweeps or unlinks anything (it never reaches its hold).
func TestTheReaperFailsClosedOnItsInheritedDescriptors(t *testing.T) {
	pidfd := deadLauncherPidfd(t)
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	regular, err := os.Create(filepath.Join(t.TempDir(), "stray"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = regular.Close() }()
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pipeR.Close(); _ = pipeW.Close() }()

	plain := reapTestSpec(t, t.TempDir(), "/sys/fs/cgroup")
	dns := plain
	dns.DNSName, dns.DNSDev, dns.DNSIno = "tego-dns-1", 1, 1
	for _, tc := range []struct {
		name  string
		spec  reapSpec
		files []*os.File
		mode  string
		want  []string // what the one line on stderr says
	}{
		{"a file for the pidfd", plain, []*os.File{regular, dir}, "run",
			[]string{"inherited launcher-pidfd at 3", sys.ErrKind.Error()}},
		{"a file for the run directory", plain, []*os.File{pidfd, regular}, "run",
			[]string{"inherited run-dir at 4", sys.ErrKind.Error()}},
		{"a pipe for the run directory", plain, []*os.File{pidfd, pipeR}, "run",
			[]string{"inherited run-dir at 4", sys.ErrKind.Error()}},
		{"a file for the DNS directory", dns, []*os.File{pidfd, dir, regular, dir, pipeR}, "run",
			[]string{"inherited dns-dir at 5", sys.ErrKind.Error()}},
		{"a file for the DNS parent", dns, []*os.File{pidfd, dir, dir, regular, pipeR}, "run",
			[]string{"inherited dns-parent at 6", sys.ErrKind.Error()}},
		{"a file for the handoff pipe", dns, []*os.File{pidfd, dir, dir, dir, regular}, "run",
			[]string{"inherited target-handoff at 7", sys.ErrKind.Error()}},
		{"no handoff pipe", dns, []*os.File{pidfd, dir, dir, dir}, "run",
			[]string{"inherited target-handoff at 7", sys.ErrKind.Error()}},
		{"a sealed sweep", plain, []*os.File{pidfd, dir}, "sealed",
			[]string{"close inherited descriptors from 5", sys.ErrSealed.Error()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := reaperCommand(os.Args[0], tc.spec, pidfd, dir, nil, nil)
			cmd.ExtraFiles = tc.files
			r := runReapMain(t, cmd, tc.mode)
			if r.code != identity.ExitError || r.hold {
				t.Fatalf("reaper exit %d, hold %t, stderr %q: want exit %d before it acts", r.code, r.hold, r.stderr,
					identity.ExitError)
			}
			lines := strings.Split(strings.TrimSuffix(r.stderr, "\n"), "\n")
			if len(lines) != 1 || !strings.HasPrefix(lines[0], "tego "+ReapCommand+": ") {
				t.Fatalf("reaper stderr %q: want its one refusal line and nothing after it", r.stderr)
			}
			for _, w := range tc.want {
				if !strings.Contains(lines[0], w) {
					t.Errorf("reaper said %q, want %q in it", lines[0], w)
				}
			}
		})
	}
	// The same layouts with every number its kind reach the hold: what failed above was the kind alone.
	for _, tc := range []struct {
		name  string
		spec  reapSpec
		files []*os.File
	}{
		{"plain run", plain, []*os.File{pidfd, dir}},
		{"a DNS broker's run", dns, []*os.File{pidfd, dir, dir, dir, pipeR}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := reaperCommand(os.Args[0], tc.spec, pidfd, dir, nil, nil)
			cmd.ExtraFiles = tc.files
			if r := runReapMain(t, cmd, "run"); r.code != 0 || !r.hold {
				t.Fatalf("reaper exit %d, hold %t, stderr %q: want its hold", r.code, r.hold, r.stderr)
			}
		})
	}
}

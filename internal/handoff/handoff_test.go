// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// The test binary plays both sides. As roleControl it is the tego-control a handoff runs: it prints its arguments
// and exits. As roleCaller it is a tego that opens the tego-control in TEGO_HANDOFF_TEST_DIR against the pin in
// TEGO_HANDOFF_TEST_PIN, lets the attack in TEGO_HANDOFF_TEST_ATTACK change the file on disk, and then Execs.
const (
	roleEnv     = "TEGO_HANDOFF_TEST_ROLE"
	roleControl = "control"
	roleCaller  = "caller"
	// roleNoexec is the first process of a new pid namespace that opens TEGO_HANDOFF_TEST_DIR's tego-control, sets
	// its namespace's vm.memfd_noexec to 2 and opens it again (TestHandoffMemfdNoexecOnTheKernel, as root).
	roleNoexec = "noexec"
	// verified is what the verified tego-control prints; evil is what the file on disk says after an attack.
	verified = "verified-control"
	evil     = "EVIL"
)

func TestMain(m *testing.M) {
	switch os.Getenv(roleEnv) {
	case roleControl:
		fmt.Printf("%s args=%q\n", verified, os.Args)
		reportFDs(len(os.Args) > 1 && os.Args[1] == "fds")
		if os.Getenv(nofileEnv) != "" {
			reportChildNofile()
		}
		os.Exit(0)
	case roleCaller:
		os.Exit(callerMain())
	case roleNoexec:
		os.Exit(noexecMain())
	}
	os.Exit(m.Run())
}

// noexecMain opens the planted tego-control, sets this pid namespace's vm.memfd_noexec to 2, and opens it again,
// printing each result. The caller is root, so the open is asked for an unprivileged caller (euid 65534), which
// only the root refusal reads; the file is root's, which the owner check admits.
func noexecMain() int {
	c := config{dir: os.Getenv("TEGO_HANDOFF_TEST_DIR"), pin: os.Getenv("TEGO_HANDOFF_TEST_PIN"), euid: 65534}
	report := func(step string) {
		b, err := c.open()
		var e *Error
		switch {
		case err == nil:
			_ = b.Close()
			fmt.Printf("%s: ok\n", step)
		case errors.As(err, &e):
			fmt.Printf("%s: [%s] fix=%q\n", step, e.Code, e.Fix)
		default:
			fmt.Printf("%s: %v\n", step, err)
		}
	}
	report("before")
	if err := os.WriteFile(memfdNoexec, []byte("2\n"), 0); err != nil {
		fmt.Println("sysctl:", err)
		return 3
	}
	scope, err := os.ReadFile(memfdNoexec)
	fmt.Printf("scope=%s err=%v\n", strings.TrimSpace(string(scope)), err)
	report("after")
	return 0
}

// reportFDs prints "memfd-inherited" when this process holds a writable descriptor of a memfd named tego-control,
// "image=<fd>" for a read-only one, and with extra the contents of descriptors 3 to 6.
func reportFDs(extra bool) {
	ents, _ := os.ReadDir("/proc/self/fd")
	for _, e := range ents {
		if l, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && strings.HasPrefix(l, "/memfd:"+Name) {
			info, _ := os.ReadFile("/proc/self/fdinfo/" + e.Name())
			if readOnlyFlags(string(info)) {
				fmt.Printf("image=%s\n", e.Name())
			} else {
				fmt.Printf("memfd-inherited %q\n", info)
			}
		}
	}
	for fd := 3; extra && fd <= 6; fd++ {
		b, err := io.ReadAll(os.NewFile(uintptr(fd), "extra"))
		fmt.Printf("fd%d=%s %v\n", fd, b, err)
	}
}

// nofileEnv asks the control role to print the soft RLIMIT_NOFILE a child of it starts with; spawnEnv asks the
// caller to hand off with Spawn and wait instead of Exec.
const (
	nofileEnv = "TEGO_HANDOFF_TEST_NOFILE"
	spawnEnv  = "TEGO_HANDOFF_TEST_SPAWN"
)

// reportChildNofile prints "child-soft-nofile=N", the soft RLIMIT_NOFILE a non-Go child of this process starts with.
// This process is Go, which raised its own soft limit at start, so its own Getrlimit would show the raise; a child
// gets the limit this process started with, which Go restores in it.
func reportChildNofile() {
	out, err := exec.Command("/bin/sh", "-c", "ulimit -Sn").Output()
	fmt.Printf("child-soft-nofile=%s err=%v\n", strings.TrimSpace(string(out)), err)
}

// callerMain is a tego that hands off: Open, the attack, then Exec (or Spawn and wait, with spawnEnv). It returns
// only when the handoff failed, or after a Spawned child exited.
func callerMain() int {
	dir := os.Getenv("TEGO_HANDOFF_TEST_DIR")
	euid := os.Geteuid()
	if v := os.Getenv(euidEnv); v != "" {
		euid, _ = strconv.Atoi(v)
	}
	b, err := config{dir: dir, pin: os.Getenv("TEGO_HANDOFF_TEST_PIN"), euid: euid}.open()
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			fmt.Printf("open: [%s] %v\n", e.Code, err)
		}
		return 3
	}
	if err := attack(os.Getenv("TEGO_HANDOFF_TEST_ATTACK"), dir); err != nil {
		fmt.Println("attack:", err)
		return 4
	}
	// Exec hands the environment over verbatim, and the first of two settings of a variable wins: drop the caller's
	// role, or the exec'd image is a caller again and hands off for ever.
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, roleEnv+"=") {
			env = append(env, kv)
		}
	}
	args, env := []string{"serve", "--listen", "x"}, append(env, roleEnv+"="+roleControl)
	if os.Getenv(spawnEnv) != "" {
		cmd, _, err := Spawn(b, Child{Args: args, Env: env, Stdout: os.Stdout, Stderr: os.Stderr})
		if err == nil {
			err = cmd.Wait()
		}
		if err != nil {
			fmt.Println("spawn:", err)
			return 5
		}
		return 0
	}
	err = Exec(b, args, env)
	fmt.Println("exec:", err)
	return 5
}

// evilScript is what an attacker writes: a program that is not the verified one.
const evilScript = "#!/bin/sh\necho " + evil + "\n"

// attack changes dir's tego-control after the handoff opened it: "inplace" writes the same inode, "rename" puts
// another file at the path.
func attack(kind, dir string) error {
	path := filepath.Join(dir, Name)
	switch kind {
	case "":
		return nil
	case "inplace":
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(evilScript); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	case "rename":
		other := filepath.Join(dir, "other")
		if err := os.WriteFile(other, []byte(evilScript), 0o755); err != nil {
			return err
		}
		return os.Rename(other, path)
	}
	return fmt.Errorf("unknown attack %q", kind)
}

// plant copies the test binary to dir/tego-control, mode 0755, and returns its SHA-256.
func plant(t *testing.T, dir string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, Name), b, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// wantCode fails unless err is an *Error with code.
func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err %v, want a refusal [%s]", err, code)
	}
	if e.Code != code {
		t.Fatalf("refused [%s] %q, want [%s]", e.Code, e.Error(), code)
	}
	if e.What == "" || e.Fix == "" {
		t.Fatalf("refusal %+v lacks its sentence or its fix", e)
	}
}

// euidEnv carries the euid a caller process hands off as; unset, it is the process's own.
const euidEnv = "TEGO_HANDOFF_TEST_EUID"

// callerEUID is the euid the tests hand off as: this process's, or, when the suite runs as root (test/vm/root-suites.sh
// runs this package as root), an unprivileged one, since the handoff refuses root and the root rows test that. A file
// root planted is root's, which the owner check admits for any caller.
func callerEUID() int {
	if euid := os.Geteuid(); euid != 0 {
		return euid
	}
	return 65534
}

func open(t *testing.T, dir, pin string) (*Binary, error) {
	t.Helper()
	b, err := config{dir: dir, pin: pin, euid: callerEUID()}.open()
	if err == nil {
		t.Cleanup(func() { _ = b.Close() })
	}
	return b, err
}

// runCaller runs the test binary as a tego that hands off to dir's tego-control after attack, as callerEUID.
func runCaller(t *testing.T, dir, pin, attackKind string) string {
	t.Helper()
	return runCallerAs(t, callerEUID(), dir, pin, attackKind)
}

// runCallerAs is runCaller handing off as euid, or as the process's own euid when euid is -1, with extra added to
// the caller's environment.
func runCallerAs(t *testing.T, euid int, dir, pin, attackKind string, extra ...string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), roleEnv+"="+roleCaller, "TEGO_HANDOFF_TEST_DIR="+dir,
		"TEGO_HANDOFF_TEST_PIN="+pin, "TEGO_HANDOFF_TEST_ATTACK="+attackKind)
	cmd.Env = append(cmd.Env, extra...)
	if euid >= 0 {
		cmd.Env = append(cmd.Env, euidEnv+"="+strconv.Itoa(euid))
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 3) {
		t.Fatalf("caller: %v: %s", err, out) // 3 is a refused Open, which the caller's test reads from the output
	}
	return string(out)
}

// wantVerified fails unless out is the verified tego-control's, run as tego-control with args.
func wantVerified(t *testing.T, out string, args ...string) {
	t.Helper()
	if strings.Contains(out, evil) || !strings.Contains(out, verified) || strings.Contains(out, "memfd-inherited") {
		t.Fatalf("output %q, want the verified tego-control's", out)
	}
	if want := fmt.Sprintf("args=%q", append([]string{Name}, args...)); !strings.Contains(out, want) {
		t.Fatalf("output %q, want %s", out, want)
	}
}

// wantDiskIsEvil shows the attack worked on the file: running the path now runs the attacker's program, so the
// verified output above came from the sealed copy and not from the file.
func wantDiskIsEvil(t *testing.T, dir string) {
	t.Helper()
	out, err := exec.Command(filepath.Join(dir, Name)).CombinedOutput()
	if err != nil || !strings.Contains(string(out), evil) {
		t.Fatalf("the attacked file printed %q (%v), want %s: the attack did not take", out, err, evil)
	}
}

func TestHandoffExecsTheVerifiedCopy(t *testing.T) {
	dir := t.TempDir()
	pin := plant(t, dir)
	wantVerified(t, runCaller(t, dir, pin, ""), "serve", "--listen", "x")
}

// TestHandoffHandsOverTheSoftNofile: Go raises its own soft RLIMIT_NOFILE at start and gives what it execs or starts
// the soft limit it started with. A handoff does the same: under a lowered soft limit, the children of a tego-control
// reached by Exec, and of one reached by Spawn, start with that limit and not with the raise.
func TestHandoffHandsOverTheSoftNofile(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skipf("no /bin/sh to report a child's limit: %v", err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	const low = 1000 // not a default anywhere, so a match is the hand-over and not a coincidence
	if lim.Max < low+2 {
		t.Skipf("hard RLIMIT_NOFILE %d leaves no room below Go's raise to Max-1", lim.Max)
	}
	// Setting the limit drops this process's own record of its start limit, so the caller starts with low as it is,
	// as a tego started under `ulimit -Sn 1000` would.
	set := func(cur uint64) {
		t.Helper()
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: cur, Max: lim.Max}); err != nil {
			t.Fatal(err)
		}
	}
	set(low)
	t.Cleanup(func() { set(lim.Cur) })
	dir := t.TempDir()
	pin := plant(t, dir)
	for _, mode := range []struct{ name, env string }{{"Exec", ""}, {"Spawn", spawnEnv + "=1"}} {
		out := runCallerAs(t, callerEUID(), dir, pin, "", nofileEnv+"=1", mode.env)
		wantVerified(t, out, "serve", "--listen", "x")
		if want := fmt.Sprintf("child-soft-nofile=%d err=<nil>", low); !strings.Contains(out, want) {
			t.Errorf("%s: a child of tego-control reported %q, want %s: the handoff gave tego-control Go's raised limit",
				mode.name, out, want)
		}
	}
}

// TestHandoffRefusesHashMismatch: a tego-control whose hash is not the pin is refused, and nothing runs.
func TestHandoffRefusesHashMismatch(t *testing.T) {
	dir := t.TempDir()
	plant(t, dir)
	other := sha256.Sum256([]byte("another build"))
	_, err := open(t, dir, hex.EncodeToString(other[:]))
	wantCode(t, err, CodeMismatch)
	if out := runCaller(t, dir, hex.EncodeToString(other[:]), ""); strings.Contains(out, verified) {
		t.Fatalf("a mismatched tego-control ran: %q", out)
	}
}

// TestHandoffInPlaceWriteRace: critique 1 M8. A same-uid process that writes the opened inode in place between the
// hash and the exec does not change what runs: the sealed copy runs.
func TestHandoffInPlaceWriteRace(t *testing.T) {
	dir := t.TempDir()
	pin := plant(t, dir)
	wantVerified(t, runCaller(t, dir, pin, "inplace"), "serve", "--listen", "x")
	wantDiskIsEvil(t, dir)

	// Spawn likewise.
	pin = plant(t, dir)
	b, err := open(t, dir, pin)
	if err != nil {
		t.Fatal(err)
	}
	if err := attack("inplace", dir); err != nil {
		t.Fatal(err)
	}
	wantVerified(t, spawn(t, b, "__child"), "__child")
	wantDiskIsEvil(t, dir)
}

// TestHandoffSwapRaceExecsVerifiedFile: another file renamed over the path after the open does not run; the hashed
// file does.
func TestHandoffSwapRaceExecsVerifiedFile(t *testing.T) {
	dir := t.TempDir()
	pin := plant(t, dir)
	wantVerified(t, runCaller(t, dir, pin, "rename"), "serve", "--listen", "x")
	wantDiskIsEvil(t, dir)

	pin = plant(t, dir)
	b, err := open(t, dir, pin)
	if err != nil {
		t.Fatal(err)
	}
	if err := attack("rename", dir); err != nil {
		t.Fatal(err)
	}
	wantVerified(t, spawn(t, b, "serve"), "serve")
}

// spawn runs b as a child with args, the test binary's control role, and returns what it printed.
func spawn(t *testing.T, b *Binary, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	cmd, id, err := Spawn(b, Child{Args: args, Env: append(os.Environ(), roleEnv+"="+roleControl), Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatal(err)
	}
	if id.PID != cmd.Process.Pid || id.StartBootNS == 0 {
		t.Errorf("identity %+v for pid %d", id, cmd.Process.Pid)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child: %v: %s", err, out.String())
	}
	return out.String()
}

// TestHandoffSpawnPassesExtraFiles: Spawn's extra files arrive at 3, 4, ..., then the child's own image, read-only,
// and no other descriptor of the memfd (wantVerified).
func TestHandoffSpawnPassesExtraFiles(t *testing.T) {
	dir := t.TempDir()
	b, err := open(t, dir, plant(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	var files []*os.File
	for i := range 4 {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
		if _, err := fmt.Fprintf(w, "file-%d", i); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		files = append(files, r)
	}
	var out bytes.Buffer
	cmd, _, err := Spawn(b, Child{Args: []string{"fds"}, Env: append(os.Environ(), roleEnv+"="+roleControl), Stdout: &out,
		ExtraFiles: files})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child: %v: %s", err, out.String())
	}
	for i := range 4 {
		if want := fmt.Sprintf("fd%d=file-%d <nil>", 3+i, i); !strings.Contains(out.String(), want) {
			t.Errorf("child printed %q, want %s", out.String(), want)
		}
	}
	if !strings.Contains(out.String(), "image=7\n") || strings.Count(out.String(), "image=") != 1 {
		t.Errorf("child printed %q, want its read-only image at 7 alone", out.String())
	}
	wantVerified(t, out.String(), "fds")
}

// TestHandoffRefusesSymlinkAndWritableFile: a link at the path, a group- or world-writable file, a file owned by
// someone other than root or the caller, something that is not a regular file, a file the caller could not execute
// itself and a file on a mount that forbids exec are all refused. The memfd copy is executable whatever the source's
// mode or mount, so these two would otherwise skip an administrator's `chmod a-x` or noexec mount.
func TestHandoffRefusesSymlinkAndWritableFile(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		real, dir := t.TempDir(), t.TempDir()
		pin := plant(t, real)
		if err := os.Symlink(filepath.Join(real, Name), filepath.Join(dir, Name)); err != nil {
			t.Fatal(err)
		}
		_, err := open(t, dir, pin)
		wantCode(t, err, CodeUntrusted)
	})
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		t.Run(fmt.Sprintf("mode %04o", mode), func(t *testing.T) {
			dir := t.TempDir()
			pin := plant(t, dir)
			if err := os.Chmod(filepath.Join(dir, Name), mode); err != nil {
				t.Fatal(err)
			}
			_, err := open(t, dir, pin)
			wantCode(t, err, CodeUntrusted)
		})
	}
	// Without an execute bit for the caller's class: as a user the file is the caller's own (the owner's bits), as
	// root it is root's and the caller a third uid (the others' bits).
	for _, mode := range []os.FileMode{0o644, 0o640, 0o600, 0o444} {
		t.Run(fmt.Sprintf("not executable %04o", mode), func(t *testing.T) {
			dir := t.TempDir()
			pin := plant(t, dir)
			if err := os.Chmod(filepath.Join(dir, Name), mode); err != nil {
				t.Fatal(err)
			}
			_, err := open(t, dir, pin)
			wantCode(t, err, CodeUntrusted)
			if !strings.Contains(err.Error(), "execute") {
				t.Errorf("refusal %q does not say the file cannot be executed", err)
			}
		})
	}
	if os.Geteuid() != 0 {
		// The owner's own bits decide for the owner, whatever the others may do, as the kernel's check does.
		t.Run("not executable by its owner", func(t *testing.T) {
			dir := t.TempDir()
			pin := plant(t, dir)
			if err := os.Chmod(filepath.Join(dir, Name), 0o655); err != nil {
				t.Fatal(err)
			}
			_, err := open(t, dir, pin)
			wantCode(t, err, CodeUntrusted)
		})
	}
	t.Run("noexec mount", func(t *testing.T) {
		dir := t.TempDir()
		pin := plant(t, dir)
		saved := mountNoexec
		t.Cleanup(func() { mountNoexec = saved })
		mountNoexec = func(*sys.FD) (bool, error) { return true, nil }
		_, err := open(t, dir, pin)
		wantCode(t, err, CodeUntrusted)
		if !strings.Contains(err.Error(), "noexec") {
			t.Errorf("refusal %q does not name the noexec mount", err)
		}
	})
	t.Run("another owner", func(t *testing.T) {
		dir := t.TempDir()
		pin := plant(t, dir)
		euid := os.Geteuid() + 1
		if os.Geteuid() == 0 {
			// Root's file passes the check for any caller: give it to a third uid, neither root nor the caller.
			if err := os.Chown(filepath.Join(dir, Name), 12345, 12345); err != nil {
				t.Fatal(err)
			}
			euid = callerEUID()
		}
		_, err := config{dir: dir, pin: pin, euid: euid}.open()
		wantCode(t, err, CodeUntrusted)
	})
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, Name), 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := open(t, dir, strings.Repeat("0", 64))
		wantCode(t, err, CodeUntrusted)
	})
	t.Run("fifo", func(t *testing.T) {
		dir := t.TempDir()
		if err := unix.Mkfifo(filepath.Join(dir, Name), 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := open(t, dir, strings.Repeat("0", 64)) // must not block on the FIFO
		wantCode(t, err, CodeUntrusted)
	})
}

// TestHandoffExecutableByClass: the execute check reads the bits of the caller's class only, as the kernel's mode
// check does for a file without an ACL: the owner's for the owner, the group's for a member of the file's group (the
// effective group or a supplementary one), and the others' for anyone else.
func TestHandoffExecutableByClass(t *testing.T) {
	for _, tc := range []struct {
		name   string
		uid    uint32
		gid    uint32
		mode   uint32
		groups []int
		want   bool
	}{
		{"owner with u+x", 1000, 1000, 0o700, nil, true},
		{"owner without u+x, others with", 1000, 1000, 0o655, nil, false},
		{"root's file, others with x", 0, 0, 0o755, nil, true},
		{"root's file, others without x", 0, 0, 0o754, nil, false},
		{"root's file, a member of its group with g+x", 0, 50, 0o750, []int{7, 50}, true},
		{"root's file, a member of its group without g+x, others with", 0, 50, 0o705, []int{50}, false},
		{"root's file, not a member, only g+x", 0, 50, 0o750, []int{7}, false},
		{"no execute bit at all", 0, 0, 0o644, []int{0}, false},
	} {
		st := &unix.Stat_t{Uid: tc.uid, Gid: tc.gid, Mode: unix.S_IFREG | tc.mode}
		if got := executable(st, 1000, tc.groups); got != tc.want {
			t.Errorf("%s: executable = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestHandoffRefusesUnpinnedBuild: [control-unpinned]. A build without the pin, or with a pin that is not a
// SHA-256, runs no tego-control, even a present and well-formed one.
func TestHandoffRefusesUnpinnedBuild(t *testing.T) {
	dir := t.TempDir()
	pin := plant(t, dir)
	for _, p := range []string{"", "none", strings.ToUpper(pin), pin[:63], pin + "0"} {
		_, err := open(t, dir, p)
		wantCode(t, err, CodeUnpinned)
	}
	if out := runCaller(t, dir, "", ""); strings.Contains(out, verified) || !strings.Contains(out, CodeUnpinned) {
		t.Fatalf("an unpinned tego handed off: %q", out)
	}
}

// TestHandoffRefusesOutsideExecutableDir: Open looks beside the running tego only. A tego-control in the working
// directory or on PATH, whose hash is the pin, is never found.
func TestHandoffRefusesOutsideExecutableDir(t *testing.T) {
	elsewhere := t.TempDir()
	pin := plant(t, elsewhere)
	t.Chdir(elsewhere)
	t.Setenv("PATH", elsewhere)
	saved := controlSHA256
	controlSHA256 = pin
	t.Cleanup(func() { controlSHA256 = saved })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(self), Name)); err == nil {
		t.Skip("a tego-control is beside the test binary")
	}
	b, err := openAs(callerEUID())
	if err == nil {
		_ = b.Close()
	}
	wantCode(t, err, CodeNotInstalled)
}

// TestHandoffRefusesRoot: [control-as-root]. At euid 0 the handoff refuses before it opens anything.
func TestHandoffRefusesRoot(t *testing.T) {
	dir := t.TempDir()
	pin := plant(t, dir)
	_, err := config{dir: dir, pin: pin, euid: 0}.open()
	wantCode(t, err, CodeAsRoot)
	_, err = config{dir: filepath.Join(dir, "missing"), pin: "", euid: 0}.open()
	wantCode(t, err, CodeAsRoot)
}

// TestHandoffMemfdNoexec: a kernel that refuses MFD_EXEC (vm.memfd_noexec=2 answers EACCES) is [memfd-noexec] with
// the fix; one that does not know the flag (EINVAL: mainline before 6.3, without a backport) is asked again without it.
func TestHandoffMemfdNoexec(t *testing.T) {
	dir := t.TempDir()
	pin := plant(t, dir)
	saved := memfdCreate
	t.Cleanup(func() { memfdCreate = saved })
	memfdCreate = func(bool) (*sys.FD, error) { return nil, unix.EACCES }
	_, err := open(t, dir, pin)
	wantCode(t, err, CodeMemfdNoexec)
	wantNoexecFix(t, err.(*Error).Fix)
	wantNoexecFix(t, execRefused(unix.EACCES).(*Error).Fix)
	var asked []bool
	memfdCreate = func(exec bool) (*sys.FD, error) {
		asked = append(asked, exec)
		if exec {
			return nil, unix.EINVAL
		}
		return saved(exec)
	}
	if _, err := open(t, dir, pin); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(asked, []bool{true, false}) {
		t.Fatalf("memfd asked with MFD_EXEC %v, want with it, then without", asked)
	}
}

// wantNoexecFix fails unless fix shows the user who meets [memfd-noexec] a command that reports vm.memfd_noexec without
// root (the handoff refuses root, and tego doctor reads the setting only as root): it names the sysctl's file, which
// any user can read and which says 0, 1 or 2 where the kernel has it (TestHandoffMemfdNoexecOnTheKernel reads it in
// the namespace that refused).
func wantNoexecFix(t *testing.T, fix string) {
	t.Helper()
	if !strings.Contains(fix, "`cat "+memfdNoexec+"`") || !strings.Contains(fix, "vm.memfd_noexec=1") ||
		strings.Contains(fix, "doctor") {
		t.Errorf("fix %q: want the command that shows the setting without root, and the setting that allows it", fix)
	}
	st, err := os.Stat(memfdNoexec)
	if errors.Is(err, os.ErrNotExist) {
		return // a kernel without the setting: nothing to show
	}
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o004 == 0 {
		t.Errorf("%s is mode %v: the fix's command needs a file any user can read", memfdNoexec, st.Mode())
	}
	b, err := os.ReadFile(memfdNoexec)
	if v := strings.TrimSpace(string(b)); err != nil || (v != "0" && v != "1" && v != "2") {
		t.Errorf("%s reads %q (%v), want 0, 1 or 2", memfdNoexec, b, err)
	}
}

// TestHandoffCopyIsSealed: the copy carries every seal, refuses a write, and its hash is the pin.
func TestHandoffCopyIsSealed(t *testing.T) {
	dir := t.TempDir()
	pin := plant(t, dir)
	b, err := open(t, dir, pin)
	if err != nil {
		t.Fatal(err)
	}
	if b.SHA256() != pin || b.Source() != filepath.Join(dir, Name) {
		t.Fatalf("sha %s source %s", b.SHA256(), b.Source())
	}
	var got int
	if err := sys.FileDo(b.mem, func(n int) error {
		var err error
		got, err = unix.FcntlInt(uintptr(n), unix.F_GET_SEALS, 0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got&seals != seals {
		t.Fatalf("seals %#x, want %#x", got, seals)
	}
	if _, err := b.mem.WriteAt([]byte("x"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("a write to the sealed copy: %v, want EPERM", err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(b.mem, 0, 1<<30)); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(h.Sum(nil)) != pin {
		t.Fatal("the sealed copy's bytes are not the pinned file's")
	}
}

// TestReasonCodesMapToIdentityExits: every reason code the handoff and tego-control give maps to a pkg/spec/identity
// exit code of a subcommand, and there is no other.
func TestReasonCodesMapToIdentityExits(t *testing.T) {
	want := []string{CodeAsRoot, CodeMemfdNoexec, CodeMismatch, CodeNotInstalled, CodeUnpinned, CodeUntrusted}
	slices.Sort(want)
	if got := Codes(); !slices.Equal(got, want) {
		t.Fatalf("codes %v, want %v", got, want)
	}
	for _, c := range want {
		switch Exit(c) {
		case identity.ExitError, identity.ExitUsage, identity.ExitFinding:
		default:
			t.Errorf("[%s] exits %d, which is not a subcommand's exit in pkg/spec/identity", c, Exit(c))
		}
		if Exit(c) != identity.ExitError {
			t.Errorf("[%s] exits %d, want %d: a refused handoff is Tego's own error", c, Exit(c), identity.ExitError)
		}
	}
}

// TestNounsAreSortedAndNamed: the noun list is sorted, has no duplicate, and gives each noun a summary.
func TestNounsAreSortedAndNamed(t *testing.T) {
	ns := Nouns()
	if !IsNoun("serve") {
		t.Fatalf("serve is not a noun: %+v", ns)
	}
	for i, n := range ns {
		if n.Summary == "" || !IsNoun(n.Name) {
			t.Errorf("noun %+v", n)
		}
		if i > 0 && ns[i-1].Name >= n.Name {
			t.Errorf("nouns not sorted at %s", n.Name)
		}
	}
	if IsNoun("run") || IsNoun("version") {
		t.Error("an engine command is listed as a tego-control noun")
	}
}

// readOnlyFlags reports whether an fdinfo's flags line (octal) opens the file read-only.
func readOnlyFlags(info string) bool {
	for _, l := range strings.Split(info, "\n") {
		if v, ok := strings.CutPrefix(l, "flags:"); ok {
			f, err := strconv.ParseInt(strings.TrimSpace(v), 8, 64)
			return err == nil && f&unix.O_ACCMODE == unix.O_RDONLY
		}
	}
	return false
}

// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// inheritedHelperEnv makes this test binary, re-executed by the Inherited tests, run TestInheritedHelper in
// the given mode. Inherited fails once a process has made any other owner (the seal), and this package's own
// tests make owners, so its checks run in a process that has made none.
const inheritedHelperEnv = "TEGO_SYS_INHERITED_HELPER"

// inheritedKinds lists, in ExtraFiles order from 3 up, the kinds the parent hands the helper; "-" where the
// host could not make one (a kernel without Landlock has no ruleset).
const inheritedKindsEnv = "TEGO_SYS_INHERITED_KINDS"

var kindNames = map[string]Kind{
	"dir": KindDir, "socket": KindSocket, "fifo": KindFIFO, "regular": KindRegular,
	"pidfd": KindPidfd, "ruleset": KindRuleset,
}

// TestInheritedHelper is the re-executed process of TestInheritedKinds, TestInheritedSealed and
// TestInheritedRefusesStdio, not a test on its own. It prints one line per check and fails on the first
// that does not hold.
func TestInheritedHelper(t *testing.T) {
	mode := os.Getenv(inheritedHelperEnv)
	if mode == "" {
		t.Skip("helper process for the Inherited tests")
	}
	kinds := strings.Split(os.Getenv(inheritedKindsEnv), ",")
	switch mode {
	case "kinds":
		// Every number refuses every kind it is not, and leaves the number open, before any is owned.
		for i, name := range kinds {
			n := 3 + i
			for other, k := range kindNames {
				if other == name || name == "-" {
					continue
				}
				if _, err := Inherited(n, k, other); !errors.Is(err, ErrKind) {
					t.Fatalf("Inherited(%d, %s) of a %s = %v, want ErrKind", n, other, name, err)
				}
			}
		}
		for i, name := range kinds {
			if name == "-" {
				continue
			}
			n := 3 + i
			f, err := Inherited(n, kindNames[name], name)
			if err != nil {
				t.Fatalf("Inherited(%d, %s) = %v", n, name, err)
			}
			if err := f.Borrow(func(m int) error {
				if m != n {
					return fmt.Errorf("lent %d, want %d", m, n)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			fmt.Printf("inherited %d %s\n", n, name)
		}
		if _, err := Inherited(3+len(kinds), KindRegular, "unopened"); !errors.Is(err, ErrKind) {
			t.Fatalf("Inherited of a number not open = %v, want ErrKind", err)
		}
	case "sealed":
		if _, err := Inherited(3, kindNames[kinds[0]], kinds[0]); err != nil {
			t.Fatalf("Inherited before any owner = %v", err)
		}
		f, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := Inherited(4, kindNames[kinds[1]], kinds[1]); !errors.Is(err, ErrSealed) {
			t.Fatalf("Inherited after Own = %v, want ErrSealed", err)
		}
		fmt.Println("sealed")
	case "stdio":
		for n := 0; n <= 2; n++ {
			if _, err := Inherited(n, KindRegular, "stdio"); !errors.Is(err, ErrStdio) {
				t.Fatalf("Inherited(%d) = %v, want ErrStdio", n, err)
			}
			if _, err := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0); err != nil {
				t.Fatalf("stdio %d after the refusal: %v", n, err)
			}
		}
		fmt.Println("stdio refused")
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

// runInheritedHelper re-executes this test binary in mode with files as descriptors 3 up, and returns its
// output; it fails the test when the helper does.
func runInheritedHelper(t *testing.T, mode string, kinds []string, files []*os.File) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestInheritedHelper$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), inheritedHelperEnv+"="+mode, inheritedKindsEnv+"="+strings.Join(kinds, ","))
	cmd.ExtraFiles = files
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("the %s helper: %v\n%s", mode, err, out.String())
	}
	return out.String()
}

// inheritedFiles makes one descriptor of each kind Inherited checks: a directory, a socket, a FIFO, a regular
// file, a pidfd and, where the kernel has Landlock, a ruleset.
func inheritedFiles(t *testing.T) ([]string, []*os.File) {
	t.Helper()
	var kinds []string
	var files []*os.File
	add := func(kind string, f *os.File) {
		kinds = append(kinds, kind)
		files = append(files, f)
		if f != nil {
			t.Cleanup(func() { _ = f.Close() })
		}
	}
	dir := t.TempDir()
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	add("dir", d)
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	add("socket", os.NewFile(uintptr(sp[0]), "socket"))
	t.Cleanup(func() { _ = unix.Close(sp[1]) })
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	add("fifo", r)
	t.Cleanup(func() { _ = w.Close() })
	reg, err := os.Create(dir + "/regular")
	if err != nil {
		t.Fatal(err)
	}
	add("regular", reg)
	p, err := PidfdOpenProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	add("pidfd", os.NewFile(uintptr(p), "pidfd"))
	attr := LandlockRulesetAttr{Handled_access_fs: unix.LANDLOCK_ACCESS_FS_READ_FILE}
	if rs, err := LandlockCreateRuleset(&attr, 0); err == nil {
		add("ruleset", os.NewFile(uintptr(rs), "ruleset"))
	} else {
		t.Logf("no Landlock ruleset on this host (%v): the ruleset kind is not checked here", err)
		kinds = append(kinds, "-")
		devnull, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, devnull)
		t.Cleanup(func() { _ = devnull.Close() })
	}
	return kinds, files
}

// TestInheritedKinds: Inherited checks its number's kind at run time, by fstat's S_IFMT for a directory,
// socket, FIFO or regular file, pidfd_send_signal for a pidfd and landlock's probe for a ruleset, refuses
// every other kind and a number that is not open, and owns the number when the kind holds (A10, F1).
func TestInheritedKinds(t *testing.T) {
	kinds, files := inheritedFiles(t)
	out := runInheritedHelper(t, "kinds", kinds, files)
	for i, k := range kinds {
		if k == "-" {
			continue
		}
		if line := "inherited " + strconv.Itoa(3+i) + " " + k; !strings.Contains(out, line) {
			t.Errorf("the helper did not report %q:\n%s", line, out)
		}
	}
}

// TestInheritedSealed: once this process has made any other owner, Inherited fails, so a second owner of a
// live number cannot be minted later in the process (A10, the seal).
func TestInheritedSealed(t *testing.T) {
	kinds, files := inheritedFiles(t)
	if out := runInheritedHelper(t, "sealed", kinds, files); !strings.Contains(out, "sealed") {
		t.Fatalf("the helper did not reach its check:\n%s", out)
	}
	// An owner of this process's own, so the check does not depend on which tests ran before it.
	_ = openNull(t)
	if _, err := Inherited(3, KindRegular, "after the owners this test process made"); !errors.Is(err, ErrSealed) {
		t.Fatalf("Inherited in this process = %v, want ErrSealed", err)
	}
}

// TestInheritedRefusesStdio: Inherited refuses 0, 1 and 2 and leaves them open (A10, Range).
func TestInheritedRefusesStdio(t *testing.T) {
	if out := runInheritedHelper(t, "stdio", nil, nil); !strings.Contains(out, "stdio refused") {
		t.Fatalf("the helper did not reach its check:\n%s", out)
	}
}

// TestKindString names every kind.
func TestKindString(t *testing.T) {
	for name, k := range kindNames {
		if k.String() != name {
			t.Errorf("Kind %d is %q, want %q", k, k.String(), name)
		}
	}
	if Kind(0).String() == "" {
		t.Error("the zero Kind has no name")
	}
}

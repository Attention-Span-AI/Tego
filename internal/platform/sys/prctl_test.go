// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/testutil"
)

func TestDumpableRoundTrip(t *testing.T) {
	// The test process is an ordinary dumpable binary; setting 1 again is a no-op that must succeed.
	if err := SetDumpable(true); err != nil {
		t.Fatal(err)
	}
	on, err := Dumpable()
	if err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Fatal("PR_GET_DUMPABLE reports 0 after PR_SET_DUMPABLE 1")
	}
}

func TestNoNewPrivsQuery(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := NoNewPrivs(); err != nil {
		t.Fatal(err)
	}
}

func TestChildSubreaperToggle(t *testing.T) {
	if err := SetChildSubreaper(true); err != nil {
		t.Fatal(err)
	}
	if err := SetChildSubreaper(false); err != nil {
		t.Fatal(err)
	}
}

// makeUndumpableHelperEnv makes this test binary, re-executed, the process TestMakeUndumpable looks at: it names the
// helper's mode. "hold" makes itself undumpable, says so on stdout, and waits for its stdin to close; "again" is the
// binary that process execs, which reports its flag.
const makeUndumpableHelperEnv = "TEGO_SYS_MAKE_UNDUMPABLE_HELPER"

// TestMakeUndumpableHelper is TestMakeUndumpable's child (two modes, see makeUndumpableHelperEnv).
func TestMakeUndumpableHelper(t *testing.T) {
	mode := os.Getenv(makeUndumpableHelperEnv)
	if mode == "" {
		t.Skip("helper process for TestMakeUndumpable")
	}
	switch mode {
	case "again":
		on, err := Dumpable()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("exec dumpable=%t\n", on)
	case "hold":
		if err := MakeUndumpable(); err != nil {
			t.Fatal(err)
		}
		on, err := Dumpable()
		if err != nil || on {
			t.Fatalf("Dumpable() = %t, %v after MakeUndumpable", on, err)
		}
		fmt.Println("undumpable")
		_, _ = io.Copy(io.Discard, os.Stdin) // held until the parent closes it
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

// TestMakeUndumpable: a process that made itself undumpable is closed to a process of its own user on every channel
// that reads its memory or its descriptors (/proc/<pid>/mem, environ, fd, maps, exe), and stays open on the files the
// readers of Tego's launcher rely on (stat, cgroup, status, cmdline); and the flag does not survive an exec of the
// same binary, which is why a helper the launcher execs is dumpable until it makes itself otherwise. Root passes every
// one of those reads (CAP_SYS_PTRACE), so as root the test runs again as an ordinary uid
// (testutil.RerunAsOrdinaryUser), and the helper it starts is that uid's too.
func TestMakeUndumpable(t *testing.T) {
	if testutil.RerunAsOrdinaryUser(t) {
		return
	}
	cmd := proc.Command(os.Args[0], "-test.run=^TestMakeUndumpableHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), makeUndumpableHelperEnv+"=hold")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if _, err := proc.Start(cmd); err != nil {
		t.Fatal(err)
	}
	done := false
	t.Cleanup(func() {
		if !done {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "undumpable\n" {
		t.Fatalf("the helper said %q, %v:\n%s", line, err, errBuf.String())
	}
	pid := cmd.Process.Pid
	for _, name := range []string{"mem", "environ", "maps", "fd", "exe", "cwd", "ns/pid", "fdinfo/0"} {
		path := fmt.Sprintf("/proc/%d/%s", pid, name)
		var err error
		switch name {
		case "exe", "cwd", "ns/pid":
			_, err = os.Readlink(path)
		case "fd":
			_, err = os.ReadDir(path)
		default:
			var b []byte
			b, err = os.ReadFile(path)
			if err == nil && name != "mem" {
				t.Errorf("%s of an undumpable process read %d bytes", path, len(b))
			}
		}
		if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
			t.Errorf("%s of an undumpable process: %v, want a permission error", path, err)
		}
	}
	for _, name := range []string{"stat", "status", "cmdline", "cgroup"} {
		if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name)); err != nil {
			t.Errorf("/proc/%d/%s of an undumpable process: %v, want it readable", pid, name, err)
		}
	}
	if testutil.PtraceAttachSucceeds(pid) {
		t.Error("PTRACE_ATTACH to an undumpable process of this user succeeded")
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the helper: %v\n%s", err, errBuf.String())
	}
	done = true

	// The flag is the process's and an exec of the same readable binary sets it again.
	cmd2 := proc.Command(os.Args[0], "-test.run=^TestMakeUndumpableHelper$", "-test.count=1")
	cmd2.Env = append(os.Environ(), makeUndumpableHelperEnv+"=again")
	var out bytes.Buffer
	cmd2.Stdout, cmd2.Stderr = &out, &out
	if _, err := proc.Start(cmd2); err != nil {
		t.Fatal(err)
	}
	if err := cmd2.Wait(); err != nil || !strings.Contains(out.String(), "exec dumpable=true") {
		t.Fatalf("a fresh exec of the binary: %v\n%s", err, out.String())
	}
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The ops ADR 0032's detector and its never-set regression test take (test/conformance's execcheck test). The bit
// and the flag are linux/securebits.h's and linux/fcntl.h's from 6.14; golang.org/x/sys names neither yet.
const (
	// secbitExecRestrictFile is SECBIT_EXEC_RESTRICT_FILE (securebit 8): an interpreter that honours it checks a
	// script with execveat(AT_EXECVE_CHECK) before it runs it. commoncap.c lets an unprivileged process set it on
	// itself, since it is user space's restriction on itself, not the kernel's.
	secbitExecRestrictFile = 1 << 8
	// atExecveCheck is AT_EXECVE_CHECK: execveat runs the exec's checks and returns without executing.
	atExecveCheck = 0x10000
	// restrictExec is the actor's own stage: set SECBIT_EXEC_RESTRICT_FILE, then exec the interpreter on the script.
	restrictExec = "restrict-exec"
	// bitRefusedExit is the restrict-exec stage's exit when the kernel refuses the bit (before 6.14), before any
	// interpreter starts.
	bitRefusedExit = 125
)

// observers are the ops whose result is a value or a classification, not an allow or a refusal.
var observers = map[string]func(Action) (string, error){
	// securebits: PR_GET_SECUREBITS of the actor as the run started it.
	"securebits": func(Action) (string, error) {
		bits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%#x", bits), nil
	},
	// execve-check, the kernel half: execveat(fd, "", AT_EMPTY_PATH|AT_EXECVE_CHECK) on Path.
	"execve-check": func(a Action) (string, error) { return "", execveCheck(a.Path) },
	// script-check, the interpreter half: Path (an interpreter) runs Dest (a script) with the bit set; "runs" when
	// it exits 0, "refuses" with its exit status otherwise.
	"script-check": func(a Action) (string, error) {
		return runScript(exec.Command("/proc/self/exe", restrictExec, a.Path, a.Dest))
	},
	// script-run, script-check's control: the same interpreter on the same script without the bit.
	"script-run": func(a Action) (string, error) { return runScript(exec.Command(a.Path, a.Dest)) },
}

// runScript runs cmd with the actor's own descriptors (stdout carries the results, so the child's goes to stderr).
func runScript(cmd *exec.Cmd) (string, error) {
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return "runs", nil
	case errors.As(err, &ee) && ee.ExitCode() == bitRefusedExit && len(cmd.Args) > 1 && cmd.Args[1] == restrictExec:
		return "bit-refused", nil
	case errors.As(err, &ee):
		return fmt.Sprintf("refuses: exit %d", ee.ExitCode()), nil
	}
	return "", err
}

// execveCheck asks the kernel whether path would exec, without executing it.
func execveCheck(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd) //nolint:errcheck // read-only fd
	empty, err := unix.BytePtrFromString("")
	if err != nil {
		return err
	}
	arg0, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	argv, envv := []*byte{arg0, nil}, []*byte{nil}
	if _, _, en := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(empty)), uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envv[0])), uintptr(unix.AT_EMPTY_PATH|atExecveCheck), 0); en != 0 {
		return en
	}
	return nil
}

// checkInterp is the program name under which the actor is an interpreter that honours SECBIT_EXEC_RESTRICT_FILE, as
// ADR 0032 expects a mainstream one to: the detector's self-test, which shows the detector fires on one.
const checkInterp = "check-interp"

// checkingInterpreter runs args[0] as a script: with the bit set it first asks the kernel, as an honouring
// interpreter does, and refuses (exit 126) what the kernel would not exec; the script itself does nothing. It never
// returns.
func checkingInterpreter(args []string) {
	if len(args) != 1 {
		log.Fatal("usage: " + checkInterp + " <script>")
	}
	bits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil {
		log.Fatal("actor: PR_GET_SECUREBITS: ", err)
	}
	if bits&secbitExecRestrictFile != 0 {
		if err := execveCheck(args[0]); err != nil {
			log.Print(checkInterp, ": ", args[0], ": ", err)
			os.Exit(126)
		}
	}
	os.Exit(0)
}

// restrictedExec is the restrict-exec stage; it never returns.
func restrictedExec(interp, script string) {
	bits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil {
		log.Fatal("actor: PR_GET_SECUREBITS: ", err)
	}
	if err := unix.Prctl(unix.PR_SET_SECUREBITS, uintptr(bits|secbitExecRestrictFile), 0, 0, 0); err != nil {
		log.Print("actor: PR_SET_SECUREBITS: ", err)
		os.Exit(bitRefusedExit) // a kernel before 6.14 knows no such bit
	}
	log.Fatal("actor: exec ", interp, ": ", syscall.Exec(interp, []string{interp, script}, os.Environ()))
}

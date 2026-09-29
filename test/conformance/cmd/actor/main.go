// SPDX-License-Identifier: Apache-2.0

// Command actor is the conformance suite's agent (ADR 0017): a small static program that performs the syscalls
// a cell names, one after another, and prints each one's own result as a JSON line. The kernel's answer is the
// judge; the actor decides nothing. `actor run <script.json>` reads a list of actions, `actor noop` is what an
// exec cell starts (it exits 0 at once). It is built CGO-off and static, so it needs no loader in any guest and
// no fixture's contract has to grant one (TestActorIsStatic).
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Action mirrors test/conformance's Action (the runner writes the script, this reads it).
type Action struct {
	ID   string `json:"id"`
	Op   string `json:"op"`
	Path string `json:"path,omitempty"`
	Dest string `json:"dest,omitempty"`
	Addr string `json:"addr,omitempty"`
	// Target is a process op's peer: child, parent, orphan or a pid.
	Target string `json:"target,omitempty"`
	// Argv is an exec's whole vector, argv[0] included (an exec cell of a command rule, ADR 0048); empty for
	// [path, "noop"].
	Argv []string `json:"argv,omitempty"`
}

// noopEnv marks a child the actor started with an argv of the cell's own: the child (a copy of the actor under a
// ruled tool's name, or one run as a #! interpreter) exits 0 at once, whatever its arguments.
const noopEnv = "TEGO_ACTOR_NOOP"

// Result is one action's outcome.
type Result struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Errno int    `json:"errno,omitempty"`
	Err   string `json:"err,omitempty"`
	// Value is what an observational op read or classified (observers), empty for every other op.
	Value string `json:"value,omitempty"`
}

func main() {
	if (len(os.Args) >= 2 && os.Args[1] == "noop") || os.Getenv(noopEnv) == "1" {
		reportArgv()
		return
	}
	if len(os.Args) == 4 && os.Args[1] == argvStage {
		argvAttempt(os.Args[2], os.Args[3])
	}
	if filepath.Base(os.Args[0]) == checkInterp {
		checkingInterpreter(os.Args[1:])
	}
	if len(os.Args) == 4 && os.Args[1] == spellStage {
		stageMain(os.Args[2], os.Args[3])
	}
	if len(os.Args) == 4 && os.Args[1] == controlStage {
		controlStageMain(os.Args[2], os.Args[3])
	}
	if len(os.Args) == 2 && os.Args[1] == hostStage {
		hostMain()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == sleepStage {
		time.Sleep(10 * time.Minute) // until the attach's cell kills it
		return
	}
	if len(os.Args) == 4 && os.Args[1] == restrictExec {
		restrictedExec(os.Args[2], os.Args[3])
	}
	if len(os.Args) != 3 || os.Args[1] != "run" {
		log.Fatal("usage: actor run <script.json> | actor noop | actor " + restrictExec + " <interpreter> <script>")
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		log.Fatal("actor: ", err)
	}
	var script []Action
	if err := json.Unmarshal(data, &script); err != nil {
		log.Fatal("actor: ", err)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, a := range script {
		if a.Op == awaitLater {
			await(a.Path)
			continue
		}
		r := Result{ID: a.ID, OK: true}
		var err error
		if strings.HasPrefix(a.Addr, "$") { // an address the run made: its URL in the agent's environment
			if a.Addr, err = envAddr(a.Addr[1:]); err == nil {
				r.Value = a.Addr
			}
		}
		observe, observed := observers[a.Op]
		switch {
		case err != nil: // the address was not in the environment
		case observed:
			r.Value, err = observe(a)
		case controlOp[a.Op]:
			r.Value, err = performControl(a)
		default:
			err = perform(a)
		}
		if err != nil {
			r.OK, r.Err = false, err.Error()
			var en syscall.Errno
			if errors.As(err, &en) {
				r.Errno = int(en)
			}
		}
		_ = enc.Encode(r)
	}
}

// awaitLater is the kernel runner's handshake (test/conformance OpAwaitLater, AwaitReady): never a cell. The actor
// prints awaitReady on a line of its own and waits, at most two minutes, until the runner, outside the run, has
// written a fixture's later files and then the file at path; stat(2) of it, which no tier decides, is the wait.
const (
	awaitLater = "await-later"
	awaitReady = `{"await":"ready"}`
)

func await(path string) {
	fmt.Println(awaitReady)
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Lstat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			log.Fatal("actor: the runner wrote no ", path)
		}
	}
}

func perform(a Action) error {
	switch a.Op {
	case "read":
		f, err := os.Open(a.Path)
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck // read-only fd
		if _, err = f.Read(make([]byte, 1)); errors.Is(err, io.EOF) {
			return nil
		}
		return err
	case "write-open":
		f, err := os.OpenFile(a.Path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		return f.Close()
	case "open-trunc": // an existing file opened O_WRONLY|O_TRUNC
		f, err := os.OpenFile(a.Path, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		return f.Close()
	case "create":
		f, err := os.OpenFile(a.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		return f.Close()
	case "creat": // O_WRONLY|O_CREAT|O_TRUNC with no O_EXCL, through the legacy syscall where there is one
		fd, err := creat(a.Path)
		if err != nil {
			return err
		}
		return syscall.Close(fd)
	case "truncate":
		return syscall.Truncate(a.Path, 0)
	case "unlink":
		return syscall.Unlink(a.Path)
	case "rmdir":
		return syscall.Rmdir(a.Path)
	case "mkdir":
		return syscall.Mkdir(a.Path, 0o755)
	case "rename":
		return syscall.Rename(a.Path, a.Dest)
	case "exchange": // Path and Dest swap names in one renameat2
		return unix.Renameat2(unix.AT_FDCWD, a.Path, unix.AT_FDCWD, a.Dest, unix.RENAME_EXCHANGE)
	case "symlink": // Path is the new link, Dest what it points at
		return syscall.Symlink(a.Dest, a.Path)
	case "link": // Path is the existing file, Dest the new name
		return syscall.Link(a.Path, a.Dest)
	case "chmod":
		return syscall.Chmod(a.Path, 0o600)
	case "exec":
		// The child inherits the actor's descriptors: os/exec would otherwise open /dev/null for a nil stream,
		// a write the contract may refuse, and the cell would be about that open, not the exec.
		cmd := exec.Command(a.Path, "noop")
		if len(a.Argv) > 0 {
			cmd.Args = a.Argv
			cmd.Env = append(os.Environ(), noopEnv+"=1")
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return fmt.Errorf("started, exited %d", ee.ExitCode())
			}
			var pe *os.PathError
			if errors.As(err, &pe) {
				return pe.Err
			}
			return err
		}
		return nil
	case "map-exec": // a PROT_EXEC map of a page of the file, as a loader or a dlopen maps code (ADR 0027)
		f, err := os.Open(a.Path)
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck // read-only fd
		b, err := syscall.Mmap(int(f.Fd()), 0, os.Getpagesize(), syscall.PROT_READ|syscall.PROT_EXEC, syscall.MAP_PRIVATE)
		if err != nil {
			return err
		}
		return syscall.Munmap(b)
	case "connect-tcp", "connect-udp":
		network := "tcp"
		if a.Op == "connect-udp" {
			network = "udp"
		}
		c, err := net.DialTimeout(network, a.Addr, 3*time.Second)
		if err != nil {
			var oe *net.OpError
			if errors.As(err, &oe) {
				return oe.Err
			}
			return err
		}
		return c.Close()
	case "send-udp":
		return sendUDP(a.Addr)
	case "connect-unix": // a pathname, or @name for an abstract name (Go's net spells it so)
		c, err := net.DialTimeout("unix", a.Addr, 3*time.Second)
		if err != nil {
			var oe *net.OpError
			if errors.As(err, &oe) {
				return oe.Err
			}
			return err
		}
		return c.Close()
	}
	return performSpelling(a)
}

// envAddr is the host:port of the URL the environment variable name holds (a capture forwarder's base URL).
func envAddr(name string) (string, error) {
	u, err := url.Parse(os.Getenv(name))
	if err != nil || u.Port() == "" {
		return "", fmt.Errorf("$%s is %q, no URL with a port: %w", name, os.Getenv(name), syscall.EINVAL)
	}
	return u.Host, nil
}

// sendUDP sends one byte to addr from an unconnected UDP socket with sendto(2), so the errno is the send path's own.
func sendUDP(addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	family, sa := unix.AF_INET, unix.Sockaddr(nil)
	if ip4 := ua.IP.To4(); ip4 != nil {
		sa = &unix.SockaddrInet4{Port: ua.Port, Addr: [4]byte(ip4)}
	} else {
		family, sa = unix.AF_INET6, &unix.SockaddrInet6{Port: ua.Port, Addr: [16]byte(ua.IP.To16())}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd) //nolint:errcheck // a datagram socket that sent or failed
	return unix.Sendto(fd, []byte{0}, 0, sa)
}

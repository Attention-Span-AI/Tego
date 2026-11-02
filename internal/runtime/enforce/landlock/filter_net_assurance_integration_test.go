// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

const strictClientHelperEnv = "TEGO_STRICT_CLIENT_FILTER_HELPER"

// TestStrictClientFilterOnRealKernel verifies the native filter's import and
// listener refusals as actual syscalls in an isolated unprivileged child.
func TestStrictClientFilterOnRealKernel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStrictClientFilterHelper$")
	cmd.Env = append(os.Environ(), strictClientHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("strict filter child: %v: %s", err, out)
	}
	var got map[string]int
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("report %q: %v", out, err)
	}
	tab, _ := tableFor(NativeArch())
	if len(got) != len(tab.ClientDeny) {
		t.Fatalf("reported %v", got)
	}
	for _, s := range tab.ClientDeny {
		if got[s.Name] != int(unix.ENOSYS) {
			t.Errorf("%s actual errno=%d want ENOSYS", s.Name, got[s.Name])
		}
	}
}

func TestStrictClientFilterHelper(t *testing.T) {
	if os.Getenv(strictClientHelperEnv) != "1" {
		t.Skip("helper only")
	}
	runtime.LockOSThread()
	filter, err := assembleFilter(NativeArch(), filterOpts{abi: 10, strictNet: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0]))}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog))); errno != 0 {
		t.Fatal(errno)
	}
	tab, _ := tableFor(NativeArch())
	got := map[string]int{}
	for _, s := range tab.ClientDeny {
		_, _, errno := unix.RawSyscall(uintptr(s.NR), ^uintptr(0), 0, 0)
		got[s.Name] = int(errno)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(data))
	// No test framework cleanup or another task runs on the filtered thread.
	os.Exit(0)
}

const strictRouteHelperEnv = "TEGO_STRICT_ROUTE_HELPER"

// strictRouteProbe is what a program gets from the C library, and from a route socket read with recv(2).
const strictRouteProbe = `import errno, json, socket, struct
res = {}
def attempt(name, f):
    try:
        res[name] = f()
    except OSError as e:
        res[name] = errno.errorcode.get(e.errno, str(e.errno))
def dump():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    s.bind((0, 0))
    s.settimeout(5)
    s.sendto(struct.pack("=IHHII", 20, 18, 0x301, 1, 0) + bytes(4), (0, 0))
    return "ok" if s.recv(65536) else "empty"
def getifaddrs():
    try:
        import ctypes
    except ImportError:
        return "no ctypes"
    libc, head = ctypes.CDLL(None, use_errno=True), ctypes.c_void_p()
    if libc.getifaddrs(ctypes.byref(head)) != 0:
        raise OSError(ctypes.get_errno(), "getifaddrs")
    return "ok"
attempt("if_nameindex", lambda: "ok" if socket.if_nameindex() else "empty")
attempt("getifaddrs", getifaddrs)
attempt("addrconfig", lambda: "ok" if socket.getaddrinfo("127.0.0.1", 80, flags=socket.AI_ADDRCONFIG) else "empty")
attempt("recv", dump)
print(json.dumps(res))
`

// TestStrictFilterInterfaceLists holds, on the real kernel and under the real filter, what net.assurance: kernel does to
// interface lists (ADR 0128's residual, OPERATIONS). The filter answers recvmsg ENOSYS, and it cannot do less: no arm
// can read a msghdr, so a route socket's reply cannot be told from a unix socket's SCM_RIGHTS, and a supervisor's
// CONTINUE leaves the fd a sibling may dup2 over. glibc reads a netlink reply with recvmsg, so if_nameindex and
// getifaddrs fail ENOSYS, and Node's os.networkInterfaces with them; its AI_ADDRCONFIG check takes the failure as "assume
// both families", so getaddrinfo goes on. What reads with recvfrom works: recv(2), and Go's net.Interfaces. This runs
// with no root: the filter's other arms are continued by a listener in the helper, as the supervisor continues them, and
// the destination hooks a kernel-assurance run also has decide nothing on these calls.
func TestStrictFilterInterfaceLists(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("no python3: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStrictRouteHelper$")
	cmd.Env = append(os.Environ(), strictRouteHelperEnv+"=filter")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v: %s", err, out)
	}
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("report %q: %v", out, err)
	}
	for k, v := range map[string]string{"if_nameindex": "ENOSYS", "getifaddrs": "ENOSYS", "addrconfig": "ok", "recv": "ok", "go_interfaces": "ok"} {
		if got[k] != v && !(k == "getifaddrs" && got[k] == "no ctypes") { // a guest's python may have no ctypes; if_nameindex stands for it
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

// TestStrictRouteHelper is TestStrictFilterInterfaceLists' child. With "filter" it installs the strict filter on one
// thread, keeps a listener on another that continues everything, and runs the probes as children of the filtered thread,
// which inherit the filter. With "go" it is such a child: Go's own list, with no C library.
func TestStrictRouteHelper(t *testing.T) {
	switch os.Getenv(strictRouteHelperEnv) {
	case "":
		t.Skip("helper only")
	case "go":
		ifs, err := net.Interfaces()
		if err == nil && len(ifs) == 0 {
			err = fmt.Errorf("no interfaces")
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("ok")
		os.Exit(0)
	}
	listener := make(chan int, 1)
	go func() {
		// Started before the filter, so this thread never holds it and cannot wait on itself.
		runtime.LockOSThread()
		fd := <-listener
		for {
			var n sys.SeccompNotif
			if sys.SeccompNotifRecv(fd, &n) != nil {
				return
			}
			_ = sys.SeccompNotifSend(fd, &sys.SeccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE})
		}
	}()
	runtime.LockOSThread()
	filter, err := assembleFilter(NativeArch(), filterOpts{abi: 10, strictNet: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	fd, err := sys.SeccompSetFilterNewListener(filter)
	if err != nil {
		t.Fatal(err)
	}
	listener <- fd
	out, err := exec.Command("python3", "-c", strictRouteProbe).CombinedOutput()
	if err != nil {
		t.Fatalf("python3: %v: %s", err, out)
	}
	res := map[string]string{}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("probe %q: %v", out, err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestStrictRouteHelper$")
	child.Env = append(os.Environ(), strictRouteHelperEnv+"=go")
	gout, err := child.CombinedOutput()
	res["go_interfaces"] = strings.TrimSpace(string(gout))
	if err != nil {
		res["go_interfaces"] += " (" + err.Error() + ")"
	}
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(data))
	// No test framework cleanup or another task runs on the filtered thread.
	os.Exit(0)
}

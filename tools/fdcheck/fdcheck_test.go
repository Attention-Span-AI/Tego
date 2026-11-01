// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// root is the checkout the tests type-check against. Planted files are an overlay: nothing is written to it.
var root = filepath.Join("..", "..")

// testProducers is the checked-in list, so the fixtures see the producers the tree is checked against.
func testProducers(t *testing.T) Producers {
	t.Helper()
	p, err := readProducers(root)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// planted type-checks sets of files planted in the checkout (an overlay) under the lint's tagged amd64 build,
// with the module packages they import, in one load, and returns each set's findings.
func planted(t *testing.T, sets map[string]map[string]string) map[string][]Finding {
	t.Helper()
	ov := overlay{}
	owner := map[string]string{}
	dirs := map[string]bool{}
	for set, files := range sets {
		for name, src := range files {
			if _, dup := ov[name]; dup {
				t.Fatalf("%s is planted twice", name)
			}
			ov[name] = []byte(src)
			owner[name] = set
			dirs["./"+dirOf(name)] = true
		}
	}
	w, err := typeCheck(root, mainConfigs[0], ov, sortedKeys(dirs))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]Finding{}
	for _, f := range analyzeWorld(w, testProducers(t)) {
		if s, ok := owner[f.File]; ok {
			out[s] = append(out[s], f)
		}
	}
	return out
}

// kindsOf is "kind@line" for each finding, sorted.
func kindsOf(fs []Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Kind+"@"+itoa(f.Line))
	}
	sort.Strings(out)
	return out
}

// kinds plants one file at path and returns "kind@line" for each finding, sorted.
func kinds(t *testing.T, path, src string) []string {
	t.Helper()
	return kindsOf(planted(t, map[string]map[string]string{"one": {path: src}})["one"])
}

func itoa(n int) string { return strconv.Itoa(n) }

const hdr = "package p\n\nimport (\n\t\"fmt\"; \"net\"; \"os\"; \"strconv\"\n\t\"syscall\"\n\n\t\"github.com/cilium/ebpf/link\"\n\t\"github.com/attention-span-ai/tego/internal/platform/sys\"\n\t\"golang.org/x/sys/unix\"\n)\n\nvar _, _, _, _, _, _, _, _ = os.Args, syscall.Getpid, link.Iter{}, (*sys.FD)(nil), unix.Getpid, fmt.Sprint, net.Dial, strconv.Itoa\n\n"

// The header above ends on line 13; fixture bodies start on line 14.
const first = 14

// fixture is a table row: a body planted after hdr in a package of its own, and its findings as kind@line.
type fixture struct {
	name, body string
	want       []string
}

// runFixtures plants every row in its own package, all in one load, and compares each row's findings.
func runFixtures(t *testing.T, prefix string, cases []fixture) {
	t.Helper()
	sets := map[string]map[string]string{}
	for i, tc := range cases {
		if _, dup := sets[tc.name]; dup {
			t.Fatalf("two fixtures are named %q", tc.name)
		}
		sets[tc.name] = map[string]string{fmt.Sprintf("internal/zzfdcheck/%s%03d/x.go", prefix, i): hdr + tc.body}
	}
	got := planted(t, sets)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := append([]string{}, tc.want...)
			sort.Strings(want)
			if g := kindsOf(got[tc.name]); !reflect.DeepEqual(g, want) {
				t.Errorf("findings %v, want %v\n%s", g, want, tc.body)
			}
		})
	}
}

// l is kind@line for a fixture body's line off.
func l(k string, off int) string { return k + "@" + itoa(first+off) }

// TestFdcheckFixtures is ADR 0023 A10's table, F1–F9: each fixture, planted in a package of its own, yields
// exactly the listed findings (kind@line, line 14 being the body's first), and each negative case none.
func TestFdcheckFixtures(t *testing.T) {
	runFixtures(t, "f", []fixture{
		// A4 primitives, by call, value, alias, dot import and a split line.
		{"close", "func f(fd int) { _ = unix.Close(fd) }\n", []string{l(kClose, 0)}},
		{"syscall close and dup", "func f(fd int) { _ = syscall.Close(fd); _, _ = syscall.Dup(fd) }\n", []string{l(kClose, 0), l(kDup, 0)}},
		{"close as a value", "var closer = unix.Close\n", []string{l(kClose, 0)}},
		{"split line", "func f(fd int) {\n\t_ = unix.\n\t\tClose(fd)\n}\n", []string{l(kClose, 1)}},
		{"close range", "func f() { _ = unix.CloseRange(3, ^uint(0), 0) }\n", []string{l(kClose, 0)}},
		{"dup3", "func f(fd int) { _ = unix.Dup3(fd, 9, 0) }\n", []string{l(kDup, 0)}},
		{"newfile", "func f(fd int) { _ = os.NewFile(uintptr(fd), \"x\") }\n", []string{l(kNewFile, 0)}},
		{"rights", "func f(m *unix.SocketControlMessage) { _, _ = unix.ParseUnixRights(m) }\n", []string{l(kRights, 0)}},
		// Received descriptors are owned by sys.ReceiveRights only: a control-message decoder and the SCM_RIGHTS
		// type a hand decode selects are rights sites, and a recvmsg that can receive rights sets MSG_CMSG_CLOEXEC.
		{"control messages decoded", "func f(oob []byte) { msgs, _ := unix.ParseSocketControlMessage(oob); _ = msgs }\n", []string{l(kRights, 0)}},
		{"one control message decoded", "func f(oob []byte) { _, _, _, _ = unix.ParseOneSocketControlMessage(oob) }\n", []string{l(kRights, 0)}},
		{"syscall control messages decoded", "func f(oob []byte) { _, _ = syscall.ParseSocketControlMessage(oob) }\n", []string{l(kRights, 0)}},
		{"decoder as a value", "var parse = unix.ParseSocketControlMessage\n", []string{l(kRights, 0)}},
		{"rights type named", "func f(t int32) bool { return t == unix.SCM_RIGHTS }\n", []string{l(kRights, 0)}},
		{"rights type through a constant", "const rights = unix.SCM_RIGHTS\n\nfunc f(t int32) bool { return t == rights || t == syscall.SCM_RIGHTS }\n", []string{l(kRights, 0), l(kRights, 2), l(kRights, 2)}},
		{"recvmsg without cloexec", "func f(s int, b, oob []byte) { _, _, _, _, _ = unix.Recvmsg(s, b, oob, 0) }\n", []string{l(kCloexec, 0)}},
		{"recvmsg with variable flags", "func f(s, fl int, b, oob []byte) { _, _, _, _, _ = syscall.Recvmsg(s, b, oob, fl) }\n", []string{l(kCloexec, 0)}},
		{"recvmsg buffers without cloexec", "func f(s int, b, oob []byte) { _, _, _, _, _ = unix.RecvmsgBuffers(s, [][]byte{b}, oob, unix.MSG_PEEK) }\n", []string{l(kCloexec, 0)}},
		{"recvmsg with cloexec", "func f(s, fl int, b, oob []byte) { _, _, _, _, _ = unix.Recvmsg(s, b, oob, fl|unix.MSG_CMSG_CLOEXEC) }\n", nil},
		{"recvmsg without a control buffer", "func f(s int, b []byte) { _, _, _, _, _ = unix.Recvmsg(s, b, nil, 0) }\n", nil},
		{"recvmsg as a value", "var recv = unix.Recvmsg\n", []string{l(kCloexec, 0)}},
		{"raw recvmsg", "func f(s, m uintptr) { _, _, _ = unix.Syscall(unix.SYS_RECVMSG, s, m, unix.MSG_CMSG_CLOEXEC) }\n", []string{l(kProducer, 0)}},
		{"raw recvmmsg", "func f(s, m uintptr) { _, _, _ = unix.Syscall6(unix.SYS_RECVMMSG, s, m, 1, unix.MSG_CMSG_CLOEXEC, 0, 0) }\n", []string{l(kProducer, 0)}},
		{"io_uring trap", "func f() { _, _, _ = unix.Syscall(unix.SYS_IO_URING_SETUP, 8, 0, 0) }\n", []string{l(kIOURing, 0)}},
		{"raw close syscall", "func f(fd int) { _, _, _ = unix.Syscall(unix.SYS_CLOSE, uintptr(fd), 0, 0) }\n", []string{l(kClose, 0)}},
		// A forbidden constant reached through a module constant is a site at its declaration and at every call
		// that uses it, so one declaration pays for no other close or dup.
		{"close trap through a constant", "const sysClose = unix.SYS_CLOSE\n\nfunc f(fd int) { _, _, _ = unix.Syscall(sysClose, uintptr(fd), 0, 0) }\n", []string{l(kClose, 0), l(kClose, 2)}},
		{"close trap through a constant twice", "const sysClose = unix.SYS_CLOSE\n\nfunc f(fd int) {\n\t_, _, _ = unix.Syscall(sysClose, uintptr(fd), 0, 0)\n\t_, _, _ = unix.RawSyscall(uintptr(sysClose), uintptr(fd), 0, 0)\n}\n", []string{l(kClose, 0), l(kClose, 3), l(kClose, 4)}},
		{"dup fcntl through a constant", "const dupCmd = unix.F_DUPFD_CLOEXEC\n\nfunc f(fd int) { _, _ = unix.FcntlInt(uintptr(fd), dupCmd, 3) }\n", []string{l(kDup, 0), l(kDup, 2)}},
		{"raw dup fcntl through a constant", "const dupCmd = unix.F_DUPFD\n\nfunc f(fd int) { _, _, _ = unix.Syscall(unix.SYS_FCNTL, uintptr(fd), dupCmd, 3) }\n", []string{l(kDup, 0), l(kDup, 2)}},
		{"io_uring trap through a constant", "const ring = unix.SYS_IO_URING_ENTER\n\nfunc f() { _, _, _ = unix.Syscall6(ring, 0, 0, 0, 0, 0, 0) }\n", []string{l(kIOURing, 0), l(kIOURing, 2)}},
		{"taker over a bare number", "func f(n int) { _, _ = link.NewFromFD(n) }\n", []string{l(kFromFD, 0)}},
		// F5: Fd through embedding and an interface, cilium's FD, traps, fcntl, unshare.
		{"fd", "func f(o *os.File) { _ = o.Fd() }\n", []string{l(kFd, 0)}},
		{"promoted fd", "type w struct{ *os.File }\n\nfunc f(x w) { _ = x.Fd() }\n", []string{l(kFd, 2)}},
		{"interface fd", "func f(x any) { _ = x.(interface{ Fd() uintptr }).Fd() }\n", []string{l(kFd, 0)}},
		{"cilium fd", "type prog interface{ FD() int }\n\nfunc f(p prog) { _ = p.FD() }\n", []string{l(kFd, 2)}},
		{"fd of a call's result", "func f(g func() *os.File) uintptr { return g().Fd() }\n", []string{l(kFd, 0)}},
		{"literal trap", "func f() { _, _, _ = unix.Syscall(3, 0, 0, 0) }\n", []string{l(kTrap, 0)}},
		{"variable trap", "func f(nr uintptr) { _, _, _ = unix.RawSyscall(nr, 0, 0, 0) }\n", []string{l(kTrap, 0)}},
		{"literal constant trap", "const nr = 3\n\nfunc f() { _, _, _ = unix.Syscall(nr, 0, 0, 0) }\n", []string{l(kTrap, 2)}},
		{"constant trap of no producer", "const nr = unix.SYS_GETPID\n\nfunc f() { _, _, _ = unix.Syscall(nr, 0, 0, 0) }\n", nil},
		{"fcntl 0 is F_DUPFD", "func f(fd int) { _, _ = unix.FcntlInt(uintptr(fd), 0, 3) }\n", []string{l(kFcntl, 0)}},
		{"fcntl allowed", "func f(fd int) { _, _ = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0) }\n", nil},
		{"fcntl dup counted once", "func f(fd int) { _, _ = unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3) }\n", []string{l(kDup, 0)}},
		{"fcntl unlisted", "func f(fd int) { _, _ = unix.FcntlInt(uintptr(fd), unix.F_SETOWN, 0) }\n", []string{l(kFcntl, 0)}},
		{"unshare files", "func f() { _ = unix.Unshare(unix.CLONE_FS | unix.CLONE_FILES) }\n", []string{l(kUnshare, 0)}},
		{"unshare fs", "func f() { _ = unix.Unshare(unix.CLONE_FS) }\n", nil},
		{"unshare variable", "func f(fl int) { _ = unix.Unshare(fl) }\n", []string{l(kUnshare, 0)}},
		// F1: the birth rule and producers.
		{"raw producer", "func f() { _, _ = unix.Open(\"/\", unix.O_RDONLY|unix.O_CLOEXEC, 0) }\n", []string{l(kProducer, 0)}},
		{"owned producer", "func f() { _, _ = sys.Own(unix.Open(\"/\", unix.O_RDONLY|unix.O_CLOEXEC, 0)) }\n", nil},
		{"strict owned producer", "func f() { _, _ = sys.Strict(sys.Own(unix.Open(\"/\", unix.O_RDONLY|unix.O_CLOEXEC, 0))) }\n", nil},
		{"producer as a value", "var fanotifyInit = unix.FanotifyInit\n", []string{l(kProducer, 0)}},
		{"owner-returning seam", "var fanotifyInit = func(f, e uint) (*sys.FD, error) { return sys.Own(unix.FanotifyInit(f|unix.FAN_CLOEXEC, e)) }\n", nil},
		{"own of no producer", "func f(n int) { _, _ = sys.Own(n, nil) }\n", []string{l(kOwn, 0)}},
		{"own of another owner's number", "func f(g interface{ Num() (int, error) }) { _, _ = sys.Own(g.Num()) }\n", []string{l(kOwn, 0)}},
		{"strict of no constructor", "func f(o *sys.FD) { _, _ = sys.Strict(o, nil) }\n", []string{l(kStrict, 0)}},
		{"strict of a dup", "func f(o *sys.FD) { _, _ = sys.Strict(o.Dup()) }\n", nil},
		{"sys int producer", "func f() { _, _ = sys.PidfdOpenProcess(1) }\n", []string{l(kProducer, 0)}},
		{"own of a sys int producer", "func f() { _, _ = sys.Own(sys.PidfdOpenProcess(1)) }\n", nil},
		{"own taken as a value", "var own = sys.Own\n", []string{l(kFuncValue, 0)}},
		{"other-shape producer", "func f(p []int) { _ = unix.Pipe2(p, unix.O_CLOEXEC) }\n", []string{l(kProducer, 0)}},
		// F9: flags by their constant value, or ORed in at the top of an expression that is not constant.
		{"no cloexec", "func f() { _, _ = sys.Own(unix.Open(\"/\", unix.O_RDONLY, 0)) }\n", []string{l(kCloexec, 0)}},
		{"variable flags", "func f(fl int) { _, _ = sys.Own(unix.Open(\"/\", fl, 0)) }\n", []string{l(kCloexec, 0)}},
		{"variable flags with cloexec", "func f(fl int) { _, _ = sys.Own(unix.Open(\"/\", fl|unix.O_CLOEXEC, 0)) }\n", nil},
		{"cloexec cleared", "func f(fl int) { _, _ = sys.Own(unix.Open(\"/\", (fl|unix.O_CLOEXEC)&^unix.O_CLOEXEC, 0)) }\n", []string{l(kCloexec, 0)}},
		{"constant cloexec cleared", "func f() { _, _ = sys.Own(unix.Open(\"/\", unix.O_CLOEXEC&^unix.O_CLOEXEC, 0)) }\n", []string{l(kCloexec, 0)}},
		{"constant flags", "const oflags = unix.O_RDONLY | unix.O_CLOEXEC\n\nfunc f() { _, _ = sys.Own(unix.Open(\"/\", oflags, 0)) }\n", nil},
		{"socket cloexec", "func f() { _, _ = sys.Own(unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)) }\n", nil},
		{"socket without", "func f() { _, _ = sys.Own(unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)) }\n", []string{l(kCloexec, 0)}},
		{"openat2 literal", "func f(d int) { _, _ = sys.Own(unix.Openat2(d, \"x\", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})) }\n", nil},
		{"openat2 opaque", "func f(d int, h *unix.OpenHow) { _, _ = sys.Own(unix.Openat2(d, \"x\", h)) }\n", []string{l(kCloexec, 0)}},
		{"pidfd is kernel cloexec", "func f() { _, _ = sys.Own(unix.PidfdOpen(1, 0)) }\n", nil},
		{"epoll_create never cloexec", "func f() { _, _ = sys.Own(unix.EpollCreate(1)) }\n", []string{l(kCloexec, 0)}},
		// F10: sys.OwnSyscall's pairs, and the raw producer traps outside it.
		{"bpf prog load", "func f(a uintptr) { _, _ = sys.OwnSyscall(unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, a, 0)) }\n", nil},
		{"bpf map update", "func f(a uintptr) { _, _ = sys.OwnSyscall(unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_UPDATE_ELEM, a, 0)) }\n", []string{l(kOwnSyscall, 0)}},
		{"bpf literal command", "func f(a uintptr) { _, _ = sys.OwnSyscall(unix.Syscall(unix.SYS_BPF, 28, a, 0)) }\n", []string{l(kOwnSyscall, 0)}},
		{"seccomp without listener", "func f(a uintptr) { _, _ = sys.OwnSyscall(unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, a)) }\n", []string{l(kOwnSyscall, 0)}},
		{"seccomp listener", "func f(a uintptr) { _, _ = sys.OwnSyscall(unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, a)) }\n", nil},
		{"landlock version", "func f() { _, _ = sys.OwnSyscall(unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)) }\n", []string{l(kOwnSyscall, 0)}},
		{"landlock ruleset", "func f(a, s uintptr) { _, _ = sys.OwnSyscall(unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, a, s, 0)) }\n", nil},
		{"memfd without cloexec", "func f(n uintptr) { _, _ = sys.OwnSyscall(unix.Syscall(unix.SYS_MEMFD_CREATE, n, 0, 0)) }\n", []string{l(kCloexec, 0)}},
		{"own syscall of no syscall", "func f() { _, _ = sys.OwnSyscall(0, 0, 0) }\n", []string{l(kOwnSyscall, 0)}},
		{"raw bpf prog load", "func f(a uintptr) { _, _, _ = unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, a, 0) }\n", []string{l(kProducer, 0)}},
		{"raw bpf map update", "func f(a uintptr) { _, _, _ = unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_UPDATE_ELEM, a, 0) }\n", nil},
		{"raw bpf literal command", "const bpfLinkCreate = 28\n\nfunc f(a uintptr) { _, _, _ = unix.Syscall(unix.SYS_BPF, bpfLinkCreate, a, 0) }\n", []string{l(kProducer, 2)}},
		{"raw landlock version", "func f() { _, _, _ = unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION) }\n", nil},
		{"raw landlock ruleset", "func f(a, s, fl uintptr) { _, _, _ = unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, a, s, fl) }\n", []string{l(kProducer, 0)}},
		// Producers of every shape: mq_open, clone with a pidfd, the ioctls that answer a descriptor.
		{"raw mq_open", "func f(n uintptr) { _, _, _ = unix.Syscall6(unix.SYS_MQ_OPEN, n, unix.O_RDONLY|unix.O_CREAT, 0, 0, 0, 0) }\n", []string{l(kProducer, 0)}},
		{"raw clone3", "func f(a uintptr) { _, _, _ = unix.Syscall(unix.SYS_CLONE3, a, 88, 0) }\n", []string{l(kProducer, 0)}},
		{"raw clone with a pidfd", "func f() { _, _, _ = unix.RawSyscall(unix.SYS_CLONE, unix.CLONE_PIDFD, 0, 0) }\n", []string{l(kProducer, 0)}},
		{"raw clone without one", "func f() { _, _, _ = unix.RawSyscall(unix.SYS_CLONE, unix.CLONE_VM, 0, 0) }\n", nil},
		{"ioctl answering a descriptor", "func f(p int) { _, _ = unix.IoctlRetInt(p, unix.TIOCGPTPEER) }\n", []string{l(kIoctl, 0)}},
		{"ioctl of a variable request", "func f(fd int, r uint) { _, _ = unix.IoctlRetInt(fd, r) }\n", []string{l(kIoctl, 0)}},
		{"ioctl allowed", "func f(fd int) { _, _ = unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE) }\n", nil},
		{"raw ioctl answering a descriptor", "func f(fd uintptr) { _, _, _ = unix.Syscall(unix.SYS_IOCTL, fd, unix.NS_GET_USERNS, 0) }\n", []string{l(kIoctl, 0)}},
		{"raw ioctl of a variable request", "func f(fd, r uintptr) { _, _, _ = unix.Syscall(unix.SYS_IOCTL, fd, r, 0) }\n", []string{l(kIoctl, 0)}},
		{"raw ioctl allowed", "func f(fd, a uintptr) { _, _, _ = unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.SECCOMP_IOCTL_NOTIF_RECV), a) }\n", nil},
		// Every x/sys wrapper that takes a request runs the same allowlist.
		{"set-int ioctl answering a descriptor", "func f(fd int) { _ = unix.IoctlSetInt(fd, unix.TIOCGPTPEER, unix.O_RDWR) }\n", []string{l(kIoctl, 0)}},
		{"set-int ioctl of a variable request", "func f(fd int, r uint) { _ = unix.IoctlSetInt(fd, r, 0) }\n", []string{l(kIoctl, 0)}},
		{"get-int ioctl answering a descriptor", "func f(fd int) { _, _ = unix.IoctlGetInt(fd, unix.NS_GET_USERNS) }\n", []string{l(kIoctl, 0)}},
		{"set-pointer-int ioctl answering a descriptor", "func f(fd int) { _ = unix.IoctlSetPointerInt(fd, unix.NS_GET_PARENT, 0) }\n", []string{l(kIoctl, 0)}},
		{"termios ioctl allowed", "func f(fd int) { _, _ = unix.IoctlGetTermios(fd, unix.TCGETS) }\n", nil},
		{"flags ioctl allowed", "func f(fd int) { _, _ = unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS) }\n", nil},
		{"fixed-request ioctl", "func f(fd int, i *unix.PidfdInfo) { _ = unix.IoctlPidfdInfo(fd, i) }\n", nil},
		{"kcm clone answers a descriptor", "func f(fd int) { _, _ = unix.IoctlKCMClone(fd) }\n", []string{l(kProducer, 0)}},
		{"ioctl wrapper taken as a value", "var setInt = unix.IoctlSetInt\n", []string{l(kIoctl, 0)}},
		{"fcntl taken as a value", "var fcntl = unix.FcntlInt\n", []string{l(kFcntl, 0)}},
		{"unshare taken as a value", "var unshare = unix.Unshare\n", []string{l(kUnshare, 0)}},
		// os/exec's SysProcAttr.PidFD: the start writes a pidfd no owner holds (TestPidFDIdentity has the rest).
		{"pidfd from SysProcAttr", "func f() { var p int; _ = &syscall.SysProcAttr{PidFD: &p} }\n", []string{l(kProducer, 0)}},
		{"pidfd assigned", "func f(a *syscall.SysProcAttr) { var p int; a.PidFD = &p }\n", []string{l(kProducer, 0)}},
		{"another PidFD field", "type c struct{ PidFD int }\n\nfunc f() c { return c{PidFD: 3} }\n", nil},
		{"pidfd assigned new", "func f(a *syscall.SysProcAttr) *int { a.PidFD = new(int); return a.PidFD }\n", []string{l(kProducer, 0)}},
		{"pidfd assigned a pointer variable", "func f(a *syscall.SysProcAttr, n int) { p := &n; a.PidFD = p }\n", []string{l(kProducer, 0)}},
		{"pidfd assigned a parameter", "func f(a *syscall.SysProcAttr, p *int) { a.PidFD = p }\n", []string{l(kProducer, 0)}},
		{"pidfd assigned a call", "func g() *int { return nil }\n\nfunc f(a *syscall.SysProcAttr) { a.PidFD = g() }\n", []string{l(kProducer, 2)}},
		{"pidfd in a multi-value assignment", "func g() (*int, error) { return nil, nil }\n\nfunc f(a *syscall.SysProcAttr) { a.PidFD, _ = g() }\n", []string{l(kProducer, 2)}},
		{"pidfd cleared", "const none = -1\n\ntype c struct{ PidFD int }\n\nfunc f(a *syscall.SysProcAttr, x *c) { a.PidFD = nil; x.PidFD = -1; x.PidFD = none; x.PidFD = int(3) }\n", nil},
		{"pidfd in an elided slice element", "func f() []*syscall.SysProcAttr { var a int; return []*syscall.SysProcAttr{{PidFD: &a}} }\n", []string{l(kProducer, 0)}},
		{"pidfd in an elided map value", "func f() map[string]syscall.SysProcAttr { var a int; return map[string]syscall.SysProcAttr{\"x\": {PidFD: &a}} }\n", []string{l(kProducer, 0)}},
		{"pidfd through an alias", "type attr = syscall.SysProcAttr\n\nfunc f() *attr { var a int; return &attr{PidFD: &a} }\n", []string{l(kProducer, 2)}},
		{"pidfd through a defined type", "type attr syscall.SysProcAttr\n\nfunc f(p *int) attr { return attr{PidFD: p} }\n", []string{l(kProducer, 2)}},
		{"the package's own PidFD field", "type c struct{ PidFD int }\n\nfunc f(n int) *c { return &c{PidFD: n} }\n", nil},
		{"pidfd keyed nil", "func f() *syscall.SysProcAttr { return &syscall.SysProcAttr{PidFD: nil, Setsid: true} }\n", nil},
		{"pidfd field address", "func f(a *syscall.SysProcAttr) **int { return &a.PidFD }\n", []string{l(kProducer, 0)}},
		{"pidfd promoted through embedding", "type wrap struct{ syscall.SysProcAttr }\n\nfunc f(w *wrap, p *int) { w.PidFD = p }\n", []string{l(kProducer, 2)}},
		{"raw memfd through a constant", "const probe = unix.SYS_MEMFD_CREATE\n\nfunc f() { _, _, _ = unix.Syscall(probe, 0, 0, 0) }\n", []string{l(kProducer, 2)}},
		// F2: leases.
		{"hold returned", "func f(o *sys.FD) error {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer l.Return()\n\t_ = l.Num()\n\treturn nil\n}\n", nil},
		{"hold not returned", "func f(o *sys.FD) {\n\tl, _ := o.Hold()\n\t_ = l.Num()\n}\n", []string{l(kLease, 1)}},
		{"hold handed off", "func f(o *sys.FD) {\n\tl, _ := o.Hold()\n\tgo func(p *sys.Lease) {\n\t\tdefer p.Return()\n\t\t_ = p.Num()\n\t}(l)\n}\n", nil},
		{"hold used after hand-off", "func f(o *sys.FD) {\n\tl, _ := o.Hold()\n\tgo func(p *sys.Lease) {\n\t\tdefer p.Return()\n\t}(l)\n\t_ = l.Num()\n}\n", []string{l(kLease, 1)}},
		// Captured, and its number returned out of the literal that may run after the Return.
		{"hold captured", "func f(o *sys.FD) {\n\tl, _ := o.Hold()\n\tdefer l.Return()\n\tg := func() int { return l.Num() }\n\t_ = g\n}\n", []string{l(kLease, 1), l(kLease, 3)}},
		{"hold not assigned", "func f(o *sys.FD) { _, _ = o.Hold() }\n", []string{l(kLease, 0)}},
		// The defer (or the hand-off) is the statement after the Hold's own check, in its block, outside a loop: a
		// conditional defer, one after an early return, one in a loop, and a Hold and defer in a loop, which keeps a
		// lease per iteration until the function returns.
		{"conditional defer", "func f(o *sys.FD, keep bool) error {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn err\n\t}\n\tif keep {\n\t\tdefer l.Return()\n\t}\n\treturn unix.Fsync(l.Num())\n}\n", []string{l(kLease, 1)}},
		{"early return before the defer", "func f(o *sys.FD) error {\n\tl, _ := o.Hold()\n\tif err := unix.Fsync(l.Num()); err != nil {\n\t\treturn err\n\t}\n\tdefer l.Return()\n\treturn nil\n}\n", []string{l(kLease, 1)}},
		{"defer in a loop", "func f(o *sys.FD) {\n\tl, _ := o.Hold()\n\tfor i := 0; i < 0; i++ {\n\t\tdefer l.Return()\n\t}\n}\n", []string{l(kLease, 1)}},
		{"hold and defer in a loop", "func f(o *sys.FD) {\n\tfor i := 0; i < 2; i++ {\n\t\tl, err := o.Hold()\n\t\tif err != nil {\n\t\t\treturn\n\t\t}\n\t\tdefer l.Return()\n\t\t_ = unix.Fsync(l.Num())\n\t}\n}\n", []string{l(kLease, 2)}},
		{"hold and defer in a loop's function literal", "func f(o *sys.FD) {\n\tfor i := 0; i < 2; i++ {\n\t\tfunc() {\n\t\t\tl, err := o.Hold()\n\t\t\tif err != nil {\n\t\t\t\treturn\n\t\t\t}\n\t\t\tdefer l.Return()\n\t\t\t_ = unix.Fsync(l.Num())\n\t\t}()\n\t}\n}\n", nil},
		{"defer after another statement", "func f(o *sys.FD) {\n\tl, err := o.Hold()\n\t_ = err\n\tdefer l.Return()\n}\n", []string{l(kLease, 1)}},
		{"conditional hand-off", "func f(o *sys.FD, keep bool) {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tif keep {\n\t\tgo func(p *sys.Lease) {\n\t\t\tdefer p.Return()\n\t\t}(l)\n\t}\n}\n", []string{l(kLease, 1)}},
		{"hand-off after its check", "func f(o *sys.FD) {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tgo func(p *sys.Lease) {\n\t\tdefer p.Return()\n\t\t_ = unix.Fsync(p.Num())\n\t}(l)\n}\n", nil},
		{"handed-off lease returned twice", "func f(o *sys.FD) {\n\tl, _ := o.Hold()\n\tgo func(p *sys.Lease) {\n\t\tdefer p.Return()\n\t\tp.Return()\n\t}(l)\n}\n", []string{l(kLease, 1)}},
		// A lease is used by its Num and Return, a nil check and its hand-off, and nothing else.
		{"lease passed to a function", "func keep(l *sys.Lease) {}\n\nfunc f(o *sys.FD) {\n\tl, _ := o.Hold()\n\tdefer l.Return()\n\tkeep(l)\n}\n", []string{l(kLease, 3)}},
		{"lease boxed", "var held any\n\nfunc f(o *sys.FD) {\n\tl, _ := o.Hold()\n\tdefer l.Return()\n\theld = l\n}\n", []string{l(kLease, 3)}},
		{"lease compared with nil", "func f(o *sys.FD) {\n\tl, err := o.Hold()\n\tif l == nil || err != nil {\n\t\treturn\n\t}\n\tdefer l.Return()\n}\n", nil},
		// The check skipped before the defer is the Hold's own failure test, `err != nil` or `l == nil` joined by ||,
		// whose body only returns: a check that returns on success, or on another variable, leaks the lease on that
		// path. A backward goto around the Hold and its defer is a loop.
		{"hold returns on success", "func f(o *sys.FD) {\n\tl, err := o.Hold()\n\tif err == nil {\n\t\treturn\n\t}\n\tdefer l.Return()\n}\n", []string{l(kLease, 1)}},
		{"hold returns while held", "func f(o *sys.FD) {\n\tl, _ := o.Hold()\n\tif l != nil {\n\t\treturn\n\t}\n\tdefer l.Return()\n}\n", []string{l(kLease, 1)}},
		{"hold returns while held or failed", "func f(o *sys.FD) error {\n\tl, err := o.Hold()\n\tif l != nil || err != nil {\n\t\treturn err\n\t}\n\tdefer l.Return()\n\treturn nil\n}\n", []string{l(kLease, 1)}},
		{"hold returns on success with nil first", "func f(o *sys.FD) {\n\tl, err := o.Hold()\n\tif nil == err {\n\t\treturn\n\t}\n\tdefer l.Return()\n}\n", []string{l(kLease, 1)}},
		{"hold returns on another variable", "func f(o *sys.FD, other *int) {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tif other == nil {\n\t\treturn\n\t}\n\tdefer l.Return()\n}\n", []string{l(kLease, 1)}},
		{"hold checked twice", "func f(o *sys.FD) {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tif nil == l {\n\t\treturn\n\t}\n\tdefer l.Return()\n}\n", nil},
		{"hold and defer in a goto loop", "func f(o *sys.FD) {\n\ti := 0\nagain:\n\ti++\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer l.Return()\n\tif i < 9 {\n\t\tgoto again\n\t}\n}\n", []string{l(kLease, 4)}},
		{"hold and defer after a goto loop", "func f(o *sys.FD) {\n\ti := 0\nagain:\n\ti++\n\tif i < 9 {\n\t\tgoto again\n\t}\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer l.Return()\n}\n", nil},
		{"hold and defer in a goto loop's function literal", "func f(o *sys.FD) {\n\ti := 0\nagain:\n\ti++\n\tfunc() {\n\t\tl, err := o.Hold()\n\t\tif err != nil {\n\t\t\treturn\n\t\t}\n\t\tdefer l.Return()\n\t}()\n\tif i < 9 {\n\t\tgoto again\n\t}\n}\n", nil},
		{"hold with a forward goto", "func f(o *sys.FD, skip bool) {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer l.Return()\n\tif skip {\n\t\tgoto done\n\t}\n\t_ = unix.Fsync(l.Num())\ndone:\n\treturn\n}\n", nil},
		{"hand-off in a goto loop", "func f(o *sys.FD) {\n\ti := 0\nagain:\n\ti++\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tgo func(p *sys.Lease) {\n\t\tdefer p.Return()\n\t}(l)\n\tif i < 9 {\n\t\tgoto again\n\t}\n}\n", nil},
		{"hold as a value", "func f(o *sys.FD) { h := o.Hold; l, _ := h(); _ = l }\n", []string{l(kFuncValue, 0)}},
		{"num as a value", "var kept int\n\nfunc f(o *sys.FD) {\n\tl, _ := o.Hold()\n\tdefer l.Return()\n\tn := l.Num\n\tkept = n()\n}\n", []string{l(kLease, 3), l(kFuncValue, 5)}},
		{"handed-off lease passed on", "func keep(l *sys.Lease) {}\n\nfunc f(o *sys.FD) {\n\tl, _ := o.Hold()\n\tgo func(p *sys.Lease) {\n\t\tdefer p.Return()\n\t\tkeep(p)\n\t}(l)\n}\n", []string{l(kLease, 3)}},
		{"lender interface hold", "func f(o sys.Lender) { _, _ = o.Hold() }\n", []string{l(kLease, 0)}},
		{"lease in a field", "type s struct{ l *sys.Lease }\n", []string{l(kLease, 0)}},
		{"lease in a field through an alias", "type held = *sys.Lease\n\ntype s struct{ l []held }\n", []string{l(kLease, 2)}},
		{"lease on a channel", "func f(c chan *sys.Lease) {}\n", []string{l(kLease, 0)}},
		{"lease in a package variable", "var held *sys.Lease\n", []string{l(kLease, 0)}},
		{"lease in an inferred package variable", "var held = make(chan *sys.Lease)\n", []string{l(kLease, 0), l(kLease, 0)}},
		// F3: the released number goes to one taker's argument, and nowhere else.
		{"release to a taker", "func f(o *sys.FD) (link.Link, error) { n, err := o.ReleaseNumber(); if err != nil { return nil, err }; return link.NewFromFD(n) }\n", nil},
		{"release elsewhere", "func f(o *sys.FD) { n, _ := o.ReleaseNumber(); _ = n }\n", []string{l(kRelease, 0)}},
		{"release into a syscall", "func f(o *sys.FD) { n, _ := o.ReleaseNumber(); _ = unix.Close(n) }\n", []string{l(kClose, 0), l(kRelease, 0)}},
		{"release to two takers", "func f(o *sys.FD) { n, _ := o.ReleaseNumber(); _, _ = link.NewFromFD(n); _, _ = link.NewFromFD(n) }\n", []string{l(kFromFD, 0), l(kRelease, 0)}},
		{"release kept", "var kept int\n\nfunc f(o *sys.FD) { n, _ := o.ReleaseNumber(); kept = n }\n", []string{l(kRelease, 2)}},
		{"release not assigned", "func f(o *sys.FD) { _, _ = o.ReleaseNumber() }\n", []string{l(kRelease, 0)}},
		// The taker is the statement after the ReleaseNumber's own error check, in its block, so it runs exactly
		// once: never in a loop (two owners of one number), on a branch (none), or after a label.
		{"release taken in a loop", "func f(o *sys.FD) error {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn err\n\t}\n\tfor i := 0; i < 2; i++ {\n\t\t_, _ = link.NewFromFD(n)\n\t}\n\treturn nil\n}\n", []string{l(kRelease, 6)}},
		{"release taken on one branch", "func f(o *sys.FD, take bool) (link.Link, error) {\n\tn, err := o.ReleaseNumber()\n\tif err != nil || !take {\n\t\treturn nil, err\n\t}\n\treturn link.NewFromFD(n)\n}\n", []string{l(kRelease, 5)}},
		{"release taken inside a branch", "func f(o *sys.FD, take bool) (link.Link, error) {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tif take {\n\t\treturn link.NewFromFD(n)\n\t}\n\treturn nil, nil\n}\n", []string{l(kRelease, 6)}},
		// Its check returns on failure only, `err != nil`, and the taker is the statement
		// itself or its right-hand side: in a for condition it runs per iteration, in an if or switch condition, a
		// go or a defer it is not the plain call F3 sanctions. A goto loop around the release and its taker
		// gives each pass's number one owner, as a for loop around both does.
		{"release returns on success", "func f(o *sys.FD) (link.Link, error) {\n\tn, err := o.ReleaseNumber()\n\tif err == nil {\n\t\treturn nil, nil\n\t}\n\treturn link.NewFromFD(n)\n}\n", []string{l(kRelease, 5)}},
		{"release returns on another variable", "func f(o *sys.FD, p *int) (link.Link, error) {\n\tn, err := o.ReleaseNumber()\n\tif p == nil {\n\t\treturn nil, err\n\t}\n\treturn link.NewFromFD(n)\n}\n", []string{l(kRelease, 5)}},
		{"release taken in a for condition", "func ok(link.Link, error) bool { return false }\n\nfunc f(o *sys.FD) error {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn err\n\t}\n\tfor ok(link.NewFromFD(n)) {\n\t}\n\treturn nil\n}\n", []string{l(kRelease, 7)}},
		{"release taken in an if condition", "func ok(link.Link, error) bool { return false }\n\nfunc f(o *sys.FD) error {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn err\n\t}\n\tif ok(link.NewFromFD(n)) {\n\t\treturn nil\n\t}\n\treturn nil\n}\n", []string{l(kRelease, 7)}},
		{"release taken in a switch tag", "func ok(link.Link, error) bool { return false }\n\nfunc f(o *sys.FD) error {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn err\n\t}\n\tswitch ok(link.NewFromFD(n)) {\n\t}\n\treturn nil\n}\n", []string{l(kRelease, 7)}},
		// && and || skip their right operand when the left one settles the result, so a taker there may never
		// run and the number leaks; their left operand always runs.
		{"release taken right of &&", "func use(link.Link, error) bool { return false }\n\nfunc f(o *sys.FD, flag bool, m map[bool]int) bool {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn false\n\t}\n\tok := flag && use(link.NewFromFD(n))\n\treturn ok\n}\n", []string{l(kRelease, 7)}},
		{"release taken right of || in a return", "func use(link.Link, error) bool { return false }\n\nfunc f(o *sys.FD, flag bool, m map[bool]int) bool {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn false\n\t}\n\treturn flag || use(link.NewFromFD(n))\n}\n", []string{l(kRelease, 7)}},
		{"release taken right of || in a map key", "func use(link.Link, error) bool { return false }\n\nfunc f(o *sys.FD, flag bool, m map[bool]int) bool {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn false\n\t}\n\tm[flag || use(link.NewFromFD(n))] = 1\n\treturn true\n}\n", []string{l(kRelease, 7)}},
		{"release taken right of a nested &&", "func use(link.Link, error) bool { return false }\n\nfunc f(o *sys.FD, flag bool, m map[bool]int) bool {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn false\n\t}\n\treturn (flag && use(link.NewFromFD(n))) || flag\n}\n", []string{l(kRelease, 7)}},
		{"release taken left of &&", "func use(link.Link, error) bool { return false }\n\nfunc f(o *sys.FD, flag bool, m map[bool]int) bool {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn false\n\t}\n\treturn use(link.NewFromFD(n)) && flag\n}\n", nil},
		{"release taken by a defer", "func f(o *sys.FD) {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer link.NewFromFD(n)\n}\n", []string{l(kRelease, 5)}},
		{"release taken by a go statement", "func f(o *sys.FD) {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn\n\t}\n\tgo link.NewFromFD(n)\n}\n", []string{l(kFromFD, 5), l(kRelease, 5)}},
		{"release taken as a statement", "func f(o *sys.FD) {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn\n\t}\n\tlink.NewFromFD(n)\n}\n", nil},
		{"release and taker in a goto loop", "func f(o *sys.FD) {\n\ti := 0\nagain:\n\ti++\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn\n\t}\n\t_, _ = link.NewFromFD(n)\n\tif i < 9 {\n\t\tgoto again\n\t}\n}\n", nil},
		{"release taken after a label", "func f(o *sys.FD) error {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn err\n\t}\nagain:\n\t_, err = link.NewFromFD(n)\n\tif err == nil {\n\t\tgoto again\n\t}\n\treturn err\n}\n", []string{l(kRelease, 6)}},
		{"release taken after another statement", "func f(o *sys.FD) (link.Link, error) {\n\tn, err := o.ReleaseNumber()\n\t_ = err\n\treturn link.NewFromFD(n)\n}\n", []string{l(kRelease, 3)}},
		{"release taken after its check", "func f(o *sys.FD) (link.Link, error) {\n\tvar n, err = o.ReleaseNumber()\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tl, err := link.NewFromFD(n)\n\treturn l, err\n}\n", nil},
		{"release as a value", "func f(o *sys.FD) { r := o.ReleaseNumber; _ = r }\n", []string{l(kFuncValue, 0)}},
		// F4 (the kinds the lists admit; Ratchet applies the lists).
		{"adopt", "func f(n int) { _, _ = sys.Adopt(n, \"x\") }\n", []string{l(kAdopt, 0)}},
		{"abandon", "func f(o *sys.FD) { o.Abandon() }\n", []string{l(kAbandon, 0)}},
		{"another type's abandon", "func f(w interface{ Abandon() error }) { _ = w.Abandon() }\n", nil},
		{"another type's result-less abandon", "type pending struct{}\n\nfunc (pending) Abandon() {}\n\nfunc f(p pending) { p.Abandon() }\n", nil},
		{"abandon as a value", "func f(o *sys.FD) { a := o.Abandon; a() }\n", []string{l(kFuncValue, 0)}},
		{"inherited", "func f() { _, _ = sys.Inherited(3, sys.KindDir, \"x\") }\n", []string{l(kInherited, 0)}},
		{"stdio", "func f() { _, _ = sys.Stdio(1) }\n", []string{l(kStdio, 0)}},
		{"sweep", "func f() { _ = sys.CloseInheritedFrom(3) }\n", []string{l(kSweep, 0)}},
		{"sweep as a value", "var sweep = sys.CloseInheritedFrom\n", []string{l(kFuncValue, 0)}},
		{"inert outside tests", "func f() { _ = sys.InertForTest(5) }\n", []string{l(kForTest, 0)}},
		{"a ForTest accessor outside testhooks", "func f() { _ = sys.LeakedForTest() }\n", []string{l(kForTest, 0)}},
		{"a ForTest method outside testhooks", "func f(o *sys.FD) { _ = o.HoldsForTest() }\n", []string{l(kForTest, 0)}},
		// F8, by type: the package's own name for int counts.
		{"exported fd parameter", "func Take(fd int) {}\n", []string{l(kAPI, 0)}},
		{"exported fd parameter of a named int", "type num int\n\nfunc Take(fd num) {}\n", []string{l(kAPI, 2)}},
		{"exported fd result", "func Give() (dirfd int, err error) { return 0, nil }\n", []string{l(kAPI, 0)}},
		{"exported FD-named function", "func WaitNotifyFD() (int, error) { return 0, nil }\n", []string{l(kAPI, 0)}},
		{"exported interface method", "type Lender interface{ Ruleset() (fd int, ok bool) }\n", []string{l(kAPI, 0)}},
		{"unexported function", "func take(fd int) {}\n", nil},
		{"method of an unexported type", "type t struct{}\n\nfunc (t) Take(fd int) {}\n", nil},
		{"owner parameter", "func Take(fd *sys.FD) {}\n", nil},
		// No //nolint hides a site, and a nolint that silences forbidigo is a site itself.
		{"nolint", "func f(fd int) { _ = unix.Close(fd) } //nolint:forbidigo // hidden from golangci-lint only\n", []string{l(kClose, 0), l(kNolint, 0)}},
		{"nolint for every linter", "func f(g func() *os.File) uintptr { return g().Fd() } //nolint\n", []string{l(kFd, 0), l(kNolint, 0)}},
		{"nolint with a reason", "var x = 1 // nolint // why\n", []string{l(kNolint, 0)}},
		{"nolint all", "var x = 1 //nolint:errcheck,all // why\n", []string{l(kNolint, 0)}},
		{"nolint forbidigo in a list", "var x = 1 //nolint:errcheck, Forbidigo\n", []string{l(kNolint, 0)}},
		{"nolint in a block comment", "var x = 1 /* nolint:forbidigo */\n", []string{l(kNolint, 0)}},
		{"nolint for other linters", "var x = 1 //nolint:errcheck,unconvert // why\n", nil},
		{"a word that starts with nolint", "var x = 1 // nolintlint is a linter\n", nil},
		// F3's sanctioned form needs the nolint forbidigo cannot do without; on any other line, or naming more
		// than forbidigo, it is a site.
		{"F3's nolint", "func f(o *sys.FD) (link.Link, error) { n, err := o.ReleaseNumber(); if err != nil { return nil, err }; return link.NewFromFD(n) } //nolint:forbidigo // ADR 0023 F3\n", nil},
		{"F3's nolint elsewhere", "func f(o *sys.FD) (link.Link, error) {\n\tn, err := o.ReleaseNumber()\n\tif err != nil {\n\t\treturn nil, err //nolint:forbidigo // ADR 0023 F3\n\t}\n\treturn link.NewFromFD(n)\n}\n", []string{l(kNolint, 3)}},
		{"F3's nolint for all", "func f(o *sys.FD) (link.Link, error) { n, err := o.ReleaseNumber(); if err != nil { return nil, err }; return link.NewFromFD(n) } //nolint:forbidigo,all // ADR 0023 F3\n", []string{l(kNolint, 0)}},
		// Code fdcheck cannot read is a site itself: a linkname and a function without a Go body (F6).
		{"a linked function", "//go:linkname sysClose syscall.Close\nfunc sysClose(fd int) error\n", []string{l(kOpaque, 0), l(kOpaque, 1)}},
		{"a linked variable", "//go:linkname probe github.com/cilium/ebpf.haveProbeReadKernel\nvar probe func() error\n", []string{l(kOpaque, 0)}},
		{"an assembly function", "func rawClose(fd int) int\n", []string{l(kOpaque, 0)}},
		// Nothing else.
		{"clean", "func f() { _ = unix.Getpid() }\n", nil},
	})
}

// TestUnclassifiedIoctlWrapper: an x/sys Ioctl* wrapper in none of fdcheck's lists (one an x/sys bump adds) is a
// finding until it is classified; here a listed one stands in for it.
func TestUnclassifiedIoctlWrapper(t *testing.T) {
	delete(ioctlFixed, "IoctlPidfdInfo")
	defer func() { ioctlFixed["IoctlPidfdInfo"] = true }()
	got := kinds(t, "internal/zzfdcheck/ioctl/x.go", hdr+"func f(fd int, i *unix.PidfdInfo) { _ = unix.IoctlPidfdInfo(fd, i) }\n")
	if want := []string{l(kIoctl, 0)}; !reflect.DeepEqual(got, want) {
		t.Errorf("an unclassified ioctl wrapper: %v, want %v", got, want)
	}
}

// TestLentNumber is F2's lent-number rules (lent.go; ADR 0023's 2026-10-19 design-round note): the number a
// lender lends (RawConn's Control, Read and Write, Borrow, sys.FileDo, and every function that passes its own
// callback the number) and a Lease's Num are used only in the ways the rules admit; every other use is a lease
// site. Each form found so far is a
// row, with negatives for the uses the tree makes.
func TestLentNumber(t *testing.T) {
	runFixtures(t, "lent", []fixture{
		// Stored outside the callback.
		{"control capture", "func f(c syscall.RawConn) { var keep int; _ = c.Control(func(fd uintptr) { keep = int(fd) }); _ = keep }\n", []string{l(kLease, 0)}},
		{"control capture to a global", "var keep int\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { keep = int(fd) }) }\n", []string{l(kLease, 2)}},
		{"control capture through a local", "func f(c syscall.RawConn) { var keep int; _ = c.Control(func(fd uintptr) { n := int(fd) + 0; keep = n }); _ = keep }\n", []string{l(kLease, 0)}},
		{"control capture by append", "func f(c syscall.RawConn) { var keep []int; _ = c.Control(func(fd uintptr) { keep = append(keep, int(fd)) }); _ = keep }\n", []string{l(kLease, 0)}},
		{"control capture into a field", "type s struct{ n uintptr }\n\nfunc f(c syscall.RawConn, x *s) { _ = c.Control(func(fd uintptr) { x.n = fd }) }\n", []string{l(kLease, 2)}},
		{"control capture on a channel", "func f(c syscall.RawConn, ch chan uintptr) { _ = c.Control(func(fd uintptr) { ch <- fd }) }\n", []string{l(kLease, 0)}},
		{"control capture by a goroutine", "func f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { go func() { _ = fd }() }) }\n", []string{l(kLease, 0)}},
		{"control capture by a goroutine's argument", "func use(n uintptr) {}\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { go use(fd) }) }\n", []string{l(kLease, 2)}},
		{"read capture", "func f(c syscall.RawConn) { var k uintptr; _ = c.Read(func(fd uintptr) bool { k = fd; return true }); _ = k }\n", []string{l(kLease, 0)}},
		{"borrow capture", "func f(o *sys.FD) { var k int; _ = o.Borrow(func(n int) error { k = n; return nil }); _ = k }\n", []string{l(kLease, 0)}},
		{"lender interface borrow capture", "func f(o sys.Lender) { var k int; _ = o.Borrow(func(n int) error { k = n; return nil }); _ = k }\n", []string{l(kLease, 0)}},
		{"filedo capture", "func f(o *os.File) { var k int; _ = sys.FileDo(o, func(n int) error { k = n; return nil }); _ = k }\n", []string{l(kLease, 0)}},
		{"map key outward", "var seen = map[uintptr]bool{}\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { seen[fd] = true }) }\n", []string{l(kLease, 2)}},
		{"copy outward", "func f(c syscall.RawConn, keep []uintptr) { _ = c.Control(func(fd uintptr) { copy(keep, []uintptr{fd}) }) }\n", []string{l(kLease, 0)}},
		{"range value outward", "var keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { for _, v := range []uintptr{fd} { keep = v } }) }\n", []string{l(kLease, 2)}},
		{"range assigned outward", "var keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { for _, keep = range []uintptr{fd} { } }) }\n", []string{l(kLease, 2)}},
		// A slice bound makes the slice's length the number, and len or cap of what holds it carries it too, so the
		// number cannot leave through a length (L5).
		{"slice bound and len outward", "func f(o *sys.FD, buf []byte) int {\n\tk := 0\n\t_ = o.Borrow(func(n int) error { k = len(buf[:n]); return nil })\n\treturn k\n}\n", []string{l(kLease, 2)}},
		{"slice start and cap outward", "var kept int\n\nfunc f(o *sys.FD, buf []byte) { _ = o.Borrow(func(n int) error { kept = cap(buf[n:]); return nil }) }\n", []string{l(kLease, 2)}},
		{"len of a slice bound used", "func f(o *sys.FD, buf []byte) { _ = o.Borrow(func(n int) error { if len(buf[:n]) > 0 { return nil }; return nil }) }\n", nil},
		// ProcPath lends the number as "/proc/self/fd/N": the path is held to the same closed list.
		{"proc path kept", "var kept string\n\nfunc f(o *sys.FD) { _ = o.ProcPath(func(p string) error { kept = p; return nil }) }\n", []string{l(kLease, 2)}},
		{"proc path copied out", "func f(o *sys.FD) string {\n\tvar k string\n\t_ = o.ProcPath(func(p string) error { k = p + \"\"; return nil })\n\treturn k\n}\n", []string{l(kLease, 2)}},
		{"proc path in a goroutine", "func f(o *sys.FD) { _ = o.ProcPath(func(p string) error { go func() { _, _ = os.Open(p) }(); return nil }) }\n", []string{l(kLease, 0)}},
		{"proc path read by os", "func f(o *sys.FD) (string, error) {\n\tvar t string\n\terr := o.ProcPath(func(p string) error {\n\t\tvar e error\n\t\tt, e = os.Readlink(p)\n\t\treturn e\n\t})\n\treturn t, err\n}\n", nil},
		{"proc path read by unix", "func f(o *sys.FD, buf []byte) error { return o.ProcPath(func(p string) error { _, e := unix.Readlink(p, buf); return e }) }\n", nil},
		{"proc path as a value", "func f(o *sys.FD) { pp := o.ProcPath; _ = pp }\n", []string{l(kLease, 0)}},
		// execve resolves the path at once and keeps nothing: a failed exec returns, a successful one is a new image.
		{"proc path exec'd by syscall", "func f(o *sys.FD, argv, env []string) error {\n\treturn o.ProcPath(func(p string) error { return syscall.Exec(p, argv, env) })\n}\n", nil},
		{"proc path exec'd by unix", "func f(o *sys.FD, argv, env []string) error {\n\treturn o.ProcPath(func(p string) error { return unix.Exec(p, argv, env) })\n}\n", nil},
		{"proc path as exec's argument", "func f(o *sys.FD, env []string) error {\n\treturn o.ProcPath(func(p string) error { return syscall.Exec(\"/bin/true\", []string{p}, env) })\n}\n", []string{l(kLease, 1)}},
		{"index outward", "var keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { keep = []uintptr{fd}[0] }) }\n", []string{l(kLease, 2)}},
		{"max outward", "var keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { keep = max(fd, 0) }) }\n", []string{l(kLease, 2)}},
		{"a named result", "func f(c syscall.RawConn) (keep uintptr) { _ = c.Control(func(fd uintptr) { keep = fd }); return }\n", []string{l(kLease, 0)}},
		// A store through a pointer, a slice or a map is never local, whatever the storage is.
		{"store through a local pointer", "var keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { p := &keep; *p = fd }) }\n", []string{l(kLease, 2)}},
		{"store through a copied pointer", "func f(c syscall.RawConn, keep *int) { _ = c.Control(func(fd uintptr) { p := keep; *p = int(fd) }) }\n", []string{l(kLease, 0)}},
		{"store through a local slice", "func f(c syscall.RawConn, keep []uintptr) { _ = c.Control(func(fd uintptr) { s := keep[:]; s[0] = fd }) }\n", []string{l(kLease, 0)}},
		{"store through a struct literal's pointer", "var keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { s := struct{ p *uintptr }{&keep}; *s.p = fd }) }\n", []string{l(kLease, 2)}},
		{"store through a map literal's pointer", "var keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { m := map[string]*uintptr{\"a\": &keep}; *m[\"a\"] = fd }) }\n", []string{l(kLease, 2)}},
		{"store through a field pointed outward", "type box struct{ v *uintptr }\n\nvar keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { var b box; b.v = &keep; *b.v = fd }) }\n", []string{l(kLease, 4)}},
		{"store into a fresh slice", "func f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { s := make([]uintptr, 1); s[0] = fd; _ = s }) }\n", []string{l(kLease, 0)}},
		{"store through a fresh pointer", "func f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { var n uintptr; s := []*uintptr{&n}; *s[0] = fd }) }\n", []string{l(kLease, 0)}},
		{"comma-ok assertion alias", "type box struct{ p *uintptr }\n\nvar keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { b := box{}; var i any = &b; q, _ := i.(*box); q.p = &keep; *b.p = fd }) }\n", []string{l(kLease, 4)}},
		{"comma-ok map alias", "type box struct{ p *uintptr }\n\nvar keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { b := box{}; m := map[int]*box{0: &b}; q, _ := m[0]; q.p = &keep; *b.p = fd }) }\n", []string{l(kLease, 4)}},
		{"comma-ok receive alias", "type box struct{ p *uintptr }\n\nvar keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { b := box{}; ch := make(chan *box, 1); ch <- &b; q, _ := <-ch; q.p = &keep; *b.p = fd }) }\n", []string{l(kLease, 4)}},
		{"range alias", "type box struct{ p *uintptr }\n\nvar keep uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { b := box{}; s := []*box{&b}; for _, q := range s { q.p = &keep }; *b.p = fd }) }\n", []string{l(kLease, 4)}},
		{"a local whose address is taken", "var keep *uintptr\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { var n uintptr; keep = &n; n = fd }) }\n", []string{l(kLease, 2)}},
		{"a local a pointer method reaches", "type box struct{ n uintptr }\n\nvar keep *box\n\nfunc (b *box) save() { keep = b }\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { var b box; b.save(); b.n = fd }) }\n", []string{l(kLease, 6)}},
		// Returned out of the callback.
		{"returned as a converted error", "type fdErr int\n\nfunc (fdErr) Error() string { return \"\" }\n\nfunc f(o *sys.FD) error { return o.Borrow(func(fd int) error { return fdErr(fd) }) }\n", []string{l(kLease, 4)}},
		{"returned through a held local", "type fdErr int\n\nfunc (fdErr) Error() string { return \"\" }\n\nfunc f(o *sys.FD) error { return o.Borrow(func(fd int) error { e := fdErr(fd); return e }) }\n", []string{l(kLease, 4)}},
		{"returned in a literal", "type h struct{ n int }\n\nfunc (*h) Error() string { return \"\" }\n\nfunc f(o *sys.FD) error { return o.Borrow(func(fd int) error { return &h{n: fd} }) }\n", []string{l(kLease, 4)}},
		{"returned from FileDo", "type fdErr int\n\nfunc (fdErr) Error() string { return \"\" }\n\nfunc f(g *os.File) error { return sys.FileDo(g, func(fd int) error { return fdErr(fd) }) }\n", []string{l(kLease, 4)}},
		// Uses that end in the call: the tree's own forms.
		{"control use", "func f(c syscall.RawConn) { var e error; _ = c.Control(func(fd uintptr) { e = unix.SetsockoptInt(int(fd), 1, 2, 3) }); _ = e }\n", nil},
		{"control use in a local", "func f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { n := int(fd); _ = unix.SetsockoptInt(n, 1, 2, 3) }) }\n", nil},
		{"read with the bytes read kept", "func f(c syscall.RawConn, p []byte) (int, error) { var n int; var err error; e := c.Read(func(fd uintptr) bool { n, err = unix.Read(int(fd), p); return err != unix.EAGAIN }); _ = e; return n, err }\n", nil},
		{"filedo use", "func f(o *os.File) error { return sys.FileDo(o, func(n int) error { return unix.Fchmod(n, 0o600) }) }\n", nil},
		{"compared and switched", "func f(o *sys.FD) error { return o.Borrow(func(n int) error { if n < 3 { return nil }; switch n { case 4: }; return nil }) }\n", nil},
		{"a local struct and array", "func f(c syscall.RawConn) { _ = c.Control(func(fd uintptr) { var v struct{ n uintptr }; v.n = fd; var a [2]uintptr; a[1] = fd; _ = unix.SetsockoptInt(int(v.n), 1, 2, 3); _ = unix.SetsockoptInt(int(a[1]), 1, 2, 3) }) }\n", nil},
		{"proc path read", "func f(o *sys.FD) error { buf := make([]byte, 64); return o.Borrow(func(n int) error { _, err := unix.Readlink(\"/proc/self/fd/\"+strconv.Itoa(n), buf); return err }) }\n", nil},
		{"rights sent", "func f(o *sys.FD, c *net.UnixConn) error { return o.Borrow(func(n int) error { _, _, err := c.WriteMsgUnix(nil, unix.UnixRights(n), nil); return err }) }\n", nil},
		{"polled", "func f(o *sys.FD) error { return o.Borrow(func(n int) error { _, err := unix.Poll([]unix.PollFd{{Fd: int32(n), Events: unix.POLLIN}}, 0); return err }) }\n", nil},
		// Data the kernel keeps: written out, or an epoll cookie.
		{"written as data", "func f(o *sys.FD, w int) error { return o.Borrow(func(n int) error { _, err := unix.Write(w, []byte(strconv.Itoa(n))); return err }) }\n", []string{l(kLease, 0)}},
		{"an epoll cookie", "func f(o *sys.FD, ep int) error { return o.Borrow(func(n int) error { ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(n)}; return unix.EpollCtl(ep, unix.EPOLL_CTL_ADD, n, &ev) }) }\n", []string{l(kLease, 0)}},
		{"formatted", "func f(o *sys.FD) error { return o.Borrow(func(n int) error { return fmt.Errorf(\"fd %d\", n) }) }\n", []string{l(kLease, 0)}},
		// The callback: a literal, a module function that borrows its parameter, or the enclosing function's own
		// callback parameter; anything else cannot be followed.
		{"control of a callback in a variable", "func f(c syscall.RawConn) { cb := func(fd uintptr) {}; _ = c.Control(cb) }\n", []string{l(kLease, 0)}},
		{"control of a function that keeps", "var kept uintptr\n\nfunc save(fd uintptr) { kept = fd }\n\nfunc f(c syscall.RawConn) { _ = c.Control(save) }\n", []string{l(kLease, 4)}},
		{"control of a function that borrows", "func use(fd uintptr) { _ = unix.SetsockoptInt(int(fd), 1, 2, 3) }\n\nfunc f(c syscall.RawConn) { _ = c.Control(use) }\n", nil},
		{"control of a method value that keeps", "type t struct{ kept *uintptr }\n\nfunc (x t) save(fd uintptr) { *x.kept = fd }\n\nfunc f(c syscall.RawConn, x t) { _ = c.Control(x.save) }\n", []string{l(kLease, 4)}},
		{"filedo of a function that keeps", "var kept int\n\nfunc use(n int) error { kept = n; return nil }\n\nfunc f(o *os.File) { _ = sys.FileDo(o, use) }\n", []string{l(kLease, 4)}},
		{"read of a callback in a variable", "func f(c syscall.RawConn) { var cb func(uintptr) bool; _ = c.Read(cb) }\n", []string{l(kLease, 0)}},
		{"read of a function that keeps", "var kept uintptr\n\nfunc rd(fd uintptr) bool { kept = fd; return true }\n\nfunc f(c syscall.RawConn) { _ = c.Read(rd) }\n", []string{l(kLease, 4)}},
		{"read of a function through a local", "var kept uintptr\n\nfunc keepIt(fd uintptr) bool { kept = fd; return true }\n\nfunc f(c syscall.RawConn) { cb := keepIt; _ = c.Read(cb) }\n", []string{l(kLease, 4)}},
		{"read of a slice element", "var kept uintptr\n\nfunc keepIt(fd uintptr) bool { kept = fd; return true }\n\nfunc f(c syscall.RawConn) { cbs := []func(uintptr) bool{keepIt}; _ = c.Read(cbs[0]) }\n", []string{l(kLease, 4)}},
		{"read of a call's result", "func get() func(uintptr) bool { return nil }\n\nfunc f(c syscall.RawConn) { _ = c.Read(get()) }\n", []string{l(kLease, 2)}},
		{"read of a map value", "func f(c syscall.RawConn, m map[string]func(uintptr) bool) { _ = c.Read(m[\"k\"]) }\n", []string{l(kLease, 0)}},
		{"read of a func field", "type holder struct{ cb func(uintptr) bool }\n\nfunc f(c syscall.RawConn, h holder) { _ = c.Read(h.cb) }\n", []string{l(kLease, 2)}},
		{"read of a func field through a pointer", "type holder struct{ cb func(uintptr) bool }\n\nfunc f(c syscall.RawConn, h *holder) { _ = c.Read(h.cb) }\n", []string{l(kLease, 2)}},
		{"a literal returned and lent later", "var keep uintptr\n\nfunc g() func(uintptr) { return func(fd uintptr) { keep = fd } }\n\nfunc f(c syscall.RawConn) { _ = c.Control(g()) }\n", []string{l(kLease, 4)}},
		{"a literal that never reaches a lender", "var keep uintptr\n\nfunc g() func(uintptr) { return func(fd uintptr) { keep = fd } }\n", nil},
		{"write of a buffer", "func f(w *os.File, b []byte) { _, _ = w.Write(b) }\n", nil},
		{"write of a buffer field", "type u struct{}\n\nfunc (u) data() {}\n\ntype t struct{ data []byte }\n\nfunc f(w *os.File, x t) { _, _ = w.Write(x.data) }\n", nil},
		{"io's Read as a value", "func f(r *os.File) func([]byte) (int, error) { return r.Read }\n", nil},
		{"a Control field", "type h struct{ Control *int }\n\nfunc f(x h, y *h) *int { y.Control = x.Control; return x.Control }\n", nil},
		// A parameter of an alias type is the callback's parameter all the same.
		{"control of an alias parameter", "type u = uintptr\n\nvar keep u\n\nfunc f(c syscall.RawConn) { _ = c.Control(func(fd u) { keep = fd }) }\n", []string{l(kLease, 4)}},
		{"borrow of an alias parameter", "type i = int\n\nvar keep i\n\nfunc f(o *sys.FD) { _ = o.Borrow(func(n i) error { keep = n; return nil }) }\n", []string{l(kLease, 4)}},
		// A lender taken as a value hides its callback from the call's judgement.
		{"control as a value", "var keep uintptr\n\nfunc f(c syscall.RawConn) { ctl := c.Control; _ = ctl(func(fd uintptr) { keep = fd }) }\n", []string{l(kLease, 2)}},
		{"control of a call's result as a value", "func f(g func() syscall.RawConn) { ctl := g().Control; _ = ctl }\n", []string{l(kLease, 0)}},
		{"control as a method expression value", "var ctl = syscall.RawConn.Control\n", []string{l(kLease, 0)}},
		{"read of a SyscallConn as a value", "var kept uintptr\n\nfunc store(fd uintptr) bool { kept = fd; return true }\n\nfunc f(conn *net.UnixConn) { rc, _ := conn.SyscallConn(); rd := rc.Read; _ = rd(store) }\n", []string{l(kLease, 4)}},
		{"borrow as a value", "func f(o *sys.FD) { bw := o.Borrow; _ = bw(func(n int) error { return nil }) }\n", []string{l(kLease, 0)}},
		{"filedo as a value", "func f(o *os.File) { do := sys.FileDo; _ = do(o, func(n int) error { return nil }) }\n", []string{l(kLease, 0)}},
		{"control through a method expression call", "var keep uintptr\n\nfunc f(c syscall.RawConn) { _ = syscall.RawConn.Control(c, func(fd uintptr) { keep = fd }) }\n", []string{l(kLease, 2)}},
		// A function that hands its callback parameter the lent number is a lender: its callers' callbacks are
		// judged (the ask package's AlternateFile.Control), and so is it, taken as a value.
		{"a wrapper's caller that keeps", "type file struct{ f *os.File }\n\nfunc (a *file) Control(fn func(fd int) error) error {\n\traw, err := a.f.SyscallConn()\n\tif err != nil {\n\t\treturn err\n\t}\n\tvar inner error\n\tif err := raw.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {\n\t\treturn err\n\t}\n\treturn inner\n}\n\nvar kept int\n\nfunc f(a *file) error { return a.Control(func(fd int) error { kept = fd; return nil }) }\n", []string{l(kLease, 16)}},
		{"a wrapper's caller that borrows", "type file struct{ f *os.File }\n\nfunc (a *file) Control(fn func(fd int) error) error {\n\traw, err := a.f.SyscallConn()\n\tif err != nil {\n\t\treturn err\n\t}\n\tvar inner error\n\tif err := raw.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {\n\t\treturn err\n\t}\n\treturn inner\n}\n\nfunc f(a *file) error { return a.Control(func(fd int) error { return unix.Fchmod(fd, 0o600) }) }\n", nil},
		{"a wrapper taken as a value", "type file struct{ f *os.File }\n\nfunc (a *file) Control(fn func(fd int) error) error {\n\traw, _ := a.f.SyscallConn()\n\tvar inner error\n\t_ = raw.Control(func(fd uintptr) { inner = fn(int(fd)) })\n\treturn inner\n}\n\nfunc f(a *file) { ctl := a.Control; _ = ctl }\n", []string{l(kLease, 9)}},
		{"a wrapper's wrapper", "func w1(o *sys.FD, cb func(int)) error { return o.Borrow(func(n int) error { cb(n); return nil }) }\n\nfunc w2(o *sys.FD, cb func(int)) error { return w1(o, cb) }\n\nvar kept int\n\nfunc f(o *sys.FD) { _ = w2(o, func(n int) { kept = n }) }\n", []string{l(kLease, 6)}},
		{"a wrapper of a named func type", "type cbT func(uintptr) bool\n\nfunc g(c syscall.RawConn, cb cbT) error { return c.Write(cb) }\n\nvar kept uintptr\n\nfunc store(fd uintptr) bool { kept = fd; return true }\n\nfunc f(c syscall.RawConn) { _ = g(c, store); _ = g(c, cbT(store)) }\n", []string{l(kLease, 8), l(kLease, 8)}},
		{"an interface method a wrapper implements", "type file struct{ f *os.File }\n\nfunc (a *file) Control(fn func(fd int) error) error {\n\traw, _ := a.f.SyscallConn()\n\tvar inner error\n\t_ = raw.Control(func(fd uintptr) { inner = fn(int(fd)) })\n\treturn inner\n}\n\ntype controller interface{ Control(fn func(fd int) error) error }\n\nvar kept int\n\nfunc f(c controller) error { return c.Control(func(fd int) error { kept = fd; return nil }) }\n", []string{l(kLease, 13)}},
		{"a reassigned callback parameter", "func w(o *sys.FD, cb func(int)) error { cb = func(int) {}; return o.Borrow(func(n int) error { cb(n); return nil }) }\n", []string{l(kLease, 0)}},
		// A module function the number is passed to is judged by its body (its summary), through recursion.
		{"a helper that keeps", "var kept int\n\nfunc save(n int) { kept = n }\n\nfunc f(o *sys.FD) error { return o.Borrow(func(n int) error { save(n); return nil }) }\n", []string{l(kLease, 4)}},
		{"a helper that borrows", "func use(n int) error { return unix.Fchmod(n, 0o600) }\n\nfunc f(o *sys.FD) error { return o.Borrow(func(n int) error { return use(n) }) }\n", nil},
		{"a recursive helper", "func walk(n, depth int) error {\n\tif depth == 0 {\n\t\treturn unix.Fchmod(n, 0)\n\t}\n\treturn walk(n, depth-1)\n}\n\nfunc f(o *sys.FD) error { return o.Borrow(func(n int) error { return walk(n, 3) }) }\n", nil},
		{"mutual recursion that keeps", "var kept int\n\nfunc a(n, d int) { if d == 0 { kept = n; return }; b(n, d-1) }\n\nfunc b(n, d int) { a(n, d) }\n\nfunc f(o *sys.FD) error { return o.Borrow(func(n int) error { a(n, 2); return nil }) }\n", []string{l(kLease, 6)}},
		{"a helper that returns it", "func id(n int) int { return n }\n\nvar kept int\n\nfunc f(o *sys.FD) error { return o.Borrow(func(n int) error { kept = id(n); return nil }) }\n", []string{l(kLease, 4)}},
		{"a method of the number's type", "type num int\n\nvar kept num\n\nfunc (n num) keep() { kept = n }\n\nfunc f(o *sys.FD) error { return o.Borrow(func(n int) error { num(n).keep(); return nil }) }\n", []string{l(kLease, 6)}},
		// A Lease's Num is lent for the Hold's function.
		{"num kept", "var kept int\n\nfunc f(o *sys.FD) {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer l.Return()\n\tkept = l.Num()\n}\n", []string{l(kLease, 8)}},
		{"num returned", "func f(o *sys.FD) int {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn -1\n\t}\n\tdefer l.Return()\n\treturn l.Num()\n}\n", []string{l(kLease, 6)}},
		// A callback a synchronous lender runs (RawConn's methods, sys's Borrow, FileDo, ProgramFD, MapFD) is part of
		// the function that calls it: the loop lease's number used in a Borrow per event, two Borrows nested.
		{"a held number in a nested borrow", "func f(lis, ev *sys.FD) error {\n\tl, err := lis.Hold()\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer l.Return()\n\tlfd := l.Num()\n\treturn ev.Borrow(func(efd int) error { return unix.Renameat(lfd, \"a\", efd, \"b\") })\n}\n", nil},
		// ProcPath's callback runs before it returns, like Borrow's.
		{"a held number in a nested proc path", "func f(lis, ev *sys.FD) error {\n\tl, err := lis.Hold()\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer l.Return()\n\tlfd := l.Num()\n\treturn ev.ProcPath(func(p string) error { return unix.Fchmod(lfd, 0o600) })\n}\n", nil},
		{"two borrows nested", "func f(o, q *sys.FD) error { return o.Borrow(func(n int) error { return q.Borrow(func(m int) error { return unix.Renameat(n, \"a\", m, \"b\") }) }) }\n", nil},
		{"a held number kept in a nested borrow", "var kept int\n\nfunc f(lis, ev *sys.FD) error {\n\tl, err := lis.Hold()\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer l.Return()\n\tlfd := l.Num()\n\treturn ev.Borrow(func(efd int) error { kept = lfd; return nil })\n}\n", []string{l(kLease, 9)}},
		{"an outer number returned from a nested borrow", "type fdErr int\n\nfunc (fdErr) Error() string { return \"\" }\n\nfunc f(o, q *sys.FD) error { return o.Borrow(func(n int) error { return q.Borrow(func(m int) error { return fdErr(n) }) }) }\n", []string{l(kLease, 4)}},
		{"a nested callback stores in the outer callback's local", "func f(o, q *sys.FD) error { return o.Borrow(func(n int) error { var x int; if err := q.Borrow(func(m int) error { x = n; return nil }); err != nil { return err }; return unix.Fchmod(x, 0o600) }) }\n", nil},
		{"an outer number in a goroutine's literal", "func f(o *sys.FD) error { return o.Borrow(func(n int) error { done := make(chan int); go func() { done <- n }(); <-done; return nil }) }\n", []string{l(kLease, 0)}},
		{"an outer number in a wrapper's callback", "type file struct{ f *os.File }\n\nfunc (a *file) Control(fn func(fd int) error) error {\n\traw, _ := a.f.SyscallConn()\n\tvar inner error\n\t_ = raw.Control(func(fd uintptr) { inner = fn(int(fd)) })\n\treturn inner\n}\n\nfunc f(o *sys.FD, a *file) error { return o.Borrow(func(n int) error { return a.Control(func(m int) error { return unix.Renameat(n, \"a\", m, \"b\") }) }) }\n", []string{l(kLease, 9)}},
		// A Num's number is valid while the lease is out: an explicit Return (H8) or the hand-off (H7) ends it while
		// the holder still has the number.
		{"num used after an explicit return", "func f(o *sys.FD, buf []byte) {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer l.Return()\n\tn := l.Num()\n\tl.Return()\n\t_ = o.Close()\n\t_, _ = unix.Write(n, buf)\n}\n", []string{l(kLease, 1)}},
		{"num used after the hand-off", "func f(o *sys.FD, buf []byte) {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn\n\t}\n\tn := l.Num()\n\tgo func(p *sys.Lease) {\n\t\tdefer p.Return()\n\t}(l)\n\t_, _ = unix.Write(n, buf)\n}\n", []string{l(kLease, 1)}},
		{"num taken after a direct hand-off", "func f(o *sys.FD, buf []byte) {\n\tl, _ := o.Hold()\n\tgo func(p *sys.Lease) {\n\t\tdefer p.Return()\n\t}(l)\n\t_, _ = unix.Write(l.Num(), buf)\n}\n", []string{l(kLease, 1)}},
		{"num used", "func f(o *sys.FD) error {\n\tl, err := o.Hold()\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer l.Return()\n\tn := l.Num()\n\treturn unix.Fchmod(n, 0o600)\n}\n", nil},
	})
}

// TestCallbacksAcrossFilesAndPackages: a lender's callback is judged by the function it names wherever that
// function is declared: in another file of the package or in another package, as is a lender that
// another package's function derives, and a helper in another package the number is passed to.
func TestCallbacksAcrossFilesAndPackages(t *testing.T) {
	const a = "internal/zzfdcheck/across/a"
	got := planted(t, map[string]map[string]string{
		"two files": {
			"internal/zzfdcheck/across/two/a.go": "package two\n\nvar keep uintptr\n\nfunc store(fd uintptr) bool { keep = fd; return true }\n",
			"internal/zzfdcheck/across/two/b.go": "package two\n\nimport \"syscall\"\n\nfunc f(c syscall.RawConn) { _ = c.Read(store) }\n",
		},
		// A package calls an interface's method that a package it does not import implements as a lender.
		"interface": {
			"internal/zzfdcheck/across/ia/ia.go": "package ia\n\ntype Controller interface{ Control(fn func(n int) error) error }\n\nvar kept int\n\nfunc F(c Controller) error { return c.Control(func(n int) error { kept = n; return nil }) }\n",
			"internal/zzfdcheck/across/ib/ib.go": "package ib\n\nimport \"os\"\n\ntype File struct{ f *os.File }\n\nfunc (a *File) Control(fn func(n int) error) error {\n\traw, _ := a.f.SyscallConn()\n\tvar inner error\n\t_ = raw.Control(func(fd uintptr) { inner = fn(int(fd)) })\n\treturn inner\n}\n",
		},
		"packages": {
			a + "/a.go": "package a\n\nimport (\n\t\"syscall\"\n\n\t\"golang.org/x/sys/unix\"\n)\n\nvar kept uintptr\n\n" +
				"func Keep(n uintptr) bool { kept = n; return true }\n\n" +
				"func Use(n uintptr) bool { return unix.SetsockoptInt(int(n), 1, 2, 3) == nil }\n\n" +
				"func Lend(c syscall.RawConn, cb func(int)) error { return c.Control(func(fd uintptr) { cb(int(fd)) }) }\n\n" +
				"func Save(n int) { kept = uintptr(n) }\n",
			"internal/zzfdcheck/across/b/b.go": "package b\n\nimport (\n\t\"syscall\"\n\n\t\"github.com/attention-span-ai/tego/" + a + "\"\n)\n\nvar held int\n\n" +
				"func f(c syscall.RawConn) {\n" +
				"\t_ = c.Read(a.Keep)\n" + // line 12: keeps
				"\t_ = c.Read(a.Use)\n" + // borrows
				"\t_ = a.Lend(c, func(n int) { held = n })\n" + // line 14: a derived lender's callback keeps
				"\t_ = a.Lend(c, func(n int) { a.Save(n) })\n" + // line 15: a helper in another package keeps
				"}\n",
		},
	})
	for set, want := range map[string][]string{"two files": {"lease@5"}, "packages": {"lease@12", "lease@14", "lease@15"}, "interface": {"lease@7"}} {
		if g := kindsOf(got[set]); !reflect.DeepEqual(g, want) {
			t.Errorf("%s: findings %v, want %v (%v)", set, g, want, got[set])
		}
	}
}

// TestForbiddenConstantAcrossPackages: a forbidden constant declared once in one package (an unmigrated one, say)
// and used by another package's raw Syscall or FcntlInt is a site at each use, so the using package's count
// rises with each call.
func TestForbiddenConstantAcrossPackages(t *testing.T) {
	const a = "internal/zzfdcheck/constacross/a"
	got := planted(t, map[string]map[string]string{
		"declaring": {a + "/a.go": "package a\n\nimport \"golang.org/x/sys/unix\"\n\nconst (\n\tCloseTrap = unix.SYS_CLOSE\n\tDupCmd    = unix.F_DUPFD_CLOEXEC\n)\n"},
		"using": {"internal/zzfdcheck/constacross/b/b.go": "package b\n\nimport (\n\t\"golang.org/x/sys/unix\"\n\n\t\"github.com/attention-span-ai/tego/" + a + "\"\n)\n\n" +
			"func Shut(x int) {\n" +
			"\t_, _, _ = unix.Syscall(a.CloseTrap, uintptr(x), 0, 0)\n" + // line 10
			"\t_, _, _ = unix.Syscall(a.CloseTrap, uintptr(x), 0, 0)\n" + // line 11
			"\t_, _ = unix.FcntlInt(uintptr(x), a.DupCmd, 3)\n" + // line 12
			"}\n"},
	})
	for set, want := range map[string][]string{"declaring": {"close@6", "dup@7"}, "using": {"close@10", "close@11", "dup@12"}} {
		if g := kindsOf(got[set]); !reflect.DeepEqual(g, want) {
			t.Errorf("%s: findings %v, want %v (%v)", set, g, want, got[set])
		}
	}
}

// TestPidFDIdentity: SysProcAttr's PidFD is judged by the struct it is a field of, not by the literal's type
// syntax, so every struct identical to SysProcAttr counts: positional literals of SysProcAttr, of a defined type
// of it and of a mirror struct that converts to it, a mirror's field set by assignment, and a SysProcAttr made
// from an unsafe.Pointer. The literals are generated from the toolchain's own field list.
func TestPidFDIdentity(t *testing.T) {
	st := reflect.TypeOf(syscall.SysProcAttr{})
	var fields, zeros, withP []string
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		fields = append(fields, f.Name+" "+f.Type.String())
		zero := "nil"
		switch f.Type.Kind() {
		case reflect.String:
			zero = `""`
		case reflect.Bool:
			zero = "false"
		case reflect.Int, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			zero = "0"
		}
		zeros = append(zeros, zero)
		if f.Name == "PidFD" {
			zero = "p"
		}
		withP = append(withP, zero)
	}
	pos := func(vals []string) string { return strings.Join(vals, ", ") }
	head := "package p\n\nimport (\n\t\"syscall\"\n\t\"unsafe\"\n)\n\nvar _ = unsafe.Pointer(nil)\n\n" +
		"type attrDef syscall.SysProcAttr\n\ntype mine struct {\n\t" + strings.Join(fields, "\n\t") + "\n}\n\n"
	// head ends on line 13 + len(fields) - 1 lines of fields; the bodies follow.
	line := strings.Count(head, "\n") + 1
	cases := []fixture{
		{"positional with a pointer", "func f(p *int) syscall.SysProcAttr { return syscall.SysProcAttr{" + pos(withP) + "} }\n", []string{"producer@" + itoa(line)}},
		{"positional with nil", "func f(p *int) syscall.SysProcAttr { _ = p; return syscall.SysProcAttr{" + pos(zeros) + "} }\n", nil},
		{"a defined type, positional", "func f(p *int) syscall.SysProcAttr { return syscall.SysProcAttr(attrDef{" + pos(withP) + "}) }\n", []string{"producer@" + itoa(line)}},
		{"a mirror struct, keyed", "func f(p *int) syscall.SysProcAttr { return syscall.SysProcAttr(mine{PidFD: p}) }\n", []string{"producer@" + itoa(line)}},
		{"a mirror struct, assigned", "func f(p *int) syscall.SysProcAttr { var m mine; m.PidFD = p; return syscall.SysProcAttr(m) }\n", []string{"producer@" + itoa(line)}},
		{"from unsafe memory", "func f(b *[512]byte) *syscall.SysProcAttr { return (*syscall.SysProcAttr)(unsafe.Pointer(b)) }\n", []string{"producer@" + itoa(line)}},
		{"another struct's PidFD", "type c struct{ PidFD *int }\n\nfunc f(p *int) c { return c{PidFD: p} }\n", nil},
	}
	sets := map[string]map[string]string{}
	for i, tc := range cases {
		sets[tc.name] = map[string]string{fmt.Sprintf("internal/zzfdcheck/pidfd%02d/x.go", i): head + tc.body}
	}
	got := planted(t, sets)
	for _, tc := range cases {
		want := append([]string{}, tc.want...)
		if g := kindsOf(got[tc.name]); !reflect.DeepEqual(g, want) && !(len(g) == 0 && len(want) == 0) {
			t.Errorf("%s: findings %v, want %v", tc.name, g, want)
		}
	}
}

// TestFdcheckImportForms is F1 under an aliased and a dot import, a ForTest accessor in a tegotesthooks file
// (admitted) against one in an ordinary file (refused), and sys's own names in a sys file that is not the owner's.
func TestFdcheckImportForms(t *testing.T) {
	got := planted(t, map[string]map[string]string{
		"alias": {"internal/zzfdcheck/imports/a/a.go": "package p\n\nimport u \"golang.org/x/sys/unix\"\n\nfunc f(fd int) { _ = u.Close(fd) }\n"},
		"dot":   {"internal/zzfdcheck/imports/d/d.go": "package p\n\nimport . \"golang.org/x/sys/unix\"\n\nfunc f(fd int) { _ = Close(fd); _, _ = Dup(fd) }\n"},
		"hooks": {"internal/zzfdcheck/imports/h/h_testhook.go": "//go:build tegotesthooks\n\npackage p\n\nimport \"github.com/attention-span-ai/tego/internal/platform/sys\"\n\nfunc f() { _ = sys.LeakedForTest() }\n"},
		"sys":   {"internal/platform/sys/zz_fdcheck_own.go": "package sys\n\nfunc zzA() { _, _ = Own(PidfdOpenProcess(1)) }\n\nfunc zzB() { _, _ = PidfdOpenProcess(1) }\n"},
	})
	for set, want := range map[string][]string{"alias": {"close@5"}, "dot": {"close@5", "dup@5"}, "hooks": {}, "sys": {"producer@5"}} {
		if g := kindsOf(got[set]); !reflect.DeepEqual(g, want) {
			t.Errorf("%s: %v, want %v", set, g, want)
		}
	}
}

// TestFdcheckMethodValues is F5's method values and method expressions of Fd and FD: each is counted whatever
// the receiver is (a parameter, an opened file, a call's result, a package-level variable or type in another
// file, an embedded *os.File, a named or literal interface, a cilium object); a field named Fd or FD is not.
func TestFdcheckMethodValues(t *testing.T) {
	runFixtures(t, "mv", []fixture{
		{"method value", "func f(o *os.File) func() uintptr { return o.Fd }\n", []string{"fd@14"}},
		{"method value assigned", "func f(o *os.File) { g := o.Fd; _ = g }\n", []string{"fd@14"}},
		{"method value of an opened file", "func f() { o, _ := os.Open(\"x\"); g := o.Fd; _ = g }\n", []string{"fd@14"}},
		{"method value of a call's result", "func f(h func() *os.File) { g := h().Fd; _ = g }\n", []string{"fd@14"}},
		{"method value of a package variable", "var g = os.Stdin.Fd\n", []string{"fd@14"}},
		{"method expression", "var g = (*os.File).Fd\n", []string{"fd@14"}},
		{"promoted", "type w struct{ *os.File }\n\nfunc f(x w) { g := x.Fd; _ = g }\n", []string{"fd@16"}},
		{"promoted through a pointer", "type w struct{ *os.File }\n\nfunc f(x *w) { g := (*x).Fd; _ = g }\n", []string{"fd@16"}},
		{"promoted method expression", "type w struct{ *os.File }\n\nvar g = w.Fd\n", []string{"fd@16"}},
		{"interface literal", "func f(x interface{ Fd() uintptr }) { g := x.Fd; _ = g }\n", []string{"fd@14"}},
		{"interface literal method expression", "var g = interface{ Fd() uintptr }.Fd\n", []string{"fd@14"}},
		{"named interface", "type fder interface{ Fd() uintptr }\n\nfunc f(x fder) { g := x.Fd; _ = g }\n", []string{"fd@16"}},
		{"named interface method expression", "type fder interface{ Fd() uintptr }\n\nvar g = fder.Fd\n", []string{"fd@16"}},
		{"a type's own Fd method", "type t struct{}\n\nfunc (t) Fd() uintptr { return 0 }\n\nfunc f(x t) { g := x.Fd; _ = g }\n", []string{"fd@18"}},
		{"a field of x/sys", "func f(p unix.PollFd) int32 { return p.Fd }\n", nil},
		{"a field assigned", "func f(p *unix.EpollEvent) { p.Fd = 3 }\n", nil},
		{"a local struct's field", "type e struct{ FD int }\n\nfunc f(x e) int { return x.FD }\n", nil},
		{"a field read through a struct", "type e struct{ FD int }\n\ntype s struct{ in e }\n\nfunc f(x s) int { return x.in.FD }\n", nil},
	})
	got := planted(t, map[string]map[string]string{
		"cilium": {"internal/zzfdcheck/mvc/c.go": "package p\n\nimport \"github.com/cilium/ebpf\"\n\nfunc f(p *ebpf.Program) { g := p.FD; _ = g }\n\nvar h = (*ebpf.Map).FD\n"},
		"other file": {
			"internal/zzfdcheck/mvo/a.go": "package p\n\ntype fder interface{ Fd() uintptr }\n\nvar held fder\n",
			"internal/zzfdcheck/mvo/b.go": "package p\n\nfunc f(x fder) { g := x.Fd; _ = g }\n\nvar e = fder.Fd\n\nvar k = held.Fd\n",
		},
	})
	if g := kindsOf(got["cilium"]); !reflect.DeepEqual(g, []string{"fd@5", "fd@7"}) {
		t.Errorf("cilium method values: %v", g)
	}
	if g := kindsOf(got["other file"]); !reflect.DeepEqual(g, []string{"fd@3", "fd@5", "fd@7"}) {
		t.Errorf("a type and a variable declared in another file: %v", g)
	}
}

// TestOwnSyscallOpenat2 is the admitted pair F9 cannot read: a raw SYS_OPENAT2's flags sit behind a pointer, so
// it is refused with a message that says so and names the form F9 reads (sys.Own(unix.Openat2(..., &how))).
func TestOwnSyscallOpenat2(t *testing.T) {
	fs := planted(t, map[string]map[string]string{"x": {"internal/zzfdcheck/openat2/x.go": hdr +
		"func f(d uintptr) { _, _ = sys.OwnSyscall(unix.Syscall6(unix.SYS_OPENAT2, d, 0, 0, 24, 0, 0)) }\n"}})["x"]
	if len(fs) != 1 || fs[0].Kind != kCloexec || !strings.Contains(fs[0].What, "behind a pointer") ||
		!strings.Contains(fs[0].What, "sys.Own(unix.Openat2") {
		t.Errorf("a raw SYS_OPENAT2 under OwnSyscall: %v", fs)
	}
}

// TestFdcheckExemptions is A7: test files, internal/testutil, tools, test, testdata fixtures, the owner's files
// and internal/bpf/fdborrow.go are exempt; a sys file that is not the owner's, a *_testhook.go file and a
// migrated package's file are checked.
func TestFdcheckExemptions(t *testing.T) {
	for _, p := range []string{"internal/x/x_test.go", "internal/testutil/x.go", "tools/x/x.go", "test/x/x.go",
		"scripts/testdata/x/x.go", "internal/platform/sys/fd.go", "internal/platform/sys/inert.go", "internal/bpf/fdborrow.go"} {
		if !Exempt(p) {
			t.Errorf("%s is not exempt", p)
		}
	}
	const src = "import \"golang.org/x/sys/unix\"\n\nfunc zzF(fd int) { _ = unix.Close(fd) }\n"
	got := planted(t, map[string]map[string]string{
		"testutil": {"internal/testutil/zz_fdcheck.go": "package testutil\n\n" + src},
		"sys":      {"internal/platform/sys/zz_fdcheck.go": "package sys\n\n" + src},
		"testhook": {"internal/zzfdcheck/exempt/plane_testhook.go": "package p\n\n" + src},
		"proc":     {"internal/platform/proc/zz_fdcheck.go": "package proc\n\n" + src},
	})
	if g := kindsOf(got["testutil"]); len(g) != 0 {
		t.Errorf("internal/testutil is exempt, have %v", g)
	}
	for _, set := range []string{"sys", "testhook", "proc"} {
		if g := kindsOf(got[set]); !reflect.DeepEqual(g, []string{"close@5"}) {
			t.Errorf("%s is checked, have %v", set, g)
		}
	}
}

// TestCoverage is F6: every in-scope file is type-checked under a configuration that builds it, the arm64 and
// untagged builds, and the cgo, big-endian and macOS builds for the files the main ones do not build (a macOS
// file is judged like a Linux one, ADR 0023's 2026-10-24 note); a file no configuration builds is reported,
// never skipped.
func TestCoverage(t *testing.T) {
	file := func(constraint, fn string) string {
		return constraint + "package p\n\nimport \"golang.org/x/sys/unix\"\n\nfunc " + fn + "(fd int) { _ = unix.Close(fd) }\n"
	}
	files := map[string]string{
		"internal/zzfdcheck/cov/arm64.go":    file("//go:build arm64\n\n", "a"),
		"internal/zzfdcheck/cov/plain.go":    file("//go:build !tegobpf\n\n", "b"),
		"internal/zzfdcheck/cov/cgo.go":      file("//go:build cgo\n\n", "c"),
		"internal/zzfdcheck/cov/s390x.go":    file("//go:build s390x\n\n", "d"),
		"internal/zzfdcheck/cov/never.go":    file("//go:build ignore\n\n", "e"),
		"internal/zzfdcheck/cov/x_darwin.go": file("", "i"),
		"internal/zzfdcheck/cov3/mac.go":     file("//go:build darwin\n\n", "j"), // a package only macOS builds
		"internal/zzfdcheck/cov/x_amd64.go":  file("", "g"),
		"internal/zzfdcheck/cov2/only.go":    file("//go:build ignore\n\n", "h"), // a package no build has
	}
	ov := overlay{}
	var scope []string
	for n, src := range files {
		ov[n] = []byte(src)
		scope = append(scope, n)
	}
	sort.Strings(scope)
	m, err := measureFiles(root, ov, scope, testProducers(t), []string{"./internal/zzfdcheck/cov", "./internal/zzfdcheck/cov2", "./internal/zzfdcheck/cov3"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"internal/zzfdcheck/cov/never.go", "internal/zzfdcheck/cov2/only.go"}; !reflect.DeepEqual(m.uncovered, want) {
		t.Errorf("uncovered %v, want %v", m.uncovered, want)
	}
	found := map[string]int{}
	for _, f := range m.findings {
		if f.Kind == kClose {
			found[f.File]++
		}
	}
	for _, n := range []string{"cov/arm64.go", "cov/plain.go", "cov/cgo.go", "cov/s390x.go", "cov/x_amd64.go", "cov/x_darwin.go", "cov3/mac.go"} {
		if found["internal/zzfdcheck/"+n] != 1 {
			t.Errorf("%s: %d close sites, want 1 (found under the configuration that builds it, once)", n, found["internal/zzfdcheck/"+n])
		}
	}
	if p := uncoveredProblems(m.uncovered); len(p) != 2 || !strings.Contains(p[0], "never.go") || !strings.Contains(p[0], "F6") {
		t.Errorf("the problem for an uncovered file: %v", p)
	}
}

// TestDarwinTermios: the macOS build judges ioctls as the Linux ones do, and admits macOS's termios requests
// (TIOCGETA and TIOCSETA, the maze setup tool's TCGETS and TCSETS), while a request it cannot name stays a finding.
func TestDarwinTermios(t *testing.T) {
	files := map[string]string{
		"internal/zzfdcheck/mac/term_darwin.go": "package mac\n\nimport \"golang.org/x/sys/unix\"\n\n" +
			"func f(fd int) error {\n\tt, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)\n\tif err != nil {\n\t\treturn err\n\t}\n" +
			"\treturn unix.IoctlSetTermios(fd, unix.TIOCSETA, t)\n}\n",
		"internal/zzfdcheck/mac/var_darwin.go": "package mac\n\nimport \"golang.org/x/sys/unix\"\n\n" +
			"func g(fd int, r uint) { _, _ = unix.IoctlGetInt(fd, r) }\n",
	}
	ov := overlay{}
	var scope []string
	for n, src := range files {
		ov[n] = []byte(src)
		scope = append(scope, n)
	}
	sort.Strings(scope)
	m, err := measureFiles(root, ov, scope, testProducers(t), []string{"./internal/zzfdcheck/mac"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.uncovered) != 0 {
		t.Errorf("uncovered %v", m.uncovered)
	}
	got := map[string][]string{}
	for _, f := range m.findings {
		got[f.File] = append(got[f.File], f.Kind)
	}
	if g := got["internal/zzfdcheck/mac/term_darwin.go"]; len(g) != 0 {
		t.Errorf("macOS's termios ioctls: %v, want none", g)
	}
	if g := got["internal/zzfdcheck/mac/var_darwin.go"]; !reflect.DeepEqual(g, []string{kIoctl}) {
		t.Errorf("a variable request under the macOS build: %v, want [%s]", g, kIoctl)
	}
}

// TestDarwinProducers: the macOS build knows macOS's producers. Its x/sys and syscall wrappers (Kqueue) are in
// the generated list, its descriptor traps (kqueue, shm_open, the _nocancel and guarded opens, fileport_makefd)
// are producers, its close variants are A4's close, and a raw trap fdcheck does not classify is a finding there
// (fail closed): the Linux trap list says nothing about another system's syscalls. fcntl_nocancel is judged as
// fcntl, and macOS's fixed-request ioctl wrappers (IoctlCtlInfo) answer no descriptor.
func TestDarwinProducers(t *testing.T) {
	const pre = "package mac\n\nimport (\n\t\"syscall\"\n\n\t\"golang.org/x/sys/unix\"\n)\n\nvar _ = syscall.Getpid\nvar _ = unix.Getpid\n\n"
	cases := map[string]struct {
		body string
		want []string
	}{
		"kq_darwin.go":       {"func f() { _, _ = unix.Kqueue() }\n", []string{kProducer}},
		"skq_darwin.go":      {"func f() { _, _ = syscall.Kqueue() }\n", []string{kProducer}},
		"rawkq_darwin.go":    {"func f() { _, _, _ = unix.Syscall(unix.SYS_KQUEUE, 0, 0, 0) }\n", []string{kProducer}},
		"shm_darwin.go":      {"func f(p uintptr) { _, _, _ = unix.Syscall(unix.SYS_SHM_OPEN, p, 0, 0) }\n", []string{kProducer}},
		"nocancel_darwin.go": {"func f(p uintptr) { _, _, _ = unix.Syscall(unix.SYS_OPEN_NOCANCEL, p, 0, 0) }\n", []string{kProducer}},
		"guarded_darwin.go":  {"func f(p uintptr) { _, _, _ = unix.Syscall6(unix.SYS_GUARDED_OPEN_NP, p, 0, 0, 0, 0, 0) }\n", []string{kProducer}},
		"fileport_darwin.go": {"func f(p uintptr) { _, _, _ = syscall.Syscall(syscall.SYS_FILEPORT_MAKEFD, p, 0, 0) }\n", []string{kProducer}},
		"close_darwin.go":    {"func f(fd uintptr) { _, _, _ = unix.Syscall(unix.SYS_CLOSE_NOCANCEL, fd, 0, 0) }\n", []string{kClose}},
		"other_darwin.go":    {"func f() { _, _, _ = unix.Syscall(unix.SYS_GETPID, 0, 0, 0) }\n", []string{kTrap}},
		"ctl_darwin.go":      {"func f(fd int) error { return unix.IoctlCtlInfo(fd, &unix.CtlInfo{}) }\n", nil},
		"fcntl_darwin.go":    {"func f(fd uintptr) { _, _, _ = unix.Syscall(unix.SYS_FCNTL_NOCANCEL, fd, unix.F_GETFL, 0) }\n", nil},
		"fcntlx_darwin.go":   {"func f(fd, c uintptr) { _, _, _ = unix.Syscall(unix.SYS_FCNTL_NOCANCEL, fd, c, 0) }\n", []string{kFcntl}},
	}
	const dir = "internal/zzfdcheck/macprod/"
	ov := overlay{}
	var scope []string
	for n, c := range cases {
		ov[dir+n] = []byte(pre + strings.Replace(c.body, "func f(", "func "+strings.TrimSuffix(n, "_darwin.go")+"(", 1))
		scope = append(scope, dir+n)
	}
	sort.Strings(scope)
	m, err := measureFiles(root, ov, scope, testProducers(t), []string{"./" + strings.TrimSuffix(dir, "/")})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.uncovered) != 0 {
		t.Errorf("uncovered %v", m.uncovered)
	}
	got := map[string][]string{}
	for _, f := range m.findings {
		n := strings.TrimPrefix(f.File, dir)
		got[n] = append(got[n], f.Kind)
	}
	for n, c := range cases {
		if g := got[n]; !reflect.DeepEqual(g, c.want) {
			t.Errorf("%s: %v, want %v", n, g, c.want)
		}
	}
}

func finding(pkg, file, fn, kind string, line int) Finding {
	return Finding{Pkg: pkg, File: file, Line: line, Func: fn, Kind: kind}
}

// TestRatchet is A9 and F7, with F4's lists: exact counts per package and kind, no site in an unlisted package,
// no stale line, the list and .golangci.yml naming the same packages, and listed sites admitted only up to
// their count.
func TestRatchet(t *testing.T) {
	ledger := func(n int, kind string) []Finding {
		var fs []Finding
		for i := 0; i < n; i++ {
			fs = append(fs, finding("internal/ledger", "internal/ledger/w.go", "f", kind, i+1))
		}
		return fs
	}
	cfg := func(b Baseline) Config {
		sh := map[string]bool{}
		for d := range b {
			sh[d] = true
		}
		return Config{Baseline: b, Shrinking: sh, Sites: map[string]map[[2]string]int{}}
	}
	has := func(ps []string, sub string) bool {
		for _, p := range ps {
			if strings.Contains(p, sub) {
				return true
			}
		}
		return false
	}
	base := Baseline{"internal/ledger": {kClose: 2}}
	if p := Ratchet(cfg(base), ledger(2, kClose)); len(p) != 0 {
		t.Errorf("equal counts: %v", p)
	}
	if p := Ratchet(cfg(base), ledger(3, kClose)); !has(p, "rose from 2 to 3") {
		t.Errorf("a new close in a listed package: %v", p)
	}
	if p := Ratchet(cfg(base), ledger(1, kClose)); !has(p, "fell from 2 to 1") || !has(p, `"internal/ledger close=1"`) {
		t.Errorf("a removed close must lower the line: %v", p)
	}
	if p := Ratchet(cfg(base), append(ledger(2, kClose), ledger(1, kNewFile)...)); !has(p, "newfile sites rose from 0 to 1") {
		t.Errorf("a swap of kinds: %v", p)
	}
	if p := Ratchet(cfg(base), nil); !has(p, "no raw site left") {
		t.Errorf("a listed package at zero: %v", p)
	}
	// A migrated package (not listed) gains a raw close, dup and os.NewFile: each is named, and the package.
	migrated := []Finding{finding("internal/platform/proc", "internal/platform/proc/a.go", "f", kClose, 3),
		finding("internal/platform/proc", "internal/platform/proc/a.go", "f", kDup, 4),
		finding("internal/platform/proc", "internal/platform/proc/a.go", "f", kNewFile, 5)}
	p := Ratchet(cfg(base), append(ledger(2, kClose), migrated...))
	for _, want := range []string{"a.go:3: [close]", "a.go:4: [dup]", "a.go:5: [newfile]", "internal/platform/proc: 3 raw descriptor sites"} {
		if !has(p, want) {
			t.Errorf("a migrated package's new sites: want %q in %v", want, p)
		}
	}
	// .golangci.yml and the baseline disagree, both ways.
	c := cfg(base)
	c.Shrinking = map[string]bool{"internal/doctor": true}
	p = Ratchet(c, ledger(2, kClose))
	if !has(p, "no ADR 0023 exclusion for internal/ledger") || !has(p, "exclusion for internal/doctor names a package") {
		t.Errorf("a list mismatch: %v", p)
	}
	// F4: a listed Abandon is admitted, a second one in the same function is a raw site, and a list entry with
	// no site left is stale.
	c = cfg(base)
	c.Sites = map[string]map[[2]string]int{kAbandon: {{"internal/ledger/w.go", "f"}: 1}, kAdopt: {{"internal/ledger/w.go", "g"}: 1}}
	ab := ledger(1, kAbandon)
	if p := Ratchet(c, append(ledger(2, kClose), ab...)); !has(p, "adopt.txt: internal/ledger/w.go g admits 1 sites, the code has 0") || len(p) != 1 {
		t.Errorf("a listed abandon and a stale adopt entry: %v", p)
	}
	if p := Ratchet(c, append(ledger(2, kClose), ledger(2, kAbandon)...)); !has(p, "abandon sites rose from 0 to 1") {
		t.Errorf("an abandon beyond its list: %v", p)
	}
}

// TestMeasuredBaselineMeetsRatchet: the baseline -baseline prints is one the ratchet passes, including a listed
// kind's site beyond its list (an Abandon that abandon.txt does not admit counts in its package) and none for an
// admitted one.
func TestMeasuredBaselineMeetsRatchet(t *testing.T) {
	sites := map[string]map[[2]string]int{kAbandon: {{"internal/ledger/w.go", "f"}: 1}}
	findings := []Finding{
		finding("internal/ledger", "internal/ledger/w.go", "f", kClose, 1),
		finding("internal/ledger", "internal/ledger/w.go", "f", kAbandon, 2),
		finding("internal/ledger", "internal/ledger/w.go", "f", kAbandon, 3),
		finding("internal/doctor", "internal/doctor/d.go", "g", kAbandon, 4),
	}
	b := MeasuredBaseline(sites, findings)
	want := Baseline{"internal/ledger": {kClose: 1, kAbandon: 1}, "internal/doctor": {kAbandon: 1}}
	if !reflect.DeepEqual(b, want) {
		t.Errorf("measured %v, want %v", b, want)
	}
	sh := map[string]bool{}
	for d := range b {
		sh[d] = true
	}
	if p := Ratchet(Config{Baseline: b, Shrinking: sh, Sites: sites}, findings); len(p) != 0 {
		t.Errorf("the measured baseline fails the ratchet: %v", p)
	}
}

// TestTreeRatchetAndPlantedSites is ADR 0023 C3's acceptance on this checkout, end to end through the files git
// lists, every build configuration and the checked-in baseline.txt, F4 lists and .golangci.yml: the tree as it
// is meets them exactly; a raw close, dup, os.NewFile and sweep planted in a package the baseline does not list
// (internal/platform/proc, never on it) each fail and name their line, as does its use of another package's
// bare-number API (A6's edge); and in a listed package one more close fails as a rise, as do an Fd method value
// and method expression. The planted sites go through Check itself, the gate's whole list of problems.
func TestTreeRatchetAndPlantedSites(t *testing.T) {
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Baseline["internal/platform/proc"] != nil || cfg.Baseline["internal/doctor"] == nil {
		t.Fatalf("the fixture assumes internal/platform/proc unlisted and internal/doctor listed: %v", cfg.Baseline)
	}
	ov := overlay{
		"internal/platform/proc/zz_planted.go": []byte("package proc\n\nimport (\n\t\"os\"\n\n\t\"github.com/attention-span-ai/tego/internal/platform/sys\"\n\t\"golang.org/x/sys/unix\"\n)\n\n" +
			"func planted(fd int) {\n\t_ = unix.Close(fd)\n\t_, _ = unix.Dup(fd)\n\t_ = os.NewFile(uintptr(fd), \"x\")\n\t_ = sys.CloseInheritedFrom(fd)\n\t_ = sys.IsTerminal(0)\n}\n"),
		"internal/doctor/zz_planted.go": []byte("package doctor\n\nimport (\n\t\"os\"\n\n\t\"golang.org/x/sys/unix\"\n)\n\n" +
			"func planted(fd int) { _ = unix.Close(fd) }\n\nfunc plantedFd(f *os.File) (func() uintptr, func(*os.File) uintptr) { return f.Fd, (*os.File).Fd }\n"),
	}
	m, _, err := measure(root, ov)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.uncovered) != 0 {
		t.Errorf("files no configuration builds: %v", m.uncovered)
	}
	var tree []Finding
	for _, f := range m.findings {
		if _, isPlanted := ov[f.File]; !isPlanted {
			tree = append(tree, f)
		}
	}
	if p := Ratchet(cfg, tree); len(p) != 0 {
		t.Fatalf("the tree does not meet its own baseline:\n%s", strings.Join(p, "\n"))
	}
	problems, err := Check(root, "", ov)
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Join(problems, "\n")
	wasClose, wasFd := cfg.Baseline["internal/doctor"][kClose], cfg.Baseline["internal/doctor"][kFd]
	for _, want := range []string{"zz_planted.go:11: [close]", "zz_planted.go:12: [dup]", "zz_planted.go:13: [newfile]",
		"zz_planted.go:14: [sweep]", "internal/platform/proc: 4 raw descriptor sites in a package that has none",
		"internal/doctor: close sites rose from " + itoa(wasClose) + " to " + itoa(wasClose+1),
		"internal/doctor: fd sites rose from " + itoa(wasFd) + " to " + itoa(wasFd+2),
		"A6: internal/platform/proc is migrated (baseline.txt does not list it) but uses internal/platform/sys.IsTerminal",
		"tools/fdcheck/edges.txt is stale"} {
		if !strings.Contains(p, want) {
			t.Errorf("want %q in\n%s", want, p)
		}
	}
}

// TestBaselineFile parses the format, refuses a malformed line, and round-trips.
func TestBaselineFile(t *testing.T) {
	b, err := ParseBaseline([]byte("# c\ninternal/a close=2 fd=1\n\ninternal/b producer=3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Total() != 6 || b["internal/a"][kFd] != 1 {
		t.Errorf("parsed %v", b)
	}
	again, err := ParseBaseline(FormatBaseline(b))
	if err != nil || !reflect.DeepEqual(again, b) {
		t.Errorf("round trip: %v %v", again, err)
	}
	for _, bad := range []string{"internal/a\n", "internal/a close=0\n", "internal/a nosuch=1\n", "internal/a close=1\ninternal/a fd=1\n", "internal/a close=1 close=2\n"} {
		if _, err := ParseBaseline([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, err := ParseSites("adopt.txt", []byte("internal/a/x.go f\n")); err == nil {
		t.Error("a site line without a count parsed")
	}
}

// TestParseShrinking reads the per-package exclusions, ignores the permanent ones and the other ADRs', and
// refuses an alternation, a second linter and a package listed twice, and any other exclusion that would hide an
// ADR 0023 rule from forbidigo: a wider path, no text, or a text that matches an ADR 0023 message.
func TestParseShrinking(t *testing.T) {
	cfg := `version: "2"
run:
  timeout: 5m
  build-tags: [integration, tegobpf, tegotesthooks]
linters:
  enable:
    - errcheck
    - forbidigo
  settings:
    forbidigo:
      analyze-types: true
      forbid:
        - pattern: ^(unix|syscall)\.(Close|CloseRange)$
          msg: "close through the owner, never a bare number (ADR 0023)"
        - pattern: ^proc\.Start$
          msg: "only a reviewed process-start site may start a process (ADR 0021 (6))"
  exclusions:
    generated: disable
    rules:
      - path: _test\.go
        linters: [errcheck, gocritic]
      - path: ` + permanentExclusions[0] + `
        linters: [forbidigo]
        text: ADR 0023
      - path: ` + permanentExclusions[1] + `
        linters: [forbidigo]
        text: ADR 0023
      - path: ^internal/runtime/launch/launcher\.go$
        linters: [forbidigo]
        text: reviewed process-start site
      - path: ^internal/ledger/[^/]+\.go$
        linters: [forbidigo]
        text: ADR 0023
      - path: ^internal/runtime/enforce/cgroup/[^/]+\.go$
        linters: [forbidigo]
        text: "ADR 0023"
      - path: ^internal/doctor/[^/]+\.go$
        linters: [forbidigo]
        text: ADR 0021
formatters:
  enable: [gofmt]
`
	got, err := ParseShrinking([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]bool{"internal/ledger": true, "internal/runtime/enforce/cgroup": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("shrinking %v, want %v", got, want)
	}
	withRule := func(rule string) string { return strings.Replace(cfg, "formatters:", rule+"formatters:", 1) }
	for _, bad := range []string{
		strings.Replace(cfg, `^internal/ledger/[^/]+\.go$`, `^internal/(ledger|cli)/[^/]+\.go$`, 1),
		strings.Replace(cfg, "        linters: [forbidigo]\n        text: ADR 0023\n      - path: ^internal/runtime", "        linters: [forbidigo, errcheck]\n        text: ADR 0023\n      - path: ^internal/runtime", 1),
		strings.Replace(cfg, `^internal/runtime/enforce/cgroup/`, `^internal/ledger/`, 1),
		// Wider than A7's permanent exemptions or one package's own files.
		withRule("      - path: ^internal/\n        linters: [forbidigo]\n        text: ADR 0023\n"),
		strings.Replace(cfg, permanentExclusions[1], `(_test\.go$|^tools/)`, 1),
		strings.Replace(cfg, `|inert)`, `|inert|seccomp)`, 1),
		// No text, or a text that matches an ADR 0023 message, hides the descriptor rules too.
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [forbidigo]\n"),
		withRule("      - path: ^internal/x/y\\.go$\n        text: ADR 0023\n"),
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [forbidigo]\n        text: \"0023\"\n"),
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [forbidigo]\n        text: close through\n"),
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [forbidigo]\n        text: ^use of `syscall\\.Close`\n"),
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [forbidigo]\n        text: \"(\"\n"),
		// YAML's other spellings of a value are read as golangci-lint reads them.
		withRule("      - path: ^internal/\n        linters: [forbidigo]\n        text: 'ADR 0023'\n"),
		withRule("      - path: ^internal/\n        linters: [forbidigo]\n        text: >-\n          ADR 0023\n"),
		withRule("      - path: ^internal/\n        linters: [forbidigo]\n        text: ADR 0023 # wide\n"),
		withRule("      - path: ^internal/\n        linters:\n          - forbidigo\n        text: ADR 0023\n"),
		withRule("      - path: ^internal/\n        linters: ['forbidigo']\n        text: ADR 0023\n"),
		// golangci-lint matches a text case-insensitively.
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [forbidigo]\n        text: adr 0023\n"),
		// A text that could match a report's expression, which fdcheck cannot list: only a literal of another
		// rule's message, with a space, is another ADR's.
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [forbidigo]\n        text: probeGetF\n"),
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [forbidigo]\n        text: ADR 0021|x\n"),
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [forbidigo]\n        text: forbidden because\n"),
		// A narrowing or unknown key on an ADR 0023 rule.
		strings.Replace(cfg, "      - path: ^internal/ledger/[^/]+\\.go$\n", "      - path: ^internal/ledger/[^/]+\\.go$\n        path-except: x\\.go\n", 1),
		strings.Replace(cfg, "      - path: ^internal/ledger/[^/]+\\.go$\n", "      - path: ^internal/ledger/[^/]+\\.go$\n        source: Close\n", 1),
		strings.Replace(cfg, "      - path: ^internal/ledger/[^/]+\\.go$\n", "      - path: ^internal/ledger/[^/]+\\.go$\n        <<: {text: x}\n", 1),
		// The exclusions block's other keys: paths, presets, and generated files left out.
		strings.Replace(cfg, "    generated: disable\n", "    generated: disable\n    paths:\n      - internal/platform/proc/zz\\.go\n", 1),
		strings.Replace(cfg, "    generated: disable\n", "    generated: disable\n    paths-except:\n      - x\\.go\n", 1),
		strings.Replace(cfg, "    generated: disable\n", "    generated: disable\n    presets: [comments]\n", 1),
		strings.Replace(cfg, "    generated: disable\n", "", 1),
		strings.Replace(cfg, "    generated: disable\n", "    generated: lax\n", 1),
		strings.Replace(cfg, "    generated: disable\n", "    generated: strict\n", 1),
		// forbidigo off, or without the types its (*os.File).Fd rule needs.
		strings.Replace(cfg, "    - forbidigo\n", "", 1),
		strings.Replace(cfg, "  enable:\n", "  disable: [forbidigo]\n  enable:\n", 1),
		strings.Replace(cfg, "      analyze-types: true\n", "", 1),
		// The issues block's diff modes hide every report on code outside the diff, and fix rewrites files; an unknown
		// issues key is refused too.
		cfg + "issues:\n  new: true\n",
		cfg + "issues:\n  new-from-rev: HEAD~1\n",
		cfg + "issues:\n  new-from-merge-base: main\n",
		cfg + "issues:\n  new-from-patch: x.patch\n",
		cfg + "issues:\n  whole-files: true\n",
		cfg + "issues:\n  fix: true\n",
		cfg + "issues:\n  max-same-issues: 0\n  exclude-dirs: [internal]\n",
		cfg + "issues: [new]\n",
		// run: an exit code on issues other than golangci-lint's 1 (it does not check the value, and the OS keeps only the
		// low byte, so 256, 512, -256 and 0x100 exit 0 with reports), a
		// build tag of the lint left out, an unknown key.
		strings.Replace(cfg, "  timeout: 5m\n", "  timeout: 5m\n  issues-exit-code: 0\n", 1),
		strings.Replace(cfg, "  timeout: 5m\n", "  timeout: 5m\n  issues-exit-code: 256\n", 1),
		strings.Replace(cfg, "  timeout: 5m\n", "  timeout: 5m\n  issues-exit-code: 512\n", 1),
		strings.Replace(cfg, "  timeout: 5m\n", "  timeout: 5m\n  issues-exit-code: -256\n", 1),
		strings.Replace(cfg, "  timeout: 5m\n", "  timeout: 5m\n  issues-exit-code: 0x100\n", 1),
		strings.Replace(cfg, "  timeout: 5m\n", "  timeout: 5m\n  issues-exit-code: 2\n", 1),
		strings.Replace(cfg, "  timeout: 5m\n", "  timeout: 5m\n  issues-exit-code: \"1\"\n", 1),
		strings.Replace(cfg, "  timeout: 5m\n", "  timeout: 5m\n  issues-exit-code: 1.0\n", 1),
		strings.Replace(cfg, "[integration, tegobpf, tegotesthooks]", "[integration, tegobpf]", 1),
		strings.Replace(cfg, "  build-tags: [integration, tegobpf, tegotesthooks]\n", "", 1),
		strings.Replace(cfg, "  timeout: 5m\n", "  timeout: 5m\n  skip-files: [x]\n", 1),
		// A top-level key golangci-lint 2 does not have.
		cfg + "exclude-rules: x\n",
		// Not YAML.
		"linters: [\n",
	} {
		if _, err := ParseShrinking([]byte(bad)); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
	// Another ADR's exclusion, scoped to its own text, and another linter's, are not ADR 0023's.
	for _, good := range []string{
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [forbidigo]\n        text: ADR 0021\n"),
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [errcheck]\n"),
		withRule("      - path: ^internal/x/y\\.go$\n        linters:\n          - forbidigo\n        text: 'reviewed process-start site' # a comment\n"),
		withRule("      - path: ^internal/x/y\\.go$\n        linters: [errcheck]\n        text: (?i)anything|at+all\n"),
		// Caps on the reports shown leave the run failing on any report.
		cfg + "issues:\n  max-issues-per-linter: 0\n  max-same-issues: 0\n  uniq-by-line: false\n",
		strings.Replace(cfg, "  timeout: 5m\n", "  timeout: 5m\n  issues-exit-code: 1\n  tests: true\n  concurrency: 4\n", 1),
		strings.Replace(cfg, "[integration, tegobpf, tegotesthooks]", "[integration, tegobpf, tegotesthooks, other]", 1),
		cfg + "output:\n  show-stats: true\nseverity:\n  default: error\n",
	} {
		if _, err := ParseShrinking([]byte(good)); err != nil {
			t.Errorf("refused: %v\n%s", err, good)
		}
	}
	// The repository's own file parses, and names exactly the baseline's packages.
	src, err := os.ReadFile(filepath.Join("..", "..", ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := ParseShrinking(src)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := os.ReadFile("baseline.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBaseline(bs)
	if err != nil {
		t.Fatal(err)
	}
	for d := range b {
		if !sh[d] {
			t.Errorf(".golangci.yml has no exclusion for %s", d)
		}
	}
	if len(sh) != len(b) {
		t.Errorf(".golangci.yml has %d exclusions, the baseline %d packages", len(sh), len(b))
	}
}

// TestMoveScope is a site's identity across packages: the declaration it is in names it, a
// site moves only when that declaration leaves the one package and arrives in the other, and init, main and a
// blank `var _`, which any package declares, never move between packages.
func TestMoveScope(t *testing.T) {
	fs := planted(t, map[string]map[string]string{"x": {"internal/zzfdcheck/move/x.go": hdr +
		"var closeHook = func(fd int) error { return unix.Close(fd) }\n\nvar a, b = unix.Close, 1\n\ntype t struct{ f func(int) error }\n\nvar _ = t{f: unix.Close}\n\nfunc init() { var c = unix.Close; _ = c }\n"}})["x"]
	var got []string
	for _, f := range fs {
		got = append(got, f.Func)
	}
	if want := []string{"<package>:closeHook", "<package>:a,b", "<package>:_", "init"}; !reflect.DeepEqual(got, want) {
		t.Errorf("package-level names %q, want %q", got, want)
	}
	site := func(pkg, fn string) Finding {
		return Finding{Pkg: pkg, File: pkg + "/x.go", Line: 1, Func: fn, Kind: kClose, What: "unix.Close"}
	}
	// decls is a declSet of "pkg name" pairs.
	decls := func(pairs ...string) declSet {
		d := declSet{}
		for _, p := range pairs {
			pkg, name, _ := strings.Cut(p, " ")
			if d[pkg] == nil {
				d[pkg] = map[string]bool{}
			}
			d[pkg][name] = true
		}
		return d
	}
	for _, tc := range []struct {
		name               string
		was, cur           []Finding
		wasDecls, curDecls declSet
		fails              bool
	}{
		{"a package-level site moved with its name", []Finding{site("internal/a", "<package>:closeHook")}, []Finding{site("internal/b", "<package>:closeHook")},
			decls("internal/a <package>:closeHook"), decls("internal/b <package>:closeHook"), false},
		{"another package-level name", []Finding{site("internal/a", "<package>:closeHook")}, []Finding{site("internal/b", "<package>:other")},
			decls("internal/a <package>:closeHook"), decls("internal/b <package>:other"), true},
		{"init in another package", []Finding{site("internal/a", "init")}, []Finding{site("internal/b", "init")},
			decls("internal/a init"), decls("internal/b init"), true},
		{"main in another package", []Finding{site("cmd/a", "main")}, []Finding{site("cmd/b", "main")},
			decls("cmd/a main"), decls("cmd/b main"), true},
		{"a blank var in another package", []Finding{site("internal/a", "<package>:_")}, []Finding{site("internal/b", "<package>:_")},
			decls("internal/a <package>:_"), decls("internal/b <package>:_"), true},
		{"two blank vars in another package", []Finding{site("internal/a", "<package>:_,_")}, []Finding{site("internal/b", "<package>:_,_")},
			decls("internal/a <package>:_,_"), decls("internal/b <package>:_,_"), true},
		{"a function moved", []Finding{site("internal/a", "helper")}, []Finding{site("internal/b", "helper")},
			decls("internal/a helper"), decls("internal/b helper"), false},
		{"a function of the same name that stays in both", []Finding{site("internal/a", "helper")}, []Finding{site("internal/b", "helper")},
			decls("internal/a helper", "internal/b helper"), decls("internal/a helper", "internal/b helper"), true},
		{"a function copied, its original kept", []Finding{site("internal/a", "helper")}, []Finding{site("internal/b", "helper")},
			decls("internal/a helper"), decls("internal/a helper", "internal/b helper"), true},
	} {
		if p := moveCheck("BASE", tc.was, tc.cur, tc.wasDecls, tc.curDecls); (len(p) != 0) != tc.fails {
			t.Errorf("%s: problems %q, want failing %v", tc.name, p, tc.fails)
		}
	}
}

// TestGolangciShadow:a .golangci.json, .golangci.toml or .golangci.yaml at the root is what a run without
// --config reads before .golangci.yml, so loadConfig refuses it, tracked or not.
func TestGolangciShadow(t *testing.T) {
	root := t.TempDir()
	if err := golangciShadow(root); err != nil {
		t.Fatalf("an empty root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".golangci.yml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := golangciShadow(root); err != nil {
		t.Fatalf(".golangci.yml alone: %v", err)
	}
	for _, n := range []string{".golangci.json", ".golangci.toml", ".golangci.yaml"} {
		p := filepath.Join(root, n)
		if err := os.Symlink("absent", p); err != nil { // a dangling link shadows as well
			t.Fatal(err)
		}
		if err := golangciShadow(root); err == nil || !strings.Contains(err.Error(), n) {
			t.Errorf("%s: %v, want a refusal naming it", n, err)
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	// loadConfig runs the check: a copy of the checkout's configuration loads, and fails with a shadow.
	cp := func(rel string) {
		src, err := os.ReadFile(filepath.Join("..", "..", rel))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, rel), src, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cp(".golangci.yml")
	cp("tools/fdcheck/baseline.txt")
	for _, name := range listedKinds {
		cp("tools/fdcheck/" + name)
	}
	if _, err := loadConfig(root); err != nil {
		t.Fatalf("the copied configuration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".golangci.json"), []byte(`{"version":"2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(root); err == nil || !strings.Contains(err.Error(), ".golangci.json") {
		t.Errorf("loadConfig with a .golangci.json: %v, want a refusal naming it", err)
	}
}

// TestReach is F11's classification: test code, tools, test harnesses and testdata fixtures in a binary's
// dependencies fail; the module's product packages and other modules' do not.
func TestReach(t *testing.T) {
	deps := []string{"os", "github.com/attention-span-ai/tego/internal/runtime", "github.com/attention-span-ai/tego/internal/testutil",
		"github.com/attention-span-ai/tego/internal/testutil/uring", "github.com/attention-span-ai/tego/tools", "github.com/attention-span-ai/tego/test/perf/cmd/openbench",
		"github.com/attention-span-ai/tego/scripts/testdata/fdlint", "github.com/other/test", "github.com/attention-span-ai/tego/internal/testutilx"}
	got := ReachProblems("linux/arm64 tegobpf", deps)
	if len(got) != 5 {
		t.Fatalf("problems %v, want 5", got)
	}
	for _, p := range got {
		if !strings.Contains(p, "(linux/arm64 tegobpf)") {
			t.Errorf("problem names no build: %s", p)
		}
	}
	if strings.Contains(strings.Join(got, "\n"), "testutilx") || strings.Contains(strings.Join(got, "\n"), "other/test") {
		t.Errorf("a non-exempt package reported: %v", got)
	}
}

// TestReachEveryArchitecture: F11 lists ./cmd/...'s dependencies under every build the project ships, so an
// exempt package that only an arm64 file imports is found, as is one only a cgo file imports, and the host's
// GOARCH, GOFLAGS and CGO_ENABLED change nothing, nor do a GOFLAGS kept in the user's go env file
// (`go env -w`) and the architecture-level and experiment variables, which also set build tags.
// The module is a temporary one with the project's path.
func TestReachEveryArchitecture(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                               "module " + modulePath + "\n\ngo 1.22\n",
		"cmd/x/main.go":                        "package main\n\nimport _ \"" + modulePath + "/internal/p\"\n\nfunc main() {}\n",
		"internal/p/p.go":                      "package p\n",
		"internal/p/zz_arm64.go":               "package p\n\nimport _ \"" + modulePath + "/internal/p/testdata/evil\"\n",
		"internal/p/zz_cgo.go":                 "//go:build cgo\n\npackage p\n\nimport _ \"" + modulePath + "/internal/testutil/cgoonly\"\n",
		"internal/p/testdata/evil/evil.go":     "package evil\n",
		"internal/testutil/cgoonly/cgoonly.go": "package cgoonly\n",
		"internal/p/zz_hide.go":                "//go:build !hide && !amd64.v3 && !arm64.v9.0 && !goexperiment.arenas\n\npackage p\n\nimport _ \"" + modulePath + "/internal/p/testdata/hidden\"\n",
		"internal/p/testdata/hidden/hidden.go": "package hidden\n",
		"xdg/go/env":                           "GOFLAGS=-tags=hide\n",
	}
	for n, src := range files {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOARCH", "amd64")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOENV", "") // the default file, under XDG_CONFIG_HOME
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
	t.Setenv("GOAMD64", "v3")
	t.Setenv("GOARM64", "v9.0")
	t.Setenv("GOEXPERIMENT", "arenas")
	got, err := Reach(dir)
	if err != nil {
		t.Fatal(err)
	}
	evil, cgo, hidden := 0, 0, 0
	for _, p := range got {
		switch {
		case strings.Contains(p, "testdata/hidden"):
			hidden++
		case strings.Contains(p, "testdata/evil") && strings.Contains(p, "(linux/arm64"):
			evil++
		case strings.Contains(p, "testutil/cgoonly") && strings.Contains(p, "(linux/amd64 cgo"):
			cgo++
		default:
			t.Errorf("an unexpected problem: %s", p)
		}
	}
	if evil != len(reachTags) || cgo != len(reachTags) || hidden != len(reachBuilds()) {
		t.Errorf("arm64-only problems %d, cgo-only %d, want %d each; hidden by the host %d, want %d: %v", evil, cgo,
			len(reachTags), hidden, len(reachBuilds()), got)
	}
}

// TestProducerSourcesEnvironment: the producer list's sources are found in the go command's own environment, so
// a user's GOFLAGS (or go.work) cannot change which x/sys is read.
func TestProducerSourcesEnvironment(t *testing.T) {
	t.Setenv("GOFLAGS", "-mod=bogus")
	if _, _, err := producerSources(root); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(t.TempDir(), "goenv")
	if err := os.WriteFile(env, []byte("GOFLAGS=-mod=bogus\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOENV", env)
	if _, _, err := producerSources(root); err != nil {
		t.Errorf("a GOFLAGS in the go env file: %v", err)
	}
}

// TestGenerateProducers is F1's generation on a planted package: an int named fd or nfd is a producer, in a
// file built for linux or darwin; a file of another system (windows) is not read; an unclassifiable fd-like name
// fails generation; the forbidden primitives are never producers.
func TestGenerateProducers(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a_linux.go", "package unix\n\nfunc Open(p string) (fd int, err error) { return }\nfunc Accept4(s int) (nfd int, sa any, err error) { return }\nfunc Dup(o int) (fd int, err error) { return }\nfunc Getpid() (pid int) { return }\n")
	write("b_darwin.go", "package unix\n\nfunc Kqueue() (fd int, err error) { return }\n")
	write("b_windows.go", "package unix\n\nfunc Winsock() (fd int, err error) { return }\n")
	got, declared, err := GenerateProducers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Accept4", "Kqueue", "Open"}; !reflect.DeepEqual(got, want) {
		t.Errorf("producers %v, want %v", got, want)
	}
	if !declared["Getpid"] || !declared["Kqueue"] || declared["Winsock"] {
		t.Errorf("declared %v", declared)
	}
	write("c_linux.go", "package unix\n\nfunc Weird() (efd int, err error) { return }\n")
	if _, _, err := GenerateProducers(dir); err == nil || !strings.Contains(err.Error(), "Weird (efd)") {
		t.Errorf("an unclassifiable producer: %v", err)
	}
}

// TestCheckedInProducers holds the checked-in list to the producers ADR 0023 A10 F1 names.
func TestCheckedInProducers(t *testing.T) {
	p := testProducers(t)
	for _, n := range []string{"Open", "Openat", "Openat2", "OpenByHandleAt", "Socket", "InotifyInit1", "FanotifyInit",
		"EpollCreate1", "Eventfd", "MemfdCreate", "PidfdOpen", "PidfdGetfd", "Fsopen", "Fsmount", "OpenTree", "Fspick",
		"PerfEventOpen", "TimerfdCreate", "Signalfd", "Pipe2", "Socketpair", "Accept4"} {
		if !p.Unix[n] {
			t.Errorf("producers.txt lacks unix.%s", n)
		}
	}
	for n := range forbiddenCall {
		if p.Unix[n] || p.Syscall[n] {
			t.Errorf("forbidden %s is listed as a producer", n)
		}
	}
	if p.Unix["IoUringSetup"] {
		t.Error("IoUringSetup is forbidden, not a producer")
	}
	if !p.Unix["Kqueue"] || !p.Syscall["Kqueue"] {
		t.Error("producers.txt lacks macOS's Kqueue (the list is generated for darwin too)")
	}
}

// TestEdges is A6's generated list: an exported API that passes a bare number, with the packages that use it;
// a method of the same name reached through another type (an interface) is not a use.
func TestEdges(t *testing.T) {
	const dir = "internal/zzfdcheck/edges"
	ov := overlay{
		dir + "/a/a.go":      []byte("package a\n\nfunc Give() (fd int, err error) { return }\n\ntype H struct{}\n\nfunc (H) Lend() (fd int) { return }\n\nfunc Other() int { return 0 }\n"),
		dir + "/b/b.go":      []byte("package b\n\nimport \"github.com/attention-span-ai/tego/" + dir + "/a\"\n\nfunc f(h a.H) { _, _ = a.Give(); _ = h.Lend() }\n"),
		dir + "/c/c.go":      []byte("package c\n\nfunc g(x interface{ Lend() int }) { _ = x.Lend() }\n"),
		dir + "/a/a_test.go": []byte("package a\n\nfunc Test(fd int) {}\n"),
	}
	w, err := typeCheck(root, mainConfigs[0], ov, []string{"./" + dir + "/..."})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range Edges([]*typedWorld{w}) {
		if strings.HasPrefix(e, dir+"/") {
			got = append(got, e)
		}
	}
	if want := []string{dir + "/a Give " + dir + "/b", dir + "/a H.Lend " + dir + "/b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("edges %v, want %v", got, want)
	}
}

// TestEdgeUsers: a package baseline.txt does not list (a migrated one) may not use an edge API, a bare-number
// API of another package, since it would hold or pass back a number no owner holds (A6); a listed
// package may, until it migrates, and an API with no user is no problem.
func TestEdgeUsers(t *testing.T) {
	base := Baseline{"internal/a": {kClose: 1}, "internal/b": {kAPI: 1}}
	edges := []string{"internal/p Give internal/a,internal/b", "internal/p Lend internal/a,internal/m", "internal/p Unused -"}
	got := edgeProblems(edges, base)
	if len(got) != 1 || !strings.Contains(got[0], "internal/m") || !strings.Contains(got[0], "internal/p.Lend") {
		t.Errorf("problems %q, want one naming internal/m and internal/p.Lend", got)
	}
	if p := edgeProblems(edges[:1], base); len(p) != 0 {
		t.Errorf("listed users: %q", p)
	}
}

// TestTotalCheck is A9's total against a base revision: a rise fails, a move of counts between packages does
// not, and a base without the file is no failure. The base is extracted from git and type-checked as a module.
func TestTotalCheck(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	prod := testProducers(t)
	sum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's go.mod names the version the repository's go.sum has the module's own hash for, so a bump of
	// x/sys moves it too; a go.mod-only line is an older version's, which the build does not use.
	var sysSum []string
	var sysVersion string
	for _, line := range strings.Split(string(sum), "\n") {
		if strings.HasPrefix(line, "golang.org/x/sys ") {
			sysSum = append(sysSum, line)
			if f := strings.Fields(line); len(f) == 3 && !strings.HasSuffix(f[1], "/go.mod") {
				sysVersion = f[1]
			}
		}
	}
	if sysVersion == "" {
		t.Fatal("go.sum holds no hash of the golang.org/x/sys module")
	}
	repo := t.TempDir()
	// Run from .githooks/pre-commit, git's GIT_DIR and GIT_INDEX_FILE name the outer repository; the throwaway
	// one must not see them (totalCheck's own `git -C` runs below inherit the cleared values too).
	for _, v := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR"} {
		t.Setenv(v, "")
		_ = os.Unsetenv(v)
	}
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", repo, "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	write := func(name, src string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", name)
	}
	write("README", "x")
	git("commit", "-qm", "no baseline")
	noBase := git("rev-parse", "HEAD")
	// The base's tree is measured, not its baseline.txt: it holds two closes and an Fd() call, as its file says,
	// and an ioctl of a variable request that a rule newer than the file counts.
	const bSrc = "package b\n\nimport (\n\t\"os\"\n\n\t\"golang.org/x/sys/unix\"\n)\n\nfunc f(o *os.File, r uint) { _ = o.Fd(); _, _ = unix.IoctlRetInt(0, r) }\n"
	write("go.mod", "module "+modulePath+"\n\ngo 1.27\n\nrequire golang.org/x/sys "+sysVersion+"\n")
	write("go.sum", strings.Join(sysSum, "\n")+"\n")
	write("tools/fdcheck/baseline.txt", "internal/a close=2\ninternal/b fd=1\n")
	write("internal/a/a.go", "package a\n\nimport \"golang.org/x/sys/unix\"\n\nfunc f(fd int) { _ = unix.Close(fd) }\n\nfunc h(fd int) { _ = unix.Close(fd) }\n")
	write("internal/b/b.go", bSrc)
	write("internal/b/b_test.go", "package b\n\nimport \"golang.org/x/sys/unix\"\n\nfunc g(fd int) { _ = unix.Close(fd) }\n")
	git("commit", "-qm", "baseline")
	withBase := git("rev-parse", "HEAD")
	// A base whose lint names the tagged builds otherwise (before ADR 0060 renamed them) is not measured under this
	// checkout's tags; its total is not held. The file is taken out again so later bases do not carry it.
	write(".golangci.yml", "run:\n  build-tags: [integration, formerbpf, formertesthooks]\n")
	git("commit", "-qm", "the lint's tags under former names")
	retagged := git("rev-parse", "HEAD")
	git("rm", "-q", ".golangci.yml")
	git("commit", "-qm", "the lint file taken out again")

	cfg := func(b Baseline, adopt int) Config {
		b["internal/b"][kIoctl] = 1 // the newer rule's site, counted on both sides
		c := Config{Baseline: b, Sites: map[string]map[[2]string]int{kAdopt: {}}}
		if adopt > 0 {
			c.Sites[kAdopt][[2]string{"internal/a/x.go", "f"}] = adopt
		}
		return c
	}
	// tree is the checkout's raw sites: the repository's files with these standing in or added (the base's
	// internal/b unchanged).
	tree := func(files ...string) measured {
		t.Helper()
		ov := overlay{"internal/b/b.go": []byte(bSrc)}
		names := []string{"internal/a/a.go", "internal/b/b.go"}
		for i := 0; i+1 < len(files); i += 2 {
			ov[files[i]] = []byte(files[i+1])
			names = append(names, files[i])
		}
		m, err := measureFiles(repo, ov, inScope(names), prod, []string{"./..."})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	bases := map[string]baseMeasure{}
	var curTree measured
	check := func(name string, cur Config, base string, want ...string) {
		t.Helper()
		b, ok := bases[base]
		if !ok {
			var err error
			if b, err = measureBase(repo, base, prod); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			bases[base] = b
		}
		p := holdToBase(b, cur, curTree.findings, curTree.decls)
		if len(p) != len(want) {
			t.Errorf("%s: %d problems %q, want %d", name, len(p), p, len(want))
			return
		}
		for i, w := range want {
			if !strings.Contains(p[i], w) {
				t.Errorf("%s: problem %q, want %q in it", name, p[i], w)
			}
		}
	}
	moved := Baseline{"internal/a": {kClose: 1}, "internal/c": {kClose: 1}, "internal/b": {kFd: 1}}
	check("a moved count", cfg(moved, 0), withBase)
	rose := Baseline{"internal/a": {kClose: 3}, "internal/b": {kFd: 1}}
	check("a rise", cfg(rose, 0), withBase, "close sites total 3 across packages, "+withBase+"'s 2")
	// A removed close cannot pay for a new os.NewFile, here or in another package.
	check("a swap of kinds", cfg(Baseline{"internal/a": {kClose: 1, kNewFile: 1}, "internal/b": {kFd: 1}}, 0), withBase,
		"newfile sites total 1 across packages, "+withBase+"'s 0")
	check("a swap across packages", cfg(Baseline{"internal/a": {kClose: 1}, "internal/c": {kDup: 1}, "internal/b": {kFd: 1}}, 0), withBase,
		"dup sites total 1 across packages")
	// A listed site is paid for by raw sites the same change removes, and only so.
	check("a new listed site", cfg(Baseline{"internal/a": {kClose: 2}, "internal/b": {kFd: 1}}, 1), withBase,
		"the F4 lists admit 1 sites, "+withBase+"'s 0")
	check("a listed site a migration pays for", cfg(Baseline{"internal/a": {kClose: 1}, "internal/b": {kFd: 1}}, 1), withBase)
	check("a base without the file", cfg(rose, 1), noBase)
	check("a base whose lint names its tags otherwise", cfg(rose, 1), retagged)
	if b := bases[retagged]; !b.none || !b.retagged {
		t.Errorf("a base with other lint tags: none %v, retagged %v, want both", b.none, b.retagged)
	}
	if _, err := measureBase(repo, "no-such-revision", prod); err == nil {
		t.Error("an unknown revision passed")
	}

	// A package's count rises only by a site moved from another package, with its kind and form and the
	// declaration it is in: a new close in internal/c cannot ride on a close internal/a migrated,
	// nor on one taken out of a function of the same name that stays in internal/a.
	const hOnly = "package a\n\nimport \"golang.org/x/sys/unix\"\n\nfunc h(fd int) { _ = unix.Close(fd) }\n"
	curTree = tree("internal/a/a.go", hOnly,
		"internal/c/c.go", "package c\n\nimport \"golang.org/x/sys/unix\"\n\nfunc f(fd int) { _ = unix.Close(fd) }\n")
	check("a site moved with its function", cfg(moved, 0), withBase)
	curTree = tree("internal/a/a.go", hOnly,
		"internal/c/c.go", "package c\n\nimport \"golang.org/x/sys/unix\"\n\nfunc g(fd int) { _ = unix.Close(fd) }\n")
	check("a new site riding on a migration elsewhere", cfg(moved, 0), withBase,
		"internal/c has 1 close sites, "+withBase+"'s 0")
	curTree = tree("internal/a/a.go", hOnly,
		"internal/c/c.go", "package c\n\nimport \"golang.org/x/sys/unix\"\n\nfunc f(fd int) { _ = unix.Close(fd); _ = unix.Close(fd) }\n")
	check("one site moved and one new", cfg(Baseline{"internal/a": {kClose: 1}, "internal/c": {kClose: 2}, "internal/b": {kFd: 1}}, 0), withBase,
		"close sites total 3 across packages", "internal/c has 2 close sites, "+withBase+"'s 0")
	// A site of another form in the moved function is not the moved one.
	curTree = tree("internal/a/a.go", hOnly,
		"internal/c/c.go", "package c\n\nimport \"golang.org/x/sys/unix\"\n\nfunc f(fd int) { _ = unix.CloseRange(uint(fd), 9, 0) }\n")
	check("another form under the moved function's name", cfg(moved, 0), withBase,
		"internal/c has 1 close sites, "+withBase+"'s 0")
	// The close leaves internal/a's f, but f stays there: the close in internal/c's f is a new one.
	curTree = tree("internal/a/a.go", hOnly+"\nfunc f(fd int) {}\n",
		"internal/c/c.go", "package c\n\nimport \"golang.org/x/sys/unix\"\n\nfunc f(fd int) { _ = unix.Close(fd) }\n")
	check("a site under a same-named function that stays", cfg(moved, 0), withBase,
		"internal/c has 1 close sites, "+withBase+"'s 0")
	curTree = measured{}

	// measure judges the files git lists that are on disk: a tracked file deleted from the working tree is not
	// "uncovered", and an ignored file's sites are not counted (its package is still type-checked with it).
	prodSrc, err := os.ReadFile(filepath.Join(root, "tools", "fdcheck", "producers.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "tools", "fdcheck", "producers.txt"), prodSrc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("ignored.go\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "internal", "b", "ignored.go"), []byte("package b\n\nimport \"golang.org/x/sys/unix\"\n\nfunc ig(fd int) { _ = unix.Close(fd) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(repo, "internal", "a", "a.go")); err != nil {
		t.Fatal(err)
	}
	m, _, err := measure(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.uncovered) != 0 {
		t.Errorf("a deleted file is uncovered: %v", m.uncovered)
	}
	for _, f := range m.findings {
		if f.File != "internal/b/b.go" {
			t.Errorf("a finding outside the listed files on disk: %v", f)
		}
	}
}

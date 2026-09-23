// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The integration suite re-executes the test binary as a helper (§10): the parent runs Prepare,
// hands the ruleset fd over as fd 3 and reads a JSON report back. Runs unprivileged
// (Landlock, no_new_privs) with CGO_ENABLED=0 so syscall.AllThreadsSyscall works.
const (
	helperEnv   = "TEGO_LANDLOCK_HELPER"
	helperRoot  = "TEGO_LANDLOCK_ROOT"
	helperPort  = "TEGO_LANDLOCK_PORT"
	helperFull  = "TEGO_LANDLOCK_FULL"
	rulesetFD   = 3
	helperLimit = 30 * time.Second
)

// check is one helper result.
type check struct {
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
	Out string `json:"out,omitempty"`
}

type report struct {
	Skip     string           `json:"skip,omitempty"`
	Checks   map[string]check `json:"checks"`
	Notified map[string]int   `json:"notified,omitempty"`
}

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "landlock":
		os.Exit(emit(landlockHelper()))
	case "restrict":
		os.Exit(emit(restrictHelper()))
	case "seccomp":
		os.Exit(emit(seccompHelper()))
	case "net":
		os.Exit(emit(netHelper()))
	case "snapshot":
		os.Exit(emit(snapshotHelper()))
	}
	// The same leak gate as the unit build's TestMain (leakcheck_test.go).
	os.Exit(testutil.LeakCheckMain(m))
}

func emit(r report) int {
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		return 3
	}
	return 0
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func record(r *report, name string, err error, out string) {
	r.Checks[name] = check{OK: err == nil, Err: errStr(err), Out: out}
}

// runHelper spawns the helper mode with fd 3 = rulesetFD (when >= 0) and decodes its report.
//
// fd belongs to the Handle, which closes it in Close. The child gets a dup instead, owned by a File that
// is closed here once the helper has exited, as the launcher hands over its own (launch.newHandshake).
// A File built on fd itself closed the number a second time from its finalizer, at whatever moment the
// GC chose, once inside a later test's Prepare, on a number the builder then held.
func runHelper(t *testing.T, mode string, fd int, env ...string) report {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), helperLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), append(env, helperEnv+"="+mode)...)
	if fd >= 0 {
		dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("dup ruleset fd %d: %v", fd, err)
		}
		ruleset := os.NewFile(uintptr(dup), "ruleset")
		defer func() { _ = ruleset.Close() }()
		cmd.ExtraFiles = []*os.File{ruleset}
	}
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper %s: %v\n%s", mode, err, out)
	}
	var r report
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("helper %s output %q: %v", mode, out, err)
	}
	if r.Skip != "" {
		t.Skip(r.Skip)
	}
	return r
}

// applyAllThreads sets no_new_privs and installs the ruleset on every thread of the helper, the
// way the child stage does on its single locked thread before execve.
func applyAllThreads(fd int) error {
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", errno)
	}
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

// integrationTable is the contract every landlock helper runs under: two write dirs, one secret that
// also carries a second, more specific deny_read entry inside it (E29), a watched deny_read file with a
// hardlink beside it (E32), python3 and bwrap granted, net either empty (every connect refused) or one
// declared port.
func integrationTable(t *testing.T, root string, ports ...int) *agent.RuleTable {
	t.Helper()
	mkTree(t, root, "allowed/a", "allowed/c", "allowed2/", "secret/key", "secret/other.txt", "secret/inner/deep.key", "public/note", "other/", "watched.key")
	if err := os.Link(filepath.Join(root, "watched.key"), filepath.Join(root, "watched.alias")); err != nil {
		t.Fatalf("hardlink: %v", err)
	}
	c := &agent.Contract{Exec: &agent.ExecSection{}, Net: &agent.NetSection{}}
	rt := &agent.RuleTable{
		Contract: c,
		Record:   agent.RecordSummary,
		FS: []agent.FSRule{
			fsRule(agent.FSWrite, filepath.Join(root, "allowed")),
			fsRule(agent.FSWrite, filepath.Join(root, "allowed2")),
			fsRule(agent.FSDenyRead, filepath.Join(root, "secret")),
			// E29: a target nested inside another. Enumerating it would walk the levels inside
			// root/secret and grant its other children the read set, which is what the two
			// read_secret_* checks below measure on the real kernel.
			fsRule(agent.FSDenyRead, filepath.Join(root, "secret", "inner", "deep.key")),
			// E32: fs.watch holds the target's inode first, with no rights, under its own kind; the
			// hardlink beside it is enumerated as a sibling of root. Unless the watch entry is sealed
			// as the target, that sibling grant lands on the secret's inode and both names read.
			fsRule(agent.FSWatch, filepath.Join(root, "watched.key")),
			fsRule(agent.FSDenyRead, filepath.Join(root, "watched.key")),
			fsRule(agent.FSImplicit, "/sys/fs/cgroup"),
		},
	}
	for _, bin := range []string{"/usr/bin/python3", "/usr/bin/bwrap"} {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		r := execRule(bin, agent.ExecSourceAllow)
		r.Interp, _ = agent.ReadInterp(bin)
		rt.Exec = append(rt.Exec, r)
	}
	for _, p := range ports {
		rt.Net = append(rt.Net, agent.NetRule{Raw: fmt.Sprintf("127.0.0.1:%d", p), Host: "127.0.0.1", Port: p, Proto: agent.ProtoInet, Static: true})
	}
	return rt
}

func realPrepare(t *testing.T, rt *agent.RuleTable) *Handle {
	t.Helper()
	abi, err := ProbeABI()
	if err != nil {
		t.Skipf("no Landlock: %v", err)
	}
	if abi < 2 {
		t.Skipf("ABI %d is below the tested floor", abi)
	}
	h, err := New(Options{ABI: abi}).Prepare(context.Background(), rt, Run{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// TestIntegrationLandlock applies a real ruleset in a helper and checks write, deny_read, listing,
// exec via the loader, REFER renames, unlisted exec, mount refusal and TCP with net.allow empty, at
// whatever ABI this kernel has.
//
// Spec: docs/p0/enforce-landlock.md E10 (a file created after restrict_self is unreadable).
func TestIntegrationLandlock(t *testing.T) {
	root := tempDir(t)
	h := realPrepare(t, integrationTable(t, root))
	fd, _ := h.LandlockRuleset()
	// E10: a file created at an enumerated level after Prepare has no rule, and its level (root, an
	// ancestor of the secret) grants READ_DIR only, so it is unreadable: more restrictive than intended.
	mkTree(t, root, "late.txt")
	r := runHelper(t, "landlock", fd, helperRoot+"="+root)
	want := map[string]struct {
		ok  bool
		err string
	}{
		"write_outside": {false, "permission denied"},
		"write_inside":  {true, ""},
		"read_secret":   {false, "permission denied"},
		// E29 on the real kernel: the second, more specific deny_read entry must not make the broader
		// one weaker. Landlock rules only ever add rights, so a sibling grant built inside root/secret
		// would make these two readable whatever root/secret itself carries.
		"read_secret_sibling": {false, "permission denied"},
		"read_secret_nested":  {false, "permission denied"},
		"read_sibling":        {true, ""},
		"read_created_late":   {false, "permission denied"},
		"stat_secret":         {true, ""},
		"list_root":           {true, ""},
		"list_secret":         {true, ""}, // READ_DIR on the ancestor is hierarchical: names show, contents do not
		"mkdir_outside":       {false, "permission denied"},
		"unlink_inside":       {true, ""},
		"rename_refer":        {true, ""},
		"rename_out":          {false, "permission denied"}, // the destination has no MAKE_REG; EXDEV only without REFER
		// ADR 0059: a run cannot give a file in a directory no write entry reaches a second name inside one that
		// does (link(2) reparents, and REFER is granted only where a write entry is), so the one name a policy file
		// has when it is loaded stays its only name for the run.
		"link_in":        {false, ""},
		"link_inside":    {true, ""},
		"python":         {true, ""},
		"exec_unlisted":  {false, "permission denied"},
		"connect_denied": {false, "permission denied"},

		// E32 on the real kernel: a rule keyed on the watched target's inode reads it by both names.
		"read_watched":       {false, "permission denied"},
		"read_watched_alias": {false, "permission denied"},
	}
	// Landlock has TCP rules from ABI 4 on (E4). Below that the ruleset handles no net right and this helper installs no
	// seccomp filter, so nothing refuses the connect: it reaches 127.0.0.1:1, where nothing listens, and the answer is
	// the network's. Asking for that exact error shows the domain left it alone; at tier 1 the supervisor decides it.
	if h.abi < 4 {
		w := want["connect_denied"]
		w.err = "connection refused"
		want["connect_denied"] = w
	}
	for name, w := range want {
		c, ok := r.Checks[name]
		if !ok {
			t.Errorf("%s: no result", name)
			continue
		}
		if c.OK != w.ok || (w.err != "" && !strings.Contains(c.Err, w.err)) {
			t.Errorf("%s = %+v, want ok=%v err~%q", name, c, w.ok, w.err)
		}
	}
	if c := r.Checks["python"]; strings.TrimSpace(c.Out) != "42" {
		t.Errorf("python output %q", c.Out)
	}
	if c := r.Checks["list_root"]; !strings.Contains(c.Out, "secret") {
		t.Errorf("listing lacks the secret's name: %q", c.Out)
	}
	// bwrap is refused before it ever mounts: writing /proc/self/uid_map is a WRITE_FILE the domain
	// refuses (EACCES); a kernel that let it through would refuse the mount itself with EPERM.
	if c, ok := r.Checks["bwrap"]; ok && (c.OK || !(strings.Contains(c.Out, "not permitted") || strings.Contains(c.Out, "Permission denied"))) {
		t.Errorf("bwrap = %+v, want a refusal", c)
	}
}

// TestIntegrationDeclaredPort is R6: a declared TCP port passes the Landlock backstop.
func TestIntegrationDeclaredPort(t *testing.T) {
	root := tempDir(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	h := realPrepare(t, integrationTable(t, root, port))
	if h.abi < 4 {
		t.Skip("no net rules below ABI 4")
	}
	fd, _ := h.LandlockRuleset()
	r := runHelper(t, "landlock", fd, helperRoot+"="+root, fmt.Sprintf("%s=%d", helperPort, port))
	if c := r.Checks["connect_declared"]; !c.OK {
		t.Errorf("connect to the declared port: %+v", c)
	}
	if c := r.Checks["connect_denied"]; c.OK {
		t.Errorf("connect to an undeclared port succeeded: %+v", c)
	}
}

// TestIntegrationRestrictSelf applies a prepared ruleset on the real kernel the way the child stage does
// (no_new_privs by prctl, then landlock_restrict_self on the locked thread, R18) and checks the domain refuses a
// write outside every entry. The child stage's flag handling is sys.RestrictSelf's (TestRestrictSelfFallbackAndNoNewPrivs).
func TestIntegrationRestrictSelf(t *testing.T) {
	root := tempDir(t)
	h := realPrepare(t, integrationTable(t, root))
	fd, _ := h.LandlockRuleset()
	r := runHelper(t, "restrict", fd, helperRoot+"="+root)
	if c := r.Checks["restrict"]; !c.OK {
		t.Fatalf("landlock_restrict_self: %+v", c)
	}
	if c := r.Checks["write_outside"]; c.OK || !strings.Contains(c.Err, "permission denied") {
		t.Errorf("write outside after landlock_restrict_self = %+v", c)
	}
}

// TestIntegrationSeccomp installs the filter in a helper with a mini supervisor: read-opens never
// notify, a write-open notifies once, io_uring_setup and openat2 return ENOSYS, connect is decided
// by the reply, sendto notifies only with an address.
func TestIntegrationSeccomp(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprintf("full=%v", full), func(t *testing.T) {
			r := runHelper(t, "seccomp", -1, fmt.Sprintf("%s=%v", helperFull, full), helperRoot+"="+tempDir(t))
			for name, c := range r.Checks {
				if !c.OK {
					t.Errorf("%s: %+v", name, c)
				}
			}
			wantOpenAt := 1
			if full {
				wantOpenAt = 2
			}
			if got := r.Notified["openat"]; got != wantOpenAt {
				t.Errorf("openat notifications = %d, want %d (%v)", got, wantOpenAt, r.Notified)
			}
			want := []string{"connect", "mkdirat", "sendto"}
			if NativeArch() == ArchX86_64 {
				want = append(want, "rmdir") // a directory deleted with no line otherwise
			}
			for _, name := range want {
				if r.Notified[name] != 1 {
					t.Errorf("%s notifications = %d, want 1 (%v)", name, r.Notified[name], r.Notified)
				}
			}
			for name := range r.Notified {
				switch name {
				case "openat", "connect", "mkdirat", "sendto", "rmdir":
				default:
					t.Errorf("unexpected notification %s (%v)", name, r.Notified)
				}
			}
		})
	}
}

// landlockHelper is the "landlock" mode: apply fd 3 on all threads, then probe the tree.
func landlockHelper() report {
	r := report{Checks: map[string]check{}}
	root := os.Getenv(helperRoot)
	if err := applyAllThreads(rulesetFD); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			r.Skip = "AllThreadsSyscall needs CGO_ENABLED=0"
			return r
		}
		record(&r, "apply", err, "")
		return r
	}
	openErr := func(p string, flags int) error {
		fd, err := unix.Open(p, flags|unix.O_CLOEXEC, 0o644)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}
	record(&r, "write_outside", openErr(filepath.Join(root, "other", "x"), unix.O_WRONLY|unix.O_CREAT), "")
	record(&r, "write_inside", openErr(filepath.Join(root, "allowed", "x"), unix.O_WRONLY|unix.O_CREAT), "")
	record(&r, "read_secret", openErr(filepath.Join(root, "secret", "key"), unix.O_RDONLY), "")
	record(&r, "read_secret_sibling", openErr(filepath.Join(root, "secret", "other.txt"), unix.O_RDONLY), "")
	record(&r, "read_secret_nested", openErr(filepath.Join(root, "secret", "inner", "deep.key"), unix.O_RDONLY), "")
	record(&r, "read_sibling", openErr(filepath.Join(root, "public", "note"), unix.O_RDONLY), "")
	record(&r, "read_created_late", openErr(filepath.Join(root, "late.txt"), unix.O_RDONLY), "")
	record(&r, "read_watched", openErr(filepath.Join(root, "watched.key"), unix.O_RDONLY), "")
	record(&r, "read_watched_alias", openErr(filepath.Join(root, "watched.alias"), unix.O_RDONLY), "")
	var st unix.Stat_t
	record(&r, "stat_secret", unix.Stat(filepath.Join(root, "secret", "key"), &st), "")
	ents, err := os.ReadDir(root)
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	record(&r, "list_root", err, strings.Join(names, ","))
	_, err = os.ReadDir(filepath.Join(root, "secret"))
	record(&r, "list_secret", err, "")
	record(&r, "mkdir_outside", unix.Mkdir(filepath.Join(root, "other", "d"), 0o755), "")
	record(&r, "unlink_inside", unix.Unlink(filepath.Join(root, "allowed", "x")), "")
	record(&r, "rename_refer", os.Rename(filepath.Join(root, "allowed", "a"), filepath.Join(root, "allowed2", "b")), "")
	record(&r, "rename_out", os.Rename(filepath.Join(root, "allowed", "c"), filepath.Join(root, "other", "c")), "")
	record(&r, "link_in", os.Link(filepath.Join(root, "public", "note"), filepath.Join(root, "allowed", "note.alias")), "")
	record(&r, "link_inside", os.Link(filepath.Join(root, "allowed2", "b"), filepath.Join(root, "allowed2", "b.alias")), "")
	out, err := exec.Command("/usr/bin/python3", "-c", "print(42)").Output()
	record(&r, "python", err, string(out))
	_, err = exec.Command("/usr/bin/true").Output()
	record(&r, "exec_unlisted", err, "")
	if _, err := os.Stat("/usr/bin/bwrap"); err == nil {
		out, err := exec.Command("/usr/bin/bwrap", "--ro-bind", "/", "/", "/usr/bin/true").CombinedOutput()
		record(&r, "bwrap", err, string(out))
	}
	record(&r, "connect_denied", tcpConnect("127.0.0.1:1"), "")
	if port := os.Getenv(helperPort); port != "" {
		record(&r, "connect_declared", tcpConnect("127.0.0.1:"+port), "")
	}
	return r
}

func tcpConnect(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		c.Close()
	}
	return err
}

// restrictHelper is the "restrict" mode: the ruleset applied on the locked main thread, then one check.
func restrictHelper() report {
	runtime.LockOSThread()
	r := report{Checks: map[string]check{}}
	root := os.Getenv(helperRoot)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		record(&r, "restrict", err, "prctl")
		return r
	}
	var err error
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), 0, 0); errno != 0 {
		err = errno
	}
	record(&r, "restrict", err, "")
	if err != nil {
		return r
	}
	fd, err := unix.Open(filepath.Join(root, "other", "y"), unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o644)
	if err == nil {
		_ = unix.Close(fd)
	}
	record(&r, "write_outside", err, "")
	return r
}

// seccomp_data, seccomp_notif and seccomp_notif_resp (uapi/linux/seccomp.h), little-endian.
type seccompDataRaw struct {
	Nr   int32
	Arch uint32
	IP   uint64
	Args [6]uint64
}

type seccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Data  seccompDataRaw
}

type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

type seccompNotifSizes struct {
	Notif     uint16
	NotifResp uint16
	Data      uint16
}

// installFilter installs the tier-1 filter on the calling thread with NEW_LISTENER.
func installFilter(full bool) (int, error) {
	raw, err := assembleFilter(NativeArch(), filterOpts{full: full, abi: minTruncateABI})
	if err != nil {
		return -1, err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		filter[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return -1, fmt.Errorf("seccomp(SET_MODE_FILTER, NEW_LISTENER): %w", errno)
	}
	return int(fd), nil
}

// notifyLoop is the mini supervisor: it runs on an unfiltered thread, records every notification
// by name and answers CONTINUE, except connect which it refuses with EACCES.
func notifyLoop(fd int, names map[uint32]string, mu *sync.Mutex, counts map[string]int) {
	for {
		var n seccompNotif
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_RECV, uintptr(unsafe.Pointer(&n)))
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			return
		}
		name, ok := names[uint32(n.Data.Nr)]
		if !ok {
			name = fmt.Sprintf("nr%d", n.Data.Nr)
		}
		mu.Lock()
		counts[name]++
		mu.Unlock()
		resp := seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		if name == "connect" {
			resp = seccompNotifResp{ID: n.ID, Error: -int32(unix.EACCES)}
		}
		unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_SEND, uintptr(unsafe.Pointer(&resp)))
	}
}

// seccompHelper is the "seccomp" mode: install the filter on the locked main thread, serve
// notifications from another thread, run the checks on the filtered thread.
func seccompHelper() report {
	runtime.LockOSThread()
	r := report{Checks: map[string]check{}, Notified: map[string]int{}}
	full := os.Getenv(helperFull) == "true"
	var sizes seccompNotifSizes
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes))); errno != 0 {
		record(&r, "sizes", errno, "")
		return r
	}
	if int(sizes.Notif) != int(unsafe.Sizeof(seccompNotif{})) || int(sizes.NotifResp) != int(unsafe.Sizeof(seccompNotifResp{})) {
		record(&r, "sizes", fmt.Errorf("kernel notif sizes %+v differ from the structs", sizes), "")
		return r
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		record(&r, "prctl", err, "")
		return r
	}
	dir := os.Getenv(helperRoot) // owned and removed by the parent: no cleanup syscalls run under the filter
	tbl, _ := tableFor(NativeArch())
	names := map[uint32]string{tbl.SendTo: "sendto", tbl.OpenAt: "openat"}
	if tbl.Open != noSyscall {
		names[tbl.Open] = "open"
	}
	for _, s := range tbl.Notify {
		names[s.NR] = s.Name
	}
	fd, err := installFilter(full)
	if err != nil {
		record(&r, "install", err, "")
		return r
	}
	var mu sync.Mutex
	go notifyLoop(fd, names, &mu, r.Notified)

	// Every syscall below runs on the filtered thread.
	rfd, err := unix.Open("/etc/hostname", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(rfd)
	}
	record(&r, "read_open", err, "")
	wfd, err := unix.Open(filepath.Join(dir, "w"), unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err == nil {
		_ = unix.Close(wfd)
	}
	record(&r, "write_open", err, "")
	var params [120]byte
	_, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 4, uintptr(unsafe.Pointer(&params[0])), 0)
	record(&r, "io_uring_setup_enosys", expectErrno(errno, unix.ENOSYS), "")
	var how struct{ Flags, Mode, Resolve uint64 }
	how.Flags = unix.O_RDONLY
	p, _ := unix.BytePtrFromString("/etc/hostname")
	_, _, errno = unix.Syscall6(unix.SYS_OPENAT2, uintptr(atFDCWD), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	record(&r, "openat2_enosys", expectErrno(errno, unix.ENOSYS), "")
	// A handle that would decode, if the kernel got that far: ENOSYS must come from the filter first.
	for _, s := range tbl.ENOSYS {
		if s.Name != "open_by_handle_at" {
			continue
		}
		var fh struct {
			Bytes, Type uint32
			Handle      [128]byte
		}
		fh.Bytes = 128
		_, _, errno = unix.Syscall(uintptr(s.NR), uintptr(atFDCWD), uintptr(unsafe.Pointer(&fh)), unix.O_RDONLY)
		record(&r, "open_by_handle_at_enosys", expectErrno(errno, unix.ENOSYS), "")
	}
	record(&r, "mkdir", unix.Mkdirat(unix.AT_FDCWD, filepath.Join(dir, "d"), 0o755), "")
	// x86-64's own rmdir(2), the number glibc's rmdir(3) uses; unix.Rmdir would go through unlinkat.
	// arm64 has no such number, and its table no such entry.
	for _, s := range tbl.Notify {
		if s.Name != "rmdir" {
			continue
		}
		d, _ := unix.BytePtrFromString(filepath.Join(dir, "d"))
		_, _, errno := unix.Syscall(uintptr(s.NR), uintptr(unsafe.Pointer(d)), 0, 0)
		var err error
		if errno != 0 {
			err = errno
		}
		record(&r, "rmdir", err, "")
	}
	sfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = expectErrno(unix.Connect(sfd, &unix.SockaddrInet4{Port: 1, Addr: [4]byte{127, 0, 0, 1}}), unix.EACCES)
		_ = unix.Close(sfd)
	}
	record(&r, "connect_refused_by_reply", err, "")
	ufd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		dst := &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}}
		// No address on an unconnected socket: never notified, the kernel answers EDESTADDRREQ.
		err = expectErrno(unix.Sendto(ufd, []byte("x"), 0, nil), unix.EDESTADDRREQ)
		if err == nil {
			err = unix.Sendto(ufd, []byte("x"), 0, dst) // with address: notified, then CONTINUE
		}
		_ = unix.Close(ufd)
	}
	record(&r, "sendto", err, "")
	mu.Lock()
	defer mu.Unlock()
	return r
}

// atFDCWD is AT_FDCWD as the kernel reads it from a register (a negative int, not a constant that
// overflows uintptr).
var (
	fdcwd   int64 = unix.AT_FDCWD
	atFDCWD       = uintptr(fdcwd)
)

func expectErrno(err error, want unix.Errno) error {
	if errors.Is(err, want) {
		return nil
	}
	return fmt.Errorf("got %v, want %v", err, want)
}

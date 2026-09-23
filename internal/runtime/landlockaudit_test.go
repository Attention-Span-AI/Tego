// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// rulesetHandle is an enforcement handle with, or without, a Landlock ruleset for the child stage to apply.
type rulesetHandle struct{ ruleset bool }

func (h rulesetHandle) LandlockRuleset() (int, bool)              { return 3, h.ruleset }
func (rulesetHandle) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
func (rulesetHandle) Attach(uint64) error                         { return nil }
func (rulesetHandle) Detach() error                               { return nil }
func (rulesetHandle) Close() error                                { return nil }

// TestLandlockAuditOptIn is the launcher half of the landlock.audit opt-in: the machine config's landlock.audit: new-exec makes the
// child stage apply its ruleset with LOG_NEW_EXEC_ON, so the kernel audits the Landlock refusals the agent
// meets after the stage's execve; off, the default, asks for nothing. A kernel whose Landlock ABI has no such
// flag (below 7) still confines the run, since the stage drops what it does not know, and the run says what it
// did not get with gap what=record why=landlock-audit-unavailable, once, after run_start. A kernel whose ABI
// has the flag but whose audit is known to log nothing (built without CONFIG_AUDIT, booted audit=0, or enabled 0)
// accepts the flag and drops every record, and the run says so with why=kernel-audit-off. An audit state the run
// could not read (AUDIT_GET refused it, as it refuses every unprivileged run) says why=kernel-audit-unknown: a
// kernel with audit compiled in and never enabled drops every record too, and without the line such a run would
// read as audited. Only an audit confirmed on says nothing. A run with no Landlock ruleset (an observe run) has
// no Landlock refusal to audit, and asks for nothing and says nothing.
func TestLandlockAuditOptIn(t *testing.T) {
	prevABI, prevAudit := landlockABI, kernelAudit
	t.Cleanup(func() { landlockABI, kernelAudit = prevABI, prevAudit })
	const unavailable, off, unknown = GapLandlockAuditUnavailable, GapKernelAuditOff, GapKernelAuditUnknown
	cases := []struct {
		name    string
		audit   string
		ruleset bool
		abi     int
		abiErr  error
		kernel  auditState
		flags   uint32
		gap     string
	}{
		{"off, the default", config.LandlockAuditOff, true, 7, nil, auditOff, 0, ""},
		{"new-exec on ABI 7", config.LandlockAuditNewExec, true, 7, nil, auditOn, launch.LandlockLogNewExecOn, ""},
		{"new-exec on ABI 11", config.LandlockAuditNewExec, true, 11, nil, auditOn, launch.LandlockLogNewExecOn, ""},
		{"new-exec on ABI 6: confined, not audited, and said", config.LandlockAuditNewExec, true, 6, nil, auditOn, launch.LandlockLogNewExecOn, unavailable},
		{"new-exec with no Landlock ruleset", config.LandlockAuditNewExec, false, 7, nil, auditOff, 0, ""},
		{"new-exec where the ABI cannot be read", config.LandlockAuditNewExec, true, 0, errors.New("ENOSYS"), auditOn, 0, unavailable},
		{"new-exec with the kernel's audit off", config.LandlockAuditNewExec, true, 7, nil, auditOff, launch.LandlockLogNewExecOn, off},
		{"new-exec with the kernel's audit unknown", config.LandlockAuditNewExec, true, 7, nil, auditUnknown, launch.LandlockLogNewExecOn, unknown},
		{"new-exec on ABI 6 with audit unknown: the ABI gap alone", config.LandlockAuditNewExec, true, 6, nil, auditUnknown, launch.LandlockLogNewExecOn, unavailable},
		{"off with the kernel's audit unknown", config.LandlockAuditOff, true, 7, nil, auditUnknown, 0, ""},
		{"new-exec with no Landlock ruleset, audit unknown", config.LandlockAuditNewExec, false, 7, nil, auditUnknown, 0, ""},
		{"new-exec on ABI 6 with audit off: the ABI gap alone", config.LandlockAuditNewExec, true, 6, nil, auditOff, launch.LandlockLogNewExecOn, unavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			landlockABI = func() (int, error) { return tc.abi, tc.abiErr }
			kernelAudit = func() auditState { return tc.kernel }
			m := config.Builtin()
			m.Landlock.Audit.Value = tc.audit
			r := &runner{
				log: slog.New(slog.DiscardHandler), queue: NewQueue(4), handle: rulesetHandle{ruleset: tc.ruleset},
				rt:   &agent.RuleTable{Tier: backend.TierLandlock, Contract: &agent.Contract{Name: "a"}},
				cmd:  []string{"/bin/true"},
				deps: Deps{Config: m, Enforce: &fakeBackend{}, Cwd: "/"},
			}
			spec, err := r.childSpec()
			if err != nil && os.Geteuid() == 0 {
				t.Skipf("childSpec as root needs sudo's identity to drop to: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			if spec.LandlockFlags != tc.flags {
				t.Errorf("ChildSpec.LandlockFlags = %#x, want %#x", spec.LandlockFlags, tc.flags)
			}
			r.emitLandlockAuditGap()
			var gaps []record.GapPayload
			for {
				select {
				case ev := <-r.queue.C():
					var p record.GapPayload
					if err := ev.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
					gaps = append(gaps, p)
					continue
				default:
				}
				break
			}
			switch {
			case tc.gap != "" && (len(gaps) != 1 || gaps[0].What != record.GapRecord || gaps[0].Why != tc.gap):
				t.Errorf("gaps %+v, want one what=record why=%s", gaps, tc.gap)
			case tc.gap == "" && len(gaps) != 0:
				t.Errorf("gaps %+v, want none", gaps)
			}
		})
	}
}

// TestParseAuditReply: the kernel's answer to AUDIT_GET is read for audit_status.enabled and pid, a refusal is an
// error (so the state reads as unknown, never as on), and a datagram with no answer to the request is read past.
func TestParseAuditReply(t *testing.T) {
	msg := func(typ uint16, seq uint32, data []byte) []byte {
		b := make([]byte, unix.NLMSG_HDRLEN+len(data))
		binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
		binary.NativeEndian.PutUint16(b[4:], typ)
		binary.NativeEndian.PutUint32(b[8:], seq)
		copy(b[unix.NLMSG_HDRLEN:], data)
		return b
	}
	status := func(enabled, pid uint32) []byte {
		b := make([]byte, 40) // struct audit_status's first ten u32s
		binary.NativeEndian.PutUint32(b[0:], 0)
		binary.NativeEndian.PutUint32(b[4:], enabled)
		binary.NativeEndian.PutUint32(b[8:], 1) // failure: AUDIT_FAIL_PRINTK
		binary.NativeEndian.PutUint32(b[12:], pid)
		return b
	}
	errno := func(e unix.Errno) []byte {
		b := make([]byte, 4+unix.NLMSG_HDRLEN)
		binary.NativeEndian.PutUint32(b, uint32(-int32(e)))
		return b
	}
	cases := []struct {
		name string
		b    []byte
		st   auditStatus
		done bool
		err  error
	}{
		{"enabled 1", msg(unix.AUDIT_GET, auditGetSeq, status(1, 0)), auditStatus{enabled: 1}, true, nil},
		{"enabled 0", msg(unix.AUDIT_GET, auditGetSeq, status(0, 0)), auditStatus{}, true, nil},
		{"enabled 2, locked", msg(unix.AUDIT_GET, auditGetSeq, status(2, 0)), auditStatus{enabled: 2}, true, nil},
		{"enabled 1, a daemon registered", msg(unix.AUDIT_GET, auditGetSeq, status(1, 812)), auditStatus{enabled: 1, pid: 812}, true, nil},
		{"no CAP_AUDIT_CONTROL", msg(unix.NLMSG_ERROR, auditGetSeq, errno(unix.EPERM)), auditStatus{}, true, unix.EPERM},
		{"outside the initial user namespace", msg(unix.NLMSG_ERROR, auditGetSeq, errno(unix.ECONNREFUSED)), auditStatus{}, true, unix.ECONNREFUSED},
		{"an ack, then nothing yet", msg(unix.NLMSG_ERROR, auditGetSeq, make([]byte, 4+unix.NLMSG_HDRLEN)), auditStatus{}, false, nil},
		{"another request's answer", msg(unix.AUDIT_GET, auditGetSeq+1, status(1, 0)), auditStatus{}, false, nil},
		{"a short status", msg(unix.AUDIT_GET, auditGetSeq, make([]byte, 12)), auditStatus{}, true, errShort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, done, err := parseAuditReply(tc.b)
			if tc.err == errShort {
				if err == nil {
					t.Errorf("no error, want one")
				}
			} else if !errors.Is(err, tc.err) {
				t.Errorf("err %v, want %v", err, tc.err)
			}
			if st != tc.st || done != tc.done {
				t.Errorf("status %+v done %v, want %+v %v", st, done, tc.st, tc.done)
			}
		})
	}
}

// errShort stands for any error in TestParseAuditReply's table.
var errShort = errors.New("any error")

// TestReadKernelAudit reads this kernel's audit state and checks it against what the test itself can know of
// it, which is what the unprivileged probes can know. /proc/self/loginuid absent is a kernel built without
// CONFIG_AUDIT, and off. audit=0 (or audit=off) on the command line is off for every caller, root or not, in any
// namespace, since the kernel then registers no audit netlink socket. Past those, AUDIT_GET answers only a caller
// with CAP_AUDIT_CONTROL in the initial user and pid namespaces (kernel/audit.c, audit_netlink_ok), so any other
// caller reads unknown, never on or off: an unprivileged run, and root in a container's namespaces. Such a caller
// (make vm-root-test, whose guest boots with no audit daemon) reads the state the command line set, audit=1 on
// and neither off, unless a daemon may have set it since: an auditd (/run/auditd.pid), any daemon registered to
// receive the records (audit_status.pid: auditbeat, go-audit), or a reader of the records' multicast group
// (journald's audit socket, which turns audit on as it starts), and then the test skips, naming it.
func TestReadKernelAudit(t *testing.T) {
	got := readKernelAudit()
	if _, err := os.Stat("/proc/self/loginuid"); errors.Is(err, fs.ErrNotExist) {
		if got != auditOff {
			t.Fatalf("no /proc/self/loginuid (CONFIG_AUDIT=n), got %v, want off", got)
		}
		return
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	boot := bootAudit(string(cmdline))
	t.Logf("cmdline %q: boot %v, got %v", strings.TrimSpace(string(cmdline)), boot, got)
	if boot == auditOff {
		if got != auditOff {
			t.Fatalf("booted audit=0: got %v, want off", got)
		}
		return
	}
	if !capAuditControl(t) {
		if got != auditUnknown {
			t.Fatalf("without CAP_AUDIT_CONTROL: got %v, want unknown", got)
		}
		return
	}
	if why := notInitialNamespaces(t); why != "" {
		if got != auditUnknown {
			t.Fatalf("%s: got %v, want unknown", why, got)
		}
		return
	}
	if got == auditUnknown {
		t.Fatalf("with CAP_AUDIT_CONTROL in the initial namespaces: got unknown, want on or off")
	}
	if _, err := os.Stat("/run/auditd.pid"); err == nil {
		t.Skip("an auditd runs here and sets its own state")
	}
	if why := auditDaemon(t); why != "" {
		t.Skipf("%s, which may set its own state", why)
	}
	want := auditOff
	if boot == auditOn {
		want = auditOn
	}
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// String names the state in a test's messages.
func (s auditState) String() string {
	switch s {
	case auditOn:
		return "on"
	case auditOff:
		return "off"
	default:
		return "unknown"
	}
}

// bootAudit is the audit state the kernel's command line sets: audit=0 or off is auditOff, audit=1 or on is
// auditOn, and neither is auditUnknown. Of several, the last is the one the kernel keeps (kernel/audit.c,
// audit_enable, called once for each).
func bootAudit(cmdline string) auditState {
	state := auditUnknown
	for _, f := range strings.Fields(cmdline) {
		v, ok := strings.CutPrefix(f, "audit=")
		if !ok {
			continue
		}
		switch strings.ToLower(v) {
		case "0", "off":
			state = auditOff
		case "1", "on":
			state = auditOn
		}
	}
	return state
}

func TestBootAudit(t *testing.T) {
	for cmdline, want := range map[string]auditState{
		"ro quiet":                       auditUnknown,
		"ro audit=0":                     auditOff,
		"ro audit=OFF":                   auditOff,
		"audit=1 audit_backlog_limit=64": auditOn,
		"audit=0 audit=1":                auditOn,
		"audit=on audit=0":               auditOff,
		"loginaudit=0":                   auditUnknown,
	} {
		if got := bootAudit(cmdline); got != want {
			t.Errorf("bootAudit(%q) = %v, want %v", cmdline, got, want)
		}
	}
}

// capAuditControl reports whether this process holds CAP_AUDIT_CONTROL in its effective set, which is what the
// kernel checks of an AUDIT_GET's sender; euid 0 alone is not it (a root with a bounding set that lacks it).
func capAuditControl(t *testing.T) bool {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			eff, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatalf("CapEff %q: %v", v, err)
			}
			return eff&(1<<unix.CAP_AUDIT_CONTROL) != 0
		}
	}
	t.Fatal("no CapEff in /proc/self/status")
	return false
}

// notInitialNamespaces names the namespace AUDIT_GET refuses this process for, or is empty in the initial user
// and pid namespaces. It compares the namespaces' inode numbers with the kernel's fixed ones for the initial
// namespaces (PROC_USER_INIT_INO, PROC_PID_INIT_INO, include/linux/proc_ns.h), not with /proc/1's: under a /proc
// mounted in a new pid namespace (unshare --pid --fork --mount-proc, or a container) /proc/1 is that namespace's
// own init, and so is the NSpid line, which lists the pids from /proc's namespace down.
func notInitialNamespaces(t *testing.T) string {
	t.Helper()
	for _, ns := range []struct{ name, want string }{
		{"user", "user:[4026531837]"}, // PROC_USER_INIT_INO, 0xEFFFFFFD
		{"pid", "pid:[4026531836]"},   // PROC_PID_INIT_INO, 0xEFFFFFFC
	} {
		got, err := os.Readlink("/proc/self/ns/" + ns.name)
		if err != nil {
			t.Fatal(err)
		}
		if got != ns.want {
			return "outside the initial " + ns.name + " namespace (" + got + ")"
		}
	}
	return ""
}

// auditDaemon names a daemon that may have set the audit state since boot, or is empty: one registered with the
// kernel to receive the records (audit_status.pid, what auditd, auditbeat and go-audit register as), or a socket
// bound to the records' multicast group (a NETLINK_AUDIT row of /proc/net/netlink with groups set, journald's).
// The many sockets that only send user messages (pid 1, login, sshd, sudo) bind no group and register nothing.
func auditDaemon(t *testing.T) string {
	t.Helper()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_AUDIT)
	if err != nil {
		t.Fatal(err)
	}
	st, err := auditGet(fd)
	unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	if st.pid != 0 {
		return fmt.Sprintf("an audit daemon (pid %d) is registered", st.pid)
	}
	table, err := os.ReadFile("/proc/net/netlink")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(table), "\n")[1:] {
		// sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != strconv.Itoa(unix.NETLINK_AUDIT) {
			continue
		}
		if groups, err := strconv.ParseUint(f[3], 16, 32); err == nil && groups != 0 {
			return fmt.Sprintf("a reader of the audit multicast group (netlink port %s) is bound", f[2])
		}
	}
	return ""
}

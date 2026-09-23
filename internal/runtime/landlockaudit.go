// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// GapLandlockAuditUnavailable is the gap a run writes, once, right after run_start, when the machine config
// asked for the kernel's audit of the Landlock refusals the agent meets (landlock.audit: new-exec) and this
// kernel's Landlock ABI has no such flag (LOG_NEW_EXEC_ON is ABI 7, Linux 6.15). The run is confined all the
// same (the child stage drops a flag its ABI does not know, launch.LandlockFlags); what it lacks is the
// kernel's own record of those refusals, and without this line the ledger would not say so.
const GapLandlockAuditUnavailable = "landlock-audit-unavailable"

// GapKernelAuditOff is the gap a run writes, once, right after run_start, when the machine config asked for the
// kernel's audit of the agent's Landlock refusals, the kernel's Landlock ABI has the flag, and the kernel's audit
// subsystem is known to log nothing: built without CONFIG_AUDIT, booted with audit=0, or enabled 0 when the run
// started (no audit=1 and no auditd that turned it on, or auditctl -e 0). Landlock counts a refusal and returns
// before logging it when audit is off (security/landlock/audit.c, landlock_log_denial), so the kernel accepts the
// flag and no record reaches any log; without this line the run would read as audited.
const GapKernelAuditOff = "kernel-audit-off"

// GapKernelAuditUnknown is the gap a run writes, once, right after run_start, when the machine config asked for
// the kernel's audit of the agent's Landlock refusals, the kernel's Landlock ABI has the flag, and the run could
// not learn whether the kernel's audit logs anything: a kernel built with CONFIG_AUDIT, not booted audit=0, whose
// AUDIT_GET refused this process (an unprivileged run, a file-capability copy, or a launcher outside the initial
// user and pid namespaces). Such a kernel with no audit=1 and no daemon that turned it on has audit off and drops
// every record, and nothing an unprivileged process can read tells it apart from one that logs, so the run
// records that its audit was asked for and not confirmed rather than reading as audited (enforce-landlock §4).
const GapKernelAuditUnknown = "kernel-audit-unknown"

// auditState is what readKernelAudit learned about the kernel's audit subsystem.
type auditState int

const (
	// auditUnknown: the run could not ask. AUDIT_GET needs CAP_AUDIT_CONTROL, and a caller in the initial user
	// and pid namespaces (kernel/audit.c, audit_netlink_ok), which an unprivileged run and a file-capability copy
	// lack, and so does root in a container's namespaces.
	auditUnknown auditState = iota
	auditOn
	auditOff
)

// kernelAudit reads the audit state for landlockFlags. A variable so tests can describe another kernel;
// production never reassigns it.
var kernelAudit = readKernelAudit

// auditReplyTimeout bounds the wait for the kernel's AUDIT_GET answer, which it gives at once; the bound only
// keeps a launch from hanging on a kernel that never answers, and that case reads as unknown.
const auditReplyTimeout = 500 * time.Millisecond

// readKernelAudit reports auditOff when the kernel is known to log no audit record: /proc/self/loginuid is absent
// (fs/proc/base.c creates it only under CONFIG_AUDIT), a NETLINK_AUDIT socket is refused with EPROTONOSUPPORT
// (audit=0 at boot: audit_init registers no audit netlink socket), or AUDIT_GET answers enabled 0. The first two
// need no privilege. It reports auditOn only when AUDIT_GET answered, and auditUnknown whenever it could not ask.
// It is a snapshot at run start: an operator who runs auditctl -e 0 during the run is not seen.
func readKernelAudit() auditState {
	if _, err := os.Stat("/proc/self/status"); err == nil {
		if _, err := os.Stat("/proc/self/loginuid"); errors.Is(err, fs.ErrNotExist) {
			return auditOff
		}
	}
	sock, err := sys.Own(unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_AUDIT))
	if errors.Is(err, unix.EPROTONOSUPPORT) {
		return auditOff
	}
	if err != nil {
		return auditUnknown
	}
	defer func() { _ = sock.Close() }()
	var st auditStatus
	err = sock.Borrow(func(fd int) error {
		var err error
		st, err = auditGet(fd)
		return err
	})
	switch {
	case err != nil:
		return auditUnknown
	case st.enabled == 0:
		return auditOff
	default:
		return auditOn // 1, or 2 (enabled and locked)
	}
}

// auditGetSeq is the sequence number of the one request auditGet sends on its own socket.
const auditGetSeq = 1

// auditStatus is the part of the kernel's struct audit_status (include/uapi/linux/audit.h) tego reads.
type auditStatus struct {
	// enabled is 0 for off, 1 for on and 2 for on and locked.
	enabled uint32
	// pid is the audit daemon the kernel sends records to (auditd, or another that registered as one), 0 for
	// none. readKernelAudit does not need it; TestReadKernelAudit does, to know when a daemon sets the state.
	pid uint32
}

// auditGet asks the kernel for its audit status.
func auditGet(fd int) (auditStatus, error) {
	tv := unix.NsecToTimeval(auditReplyTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return auditStatus{}, err
	}
	req := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(req[0:], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], unix.AUDIT_GET)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(req[8:], auditGetSeq)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return auditStatus{}, err
	}
	buf := make([]byte, os.Getpagesize())
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return auditStatus{}, err
		}
		st, done, err := parseAuditReply(buf[:n])
		if done || err != nil {
			return st, err
		}
	}
}

// parseAuditReply reads one datagram of the kernel's answer to auditGet's request: the AUDIT_GET reply carrying
// struct audit_status, whose second u32 is enabled and fourth pid, or an NLMSG_ERROR carrying the refusal (EPERM
// without CAP_AUDIT_CONTROL or outside the initial pid namespace, ECONNREFUSED outside the initial user
// namespace). done is false for a datagram that answers nothing of auditGet's, so the caller reads on.
func parseAuditReply(b []byte) (st auditStatus, done bool, err error) {
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return auditStatus{}, true, err
	}
	for _, m := range msgs {
		if m.Header.Seq != auditGetSeq {
			continue
		}
		switch m.Header.Type {
		case unix.NLMSG_ERROR:
			if len(m.Data) < 4 {
				return auditStatus{}, true, fmt.Errorf("audit: short netlink error (%d bytes)", len(m.Data))
			}
			if code := int32(binary.NativeEndian.Uint32(m.Data)); code != 0 {
				return auditStatus{}, true, unix.Errno(-code)
			}
		case unix.AUDIT_GET:
			if len(m.Data) < 16 {
				return auditStatus{}, true, fmt.Errorf("audit: short audit_status (%d bytes)", len(m.Data))
			}
			return auditStatus{
				enabled: binary.NativeEndian.Uint32(m.Data[4:8]),
				pid:     binary.NativeEndian.Uint32(m.Data[12:16]),
			}, true, nil
		}
	}
	return auditStatus{}, false, nil
}

// landlockABI is the kernel's Landlock ABI, the one the child stage reads before landlock_restrict_self. A
// variable so tests can describe another kernel; production never reassigns it.
var landlockABI = sys.LandlockABI

// landlockFlags is ChildSpec.LandlockFlags for this run: LOG_NEW_EXEC_ON when the machine config opted in
// (spec/config/v0 landlock.audit) and the run applies a Landlock ruleset, which every tier but an observe run
// does, and 0 otherwise. Without the flag the kernel audits a Landlock refusal only in the process that called
// landlock_restrict_self, until it execs, so the agent's refusals after the child stage's execve reach no audit
// record (enforce-landlock §4 RestrictSelf). It sets r.landlockAuditGap to the gap emitLandlockAuditGap writes:
// why=landlock-audit-unavailable when this kernel's ABI drops the flag, and otherwise the audit state
// readKernelAudit finds unless it is on, since only a state known to be on gets the records the flag asks for.
// An ABI that cannot be read asks for nothing: the child stage would then pass the flag as asked, and a kernel
// that refuses it would fail the confinement for the sake of a log record.
func (r *runner) landlockFlags() uint32 {
	r.landlockAuditGap = ""
	m := r.deps.Config
	if m == nil || m.Landlock.Audit.Value != config.LandlockAuditNewExec || r.handle == nil {
		return 0
	}
	if _, ok := r.handle.LandlockRuleset(); !ok {
		return 0 // no Landlock domain, so no Landlock refusal to audit
	}
	requested := launch.LandlockLogNewExecOn
	abi, err := landlockABI()
	if err != nil {
		r.landlockAuditGap = GapLandlockAuditUnavailable
		return 0
	}
	if _, dropped := launch.LandlockFlags(requested, abi); dropped&requested != 0 {
		r.landlockAuditGap = GapLandlockAuditUnavailable
		return requested
	}
	switch kernelAudit() {
	case auditOff:
		r.landlockAuditGap = GapKernelAuditOff
	case auditUnknown:
		r.landlockAuditGap = GapKernelAuditUnknown
	}
	return requested
}

// emitLandlockAuditGap writes the gap landlockFlags chose, what=record, so a run that opted into the kernel's
// audit and did not get it, or could not confirm it, says so: why=landlock-audit-unavailable when the ABI dropped
// the flag, why=kernel-audit-off when the kernel's audit is known to log nothing, and why=kernel-audit-unknown
// when the run could not read it (enforce-landlock §4). A run with the audit confirmed on writes nothing.
func (r *runner) emitLandlockAuditGap() {
	if r.landlockAuditGap != "" {
		r.emitGap(source.Gap{What: record.GapRecord, Why: r.landlockAuditGap})
	}
}

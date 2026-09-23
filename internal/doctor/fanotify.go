// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fanotifyProbeTimeout bounds the functional half of D8: the probe blocks its own opener, so a
// kernel that never delivers the permission event must not hang `tego doctor`.
const fanotifyProbeTimeout = 2 * time.Second

// fanotifyMetadataLen is sizeof(struct fanotify_event_metadata) on every architecture: event_len,
// vers, reserved, metadata_len, mask, fd, pid.
const fanotifyMetadataLen = 24

// fanotifyMetadataVersion is FANOTIFY_METADATA_VERSION, the ABI this build decodes.
const fanotifyMetadataVersion = 3

// ErrFanotify is a fanotify probe that could not complete.
var ErrFanotify = errors.New("doctor: fanotify probe failed")

// FanotifyState is what D8 learned.
type FanotifyState struct {
	// ReportFID says whether FAN_CLASS_CONTENT and FAN_REPORT_FID combine on this kernel — the
	// open question docs/p0/enforce-cgroup-observe.md §11 asks a functional probe to settle.
	ReportFID bool `json:"report_fid"`
	// PermissionMarks says whether FAN_OPEN_PERM|FAN_OPEN_EXEC_PERM was accepted on a mark.
	PermissionMarks bool `json:"permission_marks"`
	// Refuses says whether answering a permission event with FAN_DENY refused the probe's own open,
	// the one thing tier 2's listener needs of a reply (docs/p0/enforce-cgroup-observe.md §6 E2).
	Refuses bool `json:"refuses"`
	// DenyErrno says whether a FAN_DENY reply carrying EACCES, from a group of the listener's class
	// (FAN_CLASS_CONTENT), reached the opener as EACCES rather than EPERM. No kernel so far takes it:
	// FAN_DENY_ERRNO arrived in 6.14, accepted only from a FAN_CLASS_PRE_CONTENT group and never with
	// EACCES (fs/notify/fanotify/fanotify_user.c process_access_response). It is probed rather than
	// assumed so the day a kernel does take it is a measured fact; the listener sends the bare
	// FAN_DENY either way (§6 E2).
	DenyErrno bool `json:"deny_errno"`
}

// probeFanotify is D8: fanotify_init(FAN_CLASS_CONTENT|FAN_REPORT_FID), a permission mark on a file
// of its own, and one permission event answered with FAN_DENY, probed directly on the flag
// combination rather than inferred from a version: the release it is handed goes unread, because a
// backporting distribution makes it a guess in both directions. fanotify_init needs CAP_SYS_ADMIN,
// so the whole probe is root-only.
func probeFanotify(root bool, _ Version) (Result, FanotifyState) {
	var state FanotifyState
	if !root {
		return Result{ID: CheckFanotify,
			Detail: "requires root to test (fanotify_init needs CAP_SYS_ADMIN)",
			Fix:    "re-run as root: " + sudoDoctor(), Skipped: true}, state
	}
	fd, fidOK, err := fanotifyInit()
	if err != nil {
		return Result{ID: CheckFanotify, Detail: fmt.Sprintf("fanotify_init: %v (tier cgroup cannot refuse file opens)", err),
			Fix: "boot a kernel built with CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y"}, state
	}
	defer func() { _ = unix.Close(fd) }()
	state.ReportFID = fidOK

	dir, err := makeFanotifyDir()
	if err != nil {
		return Result{ID: CheckFanotify, Detail: fmt.Sprintf("%v: %v", ErrFanotify, err),
			Fix: fanotifyFixtureFix}, state
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// An inode mark on our own temporary file, never FAN_MARK_MOUNT: a mount mark would
	// intercept every open on the whole filesystem for the length of the probe.
	const mask = unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM
	target, err := markProbeTarget(fd, mask, dir)
	if err != nil {
		if errors.Is(err, ErrFanotify) { // the temporary file, not the mark
			return Result{ID: CheckFanotify, Detail: err.Error(),
				Fix: fanotifyFixtureFix}, state
		}
		return Result{ID: CheckFanotify,
			Detail: fmt.Sprintf("fanotify_mark(FAN_OPEN_PERM|FAN_OPEN_EXEC_PERM): %v", err),
			Fix:    "boot a kernel built with CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y"}, state
	}
	state.PermissionMarks = true
	defer func() { _ = unix.FanotifyMark(fd, unix.FAN_MARK_REMOVE, mask, unix.AT_FDCWD, target) }()

	reply, err := fanotifyRefusal(fd, target)
	return fanotifyVerdict(state, reply, err)
}

// fanotifyReply is what D8's one permission event taught it: whether the kernel took the errno
// reply, and what the opener's open(2) returned once it was answered.
type fanotifyReply struct {
	errnoAccepted bool
	openErr       error
}

// fanotifyVerdict is D8's Result from the marks it placed and the reply round trip. It is pure, so
// each answer a kernel could give is reachable without that kernel.
//
// A round trip that did not refuse the open fails D8, and so does one that could not be completed:
// the refusal is what tier 2's listener needs of fanotify, and marks the kernel accepts are worth
// nothing to it if a FAN_DENY does not stop the open. Doctor never claims a capability it could not
// test.
//
// Neither failure's remedy is the kernel configuration. Both are reached only after
// fanotify_init(FAN_CLASS_CONTENT) and the FAN_OPEN_PERM mark succeeded, which is what
// CONFIG_FANOTIFY_ACCESS_PERMISSIONS provides, and derive.go puts D8's fix on the doctor fix line
// whenever tier cgroup is next, so naming that option here would send the operator to rebuild a
// kernel that already has it.
func fanotifyVerdict(state FanotifyState, reply fanotifyReply, err error) (Result, FanotifyState) {
	if errors.Is(err, errRefusedBeforeListener) {
		return Result{ID: CheckFanotify,
			Detail: fmt.Sprintf("permission marks work, FAN_REPORT_FID=%v, but %v, so a FAN_DENY reply could "+
				"not be tested (tier cgroup's listener would not see such an open either)", state.ReportFID, err),
			Fix: fanotifyHostPolicyFix}, state
	}
	if err != nil {
		return Result{ID: CheckFanotify,
			Detail: fmt.Sprintf("permission marks work, FAN_REPORT_FID=%v, but a FAN_DENY reply could not be "+
				"tested: %v (tier cgroup cannot be shown to refuse a file open)", state.ReportFID, err),
			Fix: fanotifyRetryFix}, state
	}
	// EACCES counts only as the answer to a reply that asked for it; EPERM is what a bare FAN_DENY,
	// or an errno the kernel took and then collapsed, gives the opener.
	state.DenyErrno = reply.errnoAccepted && errors.Is(reply.openErr, unix.EACCES)
	state.Refuses = state.DenyErrno || errors.Is(reply.openErr, unix.EPERM)
	if !state.Refuses {
		return Result{ID: CheckFanotify,
			Detail: fmt.Sprintf("permission marks work, but the open a FAN_DENY answered returned %v, not EPERM "+
				"(tier cgroup would not refuse a file open)", reply.openErr),
			Fix: fanotifyNotRefusedFix}, state
	}
	detail := fmt.Sprintf("permission marks work, FAN_DENY refuses the open, FAN_REPORT_FID=%v, FAN_DENY_ERRNO=%v",
		state.ReportFID, state.DenyErrno)
	if !state.DenyErrno {
		detail += " (a refusal reaches the agent as EPERM: no kernel takes EACCES in a reply from the " +
			"listener's FAN_CLASS_CONTENT group; the reason record is still exact)"
	}
	return Result{ID: CheckFanotify, OK: true, Detail: detail}, state
}

// fanotifyRetryFix is D8's remedy for a FAN_DENY round trip that could not be completed on a kernel
// that took the permission mark: the event did not arrive while the opener was still waiting, the
// opener did not return within the probe's timeout, or the answer could not be written. A loaded host
// can cause the first two once. An open that failed before the event arrived is not this: it is the
// host's policy (fanotifyHostPolicyFix), and it fails every run the same way.
const fanotifyRetryFix = "re-run tego doctor; if D8 fails the same way again, report it as a tego bug"

// fanotifyFixtureFix is D8's remedy for a fixture directory or file it could not make: the fixtures live under
// /run/tego (fixtures.go), and $TMPDIR only where that directory cannot be made.
const fanotifyFixtureFix = "make /run/tego writable with space free (D8's and the plane probe's fixtures live there; " +
	"$TMPDIR only where /run/tego cannot be made)"

// fanotifyHostPolicyFix is D8's remedy for an open the kernel refused before this probe's listener
// received a permission event for it: an LSM's file_open hook runs before fsnotify's permission hook, and
// a fanotify group of higher priority is asked before this FAN_CLASS_CONTENT one, so either refuses the
// open with no event reaching D8. That is the host's policy, not a tego bug, and it applies to the
// agent's opens under tier cgroup as much as to this probe's.
const fanotifyHostPolicyFix = "find what refused D8's open of its own temporary file before its fanotify " +
	"listener saw it (an LSM rule on the fixtures directory, /run/tego, or another fanotify listener such as an antivirus or audit " +
	"agent) and exempt tego's files from it, or pin a lower tier in the machine config"

// errRefusedBeforeListener is D8's own open failing while no permission event reached its listener
// (fanotifyHostPolicyFix).
var errRefusedBeforeListener = errors.New("the probe's own open was refused before D8's listener received it")

// fanotifyNotRefusedFix is D8's remedy for an open that this probe's own listener received and
// answered with FAN_DENY and that still did not fail with EPERM. Another fanotify group or an LSM
// cannot cause that: a group of higher priority, or an LSM's file_open hook, that refuses the open
// does so before this listener sees an event at all, which is fanotifyHostPolicyFix's case. What is
// left is a kernel that did not apply the reply, or this probe misreading it.
const fanotifyNotRefusedFix = "boot a current stable kernel (this one did not refuse an open its fanotify " +
	"listener denied); if a current kernel does the same, report it as a tego bug"

// fanotifyInit opens the listener, preferring FAN_CLASS_CONTENT|FAN_REPORT_FID and falling back to
// the class alone when the kernel refuses the combination.
func fanotifyInit() (fd int, reportFID bool, err error) {
	fd, err = unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_REPORT_FID|unix.FAN_CLOEXEC, unix.O_RDONLY|unix.O_CLOEXEC)
	if err == nil {
		return fd, true, nil
	}
	fd, err = unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return -1, false, err
	}
	return fd, false, nil
}

// fanotifyProbeFile is the name, inside D8's own temporary directory, of the single object the
// probe both marks and opens.
const fanotifyProbeFile = "probe"

// markProbeTarget creates D8's probe object and puts the permission mark on that object, returning
// its path. The mark goes on the regular file the probe will open, never on its parent directory:
// fanotify_mark(2) gives a plain FAN_MARK_INODE mark only the object named, and "events for the
// immediate children of marked directories" require FAN_EVENT_ON_CHILD *in the mark mask*. A
// directory mark without it generates nothing for a child open, so the errno probe below waited out
// its whole timeout on every kernel and D8 reported FAN_DENY_ERRNO=false even where the reply works
// (verified against the running kernel by TestFanotifyProbeMarksTheObjectItOpens).
//
// Marking the file is preferred over adding FAN_EVENT_ON_CHILD to the directory's mask: with the
// directory marked for FAN_OPEN_PERM, creating this file would itself raise a permission event
// before any reader exists to answer it, and the probe would block forever in its own creat(2).
// Creating the file before the mark exists is what keeps that impossible.
func markProbeTarget(fd int, mask uint64, dir string) (string, error) {
	target := filepath.Join(dir, fanotifyProbeFile)
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		return "", fmt.Errorf("%w: %w", ErrFanotify, err)
	}
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, target); err != nil {
		return "", err
	}
	return target, nil
}

// fanotifyRefusal opens the marked file from another goroutine and answers the resulting
// permission event with FAN_DENY carrying EACCES, the code a policy refusal would want (what Landlock
// reports). A kernel that will not take the errno from this group refuses the write with EINVAL —
// every kernel so far (FanotifyState.DenyErrno) — and the event is then answered with the bare
// FAN_DENY, the reply tier 2's listener sends. Either way the opener's own error is the answer.
//
// Every path out of this function answers the event it received, so no opener is ever left blocked
// (the invariant docs/p0/enforce-cgroup-observe.md I8 states for the production listener).
func fanotifyRefusal(fd int, target string) (fanotifyReply, error) {
	opened := make(chan openResult, 1)
	go func() {
		f, err := os.Open(target)
		if err == nil {
			_ = f.Close()
		}
		opened <- openResult{err}
	}()

	var reply fanotifyReply
	meta, err := readFanotifyEvent(fd)
	if err != nil {
		return reply, noEvent(err, opened)
	}
	if meta.fd >= 0 {
		defer func() { _ = unix.Close(meta.fd) }()
	}
	resp := make([]byte, 8)
	binary.NativeEndian.PutUint32(resp[0:4], uint32(meta.fd))
	binary.NativeEndian.PutUint32(resp[4:8], uint32(unix.FAN_DENY|(int(unix.EACCES)<<unix.FAN_ERRNO_SHIFT)))
	if _, err := unix.Write(fd, resp); err == nil {
		reply.errnoAccepted = true
	} else {
		binary.NativeEndian.PutUint32(resp[4:8], unix.FAN_DENY)
		if _, werr := unix.Write(fd, resp); werr != nil {
			return reply, fmt.Errorf("%w: answer the permission event: %w", ErrFanotify, werr)
		}
	}
	select {
	case r := <-opened:
		reply.openErr = r.err
		return reply, nil
	case <-time.After(fanotifyProbeTimeout):
		return reply, fmt.Errorf("%w: the opener did not return within %s", ErrFanotify, fanotifyProbeTimeout)
	}
}

// openResult is what the probe's opener goroutine reports: its open(2)'s error, nil when it opened.
type openResult struct{ err error }

// noEvent is fanotifyRefusal's error when no permission event could be read. An opener that has already
// returned with an error was refused before the event reached this listener, by the host's policy
// (fanotifyHostPolicyFix), which a re-run does not change; the error says so and names its errno. An opener
// still blocked, or one whose open succeeded, leaves readErr as it is: an event that did not come in time.
func noEvent(readErr error, opened <-chan openResult) error {
	select {
	case r := <-opened:
		if r.err != nil {
			return fmt.Errorf("%w: %w", errRefusedBeforeListener, r.err)
		}
	default:
	}
	return readErr
}

// fanotifyMetadata is the part of struct fanotify_event_metadata this probe reads.
type fanotifyMetadata struct {
	mask uint64
	fd   int
	pid  int32
}

// readFanotifyEvent waits for one event and decodes its fixed metadata header. A short read, a
// metadata version this build does not know, or a timeout is an error — never a partially decoded
// event answered with a guessed fd.
func readFanotifyEvent(fd int) (fanotifyMetadata, error) {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(pfd, int(fanotifyProbeTimeout/time.Millisecond))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fanotifyMetadata{}, fmt.Errorf("%w: poll: %w", ErrFanotify, err)
		}
		if n == 0 {
			return fanotifyMetadata{}, fmt.Errorf("%w: no permission event within %s", ErrFanotify, fanotifyProbeTimeout)
		}
		break
	}
	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return fanotifyMetadata{}, fmt.Errorf("%w: read: %w", ErrFanotify, err)
	}
	return ParseFanotifyMetadata(buf[:n])
}

// ParseFanotifyMetadata decodes the first struct fanotify_event_metadata of a read. It is pure and
// total over kernel-supplied bytes (FuzzParseFanotifyMetadata, ARCHITECTURE §7).
func ParseFanotifyMetadata(b []byte) (fanotifyMetadata, error) {
	if len(b) < fanotifyMetadataLen {
		return fanotifyMetadata{}, fmt.Errorf("%w: %d bytes, metadata needs %d", ErrFanotify, len(b), fanotifyMetadataLen)
	}
	e := binary.NativeEndian
	eventLen := e.Uint32(b[0:4])
	version := b[4]
	if version != fanotifyMetadataVersion {
		return fanotifyMetadata{}, fmt.Errorf("%w: metadata version %d, this build decodes %d",
			ErrFanotify, version, fanotifyMetadataVersion)
	}
	if eventLen < fanotifyMetadataLen || int(eventLen) > len(b) {
		return fanotifyMetadata{}, fmt.Errorf("%w: event_len %d in a %d byte read", ErrFanotify, eventLen, len(b))
	}
	fd := int(int32(e.Uint32(b[16:20])))
	// The kernel sends either a real descriptor or FAN_NOFD. Anything else means the bytes are not
	// the struct this build thinks they are, and answering a permission event with that number
	// would close or report an unrelated descriptor.
	if fd < 0 && fd != unix.FAN_NOFD {
		return fanotifyMetadata{}, fmt.Errorf("%w: event fd %d is neither a descriptor nor FAN_NOFD", ErrFanotify, fd)
	}
	return fanotifyMetadata{
		mask: e.Uint64(b[8:16]),
		fd:   fd,
		pid:  int32(e.Uint32(b[20:24])),
	}, nil
}

// assert the metadata layout this build decodes matches the kernel's own struct on this platform.
var _ = [1]struct{}{}[unsafe.Sizeof(unix.FanotifyEventMetadata{})-fanotifyMetadataLen]

// makeFanotifyDir makes D8's fixture directory under the shared fixtures root, not $TMPDIR (makeFixtureDir).
func makeFanotifyDir() (string, error) { return makeFixtureDir(fanotifyFixturePrefix) }

// fanotifyFixturePrefix names D8's fixture directory.
const fanotifyFixturePrefix = "tego-doctor-fanotify-"

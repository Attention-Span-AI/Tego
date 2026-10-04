// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// ExecResultAttachUnavailable is the optional syscall-outcome fallback. Only
// these two programs may continue without a perf link; their absence keeps
// every exec's decision with the supervisor (no fast handover), and a failed
// exec's errno unrecorded. Call only for an actual attachment failure, never
// for an object load, pin, or adoption failure.
func ExecResultAttachUnavailable(program string, err error) bool {
	if program != ProgExecResult && program != ProgExecatResult {
		return false
	}
	if errors.Is(err, link.ErrNotSupported) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return true
	}
	if err == nil {
		return false
	}
	// The pinned cilium/ebpf v0.22.0 attachPerfEventLink uses %v rather
	// than %w, losing the syscall errno at BPF_LINK_CREATE. Accept only
	// its exact two permission messages at this attachment boundary; an
	// unrelated wrapper or permission prose must remain a hard failure.
	// Recheck this compatibility contract when upgrading the dependency.
	switch err.Error() {
	case "cannot create bpf perf link: " + unix.EPERM.Error(),
		"cannot create bpf perf link: " + unix.EACCES.Error():
		return true
	default:
		return false
	}
}

// ExecResultTracepointAvailable selects the same optional hooks for doctor and
// the loader. Errors other than absence are left to the actual load/attachment
// to report; an inaccessible tracefs is not evidence that a hook is absent.
func ExecResultTracepointAvailable(event string) bool {
	for _, base := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		_, err := os.Stat(filepath.Join(base, "events", "syscalls", event, "id"))
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

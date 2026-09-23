// SPDX-License-Identifier: Apache-2.0

//go:build integration

package launch

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// TestLandlockAuditFlagReachesTheKernel runs the child stage with LandlockLogNewExecOn and has the agent, a
// process the stage execs after landlock_restrict_self, write where the ruleset refuses. On every kernel the
// write is refused: an audit flag costs the audit at most, never the confinement (sys.RestrictSelf drops
// it below ABI 7). As root on an ABI 7 kernel booted with audit=1 the kernel then writes an
// AUDIT_LANDLOCK_ACCESS record (type 1423) naming the blocking right and the path, and the same refusal
// without the flag writes none, because by default Landlock audits the process that restricted itself only
// until it execs. The record comes from the kernel's own decision, not from the supervisor's prediction.
func TestLandlockAuditFlagReachesTheKernel(t *testing.T) {
	allowed, denied := t.TempDir(), t.TempDir()
	rs := landlockRuleset(t, allowed)
	abi, err := sys.LandlockABI()
	if err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}
	applied, dropped := LandlockFlags(LandlockLogNewExecOn, abi)
	t.Logf("Landlock ABI %d: LOG_NEW_EXEC_ON applied=%#x dropped=%#x", abi, applied, dropped)

	kmsg, audit := openKmsg(t, abi)
	// Each write goes into a directory of its own: a refused creation is recorded against the directory the
	// file would have been made in (blockers=fs.make_reg path="<dir>").
	write := func(name string, flags uint32) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(denied, name), 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(denied, name, "f")
		stderr, err := os.CreateTemp(t.TempDir(), "stderr")
		if err != nil {
			t.Fatal(err)
		}
		defer stderr.Close()
		ctx := context.Background()
		child, err := (&Launcher{}).Start(ctx, ChildSpec{
			Command: []string{"/bin/sh", "-c", "echo hi > \"$1\"", "sh", target}, Dir: "/", Stderr: stderr,
			Env: []string{"PATH=/usr/bin:/bin"}, LandlockFlags: flags,
			Handle: fakeHandle{ruleset: rs, prog: execveFilter(t)},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer child.Close()
		fd, err := child.WaitNotifyFD(ctx)
		if err != nil {
			t.Fatalf("the child stage with flags %#x did not confine itself: %v", flags, err)
		}
		defer fd.Close()
		stop := make(chan struct{})
		seen := serveContinue(fd, stop)
		if err := child.Ack(); err != nil {
			t.Fatal(err)
		}
		r, err := child.Wait(ctx)
		close(stop)
		<-seen
		if err != nil {
			t.Fatal(err)
		}
		if _, statErr := os.Stat(target); r.Status.ExitStatus() == 0 || statErr == nil {
			t.Fatalf("flags %#x: the write outside the ruleset succeeded (exit %d, stat %v)", flags,
				r.Status.ExitStatus(), statErr)
		}
	}

	write("without-flag", 0)
	write("with-flag", LandlockLogNewExecOn)
	if !audit {
		return
	}
	var records []string
	find := func(name string) string {
		for _, line := range records {
			if strings.Contains(line, "type=1423") && strings.Contains(line, `path="`+filepath.Join(denied, name)+`"`) {
				return line
			}
		}
		return ""
	}
	// kauditd prints a record from its own thread, after the syscall has returned.
	for deadline := time.Now().Add(3 * time.Second); ; {
		records = append(records, readKmsg(t, kmsg)...)
		if find("with-flag") != "" || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	line := find("with-flag")
	if line == "" {
		t.Fatalf("no AUDIT_LANDLOCK_ACCESS record for the refused write with LOG_NEW_EXEC_ON; kmsg had:\n%s",
			strings.Join(records, "\n"))
	}
	if !strings.Contains(line, "blockers=fs.") {
		t.Errorf("the record does not name the blocking right: %s", line)
	}
	t.Logf("kernel record: %s", line)
	if other := find("without-flag"); other != "" {
		t.Errorf("the refusal after exec was audited without LOG_NEW_EXEC_ON: %s", other)
	}
}

// openKmsg opens /dev/kmsg positioned at its end when this run can see the kernel's audit records: root (it
// is readable under dmesg_restrict), a Landlock ABI with audit (7), and audit enabled at boot, which is when
// the kernel prints records no auditd collects. Otherwise it reports false and says which is missing.
func openKmsg(t *testing.T, abi int) (*os.File, bool) {
	t.Helper()
	cmdline, _ := os.ReadFile("/proc/cmdline")
	switch {
	case abi < 7:
		t.Logf("Landlock ABI %d has no audit records (ABI 7, Linux 6.15); only the confinement is checked", abi)
		return nil, false
	case os.Geteuid() != 0:
		t.Log("reading /dev/kmsg needs root; only the confinement is checked")
		return nil, false
	case !bytes.Contains(cmdline, []byte("audit=1")):
		t.Log("the kernel was not booted with audit=1, so it prints no audit record; only the confinement is checked")
		return nil, false
	}
	f, err := os.OpenFile("/dev/kmsg", os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open /dev/kmsg: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	if _, err := unix.Seek(int(f.Fd()), 0, unix.SEEK_END); err != nil {
		t.Fatalf("seek /dev/kmsg: %v", err)
	}
	return f, true
}

// readKmsg returns every record written to f since it was opened.
func readKmsg(t *testing.T, f *os.File) []string {
	t.Helper()
	var out []string
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(int(f.Fd()), buf)
		if errors.Is(err, unix.EAGAIN) {
			return out
		}
		if errors.Is(err, unix.EPIPE) {
			continue // records were overwritten while reading; the next read resumes
		}
		if err != nil {
			t.Fatalf("read /dev/kmsg: %v", err)
		}
		out = append(out, strings.TrimSpace(string(buf[:n])))
	}
}

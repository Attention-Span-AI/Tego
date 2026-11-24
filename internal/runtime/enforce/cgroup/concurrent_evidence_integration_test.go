// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// The evidence a round of TestTier2ConcurrentRunsOfOneBuild prints beyond a failed run's ledger. A run that ended
// with an error under load could not be explained from its ledger alone (hosted run 43152191607, Fedora 7.0, BPF
// LSM boot): what the capture source saw is in tego's own log, what the kernel did is in its log, and a read whose
// return never paired leaves a row in the capture scratch maps.

// concurrentRunID is the run id the launcher's closing summary names on stderr.
var concurrentRunID = regexp.MustCompile(`tego run: (r-[0-9a-z-]+) ended`)

// concurrentLogKeep selects a run's own-log lines about capture, its rings and its end.
var concurrentLogKeep = regexp.MustCompile(`(?i)uprobe|capture|ring|lost|unmetered|level=(WARN|ERROR)`)

// concurrentOwnLogLines is the failed run's capture and ring lines from tego's own log in dir (every launcher of the
// round appends to one): which chunk went missing and why, which the ledger's gap counts cannot say. At most the
// last 96 lines of 1 KiB each.
func concurrentOwnLogLines(dir, stderr string) string {
	m := concurrentRunID.FindStringSubmatch(stderr)
	if m == nil {
		return "own log: no run id on stderr\n"
	}
	paths, err := filepath.Glob(filepath.Join(dir, "tego.log*"))
	if err != nil {
		return "own log: " + err.Error() + "\n"
	}
	const maxLines, maxLine = 96, 1 << 10
	var kept []string
	total := 0
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			kept = append(kept, fmt.Sprintf("own log %s: %v", p, err))
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, m[1]) || !concurrentLogKeep.MatchString(line) {
				continue
			}
			total++
			if len(line) > maxLine {
				line = line[:maxLine] + " [cut]"
			}
			kept = append(kept, line)
			if len(kept) > maxLines {
				kept = kept[1:]
			}
		}
	}
	return fmt.Sprintf("own log lines of %s (%d matched, last %d shown):\n%s\n", m[1], total, len(kept),
		strings.Join(kept, "\n"))
}

// sslScratchMaps holds the build's capture scratch maps open across a round, so a failed run's leftover rows can
// still be read after the build's last launcher has unpinned them.
type sslScratchMaps struct {
	reads, current *ebpf.Map
	err            error
}

func openSSLScratchMaps(dir string) *sslScratchMaps {
	m := &sslScratchMaps{}
	var errReads, errCurrent error
	m.reads, errReads = ebpf.LoadPinnedMap(filepath.Join(dir, bpf.MapSSLScratch), nil)
	m.current, errCurrent = ebpf.LoadPinnedMap(filepath.Join(dir, "tego_ssl_current"), nil)
	m.err = errors.Join(errReads, errCurrent)
	return m
}

func (m *sslScratchMaps) close() {
	if m == nil {
		return
	}
	for _, x := range []*ebpf.Map{m.reads, m.current} {
		if x != nil {
			_ = x.Close()
		}
	}
}

// describe counts the rows left in the two scratch maps and lists those of the process whose pid the agent wrote
// to readyFile: a read whose entry row is still there never paired with its return.
func (m *sslScratchMaps) describe(readyFile string) string {
	if m == nil {
		return "ssl scratch: not opened\n"
	}
	var out strings.Builder
	pid := uint32(0)
	if b, err := os.ReadFile(readyFile); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32); err == nil {
			pid = uint32(v)
		}
	}
	fmt.Fprintf(&out, "ssl scratch: agent pid %d, open error %v\n", pid, m.err)
	if m.reads != nil {
		var k struct{ PidTgid, SSL uint64 }
		var v [32]byte
		n, mine := 0, 0
		it := m.reads.Iterate()
		for it.Next(&k, &v) {
			n++
			if uint32(k.PidTgid>>32) == pid && mine < 8 {
				mine++
				fmt.Fprintf(&out, "ssl scratch: tego_ssl_reads row of the agent: tid %d ssl %#x\n", uint32(k.PidTgid), k.SSL)
			}
		}
		fmt.Fprintf(&out, "ssl scratch: tego_ssl_reads %d rows, %d of the agent, iterate error %v\n", n, mine, it.Err())
	}
	if m.current != nil {
		var k, v uint64
		n, mine := 0, 0
		it := m.current.Iterate()
		for it.Next(&k, &v) {
			n++
			if uint32(k>>32) == pid && mine < 8 {
				mine++
				fmt.Fprintf(&out, "ssl scratch: tego_ssl_current row of the agent: tid %d ssl %#x\n", uint32(k), v)
			}
		}
		fmt.Fprintf(&out, "ssl scratch: tego_ssl_current %d rows, %d of the agent, iterate error %v\n", n, mine, it.Err())
	}
	return out.String()
}

// kernelLog reads /dev/kmsg from where it stood when the round began. The descriptor is a raw one: an *os.File
// over a non-blocking descriptor can park a read at the end of the log in the runtime's poller.
type kernelLog struct {
	fd  int
	err error
	ops kernelLogOps
}

type kernelLogOps struct {
	open    func() (int, error)
	seekEnd func(int) error
	read    func(int, []byte) (int, error)
	close   func(int) error
}

func openKernelLog() *kernelLog {
	return openKernelLogWith(kernelLogOps{
		open: func() (int, error) {
			return syscall.Open("/dev/kmsg", syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		},
		seekEnd: func(fd int) error {
			_, err := syscall.Seek(fd, 0, io.SeekEnd)
			return err
		},
		read:  syscall.Read,
		close: syscall.Close,
	})
}

func openKernelLogWith(ops kernelLogOps) *kernelLog {
	k := &kernelLog{fd: -1, ops: ops}
	fd, err := ops.open()
	if err != nil {
		k.err = fmt.Errorf("open /dev/kmsg: %w", err)
		return k
	}
	if err := ops.seekEnd(fd); err != nil {
		k.err = fmt.Errorf("seek /dev/kmsg to the round's start: %w", err)
		if closeErr := ops.close(fd); closeErr != nil {
			k.err = errors.Join(k.err, fmt.Errorf("close /dev/kmsg after seek failure: %w", closeErr))
		}
		return k
	}
	k.fd = fd
	return k
}

func (k *kernelLog) close() {
	if k.fd >= 0 {
		_ = k.ops.close(k.fd) // Diagnostic teardown cannot improve the already collected evidence.
		k.fd = -1
	}
}

// kmsgFault selects the kernel log records that say the kernel itself failed: an oops, a protection fault, a
// warning, a stall, a task killed by a segfault. kmsgContext adds the lines around one that place it.
var (
	kmsgFault   = regexp.MustCompile(`\bBUG: |\bOops\b|general protection fault|\bWARNING: |segfault at |rcu.*stall|blocked for more than`)
	kmsgContext = regexp.MustCompile(`\bRIP: |Call Trace|bpf_prog_|uprobe|\bComm: `)
)

// ofNote keeps at most the last 60 selected records while draining. Only EAGAIN proves the readable log reached
// its current end; unavailable or overwritten evidence must not let a kernel regression pass as a clean round.
func (k *kernelLog) ofNote() (string, error) {
	if k.err != nil {
		return "", fmt.Errorf("kernel log evidence unavailable: %w", k.err)
	}
	if k.fd < 0 {
		return "", errors.New("kernel log evidence unavailable: /dev/kmsg is closed")
	}
	var evidence kernelFaultEvidence
	var incomplete error
	readAny := false
	buf := make([]byte, 8192)
	for {
		n, err := k.ops.read(k.fd, buf)
		if n > 0 {
			readAny = true
			evidence.add(kmsgText(buf[:n]))
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EPIPE) {
			if incomplete == nil {
				incomplete = fmt.Errorf("kernel log evidence incomplete: /dev/kmsg records overwritten: %w", err)
			}
			continue
		}
		if errors.Is(err, syscall.EAGAIN) {
			return evidence.faults(), incomplete
		}
		if err != nil {
			status := "unavailable"
			if readAny || incomplete != nil {
				status = "incomplete"
			}
			return evidence.faults(), errors.Join(incomplete, fmt.Errorf("kernel log evidence %s: read /dev/kmsg: %w", status, err))
		}
		if n == 0 {
			return evidence.faults(), errors.Join(incomplete, errors.New("kernel log evidence unavailable: unexpected end of /dev/kmsg"))
		}
	}
}

// kernelFaults is the records kmsgFault or kmsgContext selects (at most the last 60), or "" when none is a fault.
func kernelFaults(recs []string) string {
	var evidence kernelFaultEvidence
	for _, rec := range recs {
		evidence.add(rec)
	}
	return evidence.faults()
}

type kernelFaultEvidence struct {
	fault bool
	kept  []string
}

func (e *kernelFaultEvidence) add(rec string) {
	if kmsgFault.MatchString(rec) {
		e.fault = true
	} else if !kmsgContext.MatchString(rec) {
		return
	}
	if len(e.kept) == 60 {
		copy(e.kept, e.kept[1:])
		e.kept[len(e.kept)-1] = rec
	} else {
		e.kept = append(e.kept, rec)
	}
}

func (e *kernelFaultEvidence) faults() string {
	if !e.fault {
		return ""
	}
	return strings.Join(e.kept, "\n")
}

// kmsgText is a /dev/kmsg record's message, without its "prio,seq,usec,flags;" prefix and its trailing newline.
func kmsgText(rec []byte) string {
	if i := bytes.IndexByte(rec, ';'); i >= 0 {
		rec = rec[i+1:]
	}
	return strings.TrimSpace(string(rec))
}

// blockedTasks lists every task in uninterruptible sleep, and every tego or python task, with its kernel stack.
func blockedTasks(why string) string {
	var out strings.Builder
	fmt.Fprintf(&out, "BLOCKED-TASKS (%s)\n", why)
	tasks, _ := filepath.Glob("/proc/[0-9]*/task/[0-9]*")
	for _, p := range tasks {
		stat, err := os.ReadFile(filepath.Join(p, "stat"))
		if err != nil {
			continue
		}
		f := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
		comm, _ := os.ReadFile(filepath.Join(p, "comm"))
		name := strings.TrimSpace(string(comm))
		if len(f) == 0 || (f[0] != "D" && !strings.Contains(name, "tego") && !strings.Contains(name, "python")) {
			continue
		}
		wchan, _ := os.ReadFile(filepath.Join(p, "wchan"))
		stack, _ := os.ReadFile(filepath.Join(p, "stack"))
		cmd, _ := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(p)), "cmdline"))
		fmt.Fprintf(&out, "%s %s state %s wchan %s cmd %q\n%s", p, name, f[0], wchan,
			strings.ReplaceAll(string(cmd), "\x00", " "), stack)
	}
	return out.String()
}

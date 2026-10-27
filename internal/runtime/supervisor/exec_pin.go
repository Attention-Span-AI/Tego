// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ExecPinner writes a continued exec's pin into the run's decision plane (ADR 0048 (3) P2, (11)): the facts this loop's
// decision read, which the plane then holds the exec to in bprm_check and sched_process_exec. The runtime adapts the
// tier's handle to it; nil means the run is not pinned.
type ExecPinner interface {
	// Pin writes pin (execpin.Pin's encoding, gen and seq zero) for the thread tid, as the launcher's pid namespace
	// numbers it, whose start time is startTicks: with the run's gen and the run's next seq, which it returns.
	// ErrExecPinsFull when the slot's map has no room.
	Pin(tid uint32, startTicks uint64, pin []byte) (seq uint32, err error)
	// Sweep deletes the slot's pins whose thread live reports gone.
	Sweep(live func(tid uint32, startTicks uint64) bool) error
}

// ErrExecPinsFull is ExecPinner.Pin's answer when the slot's pin map is full.
var ErrExecPinsFull = errors.New("supervisor: the run's exec pin map is full")

// pinSkipTestHook, set only in a binary built with -tags tegotesthooks (exec_pin_testhook.go), names the images
// whose pin is not written: the exec continues unpinned, as if the write were lost, for the plane to refuse.
var pinSkipTestHook func(image string) bool

// ruleExecPin names an exec refused because no pin could carry its decision (ADR 0048 (8): rule exec.pin,
// pin_unavailable): the kernel would refuse or kill it, so this loop refuses it with the errno it answers.
const ruleExecPin = "exec.pin"

// pinRefusal is the decision for an exec whose pin could not be written.
// errPinNoKernelLine refuses a pinned run's exec whose line the kernel cannot write: no recorder reads the run, so a
// kill of it would have no line (ADR 0048 (8)).
var errPinNoKernelLine = errors.New("supervisor: no kernel recorder reads this pinned run")

func pinRefusal() execDecision {
	return execDecision{rule: ruleExecPin, verdict: record.VerdictRefused, reason: record.ReasonExecNotAllowed, answer: respErrno(refusalErrno)}
}

// pinExec writes the pin of an exec this loop is about to continue (ADR 0048 (3) "Write"): after its decision and the
// ID_VALID that closes it, immediately before CONTINUE. The pin holds what the decision read: the image's identity as
// the kernel holds it, its final name, bprm->filename, the form and #! chain a run with command rules read, and the
// argv elements the decision read (the whole vector under an exec gate, whose decision reads it). An error is the
// exec's refusal (pinRefusal); n.gone says the notification went away while it read.
func (l *Loop) pinExec(c *compiled, n *notif, r *reader, dirfd int32, raw string, img execImage, cmd execCommand, gateArgv []string, argvAddr uint64) (uint32, error) {
	if !img.kidOK {
		return 0, fmt.Errorf("%w: the image's kernel identity could not be read", execpin.ErrUnpinnable)
	}
	e := execpin.Exec{Image: img.kid.pin(), Name: pinName(img), Filename: execpin.FilenameOf(dirfd, raw)}
	hasGate := c.pol.Rules.Gate.Has(gate.Exec)
	switch {
	case c.cmds != nil && cmd.walked:
		e.Guard = cmd.guarded || hasGate
		e.Argv, e.Complete, e.K = cmd.argv, cmd.complete, max(cmd.res.K, 1)
		if hasGate {
			e.Argv, e.Complete, e.K = gateArgv, true, len(gateArgv)
		}
		switch cmd.form {
		case execmatch.FormDirect:
			e.Form = execpin.FormDirect
		case execmatch.FormScript:
			// The script pin covers binfmt_script's whole vector, which keeps argv[1:].
			e.Form = execpin.FormScript
			for i, st := range cmd.stages {
				if i >= len(cmd.kids) || cmd.kids[i] == (fileID{}) {
					return 0, fmt.Errorf("%w: interpreter %s's kernel identity could not be read", execpin.ErrUnpinnable, st.Path)
				}
				e.Chain = append(e.Chain, execpin.Stage{Path: st.Path, Arg: st.Arg, EmptyArg: st.EmptyArg, ID: cmd.kids[i].pin()})
			}
			if !e.Complete {
				e.Argv, e.Complete = r.argvBatched(argvAddr, argvEntries, execpin.MaxArea)
				if n.gone {
					return 0, errors.New("supervisor: the notification is gone")
				}
			}
		case execmatch.FormUnknown:
			// The command rules refuse such an image image-unreadable before this; no pin can hold an unread form.
			return 0, fmt.Errorf("%w: an image whose form is unknown", execpin.ErrUnpinnable)
		}
		// Every read the pin covers must be the one the command rules decided on: a later read that differs is the
		// vector changed under the decision.
		if k := min(cmd.res.K, len(cmd.argv)); len(e.Argv) < k || !slices.Equal(e.Argv[:k], cmd.argv[:k]) {
			return 0, fmt.Errorf("%w: the vector changed between two reads", execpin.ErrUnpinnable)
		}
	case c.cmds == nil && hasGate:
		// An exec gate alone: its decision read the whole vector (an incomplete one is gate.unreadable), and no command
		// rule is reachable through an interpreter, so the image's head is not read.
		e.Form, e.InterpOK, e.Guard = execpin.FormUnknown, true, true
		e.Argv, e.Complete, e.K = gateArgv, true, len(gateArgv)
	default:
		return 0, fmt.Errorf("%w: no decision read this exec's form", execpin.ErrUnpinnable)
	}
	pin, err := execpin.Build(l.pinKey, e)
	if err != nil {
		return 0, err
	}
	_, start, err := l.k.ProcStat(n.pid)
	if !l.valid(n) {
		return 0, errors.New("supervisor: the notification is gone")
	}
	if err != nil {
		return 0, fmt.Errorf("supervisor: the exec's start time: %w", err)
	}
	enc := pin.Encode()
	if pinSkipTestHook != nil && pinSkipTestHook(path.Base(img.link)) {
		// A binary built with -tags tegotesthooks may leave this exec's pin unwritten (K6's unpinned cell): the
		// plane must then refuse it, pin-missing.
		return 0, nil
	}
	seq, err := l.pinner.Pin(uint32(n.pid), start, enc)
	if errors.Is(err, ErrExecPinsFull) {
		// One sweep of the pins whose thread is gone (an exec that failed before bprm_check leaves its pin), then the
		// write once more.
		if serr := l.pinner.Sweep(l.pinLive); serr != nil {
			return 0, errors.Join(err, serr)
		}
		seq, err = l.pinner.Pin(uint32(n.pid), start, enc)
	}
	return seq, err
}

// pinLive reports whether the thread a pin names is still the one that wrote it: its /proc stat reads the same start
// time. Only an answer that it is gone (or another thread now) lets the sweep delete its pin.
func (l *Loop) pinLive(tid uint32, start uint64) bool {
	_, s, err := l.k.ProcStat(int(tid))
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, unix.ESRCH)
	}
	return s == start
}

// pin is the identity as a pin holds it.
func (id fileID) pin() execpin.Ident { return execpin.Ident{Dev: id.dev, Ino: id.ino} }

// pinName is the image's final name as its dentry holds it, which bprm_check MACs: the last component of the
// descriptor's link, without the kernel's " (deleted)" marker. The marker is on a link whose file is unlinked, and on
// one whose opened name was unlinked while another hard link keeps st_nlink above zero, which here tells apart from a
// file really named so: its link reaches this inode. A memfd's name is all of its link after the "/" d_path puts in
// front, since the name it was given may hold "/". A wrong guess costs a pin-mismatch refusal, never a pass: the kernel
// compares the name.
func pinName(img execImage) string {
	link := img.link
	if !img.linked || !img.here {
		link = strings.TrimSuffix(link, deletedSuffix)
	}
	if !img.linked && strings.HasPrefix(link, "/memfd:") {
		return link[1:]
	}
	if !strings.HasPrefix(link, "/") || link == "/" {
		return "" // an anonymous inode: no pin carries it, and the kernel refuses its exec
	}
	return path.Base(link)
}

// kernelID is the identity of the file behind the walk's descriptor fd as the plane holds it (ADR 0048 (3) "Pin
// value"): fdinfo's ino, which is the descriptor's inode's i_ino, and the device of its mount's super block, from
// mountinfo, in the kernel's encoding. fstat's values are not that on an overlay or a btrfs subvolume.
func (k sysKernel) kernelID(fd int) (fileID, error) {
	f, err := os.Open("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return fileID{}, err
	}
	defer f.Close() //nolint:errcheck // a read-only procfs file
	var mnt, ino uint64
	var haveMnt, haveIno bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := bytes.Cut(sc.Bytes(), []byte{':'})
		if !ok {
			continue
		}
		val = bytes.TrimSpace(val)
		switch string(key) {
		case "mnt_id":
			mnt, err = strconv.ParseUint(string(val), 10, 64)
			haveMnt = err == nil
		case "ino":
			ino, err = strconv.ParseUint(string(val), 10, 64)
			haveIno = err == nil
		}
	}
	if err := sc.Err(); err != nil {
		return fileID{}, err
	}
	if !haveMnt || !haveIno {
		return fileID{}, fmt.Errorf("supervisor: fdinfo of %d names no mnt_id or ino", fd)
	}
	dev, err := k.MountDev(mnt)
	if err != nil {
		return fileID{}, err
	}
	return fileID{dev: execpin.KernelDev(unix.Major(dev), unix.Minor(dev)), ino: ino}, nil
}

// SPDX-License-Identifier: Apache-2.0

//go:build integration

package conformance

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	ebpflink "github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// fanotifyInChain reports whether another party's fanotify permission refusal is part of security_file_open's return
// on this kernel, the return tier cgroup's recorder reads at fexit (ADR 0016 (3)): it was up to 6.12 upstream, where
// security_file_open returned fsnotify_open_perm's answer after the LSM chain's, and is not from 6.13, where the
// permission event runs after the function returned. The thirdparty cell's line follows it (Machine.FanotifyInChain).
// It is a probe, never the version: Debian 13's 6.12.107 runs the event after the function, as 6.13 does.
//
// The probe is the fact itself, measured: a fexit program on security_file_open keeps the return it sees for this
// thread alone, a fanotify group of the content class refuses this thread's open of a file of its own with FAN_DENY,
// and the program's return is read back: -EPERM is the refusal in the return, 0 the refusal after it. Root only (both
// the program and the group need it); not root, it answers false with no error, since only the root axes run the
// listener's lines. Any step that fails is an error, so the cell is never judged on a guess.
func fanotifyInChain() (bool, error) {
	if os.Geteuid() != 0 {
		return false, nil
	}
	dir, err := os.MkdirTemp("", "tego-fanotify-chain")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "probe")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inChain, err := waitFanotifyChainProbe(ctx, func(ctx context.Context) (bool, error) {
		// The program matches this thread's id, so the open must be made on it.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		return fanotifyChainOnThisThread(ctx, path)
	})
	if errors.Is(err, context.DeadlineExceeded) {
		return false, fmt.Errorf("the probe did not finish within 30 s: %w", err)
	}
	return inChain, err
}

// fanotifyChainSentinel is the map's value before the program writes it: no return is this.
const fanotifyChainSentinel = uint64(0xfeedface)

func fanotifyChainOnThisThread(ctx context.Context, path string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return false, fmt.Errorf("the probe's map: %w", err)
	}
	defer func() { _ = m.Close() }()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := m.Put(uint32(0), fanotifyChainSentinel); err != nil {
		return false, fmt.Errorf("the probe's map: %w", err)
	}
	tid := unix.Gettid()
	// ctx is the traced function's arguments as u64s, the return after the last: security_file_open(struct file *)
	// has one, so the return is at offset 8, an int in its low half.
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFExit, AttachTo: "security_file_open", License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.FnGetCurrentPidTgid.Call(),
			asm.LSh.Imm(asm.R0, 32),
			asm.RSh.Imm(asm.R0, 32),
			asm.JNE.Imm(asm.R0, int32(tid), "out"),
			asm.LoadMem(asm.R1, asm.R6, 8, asm.DWord),
			asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
			asm.StoreImm(asm.RFP, -12, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -12),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, -8),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
			asm.Return(),
		},
	})
	if err != nil {
		return false, fmt.Errorf("the probe's fexit program on security_file_open: %w", err)
	}
	defer func() { _ = prog.Close() }()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	group, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return false, fmt.Errorf("the probe's fanotify group: %w", err)
	}
	// The responder closes the group when it stops, including cancellation, so an open waiting for permission is
	// released. finish joins it before the worker releases any other resources.
	var closeOnce sync.Once
	closeGroup := func() { closeOnce.Do(func() { _ = unix.Close(group) }) }
	responderCtx, stop := context.WithCancel(ctx)
	defer stop()
	answered := make(chan error, 1)
	go func() { answered <- answerUntil(group, responderCtx.Done(), closeGroup) }()
	finish := func() error {
		stop()
		err := <-answered
		closeGroup()
		return err
	}
	if err := unix.FanotifyMark(group, unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM, unix.AT_FDCWD, path); err != nil {
		_ = finish()
		return false, fmt.Errorf("the probe's fanotify mark: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = finish()
		return false, err
	}
	l, err := ebpflink.AttachTracing(ebpflink.TracingOptions{Program: prog})
	if err != nil {
		_ = finish()
		return false, fmt.Errorf("attach the probe's fexit program: %w", err)
	}
	// Loading and attaching BPF objects are synchronous kernel calls without a context interface. Cancellation
	// waits for an in-flight call to return, then closes its result; it never abandons that call's worker.
	if err := ctx.Err(); err != nil {
		_ = l.Close()
		_ = finish()
		return false, err
	}
	fd, openErr := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	_ = l.Close()
	if openErr == nil {
		_ = unix.Close(fd)
	}
	if err := finish(); err != nil {
		return false, err
	}
	if !errors.Is(openErr, unix.EPERM) {
		return false, fmt.Errorf("the probe's open under a FAN_DENY answered %v, want EPERM", openErr)
	}
	var v uint64
	if err := m.Lookup(uint32(0), &v); err != nil {
		return false, fmt.Errorf("the probe's map: %w", err)
	}
	switch ret := int32(uint32(v)); {
	case v == fanotifyChainSentinel:
		return false, errors.New("the probe's open never reached security_file_open's fexit")
	case ret == -int32(unix.EPERM):
		return true, nil
	case ret == 0:
		return false, nil
	default:
		return false, fmt.Errorf("security_file_open returned %d to the probe's open", ret)
	}
}

// answerUntil answers every permission event the group reports with FAN_DENY until stop is closed, and reports
// whether it answered at least one. It closes the group on every return, releasing any open still waiting for an
// answer when its owner cancels the probe.
func answerUntil(group int, stop <-chan struct{}, closeGroup func()) error {
	defer closeGroup()
	const metadataLen = 24 // struct fanotify_event_metadata
	buf := make([]byte, 4096)
	answered := 0
	for {
		select {
		case <-stop:
			if answered == 0 {
				return errors.New("the probe's group reported no event")
			}
			return nil
		default:
		}
		pfd := []unix.PollFd{{Fd: int32(group), Events: unix.POLLIN}}
		if _, err := unix.Poll(pfd, 100); err != nil && !errors.Is(err, unix.EINTR) {
			return fmt.Errorf("poll the probe's group: %w", err)
		}
		n, err := unix.Read(group, buf)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read the probe's group: %w", err)
		}
		for off := 0; off+metadataLen <= n; {
			evLen := int(binary.NativeEndian.Uint32(buf[off : off+4]))
			evFD := int32(binary.NativeEndian.Uint32(buf[off+16 : off+20]))
			resp := unix.FanotifyResponse{Fd: evFD, Response: unix.FAN_DENY}
			_, werr := unix.Write(group, (*[unsafe.Sizeof(resp)]byte)(unsafe.Pointer(&resp))[:])
			if evFD >= 0 {
				_ = unix.Close(int(evFD))
			}
			if werr != nil {
				return fmt.Errorf("answer the probe's event: %w", werr)
			}
			answered++
			if evLen < metadataLen {
				break
			}
			off += evLen
		}
	}
}

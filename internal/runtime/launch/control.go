// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
)

// ChildStep names the child-stage step a control message reports on (docs/p0/runtime-launch.md §5, case 4).
type ChildStep uint8

// Child-stage steps in execution order for the unprivileged case; the privileged case (R4) runs Landlock and
// seccomp before the credential steps.
const (
	StepNone       ChildStep = iota
	StepSpec                 // reading the ChildSpec from the control pipe
	StepDir                  // chdir
	StepCreds                // setresgid/setgroups/setresuid (privileged only)
	StepCaps                 // capset to empty + ambient clear
	StepDumpable             // PR_SET_DUMPABLE=1 and its read-back
	StepPdeathsig            // PR_SET_PDEATHSIG=SIGKILL
	StepParent               // getppid != launcher pid: the parent died before PDEATHSIG was armed
	StepNoNewPrivs           // PR_SET_NO_NEW_PRIVS
	StepLandlock             // landlock_restrict_self
	StepSeccomp              // seccomp(SET_MODE_FILTER, NEW_LISTENER)
	StepAck                  // waiting for the ack byte
	StepExec                 // execve of the agent command failed (reported after the handshake)
)

var stepNames = [...]string{
	StepNone: "none", StepSpec: "spec", StepDir: "chdir", StepCreds: "credentials",
	StepCaps: "capabilities", StepDumpable: "dumpable", StepPdeathsig: "pdeathsig", StepParent: "parent-check",
	StepNoNewPrivs: "no_new_privs", StepLandlock: "landlock", StepSeccomp: "seccomp", StepAck: "ack",
	StepExec: "exec",
}

// String names the step for diagnostics.
func (s ChildStep) String() string {
	if int(s) < len(stepNames) {
		return stepNames[s]
	}
	return fmt.Sprintf("step(%d)", uint8(s))
}

// Control-message encoding on pipe A (child→parent), one int32 little-endian:
//
//	n >= 0            the notify fd number in the child's table
//	n == noListener   the child installed no seccomp filter (observe tier); there is no fd to fetch
//	n <= -2           a failed step: -(step<<16 | errno)
const (
	noListener  = -1
	controlSize = 4
	maxErrno    = 4095 // the kernel's error range; larger values are not errnos
)

// Message is one decoded control-pipe message.
type Message struct {
	FD    int           // valid when Kind == MessageFD
	Step  ChildStep     // valid when Kind == MessageError
	Errno syscall.Errno // valid when Kind == MessageError
	Kind  MessageKind
}

// MessageKind classifies a control message.
type MessageKind uint8

// Message kinds.
const (
	MessageFD MessageKind = iota + 1
	MessageNoListener
	MessageError
)

// ErrControl is wrapped when a control message is malformed: a negative value that decodes to no step.
var ErrControl = errors.New("launch: malformed control message")

func encodeFD(fd int) []byte { return encodeInt32(int32(fd)) }

func encodeNoListener() []byte { return encodeInt32(noListener) }

// encodeError packs a step and errno; an errno of 0 (a non-errno error) is sent as EIO so the parent still
// learns the step.
func encodeError(step ChildStep, errno syscall.Errno) []byte {
	if errno == 0 {
		errno = syscall.EIO
	}
	return encodeInt32(-(int32(step)<<16 | int32(errno)&0xffff))
}

func encodeInt32(v int32) []byte {
	var b [controlSize]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return b[:]
}

// decodeControl parses one control message. It never panics: a short buffer is an error, not a slice fault.
func decodeControl(b []byte) (Message, error) {
	if len(b) < controlSize {
		return Message{}, fmt.Errorf("%w: %d bytes", ErrControl, len(b))
	}
	v := int32(binary.LittleEndian.Uint32(b[:controlSize]))
	switch {
	case v >= 0:
		return Message{Kind: MessageFD, FD: int(v)}, nil
	case v == noListener:
		return Message{Kind: MessageNoListener}, nil
	}
	code := -v
	rawStep, rawErrno := int(code>>16), int(code&0xffff)
	// Range-check before narrowing: a garbage high half-word must not truncate into a valid step.
	if rawStep == int(StepNone) || rawStep >= len(stepNames) || rawErrno == 0 || rawErrno > maxErrno {
		return Message{}, fmt.Errorf("%w: value %d", ErrControl, v)
	}
	return Message{Kind: MessageError, Step: ChildStep(rawStep), Errno: syscall.Errno(rawErrno)}, nil
}

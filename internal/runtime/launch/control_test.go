// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"errors"
	"syscall"
	"testing"
)

func TestControlRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want Message
		err  error
	}{
		{"fd 0", encodeFD(0), Message{Kind: MessageFD, FD: 0}, nil},
		{"fd 7", encodeFD(7), Message{Kind: MessageFD, FD: 7}, nil},
		{"fd max", encodeFD(1<<31 - 1), Message{Kind: MessageFD, FD: 1<<31 - 1}, nil},
		{"no listener", encodeNoListener(), Message{Kind: MessageNoListener}, nil},
		{"landlock EPERM", encodeError(StepLandlock, syscall.EPERM), Message{Kind: MessageError, Step: StepLandlock, Errno: syscall.EPERM}, nil},
		{"seccomp EACCES", encodeError(StepSeccomp, syscall.EACCES), Message{Kind: MessageError, Step: StepSeccomp, Errno: syscall.EACCES}, nil},
		{"exec ENOENT", encodeError(StepExec, syscall.ENOENT), Message{Kind: MessageError, Step: StepExec, Errno: syscall.ENOENT}, nil},
		{"zero errno becomes EIO", encodeError(StepDir, 0), Message{Kind: MessageError, Step: StepDir, Errno: syscall.EIO}, nil},
		{"short", []byte{1, 2, 3}, Message{}, ErrControl},
		{"negative with no step", encodeInt32(-2), Message{}, ErrControl},
		{"step out of range", encodeInt32(-(200<<16 | 1)), Message{}, ErrControl},
		{"errno zero", encodeInt32(-(int32(StepDir) << 16)), Message{}, ErrControl},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeControl(tc.in)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestChildStepString(t *testing.T) {
	if StepLandlock.String() != "landlock" || StepExec.String() != "exec" || StepNone.String() != "none" {
		t.Fatal("step names")
	}
	if ChildStep(250).String() != "step(250)" {
		t.Fatalf("unknown step = %q", ChildStep(250).String())
	}
}

// Also pins runtime-launch.md E4: a landlock_restrict_self failure is ErrChildLandlock wrapping the errno, not a bare ErrChildDied.
func TestStepFailureClasses(t *testing.T) {
	tests := []struct {
		step ChildStep
		want error
	}{
		{StepLandlock, ErrChildLandlock},
		{StepSeccomp, ErrChildSeccomp},
		{StepDumpable, ErrChildSetup},
		{StepParent, ErrChildSetup},
	}
	for _, tc := range tests {
		err := stepFailure(Message{Kind: MessageError, Step: tc.step, Errno: syscall.EPERM})
		if !errors.Is(err, tc.want) || !errors.Is(err, syscall.EPERM) {
			t.Errorf("step %s: %v does not wrap %v and EPERM", tc.step, err, tc.want)
		}
	}
}

// FuzzControlPipeDecode is docs/p0/runtime-launch.md §9's fuzz target: the decoder never panics and every
// accepted message re-encodes to the same bytes.
func FuzzControlPipeDecode(f *testing.F) {
	f.Add(encodeFD(3))
	f.Add(encodeNoListener())
	f.Add(encodeError(StepSeccomp, syscall.EACCES))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := decodeControl(b)
		if err != nil {
			return
		}
		var again []byte
		switch m.Kind {
		case MessageFD:
			again = encodeFD(m.FD)
		case MessageNoListener:
			again = encodeNoListener()
		case MessageError:
			again = encodeError(m.Step, m.Errno)
		}
		if string(again) != string(b[:controlSize]) {
			t.Fatalf("re-encode of %+v = %v, input %v", m, again, b[:controlSize])
		}
	})
}

func BenchmarkControlDecode(b *testing.B) {
	in := encodeError(StepSeccomp, syscall.EACCES)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := decodeControl(in); err != nil {
			b.Fatal(err)
		}
	}
}

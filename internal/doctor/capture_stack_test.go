// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

func TestDoctorCaptureReadbackUnavailable(t *testing.T) {
	prev := checkCaptureStack
	t.Cleanup(func() { checkCaptureStack = prev })
	denied := errors.New("uprobe: cannot verify capture stack safety: read translated instructions: permission denied")
	checkCaptureStack = func(name string, _ *ebpf.Program) error {
		if name != bpfobj.ProgSSLWrite {
			t.Fatalf("checked %q", name)
		}
		return denied
	}
	detail := captureStackDetail(bpfobj.ProgSSLWrite, nil, false)
	if detail != denied.Error() {
		t.Fatalf("doctor detail %q, want %q", detail, denied)
	}
	st := probeState{hooks: []HookResult{{Hook: "uprobe/SSL_write", Capture: true, Detail: detail}}}
	if note := st.captureNote(); !strings.Contains(note, denied.Error()) {
		t.Fatalf("doctor hid the read-back refusal: %q", note)
	}
	if got := captureStackDetail(bpfobj.ProgSSLWrite, nil, true); got != "" {
		t.Fatalf("stand-in: %s", got)
	}
}

func TestDoctorCaptureDispatcherReadbackUnavailable(t *testing.T) {
	prev := checkCaptureStack
	t.Cleanup(func() { checkCaptureStack = prev })
	denied := errors.New("uprobe: dispatcher translated instructions have no tail call")
	for _, failed := range []string{bpfobj.ProgSSLMultiEnter, bpfobj.ProgSSLMultiReturn} {
		checkCaptureStack = func(name string, _ *ebpf.Program) error {
			if name == failed {
				return denied
			}
			return nil
		}
		load := func(string) (*ebpf.Program, bool, error) { return nil, false, nil }
		if err := captureDispatcherStacks(load); !errors.Is(err, denied) {
			t.Fatalf("dispatcher read-back did not reach doctor: %v", err)
		}
	}
	checked := false
	checkCaptureStack = func(string, *ebpf.Program) error { checked = true; return denied }
	loads := 0
	load := func(string) (*ebpf.Program, bool, error) {
		loads++
		if loads == 2 {
			return nil, false, errors.New("optional dispatcher load failed")
		}
		return nil, false, nil
	}
	if err := captureDispatcherStacks(load); err != nil || checked {
		t.Fatalf("optional load failure blocked the six-program fallback: checked=%v err=%v", checked, err)
	}
}

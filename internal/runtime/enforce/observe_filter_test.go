// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// seccompFor encodes a struct seccomp_data for the x/net/bpf VM, which loads big-endian words: each 32-bit
// half sits at the offset the kernel's little-endian layout gives it (nr@0, arch@4, args@16+8i).
func seccompFor(nr uint32, args ...uint64) []byte {
	b := make([]byte, 64)
	be := binary.BigEndian
	be.PutUint32(b[0:], nr)
	be.PutUint32(b[4:], uint32(landlock.NativeArch()))
	for i, a := range args {
		be.PutUint32(b[16+8*i:], uint32(a))
		be.PutUint32(b[16+8*i+4:], uint32(a>>32))
	}
	return b
}

// observeHandle prepares an observe run for record mode m through the public entry point, which is the
// wiring that was missing: the handle it returns is what the child stage installs.
func observeHandle(t *testing.T, m agent.RecordMode) api.Handle {
	t.Helper()
	h, err := Observe().Prepare(context.Background(), &agent.RuleTable{Record: m}, RunRef{})
	if err != nil {
		t.Fatalf("Observe().Prepare: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// TestObserveInstallsTheRecordFilter: `tego run --observe` recorded nothing because the observe
// handle gave the child no filter, so no listener existed and the supervisor never started. The handle must
// carry tier 1's filter, notify every exec, write-open and connect, and refuse none of the actions R2's
// truncation arms stand in for, since this run applies no Landlock ruleset for them to back up.
func TestObserveInstallsTheRecordFilter(t *testing.T) {
	const (
		notify = unix.SECCOMP_RET_USER_NOTIF
		allow  = unix.SECCOMP_RET_ALLOW
	)
	wr := uint64(unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC)
	rd := uint64(unix.O_RDONLY | unix.O_CLOEXEC)
	cases := []struct {
		name string
		mode agent.RecordMode
		data []byte
		want uint32
	}{
		{"execve is notified", agent.RecordSummary, seccompFor(unix.SYS_EXECVE), notify},
		{"connect is notified", agent.RecordSummary, seccompFor(unix.SYS_CONNECT), notify},
		{"a write-open is notified", agent.RecordSummary, seccompFor(unix.SYS_OPENAT, 0, 0, wr), notify},
		{"a read-open is not, under summary", agent.RecordSummary, seccompFor(unix.SYS_OPENAT, 0, 0, rd), allow},
		{"a read-open is, under full", agent.RecordFull, seccompFor(unix.SYS_OPENAT, 0, 0, rd), notify},
		{"unlinkat is notified", agent.RecordSummary, seccompFor(unix.SYS_UNLINKAT), notify},
		// Refusing these would be enforcement; below ABI 3 tier 1 does, for Landlock's sake (R2).
		{"truncate is not refused, only recorded", agent.RecordSummary, seccompFor(unix.SYS_TRUNCATE), notify},
		{"O_RDONLY|O_TRUNC is not refused", agent.RecordFull,
			seccompFor(unix.SYS_OPENAT, 0, 0, uint64(unix.O_RDONLY|unix.O_TRUNC)), notify},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, ok := observeHandle(t, tc.mode).SeccompFilter()
			if !ok || len(raw) == 0 {
				t.Fatalf("SeccompFilter = %d instructions, %v: an observe run with no filter records nothing", len(raw), ok)
			}
			insts, ok := bpf.Disassemble(raw)
			if !ok {
				t.Fatal("the filter does not disassemble")
			}
			vm, err := bpf.NewVM(insts)
			if err != nil {
				t.Fatalf("NewVM: %v", err)
			}
			got, err := vm.Run(tc.data)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if uint32(got) != tc.want {
				t.Errorf("filter answered %#x, want %#x", uint32(got), tc.want)
			}
		})
	}
}

// TestObserveHandleSaysObserved is the other half of the wiring: the runtime reads the handle's verdict to
// put the supervisor in observe mode, and must find it through the api.Handle it is given.
func TestObserveHandleSaysObserved(t *testing.T) {
	h := observeHandle(t, agent.RecordSummary)
	v, ok := h.(interface{ Verdict() record.Verdict })
	if !ok || v.Verdict() != record.VerdictObserved {
		t.Fatalf("observe handle %T does not report verdict observed", h)
	}
	if fd, ok := h.LandlockRuleset(); ok || fd != -1 {
		t.Errorf("LandlockRuleset = %d, %v, want none", fd, ok)
	}
}

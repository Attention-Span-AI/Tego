// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf && (386 || amd64 || arm64)

package doctor

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestCaptureStackInvariantOnThisKernel makes a refusal measurable on every full
// matrix row: every capture body loads, its translated instructions retain the
// live tail call, and the production loader and doctor's capture probe offer
// uprobes. This is a kernel test; the ELF check alone cannot prove the invariant.
func TestCaptureStackInvariantOnThisKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: capture loading, translated instruction read-back and uprobe attachment")
	}
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatalf("record guest kernel release: %v", err)
	}
	t.Logf("capture stack invariant on kernel %s", strings.TrimSpace(string(release)))
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	spec, err := bpfobj.Load(bpfobj.ObjectUprobeSSL)
	if err != nil {
		t.Fatalf("capture object: %v", err)
	}
	if len(spec.Programs) != 8 || len(bpfobj.SSLPrograms) != 8 {
		t.Fatalf("capture program inventory: object=%d names=%d, want eight", len(spec.Programs), len(bpfobj.SSLPrograms))
	}
	multiErr := features.HaveBPFLinkUprobeMulti()
	if multiErr != nil && !errors.Is(multiErr, ebpf.ErrNotSupported) {
		t.Fatalf("probe native multi-uprobe interface: %v", multiErr)
	}
	for _, name := range bpfobj.SSLPrograms {
		t.Run(name, func(t *testing.T) {
			one := spec.Copy()
			for _, m := range one.Maps {
				m.Pinning = ebpf.PinNone
			}
			p := one.Programs[name]
			if p == nil {
				t.Fatalf("capture object has no %s", name)
			}
			if multiErr != nil && (name == bpfobj.ProgSSLMultiEnter || name == bpfobj.ProgSSLMultiReturn) {
				// Such kernels never load these optional dispatchers in production.
				// Exercise their unmodified bodies as ordinary KPROBE programs;
				// this is not evidence of native multi-uprobe acceptance.
				p.AttachType = ebpf.AttachNone
				t.Log("native multi-uprobe interface absent: checking this dispatcher body with expected attach type NONE; native multi attachment is not proven")
			}
			prog, err := loadOneProgram(one, name, nil)
			if err != nil {
				t.Fatalf("capture program load: %+v", err)
			}
			defer prog.Close()
			if err := bpfobj.CheckCaptureStack(name, prog); err != nil {
				t.Fatalf("loaded capture stack invariant: %v", err)
			}
			if os.Getenv("TEGO_CAPTURE_STACK_DUMP") == "1" {
				logCaptureInstructions(t, name, p.AttachType, prog)
			}
		})
	}
	if t.Failed() {
		t.Fatal("one or more capture bodies failed the loaded stack invariant")
	}
	// Use a new build directory, as a first production capture source does. Any
	// new refusal must fail this check, rather than turn into a row-specific skip.
	root, err := os.MkdirTemp("/sys/fs/bpf", "tego-capture-stack-")
	if err != nil {
		t.Fatalf("capture pin root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.MkdirAll(filepath.Join(root, "invariant", "maps"), 0o700); err != nil {
		t.Fatalf("capture map directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "invariant", "progs"), 0o700); err != nil {
		t.Fatalf("capture program directory: %v", err)
	}
	coll, err := uprobe.LoadCollection(root, "invariant")
	if err != nil {
		t.Fatalf("production loader made uprobe capture unavailable: %v", err)
	}
	defer coll.Close()
	want := len(bpfobj.SSLPrograms)
	if multiErr != nil {
		want = len(bpfobj.SSLSinglePrograms)
	}
	if len(coll.Programs) != want {
		t.Fatalf("production loaded %d capture programs, want %d", len(coll.Programs), want)
	}
	for name, prog := range coll.Programs {
		if err := bpfobj.CheckCaptureStack(name, prog); err != nil {
			t.Fatalf("production loaded capture stack invariant: %v", err)
		}
	}
	// A later run adopts the same pinned programs and must pass read-back too.
	adopted, err := uprobe.LoadCollection(root, "invariant")
	if err != nil {
		t.Fatalf("production adoption made uprobe capture unavailable: %v", err)
	}
	defer adopted.Close()
	for name, prog := range adopted.Programs {
		if err := bpfobj.CheckCaptureStack(name, prog); err != nil {
			t.Fatalf("adopted capture stack invariant: %v", err)
		}
	}
	if multiErr == nil {
		if err := captureDispatcherStacks(func(name string) (*ebpf.Program, bool, error) {
			return loadHookProgram(hook{object: bpfobj.ObjectUprobeSSL, program: name}, nil, bpfobj.Load)
		}); err != nil {
			t.Fatalf("doctor dispatcher stack invariant: %v", err)
		}
	}
	lib := systemLibSSL(libsslDirs())
	if lib.err != nil {
		t.Fatalf("required capture fixture has no system libssl: %v", lib.err)
	}
	rows := make([]HookResult, 0, len(captureHooks))
	for _, hook := range captureHooks {
		row := testCaptureHook(hook, nil, lib, bpfobj.Load)
		if row.StandIn || row.LoadOnly || !row.OK() {
			t.Fatalf("doctor made uprobe capture unavailable at %s: %+v", hook.Name, row)
		}
		rows = append(rows, row)
	}
	st := probeState{hooks: rows}
	if note := st.captureNote(); note != "" {
		t.Fatalf("doctor does not offer uprobe capture: %s", note)
	}
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		set, notes := st.machineMatrix(tier)
		if !set[backend.CapCaptureModel] || notes[backend.CapCaptureModel] != "" {
			t.Fatalf("doctor capture capability at %s: available=%v note=%q", tier,
				set[backend.CapCaptureModel], notes[backend.CapCaptureModel])
		}
	}
	t.Logf("uprobe capture OFFERED: all eight bodies loaded and read back; production loaded %d programs; all six doctor capture rows attached", want)
}

// Keep real translated bytes in the guest console for scanner fixtures. Chunks
// avoid a long log line being truncated by an artifact viewer. Reassembly must
// match the recorded byte length and SHA256 before it becomes testdata.
func logCaptureInstructions(t *testing.T, name string, attach ebpf.AttachType, prog *ebpf.Program) {
	t.Helper()
	info, err := prog.Info()
	if err != nil {
		t.Fatalf("dump translated program info: %v", err)
	}
	insns, err := info.Instructions()
	if err != nil {
		t.Fatalf("dump translated instructions: %v", err)
	}
	data, err := marshalCaptureInstructions(insns)
	if err != nil {
		t.Fatalf("encode translated instructions: %v", err)
	}
	t.Logf("CAPTURE-XLATED program=%s attach_type=%s bytes=%d sha256=%x", name, attach, len(data), sha256.Sum256(data))
	for part, off := 0, 0; off < len(data); part, off = part+1, off+256 {
		t.Logf("CAPTURE-XLATED program=%s part=%d data=%x", name, part, data[off:min(off+256, len(data))])
	}
}

// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// D2 parses the kernel's own BTF through cilium/ebpf's per-process cache, so the program loads a run makes after
// it do not parse the 6.9 MB file a second time (R27 D2).
func TestD2ParsesTheKernelBTFThroughTheProcessCache(t *testing.T) {
	if _, err := os.Stat(defaultBTFPath); err != nil {
		t.Skip("no kernel BTF on this machine")
	}
	calls := 0
	prev := loadKernelSpec
	t.Cleanup(func() { loadKernelSpec = prev })
	loadKernelSpec = func() (*btf.Spec, error) { calls++; return prev() }
	setBTFPath(t, defaultBTFPath)
	if r := probeBTFWith(needs()); !r.OK {
		t.Fatalf("D2 on this kernel: %+v", r)
	}
	if calls != 1 {
		t.Errorf("D2 loaded the kernel BTF through the process cache %d times, want 1", calls)
	}
}

// A BTF file at another path is parsed as itself, never as the kernel's cached one.
func TestD2ParsesAnotherPathAsItself(t *testing.T) {
	calls := 0
	prev := loadKernelSpec
	t.Cleanup(func() { loadKernelSpec = prev })
	loadKernelSpec = func() (*btf.Spec, error) { calls++; return prev() }
	setBTFPath(t, writeFakeBTF(t, fakeKernelTypes()...))
	_ = probeBTFWith(needs())
	if calls != 0 {
		t.Errorf("a fake BTF path went through the kernel cache %d times", calls)
	}
}

// The process's kernel BTF parse is one parse: D2, D7 and the plane get the same spec, not one parse each.
func TestKernelSpecIsParsedOncePerProcess(t *testing.T) {
	if _, err := os.Stat(defaultBTFPath); err != nil {
		t.Skip("no kernel BTF on this machine")
	}
	a, err := loadKernelSpec()
	if err != nil {
		t.Skipf("kernel BTF does not parse here: %v", err)
	}
	b, _ := loadKernelSpec()
	if a != b {
		t.Error("two loads of the kernel BTF returned two parses")
	}
}

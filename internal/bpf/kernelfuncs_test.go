// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// TestKernelFuncNamesAreEveryQuestionARunAsks: the names a cache keeps answers for are the reader's functions, the
// optional tracing program's function and every optional plane hook's target in both modes, sorted and once each; a
// name missing here would be parsed for on every run (enforce-plane §2.18).
func TestKernelFuncNamesAreEveryQuestionARunAsks(t *testing.T) {
	names := KernelFuncNames()
	if !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
		t.Fatalf("KernelFuncNames = %v: not sorted or not unique", names)
	}
	want := slices.Clone(ReaderKfuncs)
	for _, fn := range OptionalTracePrograms {
		want = append(want, fn)
	}
	for _, m := range []PlaneMode{PlaneLSM, PlaneFmodRet} {
		for _, h := range PlaneHooks {
			if h.Optional {
				want = append(want, h.Target(m))
			}
		}
	}
	for _, name := range want {
		if !slices.Contains(names, name) {
			t.Errorf("KernelFuncNames lacks %s", name)
		}
	}
	if len(names) != len(slices.Compact(slices.Sorted(slices.Values(want)))) {
		t.Errorf("KernelFuncNames = %v, want exactly %v", names, want)
	}
}

// TestKernelHasFuncAnswersFromTheSeedWithoutParsing: a seeded name is answered from the seed and parses no BTF; a name
// the seed lacks is asked of the parsed BTF; a BTF that cannot be read answers yes (the load then names the function).
func TestKernelHasFuncAnswersFromTheSeedWithoutParsing(t *testing.T) {
	parses := 0
	kernel := kernelWith(t, "bpf_loop", "security_file_truncate")
	var fail error
	prev := loadKernelBTF
	loadKernelBTF = func() (*btf.Spec, error) { parses++; return kernel, fail }
	t.Cleanup(func() { loadKernelBTF = prev; SeedKernelFuncs(nil) })

	facts := KernelFuncFacts(kernel)
	if !facts["bpf_loop"] || !facts["security_file_truncate"] || facts["bpf_rdonly_cast"] || len(facts) != len(KernelFuncNames()) {
		t.Fatalf("KernelFuncFacts = %v", facts)
	}
	SeedKernelFuncs(facts)
	parses = 0
	for _, name := range KernelFuncNames() {
		if got := KernelHasFunc(name); got != facts[name] {
			t.Errorf("KernelHasFunc(%s) = %v, the seed says %v", name, got, facts[name])
		}
	}
	if parses != 0 {
		t.Errorf("seeded answers parsed the BTF %d times", parses)
	}
	if !KernelHasFunc("security_file_truncate") || KernelHasFunc("no_such_function") || parses != 1 {
		t.Errorf("an unseeded name: parses %d, want 1 and the BTF's answer", parses)
	}
	SeedKernelFuncs(nil)
	fail = errors.New("no BTF")
	if !KernelHasFunc("no_such_function") {
		t.Error("with no readable BTF KernelHasFunc answered no: a load would quietly leave the program out")
	}
}

// TestSeededReaderIsTheParsedOne: the reader chosen from seeded answers is ChooseReader's on the BTF they came from.
func TestSeededReaderIsTheParsedOne(t *testing.T) {
	for _, funcs := range [][]string{{"bpf_rdonly_cast", "bpf_loop"}, {"bpf_loop"}, {"bpf_rdonly_cast"}, nil} {
		kernel := kernelWith(t, funcs...)
		facts := KernelFuncFacts(kernel)
		for _, lockdown := range []string{"", "none integrity [confidentiality]"} {
			got := chooseReaderBy(func(name string) bool { return facts[name] }, lockdown)
			if want := ChooseReader(kernel, lockdown); !reflect.DeepEqual(got, want) {
				t.Errorf("kernel %v, lockdown %q: from the seed %+v, parsed %+v", funcs, lockdown, got, want)
			}
		}
	}
}

// BenchmarkKernelHasFuncSeeded is what an adopting run pays for every question it asks the kernel's BTF once doctor
// seeded the answers (enforce-plane §2.18): a map read under a lock, against the 50-100 ms of CPU a parse took in the
// KVM guests. It allocates nothing; bench-gate holds it there.
func BenchmarkKernelHasFuncSeeded(b *testing.B) {
	names := KernelFuncNames()
	facts := map[string]bool{}
	for _, n := range names {
		facts[n] = true
	}
	prev := loadKernelBTF
	loadKernelBTF = func() (*btf.Spec, error) { b.Fatal("a seeded question parsed the BTF"); return nil, nil }
	SeedKernelFuncs(facts)
	b.Cleanup(func() { loadKernelBTF = prev; SeedKernelFuncs(nil) })
	b.ReportAllocs()
	for b.Loop() {
		for _, n := range names {
			if !KernelHasFunc(n) {
				b.Fatalf("KernelHasFunc(%s) = false, seeded true", n)
			}
		}
	}
}

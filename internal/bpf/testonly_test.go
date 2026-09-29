// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// Helpers only the tests call, kept out of the package's own files so the production binary carries nothing it
// never runs.

// Argv splits an exec record's NUL-separated argument buffer into the arguments it holds. Only ArgvLen bytes
// are read, a trailing partial argument produced by truncation is kept (the record says it was truncated),
// and each element is made valid UTF-8 for display exactly as GoString does.
func Argv(e *ExecEvent) []string {
	n := int(e.ArgvLen)
	if n > len(e.Argv) {
		n = len(e.Argv)
	}
	// A complete vector ends in a NUL and a corrupt ArgvLen can point into the buffer's zero padding, so
	// the trailing NUL run is dropped before splitting. A genuinely empty final argument is indistinguishable
	// from that padding and is not reconstructed; the record's own truncation flag says when bytes were lost.
	raw := bytes.TrimRight(e.Argv[:n], "\x00")
	if len(raw) == 0 {
		return nil
	}
	var out []string
	for _, part := range bytes.Split(raw, []byte{0}) {
		out = append(out, strings.ToValidUTF8(string(part), "�"))
	}
	return out
}

// ExitStatus splits an exit record into the exit code and the terminating signal, the two halves a ledger
// event reports separately.
func ExitStatus(e *ExitEvent) (code int, signal int) {
	return int(e.Code), int(e.Signal)
}

// Raw returns the embedded ELF of one object, the probe build of one compiled per reader. The slice is the embedded
// data itself and must not be modified.
func Raw(o Object) ([]byte, error) {
	b, ok := bindingOf(o)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotGenerated, o)
	}
	return b.raw, nil
}

// PlaneHooksHere is PlaneHooksFor this kernel's BTF: an optional hook whose target it lacks (file_truncate below
// 6.2, the ACL hooks below 6.2) is left out, as the backend and doctor's probe leave it out (enforce-plane R3).
func PlaneHooksHere(m PlaneMode) []PlaneHook {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return PlaneHooks
	}
	return PlaneHooksFor(m, func(fn string) bool {
		var f *btf.Func
		return spec.TypeByName(fn, &f) == nil
	})
}

// PlaneProgramsHere lists one mode's program names of PlaneHooksHere, and its exec-pin program, which the loader
// keeps with them (ADR 0048 (3) P2).
func PlaneProgramsHere(m PlaneMode) []string {
	var out []string
	for _, h := range PlaneHooksHere(m) {
		out = append(out, h.Program(m))
	}
	return append(out, PlaneExecPinProgram(m))
}

// PlanePrograms lists one mode's program names in PlaneHooks order.
func PlanePrograms(m PlaneMode) []string {
	out := make([]string, 0, len(PlaneHooks))
	for _, h := range PlaneHooks {
		out = append(out, h.Program(m))
	}
	return out
}

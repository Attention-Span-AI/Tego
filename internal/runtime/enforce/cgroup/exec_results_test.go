// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"testing"

	bindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestExecResultPermissionFallbackRetainsSupervisorOwnership(t *testing.T) {
	for _, name := range []string{bindings.ProgExecResult, bindings.ProgExecatResult, bindings.ProgSchedExec, bindings.ProgConnect4} {
		for _, err := range []error{unix.EPERM, unix.EACCES, link.ErrNotSupported, unix.EINVAL, unix.EIO} {
			got := sharedAttachFailure(name, fmt.Errorf("cannot create bpf perf link: %w", err))
			want := (name == bindings.ProgExecResult || name == bindings.ProgExecatResult) && (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, link.ErrNotSupported))
			if errors.Is(got, errExecResultLinkUnavailable) != want || !errors.Is(got, err) || errors.Is(got, ErrProgramLoad) == want {
				t.Fatalf("%s err=%v: %v want optional=%v", name, err, got, want)
			}
			k := &bpfKernel{progs: map[string]*ebpf.Program{bindings.ProgExecResult: {}, bindings.ProgExecatResult: {}}, execResultLinks: map[string]bool{bindings.ProgExecResult: true}}
			if k.execOutcomes() {
				t.Fatal("one linked outcome hook falsely enables exec ownership handoff")
			}
			// Only sharedAttachFailure marks the actual attach error. A pin or
			// adoption error does not acquire the fallback marker by errno.
			for _, phase := range []string{"pin", "adopt"} {
				unmarked := fmt.Errorf("%w: %s optional link: %w", ErrProgramLoad, phase, err)
				if errors.Is(unmarked, errExecResultLinkUnavailable) {
					t.Fatalf("%s failure swallowed: %v", phase, unmarked)
				}
			}
		}
	}
}

func TestExecResultLibraryPermissionFallbackRetainsSupervisorOwnership(t *testing.T) {
	for _, name := range []string{bindings.ProgExecResult, bindings.ProgExecatResult, bindings.ProgSchedExec, bindings.ProgConnect4} {
		for _, errno := range []error{unix.EPERM, unix.EACCES, unix.EINVAL, unix.EIO} {
			// Exact v0.22.0 library formatting, including the absence of %w.
			libraryErr := fmt.Errorf("cannot create bpf perf link: %v", errno)
			if errors.Is(libraryErr, errno) {
				t.Fatal("fixture must reproduce the library's lost errno")
			}
			got := sharedAttachFailure(name, libraryErr)
			want := (name == bindings.ProgExecResult || name == bindings.ProgExecatResult) && (errno == unix.EPERM || errno == unix.EACCES)
			if errors.Is(got, errExecResultLinkUnavailable) != want || !errors.Is(got, libraryErr) || errors.Is(got, ErrProgramLoad) == want {
				t.Fatalf("%s err=%v: %v want optional=%v", name, libraryErr, got, want)
			}
			for _, phase := range []string{"pin", "adopt", "load"} {
				unmarked := fmt.Errorf("%w: %s optional object: %w", ErrProgramLoad, phase, libraryErr)
				if errors.Is(unmarked, errExecResultLinkUnavailable) || !errors.Is(unmarked, ErrProgramLoad) {
					t.Fatalf("non-attachment failure swallowed: %v", unmarked)
				}
			}
		}
		for _, err := range []error{
			errors.New("permission denied"),
			fmt.Errorf("unrelated operation: %w", errors.New("cannot create bpf perf link: permission denied")),
			errors.New("cannot create bpf perf link: permission denied; unrelated failure"),
		} {
			if got := sharedAttachFailure(name, err); errors.Is(got, errExecResultLinkUnavailable) || !errors.Is(got, ErrProgramLoad) {
				t.Fatalf("unrelated error hidden: %s %v: %v", name, err, got)
			}
		}
	}
}

func TestExecOutcomeSelectionRequiresBothSyscallHooks(t *testing.T) {
	for _, missing := range []string{"", "sys_exit_execve", "sys_exit_execveat", "both"} {
		spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
			bindings.ProgExecResult: {}, bindings.ProgExecatResult: {}, bindings.ProgSchedExec: {},
		}}
		dropExecResultsWhereAbsent(spec, func(event string) bool { return missing != "both" && event != missing })
		k := &bpfKernel{progs: map[string]*ebpf.Program{}, execResultLinks: map[string]bool{}}
		for name := range spec.Programs {
			k.progs[name] = &ebpf.Program{}
			k.execResultLinks[name] = true
		}
		if k.execOutcomes() != (missing == "") {
			t.Fatalf("missing %q: complete=%v", missing, k.execOutcomes())
		}
		if spec.Programs[bindings.ProgSchedExec] == nil {
			t.Fatal("optional selection removed successful exec recorder")
		}
	}
}

func TestExecResultLinkFallbackRetainsObjectAdoption(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}}
	for _, name := range bindings.TracePrograms {
		spec.Programs[name] = &ebpf.ProgramSpec{}
	}
	links := sharedLinksOf(bindings.ObjectTraceProc, spec)
	if len(links) != len(bindings.TracePrograms)-len(bindings.ExecResultTracepoints) {
		t.Fatalf("required shared links: %v", links)
	}
	for _, name := range links {
		if _, optional := bindings.ExecResultTracepoints[name]; optional {
			t.Fatalf("optional non-pinnable hook prevents adoption: %s", name)
		}
	}
	k := &bpfKernel{progs: map[string]*ebpf.Program{bindings.ProgExecResult: {}, bindings.ProgExecatResult: {}}}
	if k.execOutcomes() {
		t.Fatal("loaded programs without pinned links enabled handoff")
	}
}

// TestAttachRefusalIsNotAnOptionalLinkFallback: what bpf.AttachTrace refuses before it asks the kernel, a program of
// another type than its attach kind and a program that was never loaded, is a failed load whichever program it names.
// sharedAttachFailure turns an exec-result program's attach error into the optional-link fallback only when the
// machine refuses the perf link, so a wrong type on sys_exit_execve is a bug in the object, never a quieter run.
func TestAttachRefusalIsNotAnOptionalLinkFallback(t *testing.T) {
	for _, name := range []string{bindings.ProgExecResult, bindings.ProgExecatResult, bindings.ProgBindResult, bindings.ProgSchedExec} {
		for _, prog := range []*ebpf.Program{nil, {}} {
			l, err := bindings.AttachTrace(name, prog)
			if l != nil || !errors.Is(err, bindings.ErrAttachRefused) {
				t.Fatalf("AttachTrace(%s, %v) = %v, %v, want ErrAttachRefused", name, prog, l, err)
			}
			got := sharedAttachFailure(name, err)
			if errors.Is(got, errExecResultLinkUnavailable) || !errors.Is(got, ErrProgramLoad) || !errors.Is(got, bindings.ErrAttachRefused) {
				t.Fatalf("%s: the refusal %q became %q, want a failed load that keeps the refusal", name, err, got)
			}
		}
	}
}

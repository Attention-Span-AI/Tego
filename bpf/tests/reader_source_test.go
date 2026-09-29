// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// kernelReadRe matches a call that reads kernel memory through a helper lockdown=confidentiality refuses at load:
// bpf_probe_read_kernel and its _str, the legacy bpf_probe_read and its _str, and libbpf's BPF_CORE_READ family,
// which expands to bpf_probe_read_kernel. bpf_probe_read_user is not refused and does not match.
var kernelReadRe = regexp.MustCompile(`\b(bpf_probe_read_kernel(_str)?|bpf_probe_read(_str)?|BPF_CORE_READ[A-Z_]*|bpf_core_read(_str)?)\s*\(`)

// readerBuild returns src as the preprocessor leaves it with TEGO_TRACE_RDONLY set to rdonly, for the conditionals
// on that macro alone: `#if TEGO_TRACE_RDONLY`, `#if !TEGO_TRACE_RDONLY` and `#ifndef TEGO_TRACE_RDONLY` (the
// default, which gen.go's -D always overrides) with their #else and #endif. Any other conditional is kept whole.
// Directive lines themselves are dropped.
func readerBuild(t *testing.T, src string, rdonly bool) string {
	t.Helper()
	type frame struct{ ours, active bool }
	var stack []frame
	active := func() bool {
		for _, f := range stack {
			if !f.active {
				return false
			}
		}
		return true
	}
	var out strings.Builder
	for i, line := range strings.Split(src, "\n") {
		d := strings.Join(strings.Fields(line), " ")
		switch {
		case d == "#if TEGO_TRACE_RDONLY":
			stack = append(stack, frame{true, rdonly})
		case d == "#if !TEGO_TRACE_RDONLY":
			stack = append(stack, frame{true, !rdonly})
		case d == "#ifndef TEGO_TRACE_RDONLY":
			stack = append(stack, frame{true, false})
		case strings.HasPrefix(d, "#if"):
			stack = append(stack, frame{false, true})
		case strings.HasPrefix(d, "#el"):
			if len(stack) == 0 {
				t.Fatalf("line %d: %s with no #if", i+1, d)
			}
			if d != "#else" && stack[len(stack)-1].ours {
				t.Fatalf("line %d: %s on TEGO_TRACE_RDONLY; this reader knows #else only", i+1, d)
			}
			if stack[len(stack)-1].ours {
				stack[len(stack)-1].active = !stack[len(stack)-1].active
			}
		case strings.HasPrefix(d, "#endif"):
			if len(stack) == 0 {
				t.Fatalf("line %d: #endif with no #if", i+1)
			}
			stack = stack[:len(stack)-1]
		default:
			if active() {
				out.WriteString(line)
			}
		}
		out.WriteByte('\n')
	}
	if len(stack) != 0 {
		t.Fatalf("%d conditionals left open", len(stack))
	}
	return out.String()
}

// TestRdonlyBuildReadsNoKernelMemoryThroughAHelper is ADR 0024's tier-2 note at the source: trace_proc's rdonly
// build (TEGO_TRACE_RDONLY=1, tracerd) calls no helper lockdown=confidentiality refuses and no BPF_CORE_READ, and
// cgroup_track and cgroup_net, which have one build, call none at all. The probe build is checked to still make its
// reads, so the reader here is known to select the branches it means to. internal/bpf
// TestNoProbeBuildsMakeNoKernelProbeRead checks the compiled objects the same way.
func TestRdonlyBuildReadsNoKernelMemoryThroughAHelper(t *testing.T) {
	t.Parallel()
	trace := read(t, filepath.Join(sourceDir, "trace_proc.bpf.c"))
	rd := readerBuild(t, trace, true)
	for i, line := range strings.Split(rd, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#define") {
			continue
		}
		if m := kernelReadRe.FindString(line); m != "" {
			t.Errorf("trace_proc.bpf.c:%d: the rdonly build calls %s, which lockdown=confidentiality refuses", i+1, m)
		}
	}
	for _, want := range []string{"bpf_core_cast(", "tego_kstr(", "bpf_get_current_task_btf("} {
		if !strings.Contains(rd, want) {
			t.Errorf("the rdonly build has no %s", want)
		}
	}
	if pr := readerBuild(t, trace, false); !kernelReadRe.MatchString(pr) {
		t.Error("the probe build makes no bpf_probe_read_kernel: this test's reader selects the wrong branches")
	}
	for _, name := range []string{"cgroup_track.bpf.c", "cgroup_net.bpf.c"} {
		for i, line := range strings.Split(read(t, filepath.Join(sourceDir, name)), "\n") {
			if m := kernelReadRe.FindString(line); m != "" {
				t.Errorf("%s:%d calls %s: its one build must load under lockdown=confidentiality", name, i+1, m)
			}
		}
	}
	for _, name := range []string{"maps.h", "common.h", "events.h"} {
		if m := kernelReadRe.FindString(read(t, filepath.Join(sourceDir, "include", name))); m != "" {
			t.Errorf("include/%s calls %s, which every tier-2 object would inherit", name, m)
		}
	}
}

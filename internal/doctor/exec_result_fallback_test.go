// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestExecResultAttachUnavailableDoesNotDemoteTier(t *testing.T) {
	for _, errno := range []error{unix.EPERM, unix.EACCES, link.ErrNotSupported} {
		t.Run(errno.Error(), func(t *testing.T) {
			st := state(nil)
			for i, h := range hooks {
				if h.program != bpfobj.ProgExecResult && h.program != bpfobj.ProgExecatResult {
					continue
				}
				row := hookAttachFailure(h, HookResult{Hook: h.Name, Tier: h.Tier, Object: string(h.object), BTF: true, Loaded: true}, fmt.Errorf("cannot create bpf perf link: %w", errno))
				if !row.Absent || row.Attached || row.OK() || !strings.Contains(row.Detail, "supervisor decides every exec (no fast handover); a failed exec's errno is not recorded") {
					t.Fatalf("optional outcome failure: %+v", row)
				}
				st.hooks[i] = row
			}
			result := programsVerdict(st.hooks)
			st.byID[CheckPrograms] = result
			if !result.OK || result.Fix != "" || !strings.Contains(result.Detail, "optional exec outcome links unavailable") {
				t.Fatalf("D7: %+v", result)
			}
			for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
				if !st.probe()[tier] || len(st.missingHooks(tier)) != 0 {
					t.Fatalf("demoted %s: %+v", tier, st.missingHooks(tier))
				}
			}
		})
	}
}

func TestExecResultLibraryPermissionFailureDoesNotDemoteTier(t *testing.T) {
	for _, errno := range []error{unix.EPERM, unix.EACCES} {
		t.Run(errno.Error(), func(t *testing.T) {
			// cilium/ebpf v0.22.0 attachPerfEventLink formats with %v,
			// so the real attachment error no longer wraps the syscall errno.
			libraryErr := fmt.Errorf("cannot create bpf perf link: %v", errno)
			if errors.Is(libraryErr, errno) {
				t.Fatal("fixture must reproduce the library's lost errno")
			}
			st := state(nil)
			for i, h := range hooks {
				if h.program != bpfobj.ProgExecResult && h.program != bpfobj.ProgExecatResult {
					continue
				}
				row := hookAttachFailure(h, HookResult{Hook: h.Name, Tier: h.Tier, Object: string(h.object), BTF: true, Loaded: true}, libraryErr)
				if !row.Absent || row.Attached || !row.Loaded || row.OK() || !strings.Contains(row.Detail, libraryErr.Error()) {
					t.Fatalf("lost-errno optional failure: %+v", row)
				}
				st.hooks[i] = row
			}
			st.byID[CheckPrograms] = programsVerdict(st.hooks)
			for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
				if !st.byID[CheckPrograms].OK || !st.probe()[tier] || len(st.missingHooks(tier)) != 0 {
					t.Fatalf("lost-errno demoted %s: %+v", tier, st.missingHooks(tier))
				}
			}
		})
	}
}

func TestExecResultFallbackNeverHidesRequiredOrUnexpectedFailure(t *testing.T) {
	for _, h := range hooks {
		for _, err := range []error{unix.EPERM, unix.EACCES, link.ErrNotSupported, unix.EINVAL, unix.EIO, errors.New("broken fixture")} {
			row := hookAttachFailure(h, HookResult{Hook: h.Name, Tier: h.Tier, BTF: true, Loaded: true}, err)
			want := h.program == bpfobj.ProgExecResult || h.program == bpfobj.ProgExecatResult
			want = want && (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, link.ErrNotSupported))
			if row.Absent != want || row.Attached || row.OK() {
				t.Fatalf("%s err=%v: %+v want unavailable=%v", h.Name, err, row, want)
			}
			if !want && programsVerdict([]HookResult{row}).OK {
				t.Fatalf("required/unexpected error hidden: %s %v", h.Name, err)
			}
		}
	}
}

func TestExecResultLibraryFallbackDoesNotMatchPermissionProse(t *testing.T) {
	for _, h := range hooks {
		for _, err := range []error{
			fmt.Errorf("cannot create bpf perf link: %v", unix.EINVAL),
			fmt.Errorf("cannot create bpf perf link: %v", unix.EIO),
			errors.New("permission denied"),
			fmt.Errorf("unrelated operation: %w", errors.New("cannot create bpf perf link: permission denied")),
			errors.New("cannot create bpf perf link: permission denied; unrelated failure"),
		} {
			row := hookAttachFailure(h, HookResult{Hook: h.Name, Tier: h.Tier, BTF: true, Loaded: true}, err)
			if row.Absent || row.OK() || programsVerdict([]HookResult{row}).OK {
				t.Fatalf("unrelated error hidden: %s %v: %+v", h.Name, err, row)
			}
		}
	}
}

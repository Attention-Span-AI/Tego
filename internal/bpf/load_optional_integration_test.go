// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// TestOptionalTraceKernelFloor holds the registered result-hook skips to kernels that predate each hook.
// A backport is still loaded, and absent security_file_truncate keeps its existing selection behavior.
func TestOptionalTraceKernelFloor(t *testing.T) {
	for _, name := range []string{ProgURingBindResult, ProgURingListenResult} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				release string
				lookup  error
				drop    bool
				fail    bool
			}{
				{name: "old-rhel-absent", release: "5.14.0-570.el9.x86_64", lookup: btf.ErrNotFound, drop: true},
				{name: "before-floor-absent", release: "6.10.12", lookup: btf.ErrNotFound, drop: true},
				{name: "at-floor-absent", release: "6.11.0", lookup: btf.ErrNotFound, fail: true},
				{name: "floor-release-candidate-absent", release: "6.11.0-rc1", lookup: btf.ErrNotFound, fail: true},
				{name: "newer-absent", release: "6.17.0-41-generic", lookup: btf.ErrNotFound, fail: true},
				{name: "next-major-absent", release: "7.0.14-200.fc44.x86_64", lookup: btf.ErrNotFound, fail: true},
				{name: "unreadable-release-absent", release: "unknown", lookup: btf.ErrNotFound, fail: true},
				{name: "backport-present", release: "5.14.0-570.el9.x86_64"},
				{name: "at-floor-present", release: "6.11.0"},
				{name: "lookup-error", release: "5.14.0", lookup: unix.EPERM, fail: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{name: {Name: name}}}
					calls := 0
					dropped, err := dropOptionalTracePrograms(spec, tc.release, func(fn string, out any) error {
						calls++
						if fn != OptionalTracePrograms[name] {
							t.Fatalf("probed %s, want %s", fn, OptionalTracePrograms[name])
						}
						if _, ok := out.(**btf.Func); !ok {
							t.Fatalf("probe target is %T, want **btf.Func", out)
						}
						return tc.lookup
					})
					if calls != 1 || (err != nil) != tc.fail || (len(dropped) == 1) != tc.drop {
						t.Fatalf("selection on %s: dropped=%v err=%v probes=%d; want drop=%t fail=%t", tc.release, dropped, err, calls, tc.drop, tc.fail)
					}
					if tc.fail && tc.lookup == btf.ErrNotFound && tc.release != "unknown" && (!strings.Contains(err.Error(), "6.11") || !strings.Contains(err.Error(), OptionalTracePrograms[name])) {
						t.Errorf("missing hook failure omits hook or introduction floor: %v", err)
					}
					if tc.lookup != nil && tc.lookup != btf.ErrNotFound && !errors.Is(err, tc.lookup) {
						t.Errorf("lookup error lost: %v", err)
					}
					if _, present := spec.Programs[name]; present == tc.drop {
						t.Fatalf("program presence=%t, want dropped=%t", present, tc.drop)
					}
				})
			}
		})
	}
	t.Run("truncate-selection-unchanged", func(t *testing.T) {
		spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{ProgFileTruncate: {Name: ProgFileTruncate}}}
		dropped, err := dropOptionalTracePrograms(spec, "7.2.0", func(string, any) error { return btf.ErrNotFound })
		if err != nil || len(dropped) != 1 || dropped[0] != ProgFileTruncate {
			t.Fatalf("pre-existing truncate selection changed: dropped=%v err=%v", dropped, err)
		}
	})
}

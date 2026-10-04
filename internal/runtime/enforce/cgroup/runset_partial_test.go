// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// A kernel whose load failed on cgroup_net holds no run-set handle. The last launcher out (leaveBuild, bpf.linger 0)
// must still see a live orphan through the run set an earlier launcher pinned, and keep the build (ADR 0022 (1)).
func TestPartialKernelRunSetLiveReadsThePin(t *testing.T) {
	pins, err := newPinLayout(t.TempDir(), "hash")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(pins.Maps, ebpfbindings.MapRunSet)
	k := &bpfKernel{pins: pins, maps: map[string]*ebpf.Map{}}
	cases := []struct {
		name     string
		pinned   func(path, mount string) (bool, error)
		wantLive bool
		wantErr  bool
	}{
		{"live orphan", func(string, string) (bool, error) { return true, nil }, true, false},
		{"no live row", func(string, string) (bool, error) { return false, nil }, false, false},
		{"no pin", func(string, string) (bool, error) {
			return false, fmt.Errorf("open its run set: %w", os.ErrNotExist)
		}, false, false},
		{"unreadable pin", func(string, string) (bool, error) {
			return false, errors.New("open its run set: operation not permitted")
		}, false, true},
	}
	saved := pinnedRunSetLiveAt
	t.Cleanup(func() { pinnedRunSetLiveAt = saved })
	for _, c := range cases {
		var got string
		pinnedRunSetLiveAt = func(path, mount string) (bool, error) { got = path; return c.pinned(path, mount) }
		live, err := k.runSetLive("/sys/fs/cgroup")
		if got != want {
			t.Errorf("%s: read the pin at %q, want %q", c.name, got, want)
		}
		if live != c.wantLive || (err != nil) != c.wantErr {
			t.Errorf("%s: runSetLive = %v, %v; want live %v, error %v", c.name, live, err, c.wantLive, c.wantErr)
		}
	}
	// No pin directory at all is not an empty run set.
	if live, err := (&bpfKernel{maps: map[string]*ebpf.Map{}}).runSetLive("/sys/fs/cgroup"); live || err == nil {
		t.Errorf("runSetLive with no handle and no pin directory = %v, %v; want an error", live, err)
	}
}

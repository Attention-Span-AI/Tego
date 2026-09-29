// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// swappingAttacher renames a symlink to another file over target at the first probe it is asked to place,
// which is the traced process's move between capture's parse of a candidate and the kernel's resolution of
// the path it attaches at, and records the file each probe's path names once the swap is done.
type swappingAttacher struct {
	mu            sync.Mutex
	target, decoy string
	swapped       bool
	files         []os.FileInfo
}

func (a *swappingAttacher) Attach(path string, _ Probe) (io.Closer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.swapped {
		a.swapped = true
		tmp := a.target + ".swap"
		if err := os.Symlink(a.decoy, tmp); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, a.target); err != nil {
			return nil, err
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	a.files = append(a.files, fi)
	return &fakeLink{mu: &a.mu}, nil
}

// TestAttachPlacesProbesOnTheFileItParsed covers capture-derive.md R7: the path a traced process named is
// resolved once, and every probe lands on the inode that was identified and parsed. The process renames a
// symlink to a host library over its crafted libssl after the parse; were the attach to resolve the path
// again, the probes would be placed at the crafted file's offsets in the host library, which the launcher,
// as root, would write into for every process on the host.
func TestAttachPlacesProbesOnTheFileItParsed(t *testing.T) {
	tree := newProcTree(t)
	host, lib := sharedRootTree(t, tree, []int{71}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	target := filepath.Join(host, lib)
	parsed, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	decoy := writeELF(t, elfOptions{Dynamic: map[string]uint64{"memcpy": 0x1200}})
	att := &swappingAttacher{target: target, decoy: decoy}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnOpen(71, 41, lib)
	att.mu.Lock()
	files := append([]os.FileInfo(nil), att.files...)
	att.mu.Unlock()
	if len(files) != 3 {
		t.Fatalf("%d probes placed, want 3", len(files))
	}
	for i, fi := range files {
		if !os.SameFile(fi, parsed) {
			t.Errorf("probe %d placed on %s, not on the libssl that was parsed", i, fi.Name())
		}
	}
	u.OnExit(71)
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

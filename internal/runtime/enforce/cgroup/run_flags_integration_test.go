// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/cilium/ebpf"
)

func TestOldRunMembershipMapIsNotAdopted(t *testing.T) {
	requireBPFCaps(t)
	if err := checkBPFFS(DefaultBPFFS); err != nil {
		t.Skipf("private pinned map requires bpffs: %v", err)
	}
	dir, err := os.MkdirTemp(DefaultBPFFS, "tego-it-old-run-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	spec := &ebpf.MapSpec{Name: bpf.MapRunSet, Type: ebpf.Hash, KeySize: 8,
		ValueSize: uint32(unsafe.Sizeof(bpf.Run{})), MaxEntries: 16, Pinning: ebpf.PinByName}
	oldSpec := spec.Copy()
	oldSpec.Pinning, oldSpec.ValueSize = ebpf.PinNone, 12
	old, err := ebpf.NewMap(oldSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := old.Pin(filepath.Join(dir, bpf.MapRunSet)); err != nil {
		t.Fatal(err)
	}
	coll, adopted := adoptObjectIn(pinLayout{Maps: dir}, &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{bpf.MapRunSet: spec},
	}, nil, nil)
	if adopted || coll != nil {
		if coll != nil {
			coll.Close()
		}
		t.Fatal("legacy 12-byte membership was adopted as flagged 16-byte membership")
	}
	created, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: dir})
	if created != nil {
		created.Close()
		t.Fatal("an incompatible existing membership map was silently replaced")
	}
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		t.Fatalf("loading over the old pinned map must fail closed with map shape mismatch: %v", err)
	}
}

// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// Force real insertion failures with record off. The durable status must survive both a missing ring and
// ring exhaustion, and the original event still carries the precise error whenever there is room.
func TestTrackingFailureEmittedWithRecordOff(t *testing.T) {
	requireBPF(t)
	for _, tc := range []struct {
		name     string
		ring     bool
		children int
	}{
		{"ring-present", true, 1},
		{"ring-absent", false, 1},
		{"ring-full", true, 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := Load(ObjectCgroupTrack)
			if err != nil {
				t.Fatal(err)
			}
			unpin(spec)
			spec.Maps[MapRunSet].MaxEntries = 1
			coll, err := ebpf.NewCollection(spec)
			if err != nil {
				t.Fatal(err)
			}
			defer coll.Close()
			slot := uint32(1)
			var rd *ringbuf.Reader
			if tc.ring {
				ring, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 4096})
				if err != nil {
					t.Fatal(err)
				}
				defer ring.Close()
				if err := coll.Maps[MapEvents].Update(&slot, ring, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				rd, err = ringbuf.NewReader(ring)
				if err != nil {
					t.Fatal(err)
				}
				defer rd.Close()
			}
			root := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("tego-track-fail-%d-%s", os.Getpid(), tc.name))
			if err := os.Mkdir(root, 0755); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(root)
			st, err := os.Stat(root)
			if err != nil {
				t.Fatal(err)
			}
			parent := st.Sys().(*syscall.Stat_t).Ino
			row := Run{RunIdx: slot, Gen: 1, Descendants: 1, Record: uint8(RecordOff)}
			if err := coll.Maps[MapRunSet].Update(&parent, &row, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			hook, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs["tego_cgroup_mkdir"]})
			if err != nil {
				t.Fatal(err)
			}
			defer hook.Close()
			for i := range tc.children {
				child := filepath.Join(root, fmt.Sprintf("child-%d", i))
				if err := os.Mkdir(child, 0755); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(child)
			}
			count, err := SlotCount(coll.Maps[MapTrackingFailed], slot)
			if err != nil || count != uint64(tc.children) {
				t.Fatalf("durable failures=%d want=%d err=%v", count, tc.children, err)
			}
			other, err := SlotCount(coll.Maps[MapTrackingFailed], slot+1)
			if err != nil || other != 0 {
				t.Fatalf("other slot=%d err=%v", other, err)
			}
			if !tc.ring || tc.children > 1 {
				lost, err := SlotCount(coll.Maps[MapLost], slot)
				if err != nil || lost == 0 {
					t.Fatalf("fixture did not drop any ring records: %d %v", lost, err)
				}
			}
			if rd != nil {
				rd.SetDeadline(time.Now().Add(2 * time.Second))
				raw, err := rd.Read()
				if err != nil {
					t.Fatalf("tracking failure was not emitted under record: off: %v", err)
				}
				var got CgroupEvent
				if err := binary.Read(bytes.NewReader(raw.RawSample), binary.NativeEndian, &got); err != nil {
					t.Fatal(err)
				}
				if got.Err != -int32(unix.E2BIG) || got.ParentCgroupID != parent || got.ChildCgroupID == 0 || got.Hdr.RunIdx != slot {
					t.Fatalf("failure event: %+v", got)
				}
			}
			if err := ZeroSlot(coll.Maps[MapTrackingFailed], slot); err != nil {
				t.Fatal(err)
			}
			count, err = SlotCount(coll.Maps[MapTrackingFailed], slot)
			if err != nil || count != 0 {
				t.Fatalf("reuse did not clear failures: %d %v", count, err)
			}
		})
	}
}

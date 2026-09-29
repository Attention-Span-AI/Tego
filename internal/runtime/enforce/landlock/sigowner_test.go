// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"golang.org/x/net/bpf"
)

// TestSignalArmCoversIoctlSetown: below ABI 6 the signal arm decided fcntl's F_SETOWN and F_SETOWN_EX, while ioctl
// FIOSETOWN and SIOCSPGRP set the same owner record (sock_ioctl -> f_setown) and were allowed unseen. They are
// notified now; any other ioctl is not.
func TestSignalArmCoversIoctlSetown(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		insts, err := buildFilter(arch, filterOpts{abi: 4, signals: true})
		if err != nil {
			t.Fatal(err)
		}
		vm, err := bpf.NewVM(insts)
		if err != nil {
			t.Fatal(err)
		}
		for req, want := range map[uint64]uint32{0x8901: retNotify, 0x8902: retNotify, 0x541B: retAllow} {
			got, err := vm.Run(seccompData(arch, tab.Ioctl, 3, req, 0x1000))
			if err != nil {
				t.Fatal(err)
			}
			if uint32(got) != want {
				t.Errorf("%s ioctl %#x: %#x, want %#x", arch, req, got, want)
			}
		}
	}
}

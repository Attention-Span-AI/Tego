// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"golang.org/x/sys/unix"
)

// Run the emitted program over real ABI register layouts on both supported
// architectures. This is the instruction VM, not a privileged kernel launch.
func TestListenerAdmissionAndNoPortBindFilterBothArchitectures(t *testing.T) {
	for _, abi := range []struct {
		arch                         Arch
		bind, listen, option, getpid uint32
	}{{ArchX86_64, 49, 50, 54, 39}, {ArchARM64, 200, 201, 208, 172}} {
		t.Run(abi.arch.String(), func(t *testing.T) {
			tab, err := tableFor(abi.arch)
			if err != nil {
				t.Fatal(err)
			}
			if tab.Bind != abi.bind || tab.Listen != abi.listen || tab.Setsockopt != abi.option {
				t.Fatalf("incorrect syscall ABI bind/listen/setsockopt: %+v", tab)
			}
			controlled := filterOpts{abi: 10, listenControl: true, ingress: true}
			for _, call := range []uint32{abi.bind, abi.listen} {
				if got := planeVerdict(t, abi.arch, controlled, call, 3, 0x1234, 16); got != retNotify {
					t.Fatalf("controlled syscall%d got %#x want notify", call, got)
				}
				if got := planeVerdict(t, abi.arch, filterOpts{abi: 10}, call, 3, 0x1234, 16); got != retAllow {
					t.Fatalf("legacy syscall%d got %#x want allow", call, got)
				}
			}
			// The unix-only state, which has no net: section: bind alone is notified, for the supervisor's record of
			// the run's own unix sockets (supervisor R11a), and listen stays the kernel's. Every net: section is
			// controlled above, a listener policy or none (TestPrepareNotifiesListenUnderANetSection).
			binds := filterOpts{abi: 10, unixBinds: true}
			if got := planeVerdict(t, abi.arch, binds, abi.bind, 3, 0x1234, 16); got != retNotify {
				t.Fatalf("bind under unixBinds got %#x want notify", got)
			}
			if got := planeVerdict(t, abi.arch, binds, abi.listen, 3, 8); got != retAllow {
				t.Fatalf("listen under unixBinds got %#x want allow", got)
			}
			for _, tc := range []struct {
				name          string
				level, option uint64
				want          uint32
			}{
				{"deferred port", unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT, retEPERM},
				{"kernel int truncation", uint64(1)<<32 | unix.IPPROTO_IP, uint64(1)<<32 | unix.IP_BIND_ADDRESS_NO_PORT, retEPERM},
				{"socket keepalive", unix.SOL_SOCKET, unix.SO_KEEPALIVE, retAllow},
				{"same option on other level", unix.IPPROTO_IPV6, unix.IP_BIND_ADDRESS_NO_PORT, retAllow},
				{"ordinary IPv4 option", unix.IPPROTO_IP, unix.IP_TTL, retAllow},
				{"negative level", uint64(^uint32(0)), unix.IP_BIND_ADDRESS_NO_PORT, retAllow},
			} {
				if got := planeVerdict(t, abi.arch, controlled, abi.option, 3, tc.level, tc.option, 0x9876, 4); got != tc.want {
					t.Fatalf("%s got %#x want %#x", tc.name, got, tc.want)
				}
			}
			if got := planeVerdict(t, abi.arch, filterOpts{abi: 10}, abi.option, 3, unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT, 0x9876, 4); got != retAllow {
				t.Fatalf("legacy option got %#x want allow", got)
			}
			if got := planeVerdict(t, abi.arch, controlled, abi.getpid, 3, unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT); got != retAllow {
				t.Fatalf("guard changed unrelated syscall: %#x", got)
			}
			if got := planeVerdict(t, abi.arch, controlled, tab.Notify[0].NR, 3, unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT); got != retNotify {
				t.Fatalf("guard lost accumulator before later connect check: %#x", got)
			}
			strict := controlled
			strict.strictNet = true
			if got := planeVerdict(t, abi.arch, strict, abi.listen, 3, 8); got != retENOSYS {
				t.Fatalf("strict client listener became available: %#x", got)
			}
			strict.listenersAllowed = true
			if got := planeVerdict(t, abi.arch, strict, abi.listen, 3, 8); got != retNotify {
				t.Fatalf("declared strict listener lost notification: %#x", got)
			}
			for _, denied := range tab.ClientDeny {
				want := uint32(retENOSYS)
				if denied.Name == "listen" {
					want = retNotify
				}
				if denied.Name == "accept" || denied.Name == "accept4" {
					want = retAllow
				}
				if got := planeVerdict(t, abi.arch, strict, denied.NR); got != want {
					t.Fatalf("declared listener altered %s import/admission: got%#x want%#x", denied.Name, got, want)
				}
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSocketTripleNamesMatchKernelConstants pins record.SocketTriple's numeric tables to the kernel's constants,
// which the plane and the supervisor both name through it.
func TestSocketTripleNamesMatchKernelConstants(t *testing.T) {
	for fam, name := range map[int32]string{
		unix.AF_UNSPEC: "AF_UNSPEC", unix.AF_UNIX: "AF_UNIX", unix.AF_INET: "AF_INET", unix.AF_INET6: "AF_INET6",
		unix.AF_NETLINK: "AF_NETLINK", unix.AF_PACKET: "AF_PACKET", unix.AF_TIPC: "AF_TIPC", unix.AF_VSOCK: "AF_VSOCK",
		unix.AF_RDS: "AF_RDS", unix.AF_SMC: "AF_SMC", unix.AF_XDP: "AF_XDP", unix.AF_ALG: "AF_ALG",
		unix.AF_BLUETOOTH: "AF_BLUETOOTH", unix.AF_CAN: "AF_CAN", unix.AF_KCM: "AF_KCM", unix.AF_QIPCRTR: "AF_QIPCRTR",
	} {
		if got := record.SocketTriple(fam, unix.SOCK_STREAM, 0); !strings.HasPrefix(got, name+" ") {
			t.Errorf("family %d = %q, want prefix %s", fam, got, name)
		}
	}
	for typ, name := range map[int32]string{
		unix.SOCK_STREAM: "SOCK_STREAM", unix.SOCK_DGRAM: "SOCK_DGRAM", unix.SOCK_RAW: "SOCK_RAW",
		unix.SOCK_RDM: "SOCK_RDM", unix.SOCK_SEQPACKET: "SOCK_SEQPACKET", unix.SOCK_DCCP: "SOCK_DCCP",
		unix.SOCK_PACKET: "SOCK_PACKET",
	} {
		if got := record.SocketTriple(unix.AF_INET, typ, 0); got != "AF_INET "+name+" protocol 0" {
			t.Errorf("type %d = %q, want %s", typ, got, name)
		}
	}
}

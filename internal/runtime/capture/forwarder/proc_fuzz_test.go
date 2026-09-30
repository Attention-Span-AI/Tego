// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"net/netip"
	"strings"
	"testing"
)

// FuzzProcNetParsers feeds the three parsers of /proc text the peer lookup reads (a /proc/net/tcp table, one of its
// address cells, and /proc/self/mountinfo) arbitrary bytes. None may panic, a table hit never carries inode 0
// (which would match any non-socket descriptor of the run), and a cell that parses names a valid address.
func FuzzProcNetParsers(f *testing.F) {
	f.Add("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n")
	f.Add("h\n 0: 0100007F:1F90 0100007F:C350 01 a b c d e f 0\n")
	f.Add("h\n 0: 0100007F:1F90 0100007F:C350 01 a b c d e f -1\n")
	f.Add("0100007F:1F90")
	f.Add("00000000000000000000000001000000:0050")
	f.Add("36 35 0:30 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw\n")
	f.Add("36 35 0:30 /a\\040b /x\\134y rw - cgroup2 cgroup2 rw\n")
	f.Add(" - \n")
	f.Fuzz(func(t *testing.T, s string) {
		peer := netip.MustParseAddrPort("127.0.0.1:8080")
		local := netip.MustParseAddrPort("127.0.0.1:50000")
		if ino, ok, err := scanTCPTable(strings.NewReader(s), peer, local); ok && (err != nil || ino == 0) {
			t.Fatalf("scanTCPTable hit with inode %d err %v", ino, err)
		}
		if ap, ok := parseProcAddrPort(s); ok && !ap.IsValid() {
			t.Fatalf("parseProcAddrPort(%q) ok with invalid %v", s, ap)
		}
		if p, ok := parseCgroup2Mount(s); !ok && p != "" {
			t.Fatalf("parseCgroup2Mount(%q) miss with path %q", s, p)
		}
	})
}

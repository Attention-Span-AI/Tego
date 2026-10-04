// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// FuzzParseAuditReply feeds the audit netlink parser arbitrary datagrams. It must never panic, and a datagram it
// reports as not done carries no status and no error.
func FuzzParseAuditReply(f *testing.F) {
	ne := binary.NativeEndian
	msg := func(typ uint16, seq uint32, data []byte) []byte {
		m := make([]byte, 16+len(data))
		ne.PutUint32(m, uint32(len(m)))
		ne.PutUint16(m[4:], typ)
		ne.PutUint32(m[8:], seq)
		copy(m[16:], data)
		return m
	}
	f.Add(msg(unix.AUDIT_GET, auditGetSeq, make([]byte, 40)))
	f.Add(msg(unix.NLMSG_ERROR, auditGetSeq, []byte{0xff, 0xff, 0xff, 0xff}))
	f.Add(msg(unix.NLMSG_ERROR, auditGetSeq, []byte{1}))
	f.Add(msg(unix.AUDIT_GET, 7, make([]byte, 40)))
	f.Add(msg(unix.AUDIT_GET, auditGetSeq, make([]byte, 3)))
	f.Add([]byte{0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		st, done, err := parseAuditReply(b)
		if !done && (err != nil || st != (auditStatus{})) {
			t.Fatalf("not done but st=%+v err=%v", st, err)
		}
		if err != nil && st != (auditStatus{}) {
			t.Fatalf("error %v with status %+v", err, st)
		}
	})
}

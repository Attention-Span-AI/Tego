// SPDX-License-Identifier: Apache-2.0

package dnsbroker

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func FuzzDNSWireBoundaries(f *testing.F) {
	name, _ := dnsmessage.NewName("allowed.example.")
	q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 1}, Questions: []dnsmessage.Question{q}}
	raw, _ := m.Pack()
	f.Add(raw)
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Add(append(append([]byte(nil), raw...), 0))
	f.Add(testResponse(raw, false))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = queryMessage(raw)
		_, _, _ = responseMessage(raw, 1, q)
	})
}

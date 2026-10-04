// SPDX-License-Identifier: Apache-2.0

package dnsbroker

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

const MaxPacket = 4096

type ttlField struct {
	offset int
	value  uint32
}

// scanWire also rejects trailing bytes. Compression pointers must point to an
// earlier part of the message; Unpack separately validates their decoded names.
func scanWire(raw []byte) ([]ttlField, error) {
	if len(raw) < 12 || len(raw) > MaxPacket || raw[3]&0x40 != 0 {
		return nil, ErrProtocol
	}
	off := 12
	name := func() error {
		for labels := 0; labels < 128; labels++ {
			if off >= len(raw) {
				return ErrProtocol
			}
			n := int(raw[off])
			off++
			if n == 0 {
				return nil
			}
			if n&0xc0 == 0xc0 {
				if off >= len(raw) {
					return ErrProtocol
				}
				ptr := (n&0x3f)<<8 | int(raw[off])
				off++
				if ptr < 12 || ptr >= off-2 {
					return ErrProtocol
				}
				return nil
			}
			if n > 63 || off+n > len(raw) {
				return ErrProtocol
			}
			off += n
		}
		return ErrProtocol
	}
	questions := int(binary.BigEndian.Uint16(raw[4:6]))
	if questions != 1 {
		return nil, ErrProtocol
	}
	if err := name(); err != nil || off+4 > len(raw) {
		return nil, ErrProtocol
	}
	off += 4
	count := 0
	for i := 6; i < 12; i += 2 {
		count += int(binary.BigEndian.Uint16(raw[i : i+2]))
	}
	if count > 256 {
		return nil, ErrProtocol
	}
	var fields []ttlField
	for i := 0; i < count; i++ {
		if err := name(); err != nil || off+10 > len(raw) {
			return nil, ErrProtocol
		}
		typ := binary.BigEndian.Uint16(raw[off : off+2])
		if typ != uint16(dnsmessage.TypeOPT) {
			fields = append(fields, ttlField{off + 4, binary.BigEndian.Uint32(raw[off+4 : off+8])})
		}
		n := int(binary.BigEndian.Uint16(raw[off+8 : off+10]))
		off += 10
		if n > len(raw)-off {
			return nil, ErrProtocol
		}
		off += n
	}
	if off != len(raw) {
		return nil, ErrProtocol
	}
	return fields, nil
}

func queryMessage(raw []byte) (dnsmessage.Message, error) {
	var m dnsmessage.Message
	if _, err := scanWire(raw); err != nil {
		return m, err
	}
	if err := m.Unpack(raw); err != nil {
		return m, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if m.Response || m.OpCode != 0 || m.Truncated || m.RCode != 0 || m.Authoritative || m.RecursionAvailable || m.AuthenticData ||
		len(m.Questions) != 1 || len(m.Answers) != 0 || len(m.Authorities) != 0 || len(m.Additionals) > 1 || m.Questions[0].Class != dnsmessage.ClassINET {
		return m, ErrProtocol
	}
	if _, err := dnspolicy.CanonicalName(m.Questions[0].Name.String()); err != nil {
		return m, ErrProtocol
	}
	for _, r := range m.Additionals {
		opt, ok := r.Body.(*dnsmessage.OPTResource)
		if !ok || r.Header.Type != dnsmessage.TypeOPT || r.Header.Name.String() != "." || uint16(r.Header.Class) < 512 || uint16(r.Header.Class) > MaxPacket || r.Header.TTL & ^uint32(0x8000) != 0 || len(opt.Options) != 0 {
			return m, ErrProtocol
		}
	}
	return m, nil
}

func responseMessage(raw []byte, id uint16, q dnsmessage.Question) (dnsmessage.Message, []ttlField, error) {
	var m dnsmessage.Message
	fields, err := scanWire(raw)
	if err != nil {
		return m, nil, err
	}
	if err = m.Unpack(raw); err != nil {
		return m, nil, ErrProtocol
	}
	if !m.Response || m.OpCode != 0 || m.ID != id || len(m.Questions) != 1 || m.Questions[0].Type != q.Type || m.Questions[0].Class != q.Class || !strings.EqualFold(m.Questions[0].Name.String(), q.Name.String()) {
		return m, nil, ErrProtocol
	}
	return m, fields, nil
}

func errorReply(q dnsmessage.Message, code dnsmessage.RCode) []byte {
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RCode: code}, Questions: q.Questions}
	b, _ := m.Pack()
	return b
}

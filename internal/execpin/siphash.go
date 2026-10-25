// SPDX-License-Identifier: Apache-2.0

// Package execpin holds the userspace half of ADR 0048 P2's exec pins: the keyed MAC the supervisor writes into a pin
// and the decision plane recomputes over the kernel's own copy of argv (bpf/include/exec_pin.h is the other half).
// It imports the standard library only, so the supervisor (depguard supervisor-imports) and the tests both use it.
package execpin

import (
	"encoding/binary"
	"math/bits"
)

// The MAC domains (ADR 0048 (3) "MACs"): the one byte that starts every MAC input, so a MAC of one kind can never
// stand for another. bpf/include/exec_pin.h names the same values (TEGO_PIN_DOM_*).
const (
	DomainCovered byte = 1 // the covered prefix of a direct vector: the first k NUL-terminated strings
	DomainScript  byte = 2 // the whole vector binfmt_script maps: [interp, arg?, filename, argv[1:]...]
	DomainTail    byte = 3 // an unknown-form exec's tail: the filename binfmt puts in front of argv[1:], then argv[1:]
	DomainName    byte = 4 // the image's final name, as its dentry holds it
	DomainPath    byte = 5 // bprm->filename: the spelling the kernel looked the image up by
)

// Key is a run's 128-bit MAC key. It is generated with getrandom, handed to the supervisor and the plane's key array,
// and never written to the ledger, the run directory or a log.
type Key [16]byte

// MAC is SipHash-2-4 under k over the framed input: the domain byte, data's length as 4 little-endian bytes, then
// data. The length is framed as well as compared apart, so no two inputs of different lengths share a MAC input.
func MAC(k Key, domain byte, data []byte) uint64 {
	var hdr [5]byte
	hdr[0] = domain
	binary.LittleEndian.PutUint32(hdr[1:], uint32(len(data)))
	return sum64(k, hdr[:], data)
}

// sum64 hashes the concatenation of a and b without copying them.
func sum64(k Key, a, b []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(k[0:8])
	k1 := binary.LittleEndian.Uint64(k[8:16])
	s := state{
		v0: k0 ^ 0x736f6d6570736575,
		v1: k1 ^ 0x646f72616e646f6d,
		v2: k0 ^ 0x6c7967656e657261,
		v3: k1 ^ 0x7465646279746573,
	}
	var acc uint64
	n := 0 // bytes held in acc
	total := len(a) + len(b)
	for _, part := range [2][]byte{a, b} {
		for _, c := range part {
			acc |= uint64(c) << (8 * n)
			n++
			if n == 8 {
				s.compress(acc)
				acc, n = 0, 0
			}
		}
	}
	last := acc | uint64(total&0xff)<<56
	s.compress(last)
	s.v2 ^= 0xff
	s.round()
	s.round()
	s.round()
	s.round()
	return s.v0 ^ s.v1 ^ s.v2 ^ s.v3
}

type state struct{ v0, v1, v2, v3 uint64 }

// compress absorbs one message word with SipHash's two c-rounds.
func (s *state) compress(m uint64) {
	s.v3 ^= m
	s.round()
	s.round()
	s.v0 ^= m
}

func (s *state) round() {
	s.v0 += s.v1
	s.v1 = bits.RotateLeft64(s.v1, 13)
	s.v1 ^= s.v0
	s.v0 = bits.RotateLeft64(s.v0, 32)
	s.v2 += s.v3
	s.v3 = bits.RotateLeft64(s.v3, 16)
	s.v3 ^= s.v2
	s.v0 += s.v3
	s.v3 = bits.RotateLeft64(s.v3, 21)
	s.v3 ^= s.v0
	s.v2 += s.v1
	s.v1 = bits.RotateLeft64(s.v1, 17)
	s.v1 ^= s.v2
	s.v2 = bits.RotateLeft64(s.v2, 32)
}

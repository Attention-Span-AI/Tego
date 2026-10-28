// SPDX-License-Identifier: Apache-2.0

package mcpact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// ackDomain separates this acknowledgement from every other HMAC the key could make.
const ackDomain = "tego-mcp-ack-v1"

// ErrAck is a loosening whose acknowledgement is missing, stale or not this process's.
var ErrAck = errors.New("mcpact: this change needs the preview's acknowledgement, and the one sent is missing or out of date")

var (
	keyOnce sync.Once
	procKey [32]byte
)

// key is this process's random acknowledgement key: an acknowledgement does not outlive the dashboard that made it.
func key() []byte {
	keyOnce.Do(func() {
		_, _ = rand.Read(procKey[:]) // never fails: since Go 1.24 crypto/rand crashes the program itself instead
	})
	return procKey[:]
}

// ackOf binds a change to the overlay it was previewed against (base: the overlay file's sha256, "" for none).
func ackOf(run, server, tool, decision, base string) string {
	m := hmac.New(sha256.New, key())
	for _, s := range []string{ackDomain, run, server, tool, decision, base} {
		m.Write([]byte(s))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))
}

// ackOK reports whether ack is the acknowledgement of this change against this base.
func ackOK(ack, run, server, tool, decision, base string) bool {
	want := ackOf(run, server, tool, decision, base)
	return hmac.Equal([]byte(ack), []byte(want))
}

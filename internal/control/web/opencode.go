// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/subtle"
	"time"
)

// The one-time open code (SEC-4). `serve --open` hands its address to a browser opener ($BROWSER, xdg-open) as an
// argument, and a browser the opener starts keeps that argument in /proc/<pid>/cmdline for as long as it runs. The
// sign-in token (?t=) works any number of times for the server's life, so in argv it would stay a working key. The
// opener gets a separate code instead (?o=<32 hex>): it signs in once, within openCodeTTL, and is then gone; the
// ?t= link the person reads stays on serve's standard output only. Other uids are refused before either is looked
// at (peer.go), and a governed agent may not sign in with either (governed.go).

// openCodeTTL is how long an unused open code signs in: long enough for a browser to start cold, short enough
// that a code read later from a process list is dead.
const openCodeTTL = 60 * time.Second

// maxOpenCodes bounds the codes waiting to be used; minting one more drops the oldest.
const maxOpenCodes = 8

// openCode is one minted code and when it stops signing in.
type openCode struct {
	code  string
	until time.Time
}

// OpenURL is the address `serve --open` gives the browser opener: this server with a fresh one-time code that signs
// in once, within a minute (openCodeTTL). URL is the reusable link for the person to read.
func (s *Server) OpenURL() string {
	c := randomHex(16)
	s.openMu.Lock()
	defer s.openMu.Unlock()
	if len(s.openCodes) >= maxOpenCodes {
		s.openCodes = s.openCodes[1:]
	}
	s.openCodes = append(s.openCodes, openCode{code: c, until: s.cfg.Now().Add(openCodeTTL)})
	return s.origin + "/?o=" + c
}

// openCodeShape reports whether code looks like one OpenURL mints (32 lowercase hex), so a used or expired one is
// told so (server.go, signedOutCode). It says nothing about whether the code was ever minted.
func openCodeShape(code string) bool {
	if len(code) != 32 {
		return false
	}
	for i := 0; i < len(code); i++ {
		if c := code[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// takeOpenCode reports whether code is a minted, unexpired, unused open code, and burns it when it is: a second use
// of the same code, or any use after openCodeTTL, is refused. Expired codes are dropped on the way.
func (s *Server) takeOpenCode(code string) bool {
	if len(code) != 32 {
		return false
	}
	now := s.cfg.Now()
	s.openMu.Lock()
	defer s.openMu.Unlock()
	found := false
	kept := s.openCodes[:0]
	for _, c := range s.openCodes {
		match := subtle.ConstantTimeCompare([]byte(c.code), []byte(code)) == 1
		switch {
		case match && now.Before(c.until):
			found = true // burned: not kept
		case match, !now.Before(c.until):
			// expired: dropped
		default:
			kept = append(kept, c)
		}
	}
	s.openCodes = kept
	return found
}

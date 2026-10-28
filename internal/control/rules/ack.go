// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The preview-bound acknowledgement (SEC-3). A write that is not a narrowing needs the person's
// acknowledgement, and the acknowledgement names the one write the preview showed: every plan (ActOn's preview,
// PlanChange, PlanRaw, and each Undo History and ActOn offer) carries Ack, an HMAC under a key that never leaves
// this process of what the write would be: the change it belongs to (ref), the sha256 of the text it is made on
// (base) and the sha256 of the text it writes. The confirm posts Ack back; the write plans again on the file as it
// is and refuses with ErrNeedsAck, writing nothing, unless the posted Ack is the one that plan computes. So a
// confirm that carries a valid base and form token but a different change than the one previewed (a wider entry, a
// changed text) writes nothing. A narrowing needs no acknowledgement and ignores Ack.
//
// The Ack is deterministic: the same preview gives the same Ack, with no nonce and no clock, so a live region
// re-rendered on every revision keeps the same HTML (static/live.js swaps a region only when its hash changes).
//
// What it does not do: a same-user process that holds the session can fetch the preview and read its Ack; the
// Ack binds what is written to what was previewed, and the peer checks (internal/control/web/peer.go, governed.go)
// decide who may post at all (docs/adr/0123-dashboard-threat-model.md).

// ackDomain separates this MAC from every other use of the key.
const ackDomain = "tego-ack-v1"

// ErrAckMismatch is a confirm whose acknowledgement names another change than the one it would write: the change
// was altered after the preview, or the acknowledgement was made for another preview. It is ErrNeedsAck too.
var ErrAckMismatch = fmt.Errorf("%w (the acknowledgement was for another change than this one)", ErrNeedsAck)

// key is the service's acknowledgement key: AckKey, or 32 random bytes made on first use and kept for the
// service's life (a dashboard restart makes a new one, so an open preview's Ack stops matching and the page asks
// again).
func (s *Service) key() []byte {
	s.ackOnce.Do(func() {
		if len(s.AckKey) > 0 {
			return
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			panic("rules: no randomness for the acknowledgement key: " + err.Error())
		}
		s.AckKey = k
	})
	return s.AckKey
}

// ack is the acknowledgement of the write that puts the text whose sha256 is newSum over the text whose sha256 is
// base, for the change ref names. Each field is length-prefixed, so no two different triples share an input.
func (s *Service) ack(ref, base, newSum string) string {
	m := hmac.New(sha256.New, s.key())
	for _, f := range []string{ackDomain, ref, base, newSum} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		m.Write(n[:])
		m.Write([]byte(f))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// ackOK reports whether got is the acknowledgement of that write, compared in constant time.
func (s *Service) ackOK(got, ref, base, newSum string) bool {
	want := s.ack(ref, base, newSum)
	return len(got) == len(want) && hmac.Equal([]byte(got), []byte(want))
}

// ackErr is the refusal of a write that needs an acknowledgement and does not carry this one: ErrNeedsAck when none
// was posted, ErrAckMismatch when another one was.
func ackErr(got string) error {
	if got == "" {
		return ErrNeedsAck
	}
	return ErrAckMismatch
}

// The refs each kind of write binds its acknowledgement to.
func actRef(run string, seq uint64) string { return fmt.Sprintf("line:%s#%d", run, seq) }
func contractAckRef(ref string) string     { return "contract:" + ref }
func revertRef(id string) string           { return "revert:" + id }

// The acknowledgement of a live lift or grant (ADR 0125 decision 8): the dashboard's lift preview carries LiveAck and
// its confirm posts it back, and the lift is asked only when LiveAckOK says it is the one that preview computed. It
// binds the run, the fence entry (kind and normalized value), the absolute limit (zero: none), whether the person
// chose to keep it permanently, and the overlay's serial when the preview was made: a confirm made for another entry,
// another limit, or after any other live change of the run (a stale preview, a replay) writes nothing. A run id and a
// kind hold no colon (liveAckFields), so the ref names one entry.
func liveAckRef(run, kind, value string) string { return "live-lift:" + run + ":" + kind + ":" + value }

// liveAckFields reports whether run and kind hold no colon, so that liveAckRef cannot read two entries alike.
func liveAckFields(run, kind string) bool {
	return !strings.Contains(run, ":") && !strings.Contains(kind, ":")
}
func liveAckBase(serial uint64) string { return "serial:" + strconv.FormatUint(serial, 10) }

func liveAckSum(until time.Time, permanent bool) string {
	u := "none"
	if !until.IsZero() {
		u = until.UTC().Format(time.RFC3339Nano)
	}
	return "until:" + u + ";permanent:" + strconv.FormatBool(permanent)
}

// LiveAck is the acknowledgement of a lift of run's fence entry kind:value until until (zero: the rest of the run),
// kept permanently or not, previewed at the overlay's serial; "" for a run or kind that holds a colon.
func (s *Service) LiveAck(run, kind, value string, until time.Time, permanent bool, serial uint64) string {
	if !liveAckFields(run, kind) {
		return ""
	}
	return s.ack(liveAckRef(run, kind, value), liveAckBase(serial), liveAckSum(until, permanent))
}

// LiveAckOK reports whether got is LiveAck's for those fields, compared in constant time.
func (s *Service) LiveAckOK(got, run, kind, value string, until time.Time, permanent bool, serial uint64) bool {
	return got != "" && liveAckFields(run, kind) && s.ackOK(got, liveAckRef(run, kind, value), liveAckBase(serial), liveAckSum(until, permanent))
}

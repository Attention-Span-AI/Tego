// SPDX-License-Identifier: Apache-2.0

package askproto

import (
	"encoding/hex"
	"errors"
	"path"
	"time"
	"unicode/utf8"
)

// SocketName is the broker's socket in the run directory.
const SocketName = "ask.sock"

// Limits of one exchange.
const (
	// MaxPacket bounds a command packet.
	MaxPacket = 8 << 10
	// MaxResponse bounds a response packet; a reply that would be larger is sent as ResponseTooLarge.
	MaxResponse = 128 << 10
	// NonceLen is the hello nonce's length: 16 random bytes in lower-case hex.
	NonceLen = 32
	// Timeout bounds one exchange on either side.
	Timeout = 5 * time.Second
	// MaxAlternate bounds an alternate's path, PATH_MAX with its terminator.
	MaxAlternate = 4095
	// MaxSummaryTarget and MaxSummaryRule bound a listed request's target and rule (Summary); Detail returns
	// them whole.
	MaxSummaryTarget = 128
	MaxSummaryRule   = 64
)

// ResponseTooLarge is the reply the broker sends in place of one longer than MaxResponse.
const ResponseTooLarge = `{"error":"ask: response too large","code":"unavailable"}`

// Command actions.
const (
	ActionList   = "list"
	ActionDetail = "detail"
	ActionAnswer = "answer"
)

// Response error codes, one per sentinel error below.
const (
	CodeNotPending      = "not-pending"
	CodeNotRememberable = "not-rememberable"
	CodeStandingFull    = "standing-full"
	CodeStandingBusy    = "standing-busy"
	CodeNoAlternate     = "no-alternate"
	CodeBadAlternate    = "bad-alternate"
	CodeUnauthorized    = "unauthorized"
	CodeProtocol        = "protocol"
	CodeUnavailable     = "unavailable"
)

// The errors an exchange ends in. Their texts are on the wire (Response.Error), so they never change.
var (
	ErrUnavailable  = errors.New("ask: unavailable")
	ErrNotPending   = errors.New("ask: request is no longer pending")
	ErrUnauthorized = errors.New("ask: unauthorized peer")
	ErrProtocol     = errors.New("ask: invalid protocol")
	// ErrNotRememberable answers an "always" that cannot be kept: the ask stays pending, so the human can
	// answer it once instead. A scored gate request and a content-bound hold are never remembered.
	ErrNotRememberable = errors.New("ask: this request cannot be remembered")
	// ErrStandingFull answers an "always" when the run already holds the most standing decisions it keeps.
	ErrStandingFull = errors.New("ask: too many standing decisions in this run")
	// ErrStandingBusy answers an "always" for a key whose standing answer another "always" has already chosen and is
	// still recording: the ask stays pending, and answering again after a moment either finds it resolved by that
	// answer or, if that answer did not stand, answerable.
	ErrStandingBusy = errors.New("ask: another always answer for the same operation, rule and target is being recorded")
	// ErrNoAlternate answers an alternate for a request that cannot take one: only a held file open can be
	// completed on another file. The ask stays pending.
	ErrNoAlternate = errors.New("ask: this request cannot be answered with an alternate file")
	// ErrBadAlternate answers an alternate the held open's own check refused (not a regular file, tego's own
	// state, a protected path, one the agent's credentials cannot open as asked). The ask stays pending.
	ErrBadAlternate = errors.New("ask: the alternate cannot be used")
)

// Command is the client's one packet.
type Command struct {
	Action  string `json:"action"`
	Nonce   string `json:"nonce"`
	AskID   string `json:"ask_id,omitempty"`
	Approve *bool  `json:"approve,omitempty"`
	// Remember asks that the answer also stand for the rest of the run, for the same operation, rule and
	// exact target ("approve --always"). Only an answer may carry it.
	Remember *bool `json:"remember,omitempty"`
	// Alternate is the file a person names in place of a held open's target (`tego alternate`, ADR 0057): an
	// answer with approve false, the absolute clean path the command named the file by (ValidAlternate), shown to
	// the person only. The file itself is the one descriptor the packet passes (SCM_RIGHTS), opened by the
	// person's command when they named it: an answer with an alternate carries exactly one, and every other
	// packet none. Only an answer may carry it.
	Alternate *string `json:"alternate,omitempty"`
}

// Response is the broker's hello (Ready) or its reply: the pending requests (list), one request (detail), the
// decision (answer), or an error with its code.
type Response struct {
	Ready    string    `json:"ready,omitempty"`
	Pending  []Summary `json:"pending,omitempty"`
	Request  *Request  `json:"request,omitempty"`
	Decision *Decision `json:"decision,omitempty"`
	Error    string    `json:"error,omitempty"`
	Code     string    `json:"code,omitempty"`
}

// Request is a held operation as the broker shows it. Target is in the ledger's form (askclient.LedgerTarget, the
// form the ask line records), never the raw target the supervisor holds.
type Request struct {
	Score    *int   `json:"score,omitempty"`
	GateRule string `json:"gate_rule,omitempty"`
	AskID    string `json:"ask_id"`
	Op       string `json:"op"`
	Target   string `json:"target"`
	// Target2 is a held mutation's second name (hold "mutation", ADR 0047): a rename's or a link's new name, or a
	// symlink's stored target. Empty for every other request. A listed request cuts it as it cuts Target, and
	// TargetTruncated marks either cut.
	Target2 string `json:"target2,omitempty"`
	Rule    string `json:"rule"`
	Hold    string `json:"hold"`
	PID     int    `json:"pid"`
	TID     int    `json:"tid"`
}

// Summary is a listed request, its target cut to MaxSummaryTarget bytes (TargetTruncated) and its rule to
// MaxSummaryRule (RuleTruncated), each at a UTF-8 boundary. A cut is always marked, so a reader never takes a
// prefix for the whole value; Detail returns both whole.
type Summary struct {
	Request
	TargetTruncated bool `json:"target_truncated,omitempty"`
	RuleTruncated   bool `json:"rule_truncated,omitempty"`
}

// Decision is how a held request ended.
type Decision struct {
	AskID    string  `json:"ask_id"`
	Approved bool    `json:"approved"`
	By       string  `json:"by"`
	Reason   string  `json:"reason,omitempty"`
	AfterS   float64 `json:"after_s"`
	// Always marks a decision that set a standing decision ("approve --always") or was taken from one.
	Always bool `json:"always,omitempty"`
	// Alternate is the file a person named in place of the target (ADR 0057), by the path the supervisor's check
	// read from its descriptor. Approved is false and Reason empty: the target was not granted and nothing was
	// refused, so a consumer that does not know alternates refuses the operation.
	Alternate string `json:"alternate,omitempty"`
	// AlternateDev and AlternateIno are the alternate's identity (st_dev, st_ino), fixed when the person named it.
	AlternateDev uint64 `json:"alternate_dev,omitempty"`
	AlternateIno uint64 `json:"alternate_ino,omitempty"`
}

// ValidID reports whether id is a broker's ask id: "q-" and 32 hex digits.
func ValidID(id string) bool {
	if len(id) != 34 || id[:2] != "q-" {
		return false
	}
	_, err := hex.DecodeString(id[2:])
	return err == nil
}

// ValidAlternate reports whether p can be an alternate at all, before any file is looked at: absolute, clean (no "."
// or ".." component, no doubled or trailing slash), not "/", at most MaxAlternate bytes of valid UTF-8 with no
// control character. A control character is refused because the path is printed to a person and written to the
// ledger, where a newline or an escape sequence would forge what they read.
func ValidAlternate(p string) bool {
	if len(p) < 2 || len(p) > MaxAlternate || p[0] != '/' || p != path.Clean(p) || !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return false
		}
	}
	return true
}

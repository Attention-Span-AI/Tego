// SPDX-License-Identifier: Apache-2.0

package bizrule

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
)

const (
	// MaxBundleBytes bounds unframed canonical bundles (W016).
	MaxBundleBytes = 32768
	// MaxCallBytes bounds the decoded submitted call (W016).
	MaxCallBytes = 65536
	// MaxRequestFrameBytes includes the required framing LF (W016).
	MaxRequestFrameBytes = 524288
	// MaxResultFrameBytes includes the transport LF (W016).
	MaxResultFrameBytes = 8192
	maxMoney            = uint64(9223372036854775807)
	maxID               = ^uint64(0)
	maxJS               = uint64(9007199254740991)
	adapter             = "square.refund.v1"
)

var (
	// ErrWire means the outer request is invalid. No evaluator answer is valid.
	ErrWire = errors.New("bizrule: wire.invalid")
	// ErrBundle means the bundle is malformed or unsupported.
	ErrBundle = errors.New("bizrule: bundle.invalid")
	// ErrResult means a caller constructed a result outside the canonical profile.
	ErrResult = errors.New("bizrule: invalid result")
)

// Bundle is an immutable validated bundle. Its zero value is invalid.
// The fields remain private so caller mutation cannot change pinned meaning.
type Bundle struct {
	raw    string
	digest string
	server string
	rules  []rule
}
type rule struct {
	id, kind, currency string
	codes              []string
	limit, ask, deny   uint64
}

// Digest returns the SHA-256 of canonical bundle bytes, without framing.
func (b Bundle) Digest() string { return b.digest }

// Canonical returns a copy of the canonical bundle bytes, without framing LF.
func (b Bundle) Canonical() []byte { return []byte(b.raw) }

// Request is an immutable, outer-validated request with supplied state.
// Nested state semantics deliberately remain deferred until B064 is reached.
// A request does not authenticate topology, state provenance or epoch continuity.
type Request struct {
	raw                                                                                     string
	adapter, callHex, bundleDigest, contract, status, id, run, server, toolSource, topology string
	state                                                                                   *value
	valid                                                                                   bool
}

// Canonical returns a copy of the canonical request including exactly one LF.
func (r Request) Canonical() []byte { return []byte(r.raw) }

// Business is the business layer's deciding restriction and stable attribution.
type Business struct {
	Condition string `json:"condition"`
	RuleID    string `json:"rule_id"`
	Verdict   string `json:"verdict"`
}

// Ask identifies one barrier in the complete business ask set.
type Ask struct {
	Condition string `json:"condition"`
	RuleID    string `json:"rule_id"`
}

// Final is the composed delivery restriction. Allow is not proof of delivery.
type Final struct {
	Condition string `json:"condition"`
	Source    string `json:"source"`
	Verdict   string `json:"verdict"`
}

// Facts contains only validated submitted money, never payment IDs or keys.
type Facts struct {
	AmountMinor string `json:"amount_minor"`
	Currency    string `json:"currency"`
	Exponent    int    `json:"exponent"`
	Source      string `json:"source"`
}

// Reservation proposes one checked addition against the supplied state revision.
// Only the durable owner can commit it, after rechecking current restrictions.
type Reservation struct {
	AfterMinor    string `json:"after_minor"`
	AmountMinor   string `json:"amount_minor"`
	BeforeMinor   string `json:"before_minor"`
	Currency      string `json:"currency"`
	KeyDigest     string `json:"key_digest"`
	StateRevision string `json:"state_revision"`
}

// Record describes the evaluation observation, with no delivery claim.
type Record struct {
	Coverage      string `json:"coverage"`
	Delivery      string `json:"delivery"`
	RemoteOutcome string `json:"remote_outcome"`
	Required      bool   `json:"required"`
	Stage         string `json:"stage"`
}

// Result is the full W008 answer. EncodeResult supplies its canonical bytes.
type Result struct {
	Adapter      string       `json:"adapter"`
	Asks         []Ask        `json:"asks"`
	BundleDigest string       `json:"bundle_digest"`
	Business     Business     `json:"business"`
	CallDigest   string       `json:"call_digest"`
	Facts        *Facts       `json:"facts"`
	Final        Final        `json:"final"`
	Record       Record       `json:"record"`
	RequestID    string       `json:"request_id"`
	Reservation  *Reservation `json:"reservation"`
	RunID        string       `json:"run_id"`
	Server       string       `json:"server"`
	Version      int          `json:"version"`
}

func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func label(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || digit(c) || c == '.' || c == '_' || c == '/' || c == '-') {
			return false
		}
	}
	return true
}
func identifier(s string, bound int) bool {
	if len(s) < 1 || len(s) > bound {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || digit(c) || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func hexText(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !digit(s[i]) && !(s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
func hashText(s string) bool { return len(s) == 64 && hexText(s) }
func exponent(s string) (int, bool) {
	switch s {
	case "CAD", "USD":
		return 2, true
	case "JPY":
		return 0, true
	case "KWD":
		return 3, true
	}
	return 0, false
}
func oneOf(s string, choices ...string) bool {
	for _, c := range choices {
		if s == c {
			return true
		}
	}
	return false
}
func money(v *value) (uint64, bool) {
	if !v.is('s') {
		return 0, false
	}
	return unsigned(v.text, maxMoney, true)
}
func decimal(n uint64) string { return strconv.FormatUint(n, 10) }

// DecodeBundle validates canonical spelling and the complete closed W004 schema.
// Invalid configuration must refuse compilation/launch in the integration layer.
func DecodeBundle(data []byte) (Bundle, error) {
	v, cond := parse(data, MaxBundleBytes)
	if cond != "" || !v.fields("adapter", "rules", "server", "version") || v.get("adapter").string() != adapter || !label(v.get("server").string()) || !v.get("version").is('i') || v.get("version").text != "1" {
		return Bundle{}, ErrBundle
	}
	rules := v.get("rules")
	if !rules.is('[') || len(rules.array) < 1 || len(rules.array) > 32 {
		return Bundle{}, ErrBundle
	}
	b := Bundle{raw: string(data), digest: digest(data), server: v.get("server").string()}
	previous := ""
	for _, r := range rules.array {
		id, kind := r.get("id").string(), r.get("kind").string()
		if !label(id) || id <= previous {
			return Bundle{}, ErrBundle
		}
		previous = id
		row := rule{id: id, kind: kind, currency: r.get("currency").string()}
		switch kind {
		case "per_call", "per_run":
			if !r.fields("currency", "id", "kind", "limit") {
				return Bundle{}, ErrBundle
			}
			n, ok := money(r.get("limit"))
			if !ok {
				return Bundle{}, ErrBundle
			}
			row.limit = n
		case "threshold":
			if !r.fields("ask_above", "currency", "deny_above", "id", "kind") {
				return Bundle{}, ErrBundle
			}
			a, ok := money(r.get("ask_above"))
			d, ok2 := money(r.get("deny_above"))
			if !ok || !ok2 || a >= d {
				return Bundle{}, ErrBundle
			}
			row.ask = a
			row.deny = d
		case "currencies":
			if !r.fields("codes", "id", "kind") {
				return Bundle{}, ErrBundle
			}
			codes := r.get("codes")
			if !codes.is('[') || len(codes.array) < 1 || len(codes.array) > 4 {
				return Bundle{}, ErrBundle
			}
			prev := ""
			for _, c := range codes.array {
				code := c.string()
				if _, ok := exponent(code); !ok || code <= prev {
					return Bundle{}, ErrBundle
				}
				prev = code
				row.codes = append(row.codes, code)
			}
		default:
			return Bundle{}, ErrBundle
		}
		if kind != "currencies" {
			if _, ok := exponent(row.currency); !ok {
				return Bundle{}, ErrBundle
			}
		}
		b.rules = append(b.rules, row)
	}
	return b, nil
}

// DecodeRequest validates a complete W027 frame, including its single LF.
// It preserves canonical nested state defects for evaluation's B064 precedence.
func DecodeRequest(frame []byte) (Request, error) {
	if len(frame) < 2 || len(frame) > MaxRequestFrameBytes || frame[len(frame)-1] != '\n' {
		return Request{}, ErrWire
	}
	v, cond := parse(frame[:len(frame)-1], MaxRequestFrameBytes-1)
	if cond != "" || !v.fields("adapter", "call_hex", "contract_bundle_digest", "contract_verdict", "evaluator_status", "request_id", "run_id", "server", "state", "tool_source", "topology", "version") {
		return Request{}, ErrWire
	}
	for _, key := range []string{"adapter", "call_hex", "contract_bundle_digest", "contract_verdict", "evaluator_status", "request_id", "run_id", "server", "tool_source", "topology"} {
		if !v.get(key).is('s') {
			return Request{}, ErrWire
		}
	}
	r := Request{raw: string(frame), adapter: v.get("adapter").text, callHex: v.get("call_hex").text, bundleDigest: v.get("contract_bundle_digest").text, contract: v.get("contract_verdict").text, status: v.get("evaluator_status").text, id: v.get("request_id").text, run: v.get("run_id").text, server: v.get("server").text, state: v.get("state"), toolSource: v.get("tool_source").text, topology: v.get("topology").text, valid: true}
	_, idOK := unsigned(r.id, maxID, false)
	if !label(r.adapter) || !hexText(r.callHex) || !hashText(r.bundleDigest) || !idOK || !label(r.run) || !label(r.server) || !oneOf(r.contract, "allow", "ask", "deny", "unknown") || !oneOf(r.status, "ready", "missing", "crashed", "timed_out", "nonsense", "queue_full", "late_reply", "wrong_binding", "extra_reply", "restarted", "record_failed") || !oneOf(r.toolSource, "contract", "live") || !oneOf(r.topology, "exclusive", "unproven") || !v.get("version").is('i') || v.get("version").text != "1" || !(r.state.is('{') || r.state.is('n')) {
		return Request{}, ErrWire
	}
	return r, nil
}

// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// InitialUserNamespace is Linux's initial user namespace inode (PROC_USER_INIT_INO).
const InitialUserNamespace uint64 = askproto.InitialUserNamespace

// LocalApprovalAuthority is the mandatory floor pinned before a managed run starts.
// Its digest covers exact system config bytes; AgentUID is the verified dropped UID.
type LocalApprovalAuthority struct {
	Mode     string `json:"mode"`
	SHA256   string `json:"sha256"`
	AgentUID uint32 `json:"agent_uid"`
}

// LocalApprovalActor is the kernel-authenticated root process that answered.
// It identifies an OS process, without claiming a human or the sudo caller.
type LocalApprovalActor = askproto.LocalApprovalActor

// AnswerAuthority adds actor attribution or a typed system cause to a local answer.
// Missing fields in an older record mean not recorded.
type AnswerAuthority = askproto.AnswerAuthority

// Validate checks the root-only activation facts.
func (a LocalApprovalAuthority) Validate() error {
	if a.Mode != "owner_only" || !sha256Hex.MatchString(a.SHA256) || a.AgentUID == 0 || a.AgentUID == ^uint32(0) {
		return fmt.Errorf("record: invalid local approval authority")
	}
	return nil
}

func (e *Event) validateLocalRoles(minor int, fields []field) error {
	var authority, actor, cause []byte
	for _, f := range fields {
		for _, key := range []string{"local_approval_authority", "actor", "system_cause"} {
			if f.key != key && foldEqual(f.key, key) {
				return fieldErr("field-case", key, "key %q is not spelt %q", f.key, key)
			}
		}
		switch f.key {
		case "local_approval_authority":
			authority = f.val
		case "actor":
			actor = f.val
		case "system_cause":
			cause = f.val
		}
	}
	var p struct {
		Approved     *bool
		By           string
		AnswerReason string
		Alternate    string
	}
	if e.Kind == KindAnswer && minor >= MinorLocalRoles {
		// Read only exact member names. JSON's folded struct matching can select a
		// different decision after canonical encoding reorders the payload keys.
		for _, f := range fields {
			for _, key := range []string{"approved", "by", "answer_reason", "alternate"} {
				if f.key != key && foldEqual(f.key, key) {
					return fieldErr("field-case", key, "key %q is not spelt %q", f.key, key)
				}
			}
			var dst any
			switch f.key {
			case "approved":
				dst = &p.Approved
			case "by":
				dst = &p.By
			case "answer_reason":
				dst = &p.AnswerReason
			case "alternate":
				dst = &p.Alternate
			default:
				continue
			}
			if err := decodeField(f.key, f.val, dst); err != nil {
				return err
			}
		}
	}
	if authority == nil && actor == nil && cause == nil {
		return nil
	}
	if minor < MinorLocalRoles {
		return fieldErr("below-minor", "local-approval", "requires record_minor %d", MinorLocalRoles)
	}
	bad := func(err error) error { return fieldErr("local-approval", string(e.Kind), "%v", err) }
	if authority != nil {
		if e.Kind != KindRunStart || actor != nil || cause != nil {
			return bad(fmt.Errorf("authority belongs on run_start"))
		}
		var a LocalApprovalAuthority
		if err := decodeLocalObject("local_approval_authority", authority, &a); err != nil {
			return err
		}
		if err := a.Validate(); err != nil {
			return bad(err)
		}
		return nil
	}
	if e.Kind != KindAnswer || (actor == nil) == (cause == nil) {
		return bad(fmt.Errorf("answer requires one actor or system cause"))
	}
	if p.Approved == nil {
		return bad(fmt.Errorf("answer requires approved"))
	}
	if actor != nil {
		var a LocalApprovalActor
		if err := decodeLocalObject("actor", actor, &a); err != nil {
			return err
		}
		if err := a.Validate(); err != nil {
			return bad(err)
		}
		if p.By != fmt.Sprintf("uid:%d pid:%d", a.UID, a.PID) || p.Alternate != "" || (!*p.Approved && p.AnswerReason != "ask-denied") || (*p.Approved && p.AnswerReason != "") {
			return bad(fmt.Errorf("actor answer is not a once approve or deny"))
		}
	} else {
		var c string
		if err := decodeField("system_cause", cause, &c); err != nil {
			return err
		}
		if c != "timeout" && c != "cancelled" && c != "shutdown" && c != "unavailable" {
			return bad(fmt.Errorf("unknown system cause"))
		}
		reason := "ask-unavailable"
		if c == "timeout" {
			reason = "ask-timeout"
		}
		if *p.Approved || p.Alternate != "" || p.AnswerReason != reason || p.By != c {
			return bad(fmt.Errorf("system answer grants nothing"))
		}
	}
	return nil
}

// RunStartFloor reports whether e, a run_start, carries the root-only approval floor (local_approval_authority, an
// exactly spelt member that is not null). It reads no more than the member's presence: ValidateAt holds the member to
// its schema. Any line but a run_start reports false.
func (e *Event) RunStartFloor() bool {
	if e.Kind != KindRunStart {
		return false
	}
	fields, err := objectFields(e.Payload)
	if err != nil {
		return false
	}
	for _, f := range fields {
		if f.key == "local_approval_authority" {
			return !bytes.Equal(bytes.TrimSpace(f.val), []byte("null"))
		}
	}
	return false
}

// ValidateFloor ties an answer to its run's floor, which ValidateAt (one line at a time) cannot: in a run whose
// run_start carries the floor every answer says who decided it (an actor or a system_cause), and in a run whose
// run_start does not, no answer carries either, so a line rewritten to claim root in a run that never had the floor
// is refused here. Any line but an answer passes.
func (e *Event) ValidateFloor(floor bool) error {
	if e.Kind != KindAnswer {
		return nil
	}
	fields, err := objectFields(e.Payload)
	if err != nil {
		return fmt.Errorf("%w: payload: %w", ErrInvalidEvent, err)
	}
	attributed := false
	for _, f := range fields {
		if (f.key == "actor" || f.key == "system_cause") && !bytes.Equal(bytes.TrimSpace(f.val), []byte("null")) {
			attributed = true
		}
	}
	switch {
	case floor && !attributed:
		return fieldErr("local-approval", "answer", "an answer in a run under the root-only floor requires its actor or system cause")
	case !floor && attributed:
		return fieldErr("local-approval", "answer", "an actor or system cause belongs only to a run that started under the root-only floor")
	}
	return nil
}

// AnswerAuthorityOf is ValidatedAnswerAuthority for a reader that knows whether the run started under the floor:
// without the floor it projects no attribution, whatever the line says, so a reader never shows an answer as root's
// in a run that was never held to the root-only floor.
func AnswerAuthorityOf(payload json.RawMessage, minor int, floor bool) AnswerAuthority {
	if !floor {
		return AnswerAuthority{}
	}
	return ValidatedAnswerAuthority(payload, minor)
}

func decodeLocalObject(name string, data []byte, dst any) error {
	if err := decodeField(name, data, dst); err != nil {
		return err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return fieldErr("local-approval", name, "%v", err)
	}
	required := []string{"mode", "sha256", "agent_uid"}
	if name == "actor" {
		required = []string{"uid", "pid", "start_boot_ns", "user_namespace", "source", "role"}
	}
	for _, key := range required {
		if _, ok := members[key]; !ok {
			return fieldErr("local-approval", name, "missing %s", key)
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fieldErr("local-approval", name, "%v", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fieldErr("local-approval", name, "trailing data")
	}
	return nil
}

// ValidatedLocalApprovalAuthority projects the activation floor only after the
// complete run_start payload validates at its exactly recorded revision.
// Malformed, differently spelt and below-revision fields grant no authority.
func ValidatedLocalApprovalAuthority(payload json.RawMessage) *LocalApprovalAuthority {
	fields, err := objectFields(payload)
	if err != nil {
		return nil
	}
	minor, err := runStartMinor(fields)
	if err != nil || minor < MinorLocalRoles {
		return nil
	}
	e := Event{Kind: KindRunStart, Payload: payload}
	if e.validateMVP(minor, fields) != nil {
		return nil
	}
	var p struct {
		Authority *LocalApprovalAuthority `json:"local_approval_authority"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return nil
	}
	return p.Authority
}

// ValidatedAnswerAuthority projects authenticated attribution only at the revision
// that carries it, after the complete answer payload passes that revision's rules.
// It returns no attribution for legacy, malformed or contradictory answers.
func ValidatedAnswerAuthority(payload json.RawMessage, minor int) AnswerAuthority {
	if minor < MinorLocalRoles {
		return AnswerAuthority{}
	}
	fields, err := objectFields(payload)
	if err != nil {
		return AnswerAuthority{}
	}
	e := Event{Kind: KindAnswer, Payload: payload}
	if e.validateMVP(minor, fields) != nil {
		return AnswerAuthority{}
	}
	var a AnswerAuthority
	if json.Unmarshal(payload, &a) != nil {
		return AnswerAuthority{}
	}
	return a
}

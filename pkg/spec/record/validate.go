// SPDX-License-Identifier: Apache-2.0

package record

import (
	"fmt"
	"slices"
)

// The private arrays define the frozen vocabulary. Exported listing slices are
// detached copies, so a caller editing a list cannot change codec validation.
var kinds = [...]Kind{
	KindRunStart, KindRunEnd, KindExec, KindFS, KindNet, KindMCP, KindSSLRequest, KindSSLResponse,
	KindDecision, KindAsk, KindAnswer, KindRefused, KindGap, KindBoundary, KindLimit,
}

// Kinds lists every v1 kind in declaration order. Editing it does not change validation.
var Kinds = slices.Clone(kinds[:])

// P0Kinds lists the twelve kinds a P0 writer emits (never ask, answer, boundary).
var P0Kinds = []Kind{
	KindRunStart, KindRunEnd, KindExec, KindFS, KindNet, KindMCP, KindSSLRequest, KindSSLResponse,
	KindDecision, KindRefused, KindGap, KindLimit,
}

var verdicts = [...]Verdict{VerdictAllow, VerdictAsk, VerdictRefused, VerdictObserved}

// Verdicts lists every v1 verdict. Editing it does not change validation.
var Verdicts = slices.Clone(verdicts[:])

var authorities = [...]Authority{AuthorityRule, AuthorityGate, AuthorityHuman, AuthorityLLM}

// Authorities lists every v1 authority. Editing it does not change validation.
var Authorities = slices.Clone(authorities[:])

var sources = [...]Source{
	SourceKernel, SourceLandlock, SourceSeccomp, SourceFanotify, SourceSSL, SourceForwarder, SourceHook,
	SourcePython, SourceNode, SourceSupervisor, SourceProxy,
}

// Sources lists every v1 source. Editing it does not change validation.
var Sources = slices.Clone(sources[:])

var reasons = [...]Reason{
	ReasonWriteOutsideContract, ReasonDeleteOutsideContract, ReasonRenameOutsideContract,
	ReasonMkdirOutsideContract, ReasonReadDenied, ReasonPathUnresolved, ReasonExecNotAllowed, ReasonFSGate, ReasonExecGate,
	ReasonNetNotAllowed, ReasonNetGate, ReasonNetHTTP, ReasonAskDenied, ReasonAskTimeout, ReasonAskUnavailable,
	ReasonAskUnreadable, ReasonLandlockTopology, ReasonLimitTokens, ReasonLimitCost, ReasonLimitWall,
	ReasonLimitStall, ReasonLimitRepeats, ReasonOOM, ReasonPids,
	ReasonCredentialNotAllowed, ReasonCredentialRevoked, ReasonCredentialUnavailable, ReasonMCPToolDenied,
	ReasonModelRouteChanged,
}

// Reasons lists every v1 reason code (spec/reason/REASON-CHANNEL.md, the closed set).
// Editing it does not change validation.
var Reasons = slices.Clone(reasons[:])

var runEndReasons = [...]string{
	RunEndExit, RunEndSignal, RunEndStopped, RunEndOOM, RunEndPids, RunEndLimit, RunEndExecFailed,
	RunEndOrphaned, RunEndError,
}

// RunEndReasons lists every run_end reason (spec/record/v1/README.md); a different domain from Reason codes.
// Editing it does not change validation.
var RunEndReasons = slices.Clone(runEndReasons[:])

// IsRunEndReason reports whether s is one of the nine run_end reasons.
func IsRunEndReason(s string) bool { return slices.Contains(runEndReasons[:], s) }

var confidences = [...]string{ConfidenceExact, ConfidenceLikely, ConfidenceUnattributed}

// Confidences lists every attribution confidence value. Editing it does not change validation.
var Confidences = slices.Clone(confidences[:])

var methods = [...]string{MethodToolID, MethodTID, MethodTime, MethodNone}

// Methods lists every attribution method value. Editing it does not change validation.
var Methods = slices.Clone(methods[:])

// Valid reports whether k is one of the fifteen v1 kinds.
func (k Kind) Valid() bool { return slices.Contains(kinds[:], k) }

// IsAction reports whether k is an action kind (exec, fs, net, mcp): the kinds that carry rule, verdict,
// authority and attribution (R8).
func (k Kind) IsAction() bool {
	return k == KindExec || k == KindFS || k == KindNet || k == KindMCP
}

// Valid reports whether v is one of the v1 verdicts.
func (v Verdict) Valid() bool { return slices.Contains(verdicts[:], v) }

// Valid reports whether a is one of the v1 authorities.
func (a Authority) Valid() bool { return slices.Contains(authorities[:], a) }

// Valid reports whether s is one of the v1 sources.
func (s Source) Valid() bool { return slices.Contains(sources[:], s) }

// Valid reports whether r is one of the v1 reason codes.
func (r Reason) Valid() bool { return slices.Contains(reasons[:], r) }

// IsLimit reports whether r is one of the limit-* budget codes.
func (r Reason) IsLimit() bool {
	switch r {
	case ReasonLimitTokens, ReasonLimitCost, ReasonLimitWall, ReasonLimitStall, ReasonLimitRepeats:
		return true
	}
	return false
}

// Unattributed is the attribution a P0 writer stamps on an action that no derivation tied to a step (R8).
func Unattributed() *Attribution {
	return &Attribution{Confidence: ConfidenceUnattributed, Method: MethodNone}
}

// AttributedByTime is the attribution of an action that fell inside exactly one open step (R8, E28a).
func AttributedByTime(thread string, step int) *Attribution {
	return &Attribution{Thread: thread, Step: step, Confidence: ConfidenceLikely, Method: MethodTime}
}

// AttributedByTID is the attribution of an action its own thread made while that thread had a step: the thread is
// one a capture source named by its tid, so the step is the one that thread's own model request opened (capture-derive R42).
func AttributedByTID(thread string, step int) *Attribution {
	return &Attribution{Thread: thread, Step: step, Confidence: ConfidenceLikely, Method: MethodTID}
}

// AttributedByToolUse is the attribution of an action that fell inside exactly one reply's tool window: the reply on
// thread, in step, asked for the tool_use toolUseID and had not been told its result (capture-derive R42, E29).
func AttributedByToolUse(thread string, step int, toolUseID string) *Attribution {
	return &Attribution{Thread: thread, Step: step, ToolUseID: toolUseID, Confidence: ConfidenceLikely, Method: MethodToolID}
}

// Valid reports whether a carries a known confidence and method, and a tool_use_id only under method tool_id, the one
// method that reads one. A tool_id attribution without an id is still accepted, as v1 accepted every P1 attribution
// before record_minor 29 named the id (R8); this repository's writer always names it (AttributedByToolUse).
func (a *Attribution) Valid() bool {
	return a != nil && slices.Contains(confidences[:], a.Confidence) && slices.Contains(methods[:], a.Method) &&
		(a.ToolUseID == "" || a.Method == MethodToolID)
}

// IsAgentID reports whether s has the agent id shape [a-z0-9-]{1,40} (spec/identity/RUN-IDENTITY.md).
func IsAgentID(s string) bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Validate applies the v1 rules of docs/p0/record-ledger.md §2.1 and returns ErrInvalidEvent (wrapped with
// the failing field) on the first violation. MarshalLine calls it; readers call it on decoded events when they
// need the semantic guarantees Decode deliberately does not enforce.
func (e *Event) Validate() error {
	if e.V != Version {
		return fmt.Errorf("%w: v=%d, want %d", ErrInvalidEvent, e.V, Version)
	}
	if !e.Kind.Valid() {
		return fmt.Errorf("%w: kind %q", ErrInvalidEvent, e.Kind)
	}
	if !e.Source.Valid() {
		return fmt.Errorf("%w: source %q", ErrInvalidEvent, e.Source)
	}
	if e.Run == "" {
		return fmt.Errorf("%w: run is empty", ErrInvalidEvent)
	}
	if !IsAgentID(e.Agent) {
		return fmt.Errorf("%w: agent %q", ErrInvalidEvent, e.Agent)
	}
	if e.TS.IsZero() {
		return fmt.Errorf("%w: ts is zero", ErrInvalidEvent)
	}
	if e.ID != "" && !IsID(e.ID) {
		return fmt.Errorf("%w: id %q is not %d hex characters", ErrInvalidEvent, e.ID, IDLen)
	}
	if err := e.validateChainFields(); err != nil {
		return err
	}
	if e.Kind.IsAction() {
		return e.validateAction()
	}
	return e.validateNonAction()
}

// validateChainFields checks prev against seq: the first line has none, every later line names one id (I3).
func (e *Event) validateChainFields() error {
	if e.Seq == 0 && e.Prev != "" {
		return fmt.Errorf("%w: seq 0 must have an empty prev", ErrInvalidEvent)
	}
	if e.Seq > 0 && !IsID(e.Prev) {
		return fmt.Errorf("%w: seq %d needs a prev id", ErrInvalidEvent, e.Seq)
	}
	return nil
}

// validateAction checks the fields every exec, fs, net and mcp event must carry (§2.1, R8).
func (e *Event) validateAction() error {
	if e.Rule == "" {
		return fmt.Errorf("%w: %s event without rule", ErrInvalidEvent, e.Kind)
	}
	if !e.Verdict.Valid() {
		return fmt.Errorf("%w: %s event with verdict %q", ErrInvalidEvent, e.Kind, e.Verdict)
	}
	if !e.Authority.Valid() {
		return fmt.Errorf("%w: %s event with authority %q", ErrInvalidEvent, e.Kind, e.Authority)
	}
	if !e.Attr.Valid() {
		return fmt.Errorf("%w: %s event needs attribution {confidence, method}", ErrInvalidEvent, e.Kind)
	}
	if e.Reason != "" && !e.Reason.Valid() {
		return fmt.Errorf("%w: reason %q", ErrInvalidEvent, e.Reason)
	}
	return nil
}

// validateNonAction checks that the action-only fields are absent and that rule and reason appear only where
// v1 puts them: refused carries both (spec/reason/REASON-CHANNEL.md), limit may carry a limit-* reason, run_end
// carries its own reason domain (exit, signal, ...); every other kind carries neither.
func (e *Event) validateNonAction() error {
	if e.Verdict != "" || e.Authority != "" {
		return fmt.Errorf("%w: %s event must not carry verdict or authority", ErrInvalidEvent, e.Kind)
	}
	if e.Attr != nil {
		return fmt.Errorf("%w: %s event must not carry attribution", ErrInvalidEvent, e.Kind)
	}
	if e.Rule != "" && e.Kind != KindRefused {
		return fmt.Errorf("%w: %s event must not carry rule", ErrInvalidEvent, e.Kind)
	}
	switch e.Kind {
	case KindRefused:
		if e.Rule == "" {
			return fmt.Errorf("%w: refused event without rule", ErrInvalidEvent)
		}
		if !e.Reason.Valid() {
			return fmt.Errorf("%w: refused event with reason %q", ErrInvalidEvent, e.Reason)
		}
	case KindLimit:
		if e.Reason != "" && !e.Reason.IsLimit() {
			return fmt.Errorf("%w: limit event with reason %q", ErrInvalidEvent, e.Reason)
		}
	case KindRunEnd:
		if !IsRunEndReason(string(e.Reason)) {
			return fmt.Errorf("%w: run_end with reason %q", ErrInvalidEvent, e.Reason)
		}
	default:
		if e.Reason != "" {
			return fmt.Errorf("%w: %s event must not carry reason", ErrInvalidEvent, e.Kind)
		}
	}
	return nil
}

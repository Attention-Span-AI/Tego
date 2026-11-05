// SPDX-License-Identifier: Apache-2.0

package reason

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// MaxShownBytes is how much of a target, an op or a rule a sentence shows: a longer one is cut to this many bytes,
// with an ellipsis and its length in bytes.
const MaxShownBytes = 200

// facts is what each reason code means, as a fact about the run (never a command: a harness shows the sentence to a
// model, and text framed as an instruction reads as a prompt injection). Every code of record's closed set has one
// (TestEveryReasonCodeHasASentence). The wording is reviewed as the goldens under testdata; a wording change changes
// only them.
var facts = map[record.Reason]string{
	record.ReasonWriteOutsideContract:  "this run may not write to that path",
	record.ReasonDeleteOutsideContract: "this run may not delete files at that path",
	record.ReasonRenameOutsideContract: "this run may not rename files at that path",
	record.ReasonMkdirOutsideContract:  "this run may not create directories at that path",
	record.ReasonReadDenied:            "files under that path are not readable in this run",
	record.ReasonPathUnresolved:        "the path could not be resolved to a file the run's rules can judge, so it is refused",
	record.ReasonExecNotAllowed:        "that program is not allowed to run in this run",
	record.ReasonFSGate:                "this run's action gate refused that file operation",
	record.ReasonExecGate:              "this run's action gate refused running that program",
	record.ReasonNetNotAllowed:         "that destination is not allowed in this run",
	record.ReasonNetGate:               "this run's action gate refused that connection",
	record.ReasonNetHTTP:               "that HTTP request is not allowed in this run",
	record.ReasonAskDenied:             "it needed a person's approval, and the person declined",
	record.ReasonAskTimeout:            "it needed a person's approval, and no answer came in time",
	record.ReasonAskUnavailable:        "it needed a person's approval, and no one could be asked",
	record.ReasonAskUnreadable:         "it needed a person's approval, and the request could not be read reliably enough to ask",
	record.ReasonLandlockTopology:      "it reaches a process outside this run's sandbox",
	record.ReasonLimitTokens:           "the run reached its token limit",
	record.ReasonLimitCost:             "the run reached its cost limit",
	record.ReasonLimitWall:             "the run reached its time limit",
	record.ReasonLimitStall:            "the run made no progress for longer than its stall limit",
	record.ReasonLimitRepeats:          "the run repeated one action more times than its limit",
	record.ReasonOOM:                   "the run reached its memory limit",
	record.ReasonPids:                  "the run reached its process limit",
	record.ReasonCredentialNotAllowed:  "that credential may not be sent there; Tego puts a key only into requests to the endpoints it is allowed for",
	record.ReasonCredentialRevoked:     "that credential was revoked in Tego's vault",
	record.ReasonCredentialUnavailable: "Tego's vault does not hold that credential, or could not read it",
	record.ReasonMCPToolDenied:         "that MCP tool is not allowed in this run",
	record.ReasonModelRouteChanged:     "a person moved this model endpoint to another route while the request waited for approval; send it again",
}

// BuiltInNameMove identifies a rename refused by ADR 0043's built-in label (D1 or D5), distinct from
// ordinary fs.write/REFER refusals and literal deny_read targets. A label alone does not say whether
// the object is a file or a directory. The compiler reserves ** in labels, outside glob syntax.
func BuiltInNameMove(why record.Reason, rule string) bool {
	return why == record.ReasonRenameOutsideContract && strings.HasPrefix(rule, "fs.deny_read[") &&
		(strings.HasSuffix(rule, "/**/.env]") || strings.HasSuffix(rule, "/**/.env.*]"))
}

const nameMoveFact = "the built-in .env protection blocks this rename; directory moves that lose protected-name coverage are refused; explicit fs.write entries grant staging and destination access but add no name coverage; a pre-created target used as the launch working directory retains built-in protection, with the contract outside writable paths (C55)"

// Text is the one plain sentence a refusal is told in: what Tego refused, why, and the rule, as facts. The target is
// quoted, and the op and the rule are when they hold anything but plain printable text, so a string the agent chose
// cannot pass for text of the sentence's own (Quote); each is cut to MaxShownBytes. A code outside the closed set
// is named as it is.
func Text(reason record.Reason, op, target, rule string) string {
	return text(reason, op, target, rule, len(op), len(target), len(rule))
}

// text is Text of op, target and rule, each a string of the length given or a cut of one (Refusal.Cut): a string
// it cuts states that length.
func text(reason record.Reason, op, target, rule string, opLen, targetLen, ruleLen int) string {
	var b strings.Builder
	b.WriteString("Tego refused ")
	switch {
	case op != "" && target != "":
		b.WriteString(show(op, opLen) + " " + quote(target, targetLen))
	case op != "":
		b.WriteString(show(op, opLen))
	case target != "":
		b.WriteString(quote(target, targetLen))
	default:
		b.WriteString("an action")
	}
	b.WriteString(": ")
	if BuiltInNameMove(reason, rule) {
		b.WriteString(nameMoveFact)
	} else if f, ok := facts[reason]; ok {
		b.WriteString(f)
	} else {
		b.WriteString("the reason code is " + Show(string(reason)))
	}
	if rule != "" {
		b.WriteString(" (rule " + show(rule, ruleLen) + ")")
	}
	b.WriteString(".")
	return b.String()
}

// Quote is s, cut to MaxShownBytes, as a double-quoted string in which every byte that is not printable is escaped
// (a newline as \n, a control byte as \x01, invalid UTF-8 as \xff) and so are < and > (\u003c, \u003e), so no
// target can close or open a tag the text is shown inside. A cut string is followed by "… (N bytes)".
func Quote(s string) string { return quote(s, len(s)) }

// quote is Quote of s, a string of full bytes or a cut of one whose first MaxShownBytes are the string's: a cut
// states full.
func quote(s string, full int) string {
	shown, more := s, ""
	if full > MaxShownBytes {
		k := min(MaxShownBytes, len(s))
		for k > 0 && k < len(s) && !utf8.RuneStart(s[k]) {
			k--
		}
		shown, more = s[:k], "… ("+strconv.Itoa(full)+" bytes)"
	}
	q := strconv.Quote(shown)
	q = strings.ReplaceAll(q, "<", `\u003c`)
	q = strings.ReplaceAll(q, ">", `\u003e`)
	return q + more
}

// Show is s as it is when it is plain printable text with no space, quote, backslash or angle bracket, and no
// longer than MaxShownBytes; else Quote(s).
func Show(s string) string { return show(s, len(s)) }

// show is Show of s, a string of full bytes or a cut of one (quote).
func show(s string, full int) string {
	if full > MaxShownBytes || s == "" {
		return quote(s, full)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || c == '"' || c == '\\' || c == '<' || c == '>' || c == '`' {
			return quote(s, full)
		}
	}
	return s
}

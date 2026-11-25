// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	receiptspec "github.com/attention-span-ai/tego/pkg/spec/receipt"
)

// The receipt's JSON types are defined in pkg/spec/receipt (the specification layer, C162) and published as
// spec/receipt/receipt-v1.schema.json; this package computes them from a ledger and renders them. The names below keep
// the old spellings working for the readers (the command line, the dashboard, the CI receipt) while new code can name
// the specification directly.
type (
	TimeTaken        = receiptspec.TimeTaken
	Files            = receiptspec.Files
	Rename           = receiptspec.Rename
	Refusals         = receiptspec.Refusals
	RuleCount        = receiptspec.RuleCount
	Refusal          = receiptspec.Refusal
	OverTime         = receiptspec.OverTime
	Stall            = receiptspec.Stall
	Tests            = receiptspec.Tests
	Asks             = receiptspec.Asks
	Ask              = receiptspec.Ask
	Tokens           = receiptspec.Tokens
	Coverage         = receiptspec.Coverage
	CoverageGap      = receiptspec.CoverageGap
	Verdicts         = receiptspec.Verdicts
	Connection       = receiptspec.Connection
	Program          = receiptspec.Program
	SensitiveRead    = receiptspec.SensitiveRead
	MadeBy           = receiptspec.MadeBy
	Binding          = receiptspec.Binding
	BoundChain       = receiptspec.BoundChain
	Limit            = receiptspec.Limit
	BaselineSummary  = receiptspec.BaselineSummary
	BaselineRefusals = receiptspec.BaselineRefusals
)

// The receipt's version, the bindings' versions and the codes of its coverage and limits, as the specification names
// them.
const (
	Version                = receiptspec.Version
	BindingVersion         = receiptspec.BindingVersion
	BaselineBindingVersion = receiptspec.BaselineBindingVersion
	CodeNoCapabilities     = receiptspec.CodeNoCapabilities
	CodeRecordOff          = receiptspec.CodeRecordOff
	CodeCaptureOff         = receiptspec.CodeCaptureOff
	CodeCaptureGap         = receiptspec.CodeCaptureGap
	CodeUnmetered          = receiptspec.CodeUnmetered
	CodeModelTimeUnseen    = receiptspec.CodeModelTimeUnseen
	CodeTruncated          = receiptspec.CodeTruncated
	CodeUnpriced           = receiptspec.CodeUnpriced
	CodeNoPriceTable       = receiptspec.CodeNoPriceTable
	CodeMissedActions      = receiptspec.CodeMissedActions
	CodeMessagesDropped    = receiptspec.CodeMessagesDropped
	CodeAskRepeated        = receiptspec.CodeAskRepeated
	CodeAnswerUnpaired     = receiptspec.CodeAnswerUnpaired
	CodeModelRoutesKept    = receiptspec.CodeModelRoutesKept
	CodeRecordUncertain    = receiptspec.CodeRecordUncertain
	CodeRulesUncertain     = receiptspec.CodeRulesUncertain
	CodeNoRunEnd           = receiptspec.CodeNoRunEnd
	LimitLaunchingUser     = receiptspec.LimitLaunchingUser
	LimitRecordOnly        = receiptspec.LimitRecordOnly
	LimitTailNotSynced     = receiptspec.LimitTailNotSynced
	LimitNoSignature       = receiptspec.LimitNoSignature
)

// Receipt is the specification's receipt (the JSON, receiptspec.Receipt) with the state the text layout and the words
// read and the JSON never carries. Every field of the specification is promoted, so a reader writes rc.Files as before.
type Receipt struct {
	receiptspec.Receipt

	// home is Options.Home, or the home the run recorded, for the text layout only.
	home string
	// startBy is the tego build run_start names (tego_version and commit): the build that ran the run, as the record
	// says it. CheckResult.RecordBy carries it to a caller; it is no receipt field and is never written.
	startBy MadeBy
	// startMinor is the record revision run_start opens (record_minor, 0 when it is absent or not read as one): which
	// revision a build wrote says whether it keeps a receipt at all. CheckResult.RecordMinor carries it to a caller.
	startMinor int
	// sayNoHome is Options.SayNoHome: the text layout owes the line that the record names no home.
	sayNoHome bool
	// ulpTLS and ulpOther count the refusals Refusals.ByRule holds under unmatched and net-not-allowed that are tego's
	// built-in refusal of setsockopt(TCP_ULP) (builtInULP): kernel TLS, and any other name. Only the words read them
	// (RefusalGroups); every count a script reads keeps them as the record does.
	ulpTLS, ulpOther int
	// sameFile is each refused exec a live block refused as another name of its program's file
	// (liveblock.SameFileNote), with its count, in the order first seen, at most MaxTop: only the words read it
	// (SameFile).
	sameFile []SameFileRefusal
	// nameBlocks are the live blocks by name (NameBlocks): only the words read them.
	nameBlocks []NameBlock
	// liftNotes are the lifts that carry a note (LiftNotes): only the words read them.
	liftNotes []LiftNote
	// price is where the cost sits in Coverage (reprice); startMono and lastMono are the run_start line's clock reading
	// and the largest one of any line, which a live receipt's time taken counts from and must pass (Check).
	price               pricing
	startMono, lastMono uint64
}

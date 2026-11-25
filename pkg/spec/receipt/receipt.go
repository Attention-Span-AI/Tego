// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"fmt"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Version is the receipt's JSON version (receipt_v). Keys only grow within it.
const Version = 1

// Receipt is one run's V1 receipt. Every field that cannot be read off the ledger has Recorded false and a Note.
type Receipt struct {
	// Baseline describes recorded enforcement, never today's configuration.
	Baseline               *BaselineSummary               `json:"baseline,omitempty"`
	V                      int                            `json:"receipt_v"`
	LocalApprovalAuthority *record.LocalApprovalAuthority `json:"local_approval_authority,omitempty"`
	Run                    string                         `json:"run"`
	Agent                  string                         `json:"agent"`
	Tier                   string                         `json:"tier,omitempty"`
	Capture                string                         `json:"capture,omitempty"`
	Command                []string                       `json:"command,omitempty"`
	Cwd                    string                         `json:"cwd,omitempty"`
	Started                *time.Time                     `json:"started,omitempty"`
	Finished               *time.Time                     `json:"finished,omitempty"`
	Ended                  bool                           `json:"ended"`
	EndReason              string                         `json:"end_reason,omitempty"`
	ExitCode               *int                           `json:"exit_code,omitempty"`
	Signal                 int                            `json:"signal,omitempty"`
	// Escalated is true when the run was asked to stop and Tego then killed it with cgroup.kill, because stop_grace ran
	// out or a second interrupt came within two seconds; the record does not say which. For reason signal or stopped,
	// Signal is then the signal that started the stop; limit, oom and pids keep the kernel's signal instead
	// (spec/record/v1 run_end). Additive; receipt_v stays 1.
	Escalated bool      `json:"escalated,omitempty"`
	Time      TimeTaken `json:"time_taken"`
	Files     Files     `json:"files"`
	Refusals  Refusals  `json:"refusals"`
	OverTime  OverTime  `json:"refusals_over_time"`
	Stall     Stall     `json:"stall"`
	Tests     Tests     `json:"tests"`
	Asks      Asks      `json:"asks"`
	Tokens    Tokens    `json:"tokens"`
	// Connections is where the run connected, most often first: the top MaxTop destinations with their verdicts;
	// ConnectionsMore counts other retained destination identities, ConnectionsOverflowAttempts counts attempts
	// beyond the identity budget, and ConnectionTries counts connections in all,
	// listed or not. A routine system lookup (syslookup.Routine: nscd, systemd's userdb and resolved, the D-Bus buses,
	// a DNS lookup) is not a place the run sent its data: it is counted in SystemLookups, never here, as the
	// dashboard's verdict folds it, so "most:" can never name the nscd socket. A socket call that names no place
	// (syslookup.NoPlace: an AF_UNSPEC connect, the kernel's netlink socket) is never here either: one that was not
	// refused is counted in RoutineSockets, and a refused one (such as a send to an AF_UNSPEC address, which the
	// supervisor refuses) only in Refusals, as the dashboard's verdict counts it.
	Connections     []Connection `json:"connections"`
	ConnectionsMore int          `json:"connections_more,omitempty"`
	// ConnectionsOverflowAttempts counts attempts whose destination identity was not retained.
	ConnectionsOverflowAttempts int `json:"connections_overflow_attempts,omitempty"`
	ConnectionTries             int `json:"connection_tries"`
	// DatagramSends is how many of ConnectionTries were UDP datagrams the run sent (record.NetOpSend); the rest, a
	// UDP connect among them, sent no datagram (GAPS C172). A ledger from before the op counts a send as a connect.
	DatagramSends  int `json:"datagram_sends,omitempty"`
	SystemLookups  int `json:"system_lookups,omitempty"`
	RoutineSockets int `json:"routine_sockets,omitempty"`
	// ConnectionsNote says what the list cannot hold (a tier that records refused connections only).
	ConnectionsNote string `json:"connections_note,omitempty"`
	// Programs is the programs the run started, most often first: the top MaxTop; ProgramsMore is how many other
	// retained program identities were omitted. ProgramsOverflowAttempts separately counts starts
	// beyond the identity budget. A refused exec is not here (it never ran); Refusals lists it.
	Programs     []Program `json:"programs"`
	ProgramsMore int       `json:"programs_more,omitempty"`
	// ProgramsOverflowAttempts counts starts whose program identity was not retained.
	ProgramsOverflowAttempts int `json:"programs_overflow_attempts,omitempty"`
	// ExecsDecisionLost counts the execs that failed with permission denied (EACCES) and whose line says its decision
	// record may be among those this run lost (exec decision_lost, record revision 41). It is neither a refusal (Refusals
	// does not count it: the record cannot say Tego's rules refused it, another security module may have) nor a program that
	// ran (Programs does not count it). Absent when there is none. Additive; receipt_v stays 1.
	ExecsDecisionLost int `json:"execs_decision_lost,omitempty"`
	// SensitiveReads is every file the run opened, or tried to, that looks like a secret by its name
	// (secretpath.Is) or that an fs.deny_read or fs.ask_read rule guards, in the order first seen, with what
	// happened to the tries.
	SensitiveReads          []SensitiveRead `json:"sensitive_reads"`
	SensitiveReadsTruncated bool            `json:"sensitive_reads_truncated,omitempty"`
	// SensitiveReadsNote says what the list cannot hold (a run that did not record allowed reads).
	SensitiveReadsNote string `json:"sensitive_reads_note,omitempty"`
	// SensitiveReadsUnknown says the run did not record every read, or its ledger does not say whether it did, so an
	// empty list means nothing: a file may have been read all the same.
	SensitiveReadsUnknown bool `json:"sensitive_reads_unknown,omitempty"`
	// ReadsNotified is run_start.reads_notified as the run wrote it: whether every read open reached the supervisor,
	// so that a read the contract refused has a line, and why. nil for a record written before the field (record_minor
	// 23), which does not say.
	ReadsNotified *record.ReadsNotified `json:"reads_notified,omitempty"`
	// Coverage says which fields this run's ledger could not support in full, and why.
	Coverage Coverage `json:"coverage"`
	// Lines is how many ledger lines the receipt read.
	Lines int `json:"lines"`
	// Notes are what the pass met that neither the counts nor the coverage say: anomalies (a second run_end, lines of a
	// newer version skipped), and the modes tego gave back to the owner of its own files (restoredNote), which lost no
	// action.
	Notes []string `json:"notes,omitempty"`
	// Binding ties the receipt to the record it was computed from (Options.Bind); nil when unbound.
	Binding *Binding `json:"binding,omitempty"`
}

// TimeTaken is the run's wall clock: run_start to run_end on the ledger's monotonic clock.
type TimeTaken struct {
	Seconds float64 `json:"seconds"`
	// SoFar is set for a run still running (measured to the caller's clock) or one with no run_end (measured to
	// its last line, with Note saying so).
	SoFar bool   `json:"so_far,omitempty"`
	Note  string `json:"note,omitempty"`
}

// Files is what the run changed on disk, as its allowed fs lines record it. A refused operation is not a change, nor
// is one whose line records that it failed (an errno, or a negative syscall_ret); a read is not one either, and neither
// is a write to a device that holds no file (device: /dev/null, the terminal). Only the tier-2 kernel record, and the
// opens and mutations the supervisor makes itself, record a result: at tier landlock the supervisor continues every
// other allowed call, whose line carries none, so a call the kernel then failed is listed all the same (an unlink of a
// name that is not there; GNU mv's renameat2 with RENAME_NOREPLACE, retried as renameat where the filesystem refuses
// the flag, lists one rename twice). No line at that tier says that an open created its file, so a file an open made
// is listed as written only; a mkdir, symlink or link is listed as created.
type Files struct {
	Recorded  bool     `json:"recorded"`
	Note      string   `json:"note,omitempty"`
	Written   []string `json:"written"`
	Created   []string `json:"created"`
	Deleted   []string `json:"deleted"`
	Renamed   []Rename `json:"renamed"`
	Truncated bool     `json:"truncated,omitempty"`
}

// Rename is one rename, from its old name to its new one.
type Rename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Refusals is every refused action: the count, the count by rule, and the list.
type Refusals struct {
	Total         int         `json:"total"`
	ByRule        []RuleCount `json:"by_rule"`
	List          []Refusal   `json:"list"`
	ListTruncated bool        `json:"list_truncated,omitempty"`
}

// RuleCount is how many refusals one rule made, with the reason code the agent got.
type RuleCount struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// Refusal is one refused action. Target is a path, a destination or a program path; an exec's argv is never
// copied (it can hold a secret). The list of them is in the order the calls were received (the lines' mono_ns); TS is
// the time the line was written, so it may not rise along the list: a call held for an ask and then refused is listed
// where it was received, with the later time it was written at.
type Refusal struct {
	Seq    uint64    `json:"seq"`
	TS     time.Time `json:"ts"`
	Kind   string    `json:"kind"`
	Op     string    `json:"op"`
	Target string    `json:"target"`
	Rule   string    `json:"rule"`
	Reason string    `json:"reason"`
	// Minute is the refusal's minute from run_start (0 is the first).
	Minute int `json:"minute"`
	// LearnWithheldRun is the contract's claim about this exact endpoint, not a new verdict.
	LearnWithheldRun string `json:"learn_withheld_run,omitempty"`
}

// OverTime is the refusals per minute from run_start: Counts[i] is minute i.
type OverTime struct {
	BucketSeconds int   `json:"bucket_s"`
	Counts        []int `json:"counts"`
	Truncated     bool  `json:"truncated,omitempty"`
}

// Stall is the time the run sat quiet: whole windows with no ledger line at or above the threshold, excluding
// windows that touch a gap line or sit inside an open model exchange.
type Stall struct {
	Recorded         bool    `json:"recorded"`
	Note             string  `json:"note,omitempty"`
	ThresholdSeconds float64 `json:"threshold_s"`
	Minutes          float64 `json:"minutes"`
	Windows          int     `json:"windows"`
	EndedByStall     bool    `json:"ended_by_stall,omitempty"`
}

// Tests is the run's tests result. No ledger line records one yet, so it is always not recorded for now.
type Tests struct {
	Recorded bool   `json:"recorded"`
	Note     string `json:"note,omitempty"`
}

// Asks is the times the run asked a person, and their answers.
type Asks struct {
	Asked      int     `json:"asked"`
	Approved   int     `json:"approved"`
	Denied     int     `json:"denied"`
	TimedOut   int     `json:"timed_out"`
	Alternates int     `json:"alternates"`
	Unanswered int     `json:"unanswered"`
	WaitS      float64 `json:"wait_s"`
	List       []Ask   `json:"list"`
	Truncated  bool    `json:"truncated,omitempty"`
}

// Ask is one ask and its answer ("" while unanswered).
type Ask struct {
	record.AnswerAuthority
	AskID  string    `json:"ask_id"`
	TS     time.Time `json:"ts"`
	Op     string    `json:"op"`
	Target string    `json:"target"`
	Rule   string    `json:"rule"`
	Answer string    `json:"answer"` // approved | denied | timed-out | alternate | unavailable | ""
	By     string    `json:"by,omitempty"`
	AfterS float64   `json:"after_s,omitempty"`
	// DeliveryNote distinguishes a durable selected approval from the later action outcome.
	DeliveryNote string `json:"delivery_note,omitempty"`
}

// Tokens is the model calls and tokens the capture recorded.
type Tokens struct {
	Recorded   bool   `json:"recorded"`
	Note       string `json:"note,omitempty"`
	ModelCalls int    `json:"model_calls"`
	Metered    int    `json:"metered"`
	In         uint64 `json:"in"`
	Out        uint64 `json:"out"`
	CacheRead  uint64 `json:"cache_read"`
	CacheWrite uint64 `json:"cache_write"`
	// EstCostUSD is the summed per-response estimate from Options.Prices, the figure `tego measure` prints;
	// Unpriced is the metered responses no price covered. CostText renders it with "est." (R20).
	EstCostUSD float64 `json:"est_cost_usd"`
	Unpriced   int     `json:"unpriced_responses"`
	CostText   string  `json:"est_cost,omitempty"`
}

// Coverage is the receipt's honesty line: Complete when every field was read off a ledger that records it, else
// one Gap per field that is missing or partial.
type Coverage struct {
	Complete bool          `json:"complete"`
	Gaps     []CoverageGap `json:"gaps"`
	// DenyReadFrozen is run_start's deny_read_frozen: the directories the run's Landlock ruleset listed once at launch,
	// in which a name made during the run was unreadable to it (GAPS A12). It is what the run's rules were, not what
	// the record missed, so it is no gap and leaves Complete as it is. Absent when run_start has none.
	DenyReadFrozen *record.DenyReadFrozen `json:"deny_read_frozen,omitempty"`
}

// CoverageGap is one field the ledger could not support in full: its JSON key, why as a code a program can match (one
// of the Code constants) and why in words. Why's words may change; a code never does, and a new reason gets a new
// one.
type CoverageGap struct {
	Field string `json:"field"`
	Code  string `json:"code"`
	// Level is how much of the field the ledger supports: LevelPartial (some of it, so a count is a floor or an
	// estimate) or LevelNone (the ledger is silent on the field, so what is shown for it is not evidence). A field with no gap
	// is complete. It is set from the code (LevelOf); a receipt from before the key has none, which a reader takes as the
	// code's own level (a reader reads it through EffectiveLevel, never as written, since it must not read a gap
	// as better than it is). Additive; receipt_v stays 1.
	Level string `json:"level,omitempty"`
	Why   string `json:"why"`
}

// FrozenText is the sentence the receipt's Coverage prints for DenyReadFrozen, the same in `tego receipt` and on the
// dashboard's Receipt tab, with the paths escaped by record.Printable; "" when there is none.
func (c Coverage) FrozenText() string {
	f := c.DenyReadFrozen
	if f == nil {
		return ""
	}
	list := strings.Join(f.Dirs, ", ")
	switch {
	case f.Omitted > 0 && len(f.Dirs) > 0:
		list += fmt.Sprintf(" and %d more", f.Omitted)
	case f.Omitted > 0:
		list = fmt.Sprintf("%d directories", f.Omitted)
	}
	return "Frozen at launch: deny_read listed " + record.Printable(list) + " once; a file or directory made directly " +
		"in one of them during the run could not be read."
}

// Changed is how many distinct paths the run wrote, created, deleted or renamed.
func (f *Files) Changed() int {
	set := map[string]bool{}
	for _, l := range [][]string{f.Written, f.Created, f.Deleted} {
		for _, p := range l {
			set[p] = true
		}
	}
	for _, r := range f.Renamed {
		set[r.To] = true
	}
	return len(set)
}

// The coverage codes, each with the field it is given on. The first six are the receipt design's why codes; the
// others name the gaps this receipt reports beyond them.
const (
	// CodeNoCapabilities: the ledger has no capabilities line, so whether it records allowed writes is not known (files).
	CodeNoCapabilities = "no-capabilities-line"
	// CodeRecordOff: the run's tier records refused writes only (files).
	CodeRecordOff = "record-off"
	// CodeCaptureOff: model traffic capture was off (tokens).
	CodeCaptureOff = "capture-off"
	// CodeCaptureGap: capture gap lines say tego could not read some model traffic, so the token counts are a floor
	// (tokens.capture).
	CodeCaptureGap = "capture-gap"
	// CodeUnmetered: some model responses carried no token counts (tokens).
	CodeUnmetered = "unmetered-responses"
	// CodeModelTimeUnseen: model traffic was not captured, so time spent waiting on the model counts as quiet (stall).
	CodeModelTimeUnseen = "model-time-unseen"
	// CodeTruncated: a list stops at its cap; the counts beside it are complete (files, refusals.list).
	CodeTruncated = "truncated"
	// CodeUnpriced: some metered responses had no price (tokens.est_cost_usd).
	CodeUnpriced = "unpriced-responses"
	// CodeNoPriceTable: the run had no usable price table and the reader gave none, so the cost is not estimated
	// (tokens.est_cost_usd).
	CodeNoPriceTable = record.GapNoPriceTable
	// CodeMissedActions: gap lines say tego missed some actions, so the counts are a floor (record).
	CodeMissedActions = "missed-actions"
	// CodeMessagesDropped: MCP messages the relay could not pass on because they were past the size it reads; the
	// record has a gap line for each, naming the server, the size and the limit. No action went unrecorded
	// (record.mcp).
	CodeMessagesDropped = "messages-dropped"
	// CodeAskRepeated: an ask line repeated an ask id already asked; only the first counts (asks).
	CodeAskRepeated = "ask-repeated"
	// CodeAnswerUnpaired: an answer line pairs with no ask (it came first, names an id never asked, or answers an ask
	// already answered), and does not count as an answer (asks).
	CodeAnswerUnpaired = "answer-unpaired"
	// CodeModelRoutesKept: the forwarder could not read the run's model routes and kept the routes it read last; a
	// change made meanwhile was not applied, and no action went unrecorded (record.routes).
	CodeModelRoutesKept = "model-routes-kept"
	// CodeRecordUncertain: shared tracing counters cannot establish this run's recording coverage (record).
	CodeRecordUncertain = "recording-uncertain"
	// CodeRulesUncertain: the kernel skipped a shared program the run's rules rely on, or its counters could not be
	// read, so the receipt cannot say every rule held (refusals; ADR 0148).
	CodeRulesUncertain = "rules-uncertain"
	// CodeNoRunEnd: the run has no run_end line yet (time_taken).
	CodeNoRunEnd = "no-run-end"
)

// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/check/internal/mirror"
	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Version is the receipt's JSON version (receipt_v). Keys only grow within it.
const Version = 1

// The caps that bound the receipt's memory whatever the run's size.
const (
	// MaxPaths is the most paths each file list holds; past it the list says truncated.
	MaxPaths = 1000
	// MaxRefusals is the most refused actions the list holds, oldest first; the counts keep counting.
	MaxRefusals = 1000
	// MaxAsks is the most asks the list holds.
	MaxAsks = 1000
	// MaxPendingAsks bounds unanswered identities tracked for exact aggregate counts, independently of MaxAsks.
	MaxPendingAsks = 32_768
	// MaxPendingAskBytes bounds their estimated storage, including long IDs and a per-entry allowance.
	MaxPendingAskBytes = 8 << 20
	// MaxBuckets is the most per-minute buckets (a week); later refusals fold into the last one.
	MaxBuckets = 10080
	// DefaultStallThreshold is the quiet span from which a window counts as stalled.
	DefaultStallThreshold = 5 * time.Minute
	// MaxTop is how many destinations and programs the receipt names; the rest are counted (ConnectionsMore,
	// ProgramsMore).
	MaxTop = 10
)

// ctxEvery is how many lines Compute reads between checks of its context.
const ctxEvery = 1024

// Options tune Compute.
type Options struct {
	// NowMonoNS is the caller's monotonic clock reading (the ledger's clock). A run with no run_end measures its
	// time taken and its last quiet window to it; 0, or a reading before the last event, is ignored.
	NowMonoNS uint64
	// StallThreshold overrides the stall threshold; 0 takes min(5m, the run's limits.stall_after).
	StallThreshold time.Duration
	// Prices estimates each model response's cost, as `tego measure` does (the same interface, filled by the CLI
	// from the machine's price table). Nil prices nothing: the receipt then counts every response unpriced.
	Prices measure.Prices
	// Home is the home directory "~" stands for in the text layout (Text): a path under it prints as ~/... . The
	// ledger does not record the run's HOME, so the caller passes the one it knows (tego run its own, tego receipt
	// its reader's); "" prints every path outside the run's folder whole. JSON always keeps the full paths.
	Home string
	// Bind binds the receipt to the record it reads (Receipt.Binding), by the tego named here: the one pass that
	// computes the receipt also checks every line as Verify does and hashes the bytes it read. Only `tego receipt
	// --json` sets it; nil leaves Binding out, so the dashboard's receipt and tego run's end summary are unchanged.
	Bind *MadeBy
}

// Receipt is one run's V1 receipt. Every field that cannot be read off the ledger has Recorded false and a Note.
type Receipt struct {
	V         int        `json:"receipt_v"`
	Run       string     `json:"run"`
	Agent     string     `json:"agent"`
	Tier      string     `json:"tier,omitempty"`
	Capture   string     `json:"capture,omitempty"`
	Command   []string   `json:"command,omitempty"`
	Cwd       string     `json:"cwd,omitempty"`
	Started   *time.Time `json:"started,omitempty"`
	Finished  *time.Time `json:"finished,omitempty"`
	Ended     bool       `json:"ended"`
	EndReason string     `json:"end_reason,omitempty"`
	ExitCode  *int       `json:"exit_code,omitempty"`
	Signal    int        `json:"signal,omitempty"`
	Time      TimeTaken  `json:"time_taken"`
	Files     Files      `json:"files"`
	Refusals  Refusals   `json:"refusals"`
	OverTime  OverTime   `json:"refusals_over_time"`
	Stall     Stall      `json:"stall"`
	Tests     Tests      `json:"tests"`
	Asks      Asks       `json:"asks"`
	Tokens    Tokens     `json:"tokens"`
	// Connections is where the run connected, most often first: the top MaxTop destinations with their verdicts;
	// ConnectionsMore is how many other destinations there were and ConnectionTries how many connections in all,
	// listed or not. A routine system lookup (syslookup.Routine: nscd, systemd's userdb and resolved, the D-Bus buses,
	// a DNS lookup) is not a place the run sent its data: it is counted in SystemLookups, never here, as the
	// dashboard's verdict folds it, so "most:" can never name the nscd socket. A socket call that names no place
	// (syslookup.NoPlace: an AF_UNSPEC connect, the kernel's netlink socket) is never here either: one that was not
	// refused is counted in RoutineSockets, and a refused one (such as a send to an AF_UNSPEC address, which the
	// supervisor refuses) only in Refusals, as the dashboard's verdict counts it.
	Connections     []Connection `json:"connections"`
	ConnectionsMore int          `json:"connections_more,omitempty"`
	ConnectionTries int          `json:"connection_tries"`
	SystemLookups   int          `json:"system_lookups,omitempty"`
	RoutineSockets  int          `json:"routine_sockets,omitempty"`
	// ConnectionsNote says what the list cannot hold (a tier that records refused connections only).
	ConnectionsNote string `json:"connections_note,omitempty"`
	// Programs is the programs the run started, most often first: the top MaxTop; ProgramsMore is how many other
	// programs there were. A refused exec is not here (it never ran); Refusals lists it.
	Programs     []Program `json:"programs"`
	ProgramsMore int       `json:"programs_more,omitempty"`
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

	// home is Options.Home, for the text layout only.
	home string
	// ulpTLS and ulpOther count the refusals Refusals.ByRule holds under unmatched and net-not-allowed that are tego's
	// built-in refusal of setsockopt(TCP_ULP) (builtInULP): kernel TLS, and any other name. Only the words read them
	// (RefusalGroups); every count a script reads keeps them as the record does.
	ulpTLS, ulpOther int
	// sameFile is each refused exec a live block refused as another name of its program's file
	// (liveblock.SameFileNote), with its count, in the order first seen, at most MaxTop: only the words read it
	// (SameFile).
	sameFile []SameFileRefusal
	// price is where the cost sits in Coverage (reprice); startMono and lastMono are the run_start line's clock reading
	// and the largest one of any line, which a live receipt's time taken counts from and must pass (Check).
	price               pricing
	startMono, lastMono uint64
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
// copied (it can hold a secret).
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
}

// SameFileRefusal is a program path a live block refused because it is another name of the program file the block's
// path leads to (a multi-call program's applets are one file): Note says so (liveblock.SameFileNote), Count is how many
// times.
type SameFileRefusal struct {
	Path, Note string
	Count      int
}

// SameFile is the refused execs a live block refused as another name of its program's file, in the order first seen,
// at most MaxTop: the words the run summary and the receipt add, since the line's rule names the block's path and not
// the path that ran.
func (rc *Receipt) SameFile() []SameFileRefusal { return rc.sameFile }

// sameFileRefusal counts a refused exec of path under rule when a live block refused it as another name of its file.
func (b *builder) sameFileRefusal(rule, path string) {
	note := liveblock.SameFileNote(rule, path)
	if note == "" {
		return
	}
	for i := range b.rc.sameFile {
		if s := &b.rc.sameFile[i]; s.Path == path && s.Note == note {
			s.Count++
			return
		}
	}
	if len(b.rc.sameFile) < MaxTop {
		b.rc.sameFile = append(b.rc.sameFile, SameFileRefusal{Path: path, Note: note, Count: 1})
	}
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
	AskID  string    `json:"ask_id"`
	TS     time.Time `json:"ts"`
	Op     string    `json:"op"`
	Target string    `json:"target"`
	Rule   string    `json:"rule"`
	Answer string    `json:"answer"` // approved | denied | timed-out | alternate | unavailable | ""
	By     string    `json:"by,omitempty"`
	AfterS float64   `json:"after_s,omitempty"`
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

// CoverageGap is one field the ledger could not support in full: its JSON key, why as a code a program can match (one
// of the Code constants) and why in words. Why's words may change; a code never does, and a new reason gets a new
// one.
type CoverageGap struct {
	Field string `json:"field"`
	Code  string `json:"code"`
	Why   string `json:"why"`
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
	CodeNoPriceTable = "no-price-table"
	// CodeMissedActions: gap lines say tego missed some actions, so the counts are a floor (record).
	CodeMissedActions = "missed-actions"
	// CodeRecordUncertain: shared tracing counters cannot establish this run's recording coverage (record).
	CodeRecordUncertain = "recording-uncertain"
	// CodeNoRunEnd: the run has no run_end line yet (time_taken).
	CodeNoRunEnd = "no-run-end"
)

// ErrNoRun is a ledger whose first line is not run_start.
var ErrNoRun = errors.New("no run record")

// ErrAskLimit means exact ask accounting exceeded its pending identity count or byte budget. Compute returns no
// receipt: dropping identities would make a later answer indistinguishable from one with no recorded ask.
var ErrAskLimit = errors.New("pending ask limit exceeded")

// payload is the union of the payload keys the receipt reads.
type payload struct {
	Op           string   `json:"op"`
	Path         string   `json:"path"`
	Path2        string   `json:"path2"`
	Flags        int      `json:"flags"`
	Created      bool     `json:"created"`
	Errno        int      `json:"errno"`
	SyscallRet   int64    `json:"syscall_ret"`
	Dst          string   `json:"dst"`
	Host         string   `json:"host"`
	Target       string   `json:"target"`
	AskID        string   `json:"ask_id"`
	AskRule      string   `json:"ask_rule"`
	By           string   `json:"by"`
	AfterS       float64  `json:"after_s"`
	Approved     *bool    `json:"approved"`
	AnswerReason string   `json:"answer_reason"`
	Alternate    string   `json:"alternate"`
	RequestSeq   *uint64  `json:"request_seq"`
	Reason       string   `json:"reason"`
	ExitCode     int      `json:"exit_code"`
	Signal       int      `json:"signal"`
	Which        string   `json:"which"`
	Command      []string `json:"command"`
	Mechanism    string   `json:"mechanism"`
}

// The open flags that make an open a write (Linux values; the ledger records the raw flags).
const (
	oWronly = 0o1
	oRdwr   = 0o2
	oCreat  = 0o100
	oExcl   = 0o200
	oTrunc  = 0o1000
	oAppend = 0o2000
)

// builder holds one pass's state.
type builder struct {
	rc        *Receipt
	startMono uint64
	lastMono  uint64
	rules     map[[2]string]int
	seen      map[string]bool // path+category already listed
	asks      map[string]int  // pending ask_id -> display index, -1 beyond the display cap
	askBytes  int64           // estimated pending identity storage, independent of the display list
	// stall
	prevMono   uint64
	prevGap    bool
	openSSL    map[uint64]bool
	windows    []time.Duration
	stallAfter time.Duration
	// the lines before, for counting a refused line that mirrors a refused action once
	pairs       mirror.Pairs
	lastAsk     *payload
	lastAskRule string
	runStart    record.RunStartPayload
	prices      measure.Prices
	gapLines    int        // gap lines that may have lost actions: the record's counts are a floor
	sharedGaps  gaps.Tally // shared tracing uncertainty, with its own count semantics
	captureGaps int        // gap what=capture lines: model traffic tego could not read
	restored    int        // gap lines of a mode tego gave back to the owner of one of its own files: no action lost
	noPrice     bool       // a gap said the run had no usable price table
	devWrite    bool       // an allowed write reached a device, which Files does not list (device)
	act         activity
}

// Compute builds one run's receipt from its ledger in one streaming pass. Pending ask identities are bounded
// separately from the display list; exceeding that budget returns ErrAskLimit and no partial receipt.
func Compute(ctx context.Context, r *ledger.Reader, opt Options) (*Receipt, error) {
	if r == nil {
		return nil, fmt.Errorf("receipt: no ledger reader")
	}
	b := &builder{rc: &Receipt{V: Version}, rules: map[[2]string]int{}, seen: map[string]bool{}, asks: map[string]int{},
		openSSL: map[uint64]bool{}, prevGap: true, prices: opt.Prices, act: newActivity()}
	rc := b.rc
	rc.home = opt.Home
	rc.Connections, rc.Programs, rc.SensitiveReads = []Connection{}, []Program{}, []SensitiveRead{}
	rc.Files.Written, rc.Files.Created, rc.Files.Deleted, rc.Files.Renamed = []string{}, []string{}, []string{}, []Rename{}
	rc.Refusals.ByRule, rc.Refusals.List, rc.Asks.List = []RuleCount{}, []Refusal{}, []Ask{}
	rc.OverTime.BucketSeconds, rc.OverTime.Counts = 60, []int{}
	var binder *ledger.Binder
	if opt.Bind != nil {
		// The binder rides this pass (ledger.Reader.Bind): it sees every line before Iter decodes or skips it, so the
		// head binds exactly the lines these numbers came from, newer-version lines included.
		binder = r.Bind()
	}
	first := true
	for e, err := range r.Iter() {
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(r.Dir(), ledger.EventsFile), err)
		}
		if first && e.Kind != record.KindRunStart {
			return nil, fmt.Errorf("%w: the first line is %s, not run_start", ErrNoRun, e.Kind)
		}
		first = false
		rc.Lines++
		if rc.Lines%ctxEvery == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err := b.line(e); err != nil {
			return nil, fmt.Errorf("receipt: seq %d: %w", e.Seq, err)
		}
	}
	if first {
		return nil, fmt.Errorf("%w: the ledger holds no line", ErrNoRun)
	}
	b.finish(opt)
	if binder != nil {
		rc.Binding = bindingOf(binder.Bound(), *opt.Bind, rc.Tier)
	}
	return rc, nil
}

func (b *builder) line(e *record.Event) error {
	rc := b.rc
	if rc.Run == "" {
		rc.Run, rc.Agent = e.Run, e.Agent
	}
	var p payload
	if len(e.Payload) > 0 {
		_ = json.Unmarshal(e.Payload, &p)
	}
	if e.MonoNS > b.lastMono {
		b.lastMono = e.MonoNS
	}
	b.stallLine(e, &p)

	switch e.Kind {
	case record.KindRunStart:
		if b.startMono == 0 {
			b.startMono = e.MonoNS
			ts := e.TS
			rc.Started = &ts
			_ = e.DecodePayload(&b.runStart)
			rc.Tier, rc.Capture, rc.Command, rc.Cwd = b.runStart.Tier, b.runStart.Capture, b.runStart.Command, b.runStart.Cwd
			if l := b.runStart.Limits; l != nil && l.StallAfter != "" {
				if d, err := time.ParseDuration(l.StallAfter); err == nil && d > 0 {
					b.stallAfter = d
				}
			}
		}
	case record.KindRunEnd:
		if rc.Ended {
			rc.Notes = append(rc.Notes, fmt.Sprintf("a second run_end line at seq %d is ignored", e.Seq))
			break
		}
		rc.Ended, rc.EndReason, rc.Signal = true, p.Reason, p.Signal
		ts := e.TS
		rc.Finished = &ts
		if p.Reason == "exit" {
			code := p.ExitCode
			rc.ExitCode = &code
		}
	case record.KindFS:
		b.file(e, &p)
		b.sensitive(e, &p)
	case record.KindNet:
		b.connection(e, &p)
	case record.KindExec:
		b.program(e, &p)
	case record.KindAsk:
		if err := b.ask(e, &p); err != nil {
			return err
		}
	case record.KindAnswer:
		b.answer(&p)
	case record.KindSSLResponse:
		rc.Tokens.ModelCalls++
		if u, ok := ledger.Usage(e); ok {
			rc.Tokens.Metered++
			rc.Tokens.In = ledger.SatAdd(rc.Tokens.In, u.In)
			rc.Tokens.Out = ledger.SatAdd(rc.Tokens.Out, u.Out)
			rc.Tokens.CacheRead = ledger.SatAdd(rc.Tokens.CacheRead, u.CacheRead)
			rc.Tokens.CacheWrite = ledger.SatAdd(rc.Tokens.CacheWrite, u.CacheWrite)
			// The cost is measure's R20 estimate over the same decode (ledger.Usage) and the same Prices, so the
			// receipt and `tego measure` print one figure.
			if b.prices == nil {
				rc.Tokens.Unpriced++
			} else if c, ok := b.prices.Cost(u); ok {
				rc.Tokens.EstCostUSD += c
			} else {
				rc.Tokens.Unpriced++
			}
		}
	case record.KindGap:
		b.gap(e)
	case record.KindLimit:
		if p.Which == "stall_after" {
			rc.Stall.EndedByStall = true
		}
	}

	// A refused action counts once: the action line, or a refused line written on its own; a refused line that
	// mirrors a refused action before it is that action again (measure R19, internal/check/internal/mirror).
	mirrored := b.pairs.Take(e)
	if (e.Kind.IsAction() && e.Verdict == record.VerdictRefused) || (e.Kind == record.KindRefused && !mirrored) {
		b.refusal(e, &p)
		if e.Kind == record.KindRefused {
			b.refusedAlone(e, &p) // a refused line that mirrors no action line: its connection or read too
		}
	}
	if e.Verdict == record.VerdictAsk {
		cp := p
		b.lastAsk, b.lastAskRule = &cp, e.Rule
	}
	return nil
}

// target is what a refused line names: a path, a destination, or a program path (never an argv).
func target(e *record.Event, p *payload) string {
	switch e.Kind {
	case record.KindFS:
		if p.Path2 != "" {
			return p.Path + " -> " + p.Path2
		}
		return p.Path
	case record.KindNet:
		if p.Host != "" {
			return p.Host + " (" + p.Dst + ")"
		}
		return p.Dst
	case record.KindExec:
		return p.Path
	case record.KindRefused:
		return p.Target
	}
	return p.Path
}

func opOf(e *record.Event, p *payload) string {
	switch {
	case e.Kind == record.KindExec:
		return "exec"
	case e.Kind == record.KindNet && p.Op == "":
		return "connect"
	case p.Op != "":
		return p.Op
	}
	return string(e.Kind)
}

func (b *builder) minute(mono uint64) int {
	if mono <= b.startMono || b.startMono == 0 {
		return 0
	}
	return int((mono - b.startMono) / uint64(time.Minute))
}

func (b *builder) refusal(e *record.Event, p *payload) {
	rf := &b.rc.Refusals
	rf.Total++
	reason := string(e.Reason)
	if reason == "" && e.Kind == record.KindRefused {
		reason = p.Reason
	}
	b.rules[[2]string{e.Rule, reason}]++
	if e.Kind == record.KindExec {
		b.sameFileRefusal(e.Rule, p.Path)
	}
	if tls, ok := builtInULP(opOf(e, p), target(e, p), e.Rule, reason); ok && tls {
		b.rc.ulpTLS++
	} else if ok {
		b.rc.ulpOther++
	}
	m := b.minute(e.MonoNS)
	ot := &b.rc.OverTime
	if m >= MaxBuckets {
		m, ot.Truncated = MaxBuckets-1, true
	}
	for len(ot.Counts) <= m {
		ot.Counts = append(ot.Counts, 0)
	}
	ot.Counts[m]++
	if len(rf.List) >= MaxRefusals {
		rf.ListTruncated = true
		return
	}
	rf.List = append(rf.List, Refusal{Seq: e.Seq, TS: e.TS, Kind: string(e.Kind), Op: opOf(e, p), Target: target(e, p),
		Rule: e.Rule, Reason: reason, Minute: m})
}

func (b *builder) add(list *[]string, cat, path string) {
	if path == "" || b.seen[cat+"\x00"+path] {
		return
	}
	if len(*list) >= MaxPaths {
		b.rc.Files.Truncated = true
		return
	}
	b.seen[cat+"\x00"+path] = true
	*list = append(*list, path)
}

func (b *builder) file(e *record.Event, p *payload) {
	if e.Verdict == record.VerdictRefused || e.Verdict == record.VerdictAsk || p.Errno != 0 || p.SyscallRet < 0 {
		return
	}
	f := &b.rc.Files
	switch p.Op {
	case record.FSOpen:
		if p.Created {
			b.add(&f.Created, "c", p.Path)
		}
		// O_CREAT|O_EXCL succeeds only on a name that did not exist: the run made this file (foldTempRenames).
		if (p.Created || p.Flags&(oCreat|oExcl) == oCreat|oExcl) && len(b.act.fresh) < MaxPaths {
			b.act.fresh[p.Path] = true
		}
		if p.Flags&(oWronly|oRdwr|oTrunc|oAppend) != 0 {
			b.written(p)
		}
	case record.FSTruncate:
		b.written(p)
	case record.FSLink:
		b.add(&f.Created, "c", p.Path2)
	case record.FSMkdir, record.FSSymlink:
		b.add(&f.Created, "c", p.Path)
	case record.FSUnlink, "rmdir":
		b.add(&f.Deleted, "d", p.Path)
	case record.FSRename:
		if len(f.Renamed) >= MaxPaths {
			f.Truncated = true
			return
		}
		f.Renamed = append(f.Renamed, Rename{From: p.Path, To: p.Path2})
	}
}

// written lists p's path among the files written, unless the write reached a device that holds no file (device). An
// open that created its file made a regular file, whatever its name, so that one is listed.
func (b *builder) written(p *payload) {
	if !p.Created && device(p.Path) {
		b.devWrite = true
		return
	}
	b.add(&b.rc.Files.Written, "w", p.Path)
}

// devices are the device files a write reaches no file through: the byte sinks and sources, and the terminal. A run
// writes to them all the time (a shell's 2>/dev/null, a full-screen agent's /dev/tty, Codex's pseudo-terminals), and
// listing them had the demo's watched run say "wrote 3 files" (QA PW-12). internal/runtime's heldWriteExempt names the
// same set, which this package may not import. A name that only stands for a descriptor (/dev/stdout, /dev/fd/N,
// /proc/self/fd/N) is not one of them: a write through it can reach a regular file the ledger names nowhere else.
var devices = map[string]bool{"/dev/null": true, "/dev/zero": true, "/dev/full": true, "/dev/random": true,
	"/dev/urandom": true, "/dev/tty": true, "/dev/console": true, "/dev/ptmx": true}

// device reports whether path, as the line names it, is one of devices or a pseudo-terminal (/dev/pts/N). The name
// is compared as recorded, never cleaned: an older ledger's "/a/lk/../../dev/null" cleans to /dev/null lexically, yet
// names a file elsewhere when lk is a symlink.
func device(path string) bool { return devices[path] || strings.HasPrefix(path, "/dev/pts/") }

func pendingAskBytes(id string) int64 { return 128 + int64(len(id)) }

func (b *builder) ask(e *record.Event, p *payload) error {
	if _, pending := b.asks[p.AskID]; !pending {
		bytes := pendingAskBytes(p.AskID)
		if len(b.asks) >= MaxPendingAsks || b.askBytes+bytes > MaxPendingAskBytes {
			return fmt.Errorf("%w (maximum %d unanswered IDs or %d estimated bytes)", ErrAskLimit, MaxPendingAsks, MaxPendingAskBytes)
		}
		b.askBytes += bytes
	}
	a := &b.rc.Asks
	a.Asked++
	a.Unanswered++
	b.asks[p.AskID] = -1
	if len(a.List) >= MaxAsks {
		a.Truncated = true
		return nil
	}
	item := Ask{AskID: p.AskID, TS: e.TS, Op: p.Op, Target: p.Target, Rule: p.AskRule}
	if b.lastAsk != nil {
		if item.Op == "" {
			item.Op = opOf(e, b.lastAsk)
		}
		if item.Target == "" {
			item.Target = b.lastAsk.Path
		}
		if item.Rule == "" {
			item.Rule = b.lastAskRule
		}
	}
	if item.Rule == "" {
		item.Rule = e.Rule
	}
	b.asks[p.AskID] = len(a.List)
	a.List = append(a.List, item)
	return nil
}

func (b *builder) answer(p *payload) {
	a := &b.rc.Asks
	word := "denied"
	switch {
	case p.Alternate != "":
		word = "alternate"
		a.Alternates++
	case p.Approved != nil && *p.Approved:
		word = "approved"
		a.Approved++
	case p.AnswerReason == string(record.ReasonAskTimeout):
		word = "timed-out"
		a.TimedOut++
	case p.AnswerReason == string(record.ReasonAskUnavailable):
		word = "unavailable"
		a.Denied++
	default:
		a.Denied++
	}
	a.WaitS += p.AfterS
	// Answer totals include asks beyond the presentation cap.
	if i, pending := b.asks[p.AskID]; pending {
		a.Unanswered--
		b.askBytes -= pendingAskBytes(p.AskID)
		if i >= 0 && a.List[i].Answer == "" {
			a.List[i].Answer, a.List[i].By, a.List[i].AfterS = word, p.By, p.AfterS
		}
		delete(b.asks, p.AskID)
	}
}

// stallLine applies one line to the quiet-window scan: a window opens at the largest mono_ns so far and closes
// at the next line's; one that touches a gap, or sits inside an open model exchange, is not a stall.
func (b *builder) stallLine(e *record.Event, p *payload) {
	if !b.prevGap && e.Kind != record.KindGap && b.prevMono > 0 && e.MonoNS > b.prevMono && len(b.openSSL) == 0 {
		b.windows = append(b.windows, time.Duration(e.MonoNS-b.prevMono))
		if len(b.windows) > 4*MaxBuckets { // bounded: keep only the windows that could count
			b.compactWindows()
		}
	}
	b.prevMono, b.prevGap = max(b.prevMono, e.MonoNS), e.Kind == record.KindGap
	switch e.Kind {
	case record.KindSSLRequest:
		b.openSSL[e.Seq] = true
	case record.KindSSLResponse:
		if p.RequestSeq != nil {
			delete(b.openSSL, *p.RequestSeq)
		}
	}
}

// compactWindows drops windows below a minute, which no threshold this receipt uses can count.
func (b *builder) compactWindows() {
	kept := b.windows[:0]
	for _, w := range b.windows {
		if w >= time.Minute {
			kept = append(kept, w)
		}
	}
	b.windows = kept
}

func (b *builder) finish(opt Options) {
	rc := b.rc
	rc.startMono, rc.lastMono = b.startMono, b.lastMono
	end, live := b.lastMono, false
	if !rc.Ended && opt.NowMonoNS > b.lastMono {
		end, live = opt.NowMonoNS, true
	}
	if b.startMono > 0 && end > b.startMono {
		rc.Time.Seconds = time.Duration(end - b.startMono).Seconds()
	}
	switch {
	case live:
		rc.Time.SoFar = true
	case !rc.Ended:
		rc.Time.SoFar, rc.Time.Note = true, "no run_end line: measured to the last line"
	}
	if live && !b.prevGap && len(b.openSSL) == 0 && b.prevMono > 0 && end > b.prevMono {
		b.windows = append(b.windows, time.Duration(end-b.prevMono)) // a live run's current quiet tail
	}

	// refusals by rule: most first, then by rule
	for k, n := range b.rules {
		rc.Refusals.ByRule = append(rc.Refusals.ByRule, RuleCount{Rule: k[0], Reason: k[1], Count: n})
	}
	sort.Slice(rc.Refusals.ByRule, func(i, j int) bool {
		x, y := rc.Refusals.ByRule[i], rc.Refusals.ByRule[j]
		if x.Count != y.Count {
			return x.Count > y.Count
		}
		if x.Rule != y.Rule {
			return x.Rule < y.Rule
		}
		return x.Reason < y.Reason
	})
	if b.startMono > 0 && rc.Time.Seconds > 0 {
		need := min(b.minute(end)+1, MaxBuckets)
		for len(rc.OverTime.Counts) < need {
			rc.OverTime.Counts = append(rc.OverTime.Counts, 0)
		}
	}

	// stall
	th := opt.StallThreshold
	if th <= 0 {
		th = DefaultStallThreshold
		if b.stallAfter > 0 && b.stallAfter < th {
			th = b.stallAfter
		}
	}
	st := &rc.Stall
	st.Recorded, st.ThresholdSeconds = true, th.Seconds()
	var quiet time.Duration
	for _, w := range b.windows {
		if w >= th {
			st.Windows++
			quiet += w
		}
	}
	st.Minutes = float64(int(quiet.Minutes()*10+0.5)) / 10
	if rc.Capture == "" || rc.Capture == string(backend.CaptureOff) {
		st.Note = "model traffic was not captured, so time spent waiting on the model counts as quiet"
	}

	// files: recorded only when the run's tier records allowed opens. A ledger with no capabilities line shows it by a
	// line for an allowed write, one to a device included.
	f := &rc.Files
	if caps := b.runStart.Capabilities; caps == nil {
		f.Recorded, f.Note = b.devWrite || len(f.Written)+len(f.Created)+len(f.Deleted)+len(f.Renamed) > 0,
			"this run's ledger does not say whether allowed writes were recorded"
		if !f.Recorded {
			f.Note = "not recorded: this run's ledger has no line for an allowed write"
		}
	} else if caps[string(backend.CapRecordExecOpenNet)] {
		f.Recorded = true
	} else {
		f.Recorded, f.Note = false, "not recorded: tier "+rc.Tier+" records refused writes only, not the ones it allowed"
	}

	b.foldTempRenames()
	b.finishActivity()

	// tests
	rc.Tests.Note = "not recorded: no ledger line records a tests result yet"

	// tokens
	t := &rc.Tokens
	switch {
	case rc.Capture == "" || rc.Capture == string(backend.CaptureOff):
		t.Note = "not recorded: model traffic capture was off for this run"
	case t.ModelCalls == 0:
		t.Recorded, t.Note = true, "capture was on and recorded no model call"
	default:
		t.Recorded = true
		if t.Metered < t.ModelCalls {
			t.Note = fmt.Sprintf("%d of %d model responses carried no token counts", t.ModelCalls-t.Metered, t.ModelCalls)
		}
	}
	t.price()
	if b.restored > 0 {
		rc.Notes = append(rc.Notes, restoredNote(b.restored))
	}
	b.coverage()
}

// The why of a gap what=record that internal/runtime/limits writes when the run has no usable price table (its
// GapNoPriceTable and GapVersionMismatch), and once per model its table does not price (GapUnpricedModel). Named
// here because internal/check must not import internal/runtime.
const (
	gapNoPriceTable  = "no-price-table"
	gapPriceVersion  = "price-table-version-mismatch"
	gapUnpricedModel = "unpriced-model"
)

// gap sorts one gap line by what it means (gaps.Classify, tego status's reading too). Only a gap that may have lost
// actions makes the record's counts a floor: a person's own pause, resume or live block (the timeline shows each)
// loses nothing, a capture gap only makes the token counts a floor, a price gap only leaves the cost unestimated, and
// a mode tego gave back to the owner of one of its own files is a note (restoredNote). A line whose payload does not
// decode counts as a lost action, the conservative reading.
func (b *builder) gap(e *record.Event) {
	var g record.GapPayload
	if e.DecodePayload(&g) != nil {
		b.gapLines++
		return
	}
	switch gaps.Classify(g.What, g.Why) {
	case gaps.Uncertain:
		b.sharedGaps.Add(e)
	case gaps.Live:
	case gaps.Price:
		// An unpriced model is no missing table: the receipt prices each response itself, and its
		// tokens.est_cost_usd entry counts the unpriced ones.
		b.noPrice = b.noPrice || g.Why != gapUnpricedModel
	case gaps.Capture:
		b.captureGaps++
	case gaps.Restored:
		b.restored++
	case gaps.Missed:
		b.gapLines++
	}
}

// restoredNote is the receipt's note for n modes tego gave back to the owner of its own files: something, an agent
// most likely, had taken the rights tego needs on them. Nothing the run did went unrecorded, so it is no coverage gap.
func restoredNote(n int) string {
	return gaps.RestoredWords(n) + ", which something had taken from their owner; no action went unrecorded"
}

// coverage gathers the fields the ledger could not support in full into one list, so a reader sees at a glance
// what this receipt cannot vouch for.
func (b *builder) coverage() {
	rc := b.rc
	g := []CoverageGap{}
	add := func(field, code, why string) { g = append(g, CoverageGap{Field: field, Code: code, Why: why}) }
	if !rc.Files.Recorded || rc.Files.Note != "" {
		// finish notes files only for a ledger with no capabilities line or a tier that records refused writes only.
		code := CodeRecordOff
		if b.runStart.Capabilities == nil {
			code = CodeNoCapabilities
		}
		add("files", code, rc.Files.Note)
	}
	if rc.Files.Truncated {
		add("files", CodeTruncated, fmt.Sprintf("each list stops at %d paths", MaxPaths))
	}
	if rc.Refusals.ListTruncated {
		add("refusals.list", CodeTruncated, fmt.Sprintf("the list stops at %d refusals; the counts are complete", MaxRefusals))
	}
	if !rc.Tokens.Recorded {
		add("tokens", CodeCaptureOff, rc.Tokens.Note) // finish records tokens whenever capture was on
	} else if rc.Tokens.Metered < rc.Tokens.ModelCalls {
		add("tokens", CodeUnmetered, rc.Tokens.Note)
	}
	rc.price = pricing{at: len(g), noPriceLine: b.noPrice}
	if pg, ok := priceGap(rc.Tokens, b.noPrice && b.prices == nil); ok {
		rc.price.gap = true
		g = append(g, pg)
	}
	if b.captureGaps > 0 && rc.Tokens.Recorded {
		add("tokens.capture", CodeCaptureGap, fmt.Sprintf(
			"%d capture gap %s: model traffic tego could not read, so the token counts are a floor",
			b.captureGaps, plural(b.captureGaps, "line", "lines")))
	}
	if rc.Stall.Note != "" {
		add("stall", CodeModelTimeUnseen, rc.Stall.Note) // finish notes the stall only when capture was off
	}
	if b.gapLines > 0 {
		add("record", CodeMissedActions, fmt.Sprintf("%d gap %s: tego knows it missed some actions, so the counts are a floor",
			b.gapLines, plural(b.gapLines, "line", "lines")))
	}
	if cs := b.sharedGaps.Counts(); len(cs) > 0 {
		add("record", CodeRecordUncertain, gaps.Words(cs, false))
	}
	if !rc.Ended {
		add("time_taken", CodeNoRunEnd, "the run has no run_end line yet")
	}
	rc.Coverage = Coverage{Complete: len(g) == 0, Gaps: g, DenyReadFrozen: b.runStart.DenyReadFrozen}
}

// price writes the cost's text from the estimate and the unpriced count, for a run with a metered response: the
// estimate rounded to a micro-dollar, as measure's --json keeps it, then "est." and how many went unpriced.
func (t *Tokens) price() {
	if t.Metered == 0 {
		return
	}
	if !math.IsInf(t.EstCostUSD, 0) {
		t.EstCostUSD = math.Round(t.EstCostUSD*1e6) / 1e6
	}
	t.CostText = measure.CostText(t.EstCostUSD) + " est."
	if t.Unpriced > 0 {
		t.CostText += fmt.Sprintf(" (%d unpriced)", t.Unpriced)
	}
}

// priceGap is the coverage gap the cost estimate leaves, if any: metered responses no price covered, or, when none was
// metered, a run that said it had no usable price table and a reader that priced nothing (noTable). Only a run with
// model calls has a cost to estimate, and with prices of its own the receipt estimates it anyway, so the run's missing
// table is no gap then; a run whose traffic was not captured has the tokens note.
func priceGap(t Tokens, noTable bool) (CoverageGap, bool) {
	switch {
	case t.Metered > 0 && t.Unpriced > 0:
		return CoverageGap{Field: "tokens.est_cost_usd", Code: CodeUnpriced,
			Why: fmt.Sprintf("%d of %d metered responses had no price", t.Unpriced, t.Metered)}, true
	case t.Metered == 0 && noTable && t.Recorded && t.ModelCalls > 0:
		return CoverageGap{Field: "tokens.est_cost_usd", Code: CodeNoPriceTable,
			Why: "no price table: the cost is not estimated"}, true
	}
	return CoverageGap{}, false
}

// pricing is where the receipt's cost sits in its coverage, so Check can price a receipt again as another reader's
// table priced it (reprice): the index its price gap has, or would have, among the gaps, whether it has one, and
// whether a gap line said the run had no usable price table.
type pricing struct {
	at          int
	gap         bool
	noPriceLine bool
}

// reprice sets the cost as a reader whose table left unpriced of the metered responses unpriced and estimated the rest
// at est dollars would have computed it (table false: a reader with no table at all), with the cost's text and its
// price gap made from them as Compute makes them. Check uses it to compare everything but the two numbers, which only
// the price table of the machine that made a receipt gives.
func (rc *Receipt) reprice(est float64, unpriced int, table bool) {
	t := &rc.Tokens
	t.EstCostUSD, t.Unpriced, t.CostText = est, unpriced, ""
	t.price()
	before := rc.Coverage.Gaps[:rc.price.at]
	after := rc.Coverage.Gaps[rc.price.at:]
	if rc.price.gap {
		after = after[1:]
	}
	g := append([]CoverageGap{}, before...)
	pg, ok := priceGap(*t, rc.price.noPriceLine && !table)
	if ok {
		g = append(g, pg)
	}
	g = append(g, after...)
	rc.price.gap = ok
	rc.Coverage.Complete, rc.Coverage.Gaps = len(g) == 0, g
}

// Summary returns the receipt's headline in one plain sentence, for a list or a page head.
func (rc *Receipt) Summary() string {
	var parts []string
	parts = append(parts, "took "+Duration(rc.Time.Seconds))
	if rc.Files.Recorded {
		parts = append(parts, fmt.Sprintf("changed %d %s", rc.Files.Changed(), plural(rc.Files.Changed(), "file", "files")))
	}
	parts = append(parts, fmt.Sprintf("%d refused", rc.Refusals.Total))
	parts = append(parts, fmt.Sprintf("asked you %d %s", rc.Asks.Asked, plural(rc.Asks.Asked, "time", "times")))
	return strings.Join(parts, ", ")
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

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Duration renders seconds for people: "42s", "3m 05s", "2h 03m".
func Duration(s float64) string {
	d := time.Duration(s * float64(time.Second))
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
}

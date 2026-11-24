// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/askpair"
	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/check/mirror"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	receiptspec "github.com/attention-span-ai/tego/pkg/spec/receipt"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The caps that bound the receipt's memory whatever the run's size.
const (
	// MaxPaths is the most paths each file list holds; past it the list says truncated.
	MaxPaths = 1000
	// MaxRefusals is the most refused actions the list holds, oldest first (in the order the calls were received, see
	// builder.refusalMono); the counts keep counting. A run past it keeps the first MaxRefusals lines the ledger holds.
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
	// MaxTop is how many destinations and programs the receipt names. Other retained identities
	// and attempts beyond the identity budget are counted separately.
	MaxTop = 10
)

// ctxEvery is how many lines Compute reads between checks of its context.
const ctxEvery = 1024

// Options tune Compute.
type Options struct {
	// SensitivePath optionally adds paths protected by the caller's contract context.
	// It receives names only. Nil keeps the ledger-only name and deciding-rule checks.
	SensitivePath func(string) bool
	// NowMonoNS is the caller's monotonic clock reading (the ledger's clock). A run with no run_end measures its
	// time taken and its last quiet window to it; 0, or a reading before the last event, is ignored.
	NowMonoNS uint64
	// StallThreshold overrides the stall threshold; 0 takes min(5m, the run's limits.stall_after).
	StallThreshold time.Duration
	// Prices estimates each model response's cost, as `tego measure` does (the same interface, filled by the CLI
	// from the machine's price table). Nil prices nothing: the receipt then counts every response unpriced.
	Prices measure.Prices
	// Home is the home directory "~" stands for in the text layout (Text): a path under it prints as ~/... . Only the
	// run's own home may be passed: tego run passes its own for the run it just ran, never a reader's, since a home
	// the record does not name is not the reader's (a receipt read later, by another user or on another machine, would
	// fold the wrong folder). With "", the home the run recorded is used (its baseline evidence's owner home, when the
	// owner context was known); a record with none prints every path outside the run's folder whole. JSON always
	// keeps the full paths.
	Home string
	// SayNoHome makes the text layout say, in one line, that the record names no home when none is known, so a person
	// does not read the whole paths as a rendering fault (`tego receipt`, which reads a run some time after it ended).
	SayNoHome bool
	// Bind binds the receipt to the record it reads (Receipt.Binding), by the tego named here: the one pass that
	// computes the receipt also checks every line as Verify does and hashes the bytes it read. Only `tego receipt
	// --json` sets it; nil leaves Binding out, so the dashboard's receipt and tego run's end summary are unchanged.
	Bind *MadeBy
	// BindVersion selects a historical binding during comparison; zero writes the current version.
	BindVersion int
	// BinarySHA256 is the producer image hash. Empty hashes the running executable.
	BinarySHA256 string
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

// NameBlock is a live network block, or a restored fence entry, put in force by a host name, and what the record says
// of the addresses it was enforced on (record minor 41): Addrs as the line names them (an IPv6 zone kept), More the
// ones past its cap, none of either when the record does not say (an older ledger, or a lookup that answered none).
type NameBlock struct {
	Name  string
	Addrs []string
	More  int
}

// words is the receipt's sentence about the block: the addresses it was enforced on, or that the record does not say.
func (n NameBlock) words() string {
	if len(n.Addrs) == 0 {
		return "A live block on " + n.Name + " refuses the addresses that name resolved to; the record does not say which."
	}
	s := "A live block on " + n.Name + " was enforced on " + strings.Join(n.Addrs, ", ")
	if n.More > 0 {
		s += fmt.Sprintf(" and %d more not listed", n.More)
	}
	return s + "."
}

// NameBlocks is the live blocks and restored fence entries by name, in the order the record shows them, at most
// MaxTop, each once with every address its lines named: the words the receipt adds, since a block by name refuses by
// the addresses its name resolved to and the refusals under it name the address, not the block.
func (rc *Receipt) NameBlocks() []NameBlock { return rc.nameBlocks }

// nameBlock notes the live_block of a gap line that put a net block or fence entry in force.
func (b *builder) nameBlock(c *record.LiveBlockChange) {
	if c.Kind != record.LiveKindNet {
		return
	}
	host := c.Value
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if _, err := netip.ParseAddr(host); err == nil || host == "" || strings.HasPrefix(host, "/") || strings.HasPrefix(host, "@") {
		return // an address or a unix socket: nothing was resolved
	}
	nb := &b.rc.nameBlocks
	i := slices.IndexFunc(*nb, func(n NameBlock) bool { return n.Name == c.Value })
	if i < 0 {
		if len(*nb) >= MaxTop {
			return
		}
		*nb = append(*nb, NameBlock{Name: c.Value})
		i = len(*nb) - 1
	}
	n := &(*nb)[i]
	for _, a := range c.Addrs {
		if !slices.Contains(n.Addrs, a) {
			n.Addrs = append(n.Addrs, a)
		}
	}
	slices.SortFunc(n.Addrs, func(x, y string) int {
		ax, errx := netip.ParseAddr(x)
		ay, erry := netip.ParseAddr(y)
		if errx != nil || erry != nil {
			return strings.Compare(x, y)
		}
		return ax.Compare(ay)
	})
	n.More = max(n.More, c.AddrsMore)
}

// LiftNote is a lift or a grant of a fence entry the launcher put in force, with the note the person gave with it
// (record minor 41, live_block.note): Rule is live.fence[<kind>:<value>] and Note is record.LiveNoteShown's text, the
// words the terminal and the dashboard show. Only a lift with a note is listed.
type LiftNote struct {
	Rule string
	Note string
}

// words is the receipt's sentence about the lift.
func (l LiftNote) words() string {
	return "Lifted " + l.Rule + " with the note: " + l.Note
}

// LiftNotes is the lifts and grants that carry a note, in the order the record shows them, at most MaxTop: the words
// the receipt adds, since the refusals and allows under a lifted entry name the entry, not the person's reason.
func (rc *Receipt) LiftNotes() []LiftNote { return rc.liftNotes }

// liftNote notes the live_block of a live-rule-lifted line that carries a note.
func (b *builder) liftNote(c *record.LiveBlockChange) {
	if c.Note == "" || len(b.rc.liftNotes) >= MaxTop {
		return
	}
	b.rc.liftNotes = append(b.rc.liftNotes, LiftNote{Rule: c.Rule, Note: record.LiveNoteShown(c.Note)})
}

// ErrNoRun is a ledger whose first line is not run_start.
var ErrNoRun = errors.New("no run record")

// ErrAskLimit means exact ask accounting exceeded its pending identity count or byte budget. Compute returns no
// receipt: dropping identities would make a later answer indistinguishable from one with no recorded ask.
var ErrAskLimit = errors.New("pending ask limit exceeded")

// payload is the union of the payload keys the receipt reads.
type payload struct {
	record.AnswerAuthority
	Op           string   `json:"op"`
	Path         string   `json:"path"`
	Path2        string   `json:"path2"`
	Flags        int      `json:"flags"`
	Created      bool     `json:"created"`
	Errno        int      `json:"errno"`
	SyscallRet   int64    `json:"syscall_ret"`
	Dst          string   `json:"dst"`
	Proto        string   `json:"proto"`
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
	Escalated    bool     `json:"escalated"`
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
	learned   *record.LearnNote
	rc        *Receipt
	startMono uint64
	lastMono  uint64
	rules     map[[2]string]int
	// refusalMono is the mono_ns of each line of Refusals.List, in the list's order: the time the supervisor received
	// the refused call (R23a). finish puts the list in that order, so the list does not depend on which of two calls a
	// worker wrote first (byReceipt).
	refusalMono []uint64
	seen        map[string]bool    // path+category already listed
	asks        *askpair.Book[int] // open asks: ask_id -> display index, -1 beyond the display cap; bounded independently of the display list
	// stall
	prevMono   uint64
	prevGap    bool
	openSSL    map[uint64]bool
	windows    []time.Duration
	stallAfter time.Duration
	// the lines before, for counting a refused line that mirrors a refused action once
	pairs         mirror.Pairs
	held          askpair.Held // the last action line with verdict ask: what an ask line that names nothing asks about
	runStart      record.RunStartPayload
	prices        measure.Prices
	gapLines      int             // gap lines that may have lost actions: the record's counts are a floor
	gapLost       int             // the events those lines say their producers dropped (the lines' counts, as gaps.Tally sums them)
	sharedGaps    gaps.Tally      // shared tracing uncertainty, with its own count semantics
	ruleGaps      gaps.Tally      // skips of shared programs the run's rules rely on (gaps.RulesUncertain)
	captureGaps   int             // gap what=capture lines: model traffic tego could not read
	dropped       droppedMessages // MCP messages the relay dropped for their size (gaps.Dropped)
	routesKept    int             // gap lines of an unreadable model-route overlay (gaps.RoutesKept): no action lost
	restored      int             // gap lines of a mode tego gave back to the owner of one of its own files: no action lost
	noPrice       bool            // a gap said the run had no usable price table
	devWrite      bool            // an allowed write reached a device, which Files does not list (device)
	act           activity
	sensitivePath func(string) bool
}

// Compute builds one run's receipt from its ledger in one streaming pass. Pending ask identities are bounded
// separately from the display list; exceeding that budget returns ErrAskLimit and no partial receipt.
func Compute(ctx context.Context, r *ledger.Reader, opt Options) (*Receipt, error) {
	if r == nil {
		return nil, fmt.Errorf("receipt: no ledger reader")
	}
	b := &builder{rc: &Receipt{V: Version}, rules: map[[2]string]int{}, seen: map[string]bool{}, asks: askpair.NewBook[int](MaxPendingAsks, MaxPendingAskBytes),
		openSSL: map[uint64]bool{}, prevGap: true, prices: opt.Prices, act: newActivity(), sensitivePath: opt.SensitivePath}
	rc := b.rc
	rc.home, rc.sayNoHome = opt.Home, opt.SayNoHome
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
	rc.finishBaseline()
	if binder != nil && rc.Baseline != nil && opt.BindVersion != 0 && opt.BindVersion != BaselineBindingVersion {
		return nil, fmt.Errorf("receipt: baseline records require binding 3")
	}
	if binder != nil {
		rc.Binding = bindingOf(binder.Bound(), *opt.Bind, rc.Tier)
		if opt.BindVersion == 1 {
			rc.Binding.V = 1
			rc.Binding.Limits = limitsForBinding(rc.Tier, 1)
		} else {
			if rc.Baseline != nil && (opt.BindVersion == 0 || opt.BindVersion == BaselineBindingVersion) {
				rc.Binding.V = BaselineBindingVersion
				rc.Binding.EffectiveHash = b.runStart.EffectiveHash
				rc.Binding.BaselineSHA256 = b.runStart.Baseline.SHA256
				rc.Binding.BaselineEvidenceSHA256 = b.runStart.Baseline.EvidenceSHA256
			}
			rc.Binding.ContractHash = b.runStart.ContractHash
			rc.Binding.Capabilities = b.runStart.Capabilities
			rc.Binding.BinarySHA256 = opt.BinarySHA256
			if rc.Binding.BinarySHA256 == "" {
				var err error
				rc.Binding.BinarySHA256, err = ExecutableSHA256()
				if err != nil {
					return nil, err
				}
			}
			if !lowerSHA256(rc.Binding.BinarySHA256) {
				return nil, fmt.Errorf("receipt: producer binary_sha256 must be 64 lowercase hex digits")
			}
			if err := rc.seal(); err != nil {
				return nil, fmt.Errorf("receipt binding: %w", err)
			}
		}
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
			if err := e.DecodePayload(&b.runStart); err != nil {
				return fmt.Errorf("receipt run_start: %w", err)
			}
			b.runStart.RecordMinor, _ = e.RunStartMinor() // malformed or folded revision grants no attribution
			if src := b.runStart.ContractSource; b.runStart.RecordMinor >= record.MinorLearn && src != nil && src.Learn != nil && src.Learn.Validate() == nil {
				b.learned = src.Learn
			}
			rc.LocalApprovalAuthority = record.ValidatedLocalApprovalAuthority(e.Payload)
			if err := b.runStart.ValidateBaseline(); err != nil {
				return err
			}
			rc.Baseline = baselineSummary(b.runStart)
			// The home the run recorded: run_start.home (record minor 41, every new run), else the machine baseline's
			// owner home, else none, and the text says so.
			if rc.home == "" {
				switch bl := b.runStart.Baseline; {
				case b.runStart.RecordMinor >= record.MinorEveryLaunch && filepath.IsAbs(b.runStart.Home):
					rc.home = filepath.Clean(b.runStart.Home)
				case b.runStart.BaselineRecorded() && bl.OwnerKnown && filepath.IsAbs(bl.Home):
					rc.home = filepath.Clean(bl.Home)
				}
			}
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
		rc.Ended, rc.EndReason, rc.Signal, rc.Escalated = true, p.Reason, p.Signal, p.Escalated
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
		p.AnswerAuthority = record.AnswerAuthorityOf(e.Payload, b.runStart.RecordMinor, b.rc.LocalApprovalAuthority != nil)
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
	// mirrors a refused action before it is that action again (measure R19, internal/check/mirror).
	mirrored := b.pairs.Take(e)
	if (e.Kind.IsAction() && e.Verdict == record.VerdictRefused) || (e.Kind == record.KindRefused && !mirrored) {
		b.refusal(e, &p)
		if e.Kind == record.KindRefused {
			b.refusedAlone(e, &p) // a refused line that mirrors no action line: its connection or read too
		}
	}
	if e.Verdict == record.VerdictAsk {
		b.held.Note(opOf(e, &p), target(e, &p), e.Rule)
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
		Rule: e.Rule, Reason: reason, Minute: m, LearnWithheldRun: b.learnWithheld(e, p)})
	b.refusalMono = append(b.refusalMono, e.MonoNS)
}

// byReceipt puts a refusal list in the order the refused calls were received: by mono_ns, which the supervisor takes
// when a notification arrives (R23a), then by ledger position for lines of one instant. The ledger's own order is not
// that order across threads: the supervisor answers a call and then writes its line (R23), and it keeps the order of
// one thread's lines only. An agent whose child is refused an exec, then reads a secret itself, has the child's line and
// its own on two threads, and either may be written first; the receipt of that run listed the read before the exec in
// gate 35 (TestIntegrationReceiptOfAScriptedRunAtTierLandlock). Received order is the order the agent made the calls
// in, whenever one call's answer led to the next (a child that reported its failure, a thread that waited for another),
// and the same for every reading of one ledger. A line a writer stamped itself (another source of lines, or an old
// ledger) keeps the clock it was stamped with, which is the same CLOCK_MONOTONIC. mono[i] is list[i]'s mono_ns; both
// come back in the new order, the same slices when they were in it already.
func byReceipt(list []Refusal, mono []uint64) ([]Refusal, []uint64) {
	if len(list) != len(mono) || slices.IsSorted(mono) {
		return list, mono
	}
	idx := make([]int, len(list))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(x, y int) int { return cmp.Compare(mono[x], mono[y]) })
	sorted, sortedMono := make([]Refusal, len(list)), make([]uint64, len(list))
	for i, j := range idx {
		sorted[i], sortedMono[i] = list[j], mono[j]
	}
	return sorted, sortedMono
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
	a := &b.rc.Asks
	// The display index this ask takes, -1 beyond the display cap.
	idx := -1
	if len(a.List) < MaxAsks {
		idx = len(a.List)
	}
	switch b.asks.Ask(p.AskID, idx, pendingAskBytes(p.AskID)) {
	case askpair.Refused:
		return fmt.Errorf("%w (maximum %d unanswered IDs or %d estimated bytes)", ErrAskLimit, MaxPendingAsks, MaxPendingAskBytes)
	case askpair.Repeated:
		return nil // the first ask line of the id opened the question; this one is malformed and said so (askGaps)
	case askpair.Opened:
	}
	a.Asked++
	a.Unanswered++
	if idx < 0 {
		a.Truncated = true
		return nil
	}
	item := Ask{AskID: p.AskID, TS: e.TS, Op: p.Op, Target: p.Target, Rule: p.AskRule}
	b.held.Fill(&item.Op, &item.Target, &item.Rule)
	if item.Rule == "" {
		item.Rule = e.Rule
	}
	a.List = append(a.List, item)
	return nil
}

func (b *builder) answer(p *payload) {
	a := &b.rc.Asks
	// An answer counts only when it pairs with its ask (askpair): one that came before it, names an id never asked or
	// answers an ask already answered is malformed and never counts as an answer (askGaps).
	i, paired := b.asks.Answer(p.AskID)
	if paired == askpair.Unpaired {
		return
	}
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
	a.Unanswered--
	if paired == askpair.Paired && i >= 0 && a.List[i].Answer == "" {
		a.List[i].Answer, a.List[i].By, a.List[i].AfterS = word, p.By, p.AfterS
		a.List[i].AnswerAuthority = p.AnswerAuthority
		if word == "approved" && p.Actor != nil {
			a.List[i].DeliveryNote = "Approval records selection only; read the action and refusal lines for delivery and operation completion."
		}
	}
}

// askGaps are the coverage notes for the malformed ask and answer lines the run's record holds, in askpair's words.
func (b *builder) askGaps(add func(field, code, why string)) {
	if n := b.asks.Repeated(); n > 0 {
		add("asks", CodeAskRepeated, fmt.Sprintf("%s (%d %s): only the first line of an ask id counts", askpair.RepeatedWords, n, plural(n, "line", "lines")))
	}
	if n := b.asks.Unpaired(); n > 0 {
		add("asks", CodeAnswerUnpaired, fmt.Sprintf("%s (%d %s): it is not counted as an answer", askpair.UnpairedWords, n, plural(n, "line", "lines")))
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

	rc.Refusals.List, b.refusalMono = byReceipt(rc.Refusals.List, b.refusalMono)
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
	priceTokens(t)
	if b.restored > 0 {
		rc.Notes = append(rc.Notes, restoredNote(b.restored))
	}
	b.coverage()
}

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
	if g.LiveBlock != nil && g.What == record.GapEnforce && (g.Why == record.GapLiveBlockAdded || g.Why == record.GapLiveRuleRestored) {
		b.nameBlock(g.LiveBlock)
	}
	if g.LiveBlock != nil && g.What == record.GapEnforce && g.Why == record.GapLiveRuleLifted {
		b.liftNote(g.LiveBlock)
	}
	switch gaps.Classify(g.What, g.Why) {
	case gaps.Uncertain:
		b.sharedGaps.Add(e)
	case gaps.RulesUncertain:
		b.ruleGaps.Add(e)
	case gaps.Live:
	case gaps.Price:
		// An unpriced model is no missing table: the receipt prices each response itself, and its
		// tokens.est_cost_usd entry counts the unpriced ones.
		b.noPrice = b.noPrice || g.Why != record.GapUnpricedModel
	case gaps.Capture:
		b.captureGaps++
	case gaps.Restored:
		b.restored++
	case gaps.Dropped:
		b.dropped.add(&g)
	case gaps.RoutesKept:
		b.routesKept++
	case gaps.Missed:
		b.gapLines++
		if g.Binary == "" && g.Count > 0 {
			b.gapLost = min(b.gapLost+g.Count, math.MaxInt32)
		}
	}
}

// droppedMessages is what the receipt knows of the MCP messages the relay dropped for their size: how many, the largest
// whose size the record gives (and its server), whether any size was not learned, and the limit.
type droppedMessages struct {
	n       int
	largest int64
	server  string
	unsized int
	limit   int64
}

// add counts one gap line of the oversize whys: a line naming a message, or the counted line a run writes for the
// messages past its lines (count, no binary).
func (d *droppedMessages) add(g *record.GapPayload) {
	if g.Binary == "" {
		d.n += max(g.Count, 0)
		return
	}
	d.n++
	server, size, limit, ok := record.ParseOversizeNote(g.Binary)
	if !ok {
		d.unsized++
		return
	}
	d.limit = max(d.limit, limit)
	if size == 0 {
		d.unsized++
	} else if size > d.largest {
		d.largest, d.server = size, server
	}
}

// words is the receipt's sentence for them.
func (d *droppedMessages) words() string {
	var s string
	if d.n == 1 {
		s = "1 MCP message was too large for the relay and was dropped"
	} else {
		s = fmt.Sprintf("%d MCP messages were too large for the relay and were dropped", d.n)
	}
	switch {
	case d.largest > 0 && d.limit > 0:
		s += fmt.Sprintf(" (the largest, %d bytes from %q, against a limit of %d bytes)", d.largest, record.Printable(d.server), d.limit)
	case d.limit > 0:
		s += fmt.Sprintf(" (the size is not known; the limit is %d bytes)", d.limit)
	}
	return s + "; no action went unrecorded"
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
	add := func(field, code, why string) {
		g = append(g, CoverageGap{Field: field, Code: code, Level: receiptspec.LevelOf(code), Why: why})
	}
	if cs := b.ruleGaps.Counts(); len(cs) > 0 {
		// First: the refusals the receipt lists may not be every refusal the rules called for.
		add("refusals", CodeRulesUncertain, gaps.Words(cs, false))
	}
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
		add("tokens.capture", CodeCaptureGap, gaps.CaptureWords(b.captureGaps))
	}
	b.askGaps(add)
	if rc.Stall.Note != "" {
		add("stall", CodeModelTimeUnseen, rc.Stall.Note) // finish notes the stall only when capture was off
	}
	if b.dropped.n > 0 {
		add("record.mcp", CodeMessagesDropped, b.dropped.words())
	}
	if b.routesKept > 0 {
		add("record.routes", CodeModelRoutesKept, gaps.RoutesKeptWords(b.routesKept))
	}
	if b.gapLines > 0 {
		add("record", CodeMissedActions, gaps.MissedWords(b.gapLines, b.gapLost))
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
func priceTokens(t *Tokens) {
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
		return CoverageGap{Field: "tokens.est_cost_usd", Code: CodeUnpriced, Level: receiptspec.LevelOf(CodeUnpriced),
			Why: fmt.Sprintf("%d of %d metered responses had no price", t.Unpriced, t.Metered)}, true
	case t.Metered == 0 && noTable && t.Recorded && t.ModelCalls > 0:
		return CoverageGap{Field: "tokens.est_cost_usd", Code: CodeNoPriceTable, Level: receiptspec.LevelOf(CodeNoPriceTable),
			Why: gaps.PriceWords(true)}, true
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
	priceTokens(t)
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

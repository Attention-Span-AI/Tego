// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/check/secretpath"
	"github.com/attention-span-ai/tego/internal/check/syslookup"
	"github.com/attention-span-ai/tego/internal/ledger/runstart"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The presentation bounds. Decoding maintains full-run summary counters but keeps
// only bounded recent windows (cache.go), even for live runs. A root request selects
// at most MaxRuns directories and presents at most MaxLines events. Variables let
// tests exercise rotation without writing production-sized ledgers.
var (
	MaxRuns  = 100_000
	MaxLines = 5_000_000
)

const maxLineBytes = 4 << 20

// SystemLookupSockets are the unix sockets the C library and system services open on their own for name, user and
// host lookups (nscd, systemd's userdb and resolved, the D-Bus system bus): syslookup.Sockets, the one list the
// receipt uses too. A refusal of one is shown tagged "system lookup" with less emphasis, and is never dropped from a
// count. An entry ending in "/" is a directory.
var SystemLookupSockets = syslookup.Sockets

// IsSystemLookup reports whether target (a dst or refused target, "unix:<path>" or a bare path) names one of
// SystemLookupSockets, or a user's D-Bus session bus (/run/user/<uid>/bus), which desktop libraries open on their
// own in the same way. It is syslookup.IsSocket, so the receipt's Connections and the verdict fold the same sockets.
func IsSystemLookup(target string) bool { return syslookup.IsSocket(target) }

// Event is one ledger line, flattened for display.
type Event struct {
	// RecordMinor is read exactly from this run's run_start; zero means not recorded.
	RecordMinor int
	// LocalFloor is whether that run_start carries the root-only approval floor; an answer is shown as root's only then.
	LocalFloor bool
	Seq        uint64
	TS         time.Time
	Run        string
	Agent      string
	Kind       string
	Source     string
	Rule       string
	Verdict    string
	Authority  string
	Reason     string
	Op         string
	Target     string
	// Proto is a net line's protocol (tcp, udp, unix, raw, http), empty on other lines.
	Proto string
	// Host is the network host a net line or a refused connection names, lower-cased: the line's host when the
	// supervisor recorded one, else the host part of its destination (an IP address); empty for a unix socket, a
	// netlink socket and every other line. The Logs query's host: key and its Host facet read it.
	Host  string
	AskID string
	Raw   string
	// askOp and askTarget are what an ask or answer line is about (its payload's op and target), empty on other lines.
	askOp, askTarget string
	// askName and askName2 are the ask's target and a held mutation's second name (target2) as recorded, apart: the
	// Logs query's path: reads each whole, never askTarget's joined words, which a name holding the joiner would split.
	askName, askName2 string
	// SystemLookup is a refusal of one of SystemLookupSockets.
	SystemLookup bool
	// Step and StepMethod are the line's model step as the record states it (record.Event.ModelStep, the one reader the
	// CLI's events --step uses too): StepMethod is the attribution's method ("tool_id", "tid", "time" or "none") and ""
	// on a line that carries no attribution (only exec, fs, net and mcp lines do); Step is meaningful only when
	// ModelStep says the line is tied to one. Step 0 is an action before the first model request.
	Step       int
	StepMethod string
	stepTied   bool
	// off is the line's byte offset in its events file (Line reads it back from there).
	off int64
	// Mirror is a kind=refused line that mirrors a refused action of its run (pair.go): the same refusal as that
	// action's line, so no count counts it again.
	Mirror bool
	// Malformed is askpair's words for an ask line whose ask id was asked before and for an answer line that pairs with
	// no ask: malformed lines, which the read model shows and no count, page or fold takes as a question or an answer.
	// askRepeat and answerUnpaired say which; both are false, and Malformed is "", for every other line.
	Malformed                 string
	askRepeat, answerUnpaired bool
	// write is a mirror whose action changes a file (pair).
	write bool
	// to is what a mirror's rename or link would have replaced: its action's second name, which a mirror does not carry
	// (pair). A symlink's second name is where the link points, which is no change to that file.
	to string
	// mono and pid are the envelope's monotonic clock and process, which a mirror copies from its action.
	mono uint64
	pid  int
	// path is an exec line's program path (payload path), which its Target (the argv) may name only relatively; the
	// Logs query's path: key reads it.
	path string
	// argv is an exec line's arguments, or a run_start's command, one element per argument as recorded (from the
	// line, or from its blob within the bound resolveBlob keeps). Target joins them with spaces for display and
	// search; whatever names the program reads these (Program, recordedCommand), never the joined text.
	argv []string
	// blob is the sha of the argv (exec) or command (run_start) the writer moved to a blob, from decode until the
	// Store reads it (resolveBlob); argvMissing marks a line whose blob could not be read, so its row says so.
	blob        string
	argvMissing bool
	// sec is IsSecretPath of the line's paths, marked once as the Store takes the line (markSecret, secretPart).
	sec uint8
	// readNothing is a file line that cannot have read its file (secretpath.ReadOpen): a write-only open, a create, an
	// unlink, a failed open.
	readNothing bool
}

// ModelStep is the model step the line is tied to and whether it is tied to one: the same answer record.Event.ModelStep
// gives the CLI's events --step, so Logs' step:N and that flag select the same lines. A line carrying no attribution and
// a line stamped unattributed are tied to none.
func (e *Event) ModelStep() (step int, ok bool) { return e.Step, e.stepTied }

// ArgvMissing reports whether the line's command went to a blob (argv_blob, command_blob) that could not be read
// back: its Target is then the program's path alone.
func (e *Event) ArgvMissing() bool { return e.argvMissing }

// SameFile is, on an exec line a live block refused as another name of the program file the block's path leads to
// (a multi-call program's applets are one file), the words that say so: "same program file as /bin/ls, which is
// blocked" (liveblock.SameFileNote, read from the line's rule and its program path). "" on every other line.
func (e *Event) SameFile() string {
	if e.Kind != string(record.KindExec) {
		return ""
	}
	return liveblock.SameFileNote(e.Rule, e.path)
}

// AskTarget is what an ask line asks about, or an answer line answered (its payload's target, as the ledger holds
// it), "" on other lines and on a line written without one.
func (e *Event) AskTarget() string { return e.askTarget }

// PID is the process the line's envelope names (0 when it names none).
func (e *Event) PID() int { return e.pid }

// ByteOffset is the position of this line in its run's events file.
func (e *Event) ByteOffset() int64 { return e.off }

// Refused reports whether the line records a refusal: a refused line, or an action whose verdict is refused.
func (e *Event) Refused() bool {
	return e.Kind == string(record.KindRefused) || e.Verdict == string(record.VerdictRefused)
}

// WatchedLine reports whether line e of run r was only watched: r is a tego watch run (tier observe), which enforces
// nothing, and e was recorded as observed. No rule decided such a line, whatever rule it names: the contract entry it
// would have matched, or unmatched.
func WatchedLine(r *Run, e *Event) bool {
	return r != nil && r.Tier == "observe" && e.Verdict == string(record.VerdictObserved)
}

// Run is one run's summary, and its lines when they were loaded.
type Run struct {
	// RecordMinor is the revision run_start recorded; local approval attribution is shown only when it and the payload agree (ADR 0154).
	RecordMinor int
	// LocalApprovalAuthority is the root-only approval floor the run started under, when its run_start names one.
	LocalApprovalAuthority *record.LocalApprovalAuthority `json:"local_approval_authority,omitempty"`

	ID       string
	Agent    string
	Contract string
	Tier     string
	// Command is the run's command joined with spaces, for display and search; command is the same command one
	// element per argument, as run_start recorded it, which names the program (Run.CommandAgent, SameProgram).
	Command string
	command []string
	Cwd     string
	Start   time.Time
	End     time.Time
	Last    time.Time // the newest line's time
	Ended   bool
	Live    bool // listed in <root>/.live, its lock held (Store.liveRuns), and no run_end read
	// LiveError is why an unfinished run’s liveness could not be established.
	LiveError string
	EndReason string
	ExitCode  int
	Signal    int
	Lines     int // lines read
	Refusals  int // refusals: refused actions and refused lines that mirror none (Event.Refusal)
	// RefusalFirst and RefusalLast bound every counted refusal timestamp, even when
	// the event window is truncated or evicted. They let a date-scoped view use
	// Refusals only when that whole aggregate belongs to its period. Refusals > 0
	// establishes that bounds were seen; the zero time is a valid recorded date.
	RefusalFirst, RefusalLast time.Time
	Asks                      int // ask lines
	// StepLines counts the lines the record ties to a model step (Event.ModelStep), over the whole run as the other
	// counters are: zero for a run with no model capture, whose actions are all stamped unattributed. The timeline
	// shows model-step headers only when it is not zero.
	StepLines int
	Kinds     map[string]int
	Events    []Event
	Pending   []Ask
	// Cut means Events covers only a bounded part of the run. Summary counters
	// cover decoded records; Bad and ReadError qualify their completeness.
	Cut bool
	// PendingCut reports more simultaneous unanswered asks than the bounded display can retain.
	PendingCut bool
	// Bad counts malformed lines and unsupported record kinds.
	Bad int
	// StartError is the refusal reason for invalid run-start metadata.
	StartError string
	// LineErrors retains every complete line refused during Store refresh.
	LineErrors []LineRefusal
	// ReadError is a refusal encountered while rereading retained ledger bytes or the last events-file read failure.
	// Cached counters remain available but cannot claim completeness until a real read succeeds.
	ReadError string
	// Identity and policy, from run_start: who started the run, where, under which exact contract and build.
	User, Host, Kernel, TegoVersion, ContractHash, Harness, Capture string
	EffectiveHash, BaselineSHA256                                   string
	UID                                                             int
	// Stdin is the kind of the run's standard input (record.Stdio*) and Deployment the name in its reserved deployment
	// block, each as run_start recorded it and empty when it did not. Origin is derived from them only.
	Stdin, Deployment string
	// StoppedBy is the principal a stopped run_end names, empty when it names none.
	StoppedBy string
	// ReadsUnrecorded is a run whose run_start capability line says it kept no file read (backend.CapRecordReads
	// off: tier landlock under record: summary or off), so an empty list of secret reads proves nothing.
	// RefusedReadsUnseen is one of those whose reads_notified says Landlock refused reads without telling the
	// supervisor (SEMANTICS §7), so a refused read left no line either. RefusedReadsUnknown is one of those whose
	// run_start has no reads_notified (a ledger older than it), which cannot say whether a refused read left a line.
	// All false when run_start does not say.
	ReadsUnrecorded, RefusedReadsUnseen, RefusedReadsUnknown bool
	// ReceiptReadsUnrecorded is what this run's receipt says of its refused reads (receipt.ReadsUnrecordedBy, from
	// reads_notified alone, with or without the capability line): a read it refused left no line, so "Nothing was
	// refused." would not hold (ReceiptRefusedWords).
	ReceiptReadsUnrecorded bool
	// SysRefusals counts the refusals (Event.Refusal) of a system lookup socket (IsSystemLookup).
	SysRefusals int
	// Rev is the read model's revision at which this run last changed (lines appended, the file replaced, its live
	// state changed); LastSeq is the seq of its newest line read. See the package doc, "Revisions".
	Rev     uint64
	LastSeq uint64
	// routes is the model-route index the read model folds from every line (routes.go): RouteFacts.
	routes routeIndex
	// st is the run's cache entry (nil for a Run built for the line bound); memo its per-version derived views.
	st   *runState
	memo *runMemo
	// lastID is the newest line's id (its hash) and file the events file as read, for this version: what the chain
	// verdict cache and Line's offset read take, so neither looks at a runState another request may be reading.
	lastID string
	file   fileID
	// planeMarked is the run directory's liveblock.PlaneName mark as of this version (LiveFacts.PlaneBlocks).
	planeMarked bool
}

// LineRefusal retains a rejected line's position and decoder reason without treating it as an event.
type LineRefusal struct {
	Offset int64
	Reason string
}

// The values of Origin: how the run was started, read from run_start and from nothing else.
const (
	OriginInteractive = "interactive" // its standard input was a terminal: a person types to it
	OriginDeployed    = "deployed"    // a reserved deployment block
	OriginBackground  = "background"  // stdio recorded, none of it a terminal on stdin, and no deployment
	OriginUnknown     = "unknown"     // the record says neither (an older ledger, or a descriptor that could not be examined)
)

// Origin says how the run was started. A deployment block wins over the terminal; with no stdin kind recorded, or one
// that could not be examined, the record cannot tell and the answer is OriginUnknown.
func (r *Run) Origin() string {
	switch {
	case r.Deployment != "":
		return OriginDeployed
	case r.Stdin == record.StdioTTY:
		return OriginInteractive
	case r.Stdin == "" || r.Stdin == record.StdioUnknown:
		return OriginUnknown
	default:
		return OriginBackground
	}
}

// OriginWord is Origin as the dashboard shows it.
func (r *Run) OriginWord() string {
	o := r.Origin()
	return strings.ToUpper(o[:1]) + o[1:]
}

// State is the run's status word: running, lost (no run_end, and no live entry or no process holding its lock) or
// ended, or unknown when the live source could not be read.
func (r *Run) State() string {
	switch {
	case r.Ended:
		return "ended"
	case r.Live:
		return "running"
	case r.LiveError != "":
		return "unknown"
	default:
		return "lost"
	}
}

// Duration is end-start for an ended run, now-start for a known running one, and
// the recorded span to the newest line for a lost run or unknown running state.
// That recorded span does not establish an unknown run’s actual end.
func (r *Run) Duration(now time.Time) time.Duration {
	if r.Start.IsZero() {
		return 0
	}
	switch {
	case r.Live && !r.Ended:
		return now.Sub(r.Start)
	case r.Ended && !r.End.IsZero():
		return r.End.Sub(r.Start)
	}
	return r.Last.Sub(r.Start)
}

// Ask is an ask line with no answer line for its ask_id, in a run that has not ended. Only a live run's asks are
// waiting on a person (Snapshot.Pending); a lost run's were never answered and nothing holds them any more.
type Ask struct {
	OwnerOnly bool `json:"owner_only,omitempty"`
	Run       string
	Agent     string
	AskID     string
	Hold      string
	TS        time.Time
	Seq       uint64
	Op        string
	Target    string
	Rule      string
}

// Snapshot is one bounded scan of a ledger root.
type Snapshot struct {
	// LiveError qualifies running and actionable-queue status, independently of readable records.
	LiveError string
	// ReadErrorListed means ReadError names a retained Run with its own failure scope,
	// so it cannot erase known run-list presence or qualify an ended run’s actionable queue.
	ReadErrorListed bool
	// ReadError names the first unlisted failure, or a retained failure when every
	// failed candidate is listed. Per-run ReadError always retains each listed reason.
	ReadError string
	Root      string
	Runs      []*Run // newest start first
	TotalRuns int    // run directories found
	RunsCut   bool   // more than MaxRuns
	LinesCut  bool   // the line budget ran out
	Lines     int
	// Rev is the read model's revision this snapshot reflects: the same Rev, the same runs and lines. See the
	// package doc, "Revisions".
	Rev uint64
	// Partial is set on a LoadNow snapshot that left a run as last published (or out, when never read) because it
	// was still being read; Load and LoadRun never set it.
	Partial bool
}

// Find returns the run id in the snapshot, or nil.
func (s *Snapshot) Find(id string) *Run {
	for _, r := range s.Runs {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func validRunID(id string) bool {
	if !strings.HasPrefix(id, "r-") || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

// liveSet is the names the root's live index (<root>/.live) lists: the runs whose launcher took their lock and has
// not seen them end, and those of launchers that died first, which only their lock tells apart (Store.liveRuns).
func liveSet(root string) (map[string]bool, error) {
	out := map[string]bool{}
	ents, err := os.ReadDir(filepath.Join(root, ".live"))
	if err != nil {
		return out, err
	}
	for _, e := range ents {
		out[e.Name()] = true
	}
	return out, nil
}

// add counts one line into the summary. ev.Mirror is already set (runState.markMirror), so a refused action and the
// line that mirrors it count as one refusal (Event.Refusal).
func (r *Run) add(ev Event) {
	if ev.Refusal() {
		r.Refusals++
		if r.Refusals == 1 || ev.TS.Before(r.RefusalFirst) {
			r.RefusalFirst = ev.TS
		}
		if r.Refusals == 1 || ev.TS.After(r.RefusalLast) {
			r.RefusalLast = ev.TS
		}
		if ev.SystemLookup {
			r.SysRefusals++
		}
	}
	r.Lines++
	r.routes.take(&ev)
	kind := ev.Kind
	if !record.Kind(kind).Valid() {
		kind = "unknown"
		r.Bad++
	}
	r.Kinds[kind]++
	if ev.stepTied {
		r.StepLines++
	}
	if r.Agent == "" {
		r.Agent = ev.Agent
	}
	switch ev.Kind {
	case string(record.KindRunStart):
		r.Start = ev.TS
		start := record.Event{Kind: record.KindRunStart, Payload: json.RawMessage(ev.Raw)}
		r.RecordMinor, _ = start.RunStartMinor() // a malformed revision carries no authority
		var p struct {
			User        string `json:"launcher_user"`
			Host        string `json:"host"`
			Kernel      string `json:"kernel"`
			TegoVersion string `json:"tego_version"`
			Capture     string `json:"capture"`
			Harness     struct {
				Name string `json:"name"`
			} `json:"harness"`
			Stdio struct {
				Stdin string `json:"stdin"`
			} `json:"stdio"`
			Deployment struct {
				Name string `json:"name"`
			} `json:"deployment"`
			Capabilities  map[string]bool       `json:"capabilities"`
			ReadsNotified *record.ReadsNotified `json:"reads_notified"`
		}
		_ = json.Unmarshal([]byte(ev.Raw), &p)
		r.LocalApprovalAuthority = record.ValidatedLocalApprovalAuthority(start.Payload)
		// ev.Target is the command too, read back from its blob when the writer moved it to one (resolveBlob).
		metadata, metadataErr := runstart.Project([]byte(ev.Raw))
		if metadataErr != nil {
			r.Bad++
			r.refuseStart(metadataErr)
			break
		}
		r.StartError = ""
		r.command = ev.argv
		r.Tier, r.Command, r.Cwd, r.Contract = metadata.Tier, ev.Target, metadata.Cwd, metadata.Contract
		r.User, r.UID, r.Host, r.Kernel, r.TegoVersion = p.User, metadata.UID, p.Host, p.Kernel, p.TegoVersion
		r.EffectiveHash, r.BaselineSHA256 = metadata.EffectiveHash, metadata.BaselineSHA256
		r.ContractHash, r.Capture, r.Harness = metadata.ContractHash, p.Capture, p.Harness.Name
		r.Stdin, r.Deployment = p.Stdio.Stdin, p.Deployment.Name
		reads, said := p.Capabilities[string(backend.CapRecordReads)]
		r.ReadsUnrecorded = said && !reads
		// A root tier's kernel record carries a refused read, and a run that enforces nothing refuses none.
		rn := p.ReadsNotified
		r.RefusedReadsUnseen = r.ReadsUnrecorded && rn != nil && !rn.Notified &&
			rn.Why != record.ReadsNotifiedWhyKernel && rn.Why != record.ReadsNotifiedWhyRecordsOnly
		r.RefusedReadsUnknown = r.ReadsUnrecorded && rn == nil
		r.ReceiptReadsUnrecorded = receipt.ReadsUnrecordedBy(rn)
	case string(record.KindRunEnd):
		r.end(ev)
	case string(record.KindAsk):
		if !ev.askRepeat { // a repeated ask id is malformed and is no second question (askpair)
			r.Asks++
		}
	}
	if r.Start.IsZero() {
		r.Start = ev.TS
	}
	if ev.TS.After(r.Last) {
		r.Last = ev.TS
	}
	ev.RecordMinor, ev.LocalFloor = r.RecordMinor, r.LocalApprovalAuthority != nil
	r.Events = append(r.Events, ev)
}

func (r *Run) end(ev Event) {
	r.Ended = true
	r.End = ev.TS
	var p struct {
		Reason   string `json:"reason"`
		ExitCode int    `json:"exit_code"`
		Signal   int    `json:"signal"`
		By       string `json:"stopped_by"`
	}
	_ = json.Unmarshal([]byte(ev.Raw), &p)
	r.EndReason, r.ExitCode, r.Signal, r.StoppedBy = p.Reason, p.ExitCode, p.Signal, p.By
}

// payload is the union of the payload keys a view shows.
type payload struct {
	Op         string   `json:"op"`
	Path       string   `json:"path"`
	Path2      string   `json:"path2"`
	Flags      int      `json:"flags"`
	Created    bool     `json:"created"`
	Errno      int      `json:"errno"`
	SyscallRet int64    `json:"syscall_ret"`
	Dst        string   `json:"dst"`
	Host       string   `json:"host"`
	Proto      string   `json:"proto"`
	Method     string   `json:"method"`
	Argv       []string `json:"argv"`
	Target     string   `json:"target"`
	Target2    string   `json:"target2"` // a held fs mutation's second name (ADR 0047): shown after " → "
	AskID      string   `json:"ask_id"`
	AskRule    string   `json:"ask_rule"`
	Hold       string   `json:"hold"`
	By         string   `json:"by"`
	Approved   *bool    `json:"approved"`
	Name       string   `json:"name"`
	Tool       string   `json:"tool"`
	What       string   `json:"what"`
	Why        string   `json:"why"`
	Which      string   `json:"which"`
	Value      float64  `json:"value"`
	Ceiling    float64  `json:"ceiling"`
	Reason     string   `json:"reason"`
	ExitCode   int      `json:"exit_code"`
	Command    []string `json:"command"`
	Tier       string   `json:"tier"`
	// ArgvBlob and CommandBlob name the blob an argv or a command too long for the line went to (blobargv.go).
	ArgvBlob    string `json:"argv_blob"`
	CommandBlob string `json:"command_blob"`
}

// DisplayDst names a destination for people: family(16) is a netlink socket.
func DisplayDst(dst string) string {
	if dst == "family(16)" {
		return "netlink"
	}
	return dst
}

// fromRecord flattens a decoded line.
func fromRecord(e *record.Event) Event {
	ev := Event{Seq: e.Seq, TS: e.TS, Run: e.Run, Agent: e.Agent, Kind: string(e.Kind), Source: string(e.Source),
		Rule: e.Rule, Verdict: string(e.Verdict), Authority: string(e.Authority), Reason: string(e.Reason),
		Raw: string(e.Payload), mono: e.MonoNS, pid: e.PID}
	ev.Step, ev.stepTied = e.ModelStep()
	if e.Attr != nil {
		ev.StepMethod = e.Attr.Method
	}
	var p payload
	if len(e.Payload) > 0 {
		_ = json.Unmarshal(e.Payload, &p)
	}
	switch e.Kind {
	case record.KindFS:
		ev.Op, ev.Target = fsOp(p), p.Path
		ev.readNothing = p.SyscallRet < 0 || !secretpath.ReadOpen(p.Op, p.Flags, p.Errno, p.Created)
		if p.Path2 != "" {
			ev.Target += " → " + p.Path2
		}
	case record.KindNet:
		ev.Op, ev.Proto = "connect", p.Proto
		if p.Op != "" {
			ev.Op = p.Op
		}
		ev.Target = syslookup.PlaceOf(DisplayDst(p.Dst), e.Rule) // an observed AF_UNSPEC attempt: destination and result were not established
		if p.Host != "" {
			ev.Target = p.Host + " (" + ev.Target + ")"
		}
		ev.Host = strings.ToLower(p.Host)
		if ev.Host == "" {
			ev.Host = HostOf(p.Dst)
		}
		ev.SystemLookup = IsSystemLookup(p.Dst)
	case record.KindExec:
		ev.argv = p.Argv
		ev.Op, ev.Target, ev.path = "exec", strings.Join(p.Argv, " "), p.Path
		if ev.Target == "" {
			ev.Target, ev.blob = p.Path, p.ArgvBlob
		}
	case record.KindRefused:
		ev.Op, ev.Target = p.Op, DisplayDst(p.Target)
		if p.Op == "exec" {
			// Refusal mirrors record an executable pathname, never argv.
			ev.path = p.Target
		}
		// A refused connection names a host: by its reason (net-*), or by its operation, which a first delivery a person
		// denied (ask-denied) or that timed out has with a reason of its own. Other refusals name paths and programs.
		if strings.HasPrefix(string(e.Reason), "net-") || netRefusalOps[p.Op] {
			ev.Host = HostOf(p.Target)
		}
		ev.SystemLookup = IsSystemLookup(p.Target)
	case record.KindAsk:
		// What it asks about, as a row and the Logs search read it: "read /p/plan.md". An ask line written
		// without one names its id.
		ev.Op, ev.AskID, ev.Target = p.Hold, p.AskID, strings.TrimSpace(p.Op+" "+askNames(p.Target, p.Target2))
		if p.Target == "" {
			ev.Target = "ask " + p.AskID
		}
		ev.askOp, ev.askTarget, ev.askName, ev.askName2 = p.Op, askNames(p.Target, p.Target2), p.Target, p.Target2
		if ev.Rule == "" {
			ev.Rule = p.AskRule
		}
	case record.KindAnswer:
		ev.AskID, ev.Op = p.AskID, "answer"
		ev.askOp, ev.askTarget = p.Op, askNames(p.Target, p.Target2) // what it answered, for the Logs search
		ev.askName, ev.askName2 = p.Target, p.Target2
		ev.Target = p.AskID + " by " + p.By
		if p.Approved != nil {
			ev.Target += map[bool]string{true: ", approved", false: ", not approved"}[*p.Approved]
		}
	case record.KindRunStart:
		ev.argv = p.Command
		ev.Op, ev.Target = "start", strings.Join(p.Command, " ")
		if len(p.Command) == 0 {
			ev.blob = p.CommandBlob
		}
	case record.KindRunEnd:
		ev.Op, ev.Target = "end", p.Reason
		if p.Reason == "exit" {
			ev.Target = "exit " + strconv.Itoa(p.ExitCode)
		}
	case record.KindMCP:
		ev.Op, ev.Target = "mcp", strings.TrimSpace(p.Name+" "+p.Tool)
	case record.KindGap:
		ev.Op, ev.Target = "gap", strings.TrimSpace(p.What+" "+p.Why)
	case record.KindLimit:
		ev.Op, ev.Target = "limit", fmt.Sprintf("%s %g of %g", p.Which, p.Value, p.Ceiling)
	case record.KindDecision:
		ev.Op, ev.Target = "step", strings.TrimSpace(p.Tool+" "+p.Name)
	default:
		ev.Op = string(e.Kind)
	}
	return ev
}

// netRefusalOps are the operations of a refused line whose target is a destination, whatever its reason.
var netRefusalOps = map[string]bool{"connect": true, "first_write": true, "send": true, "net": true}

// HostOf is the host a destination names, lower-cased: "chatgpt.com" for tcp://chatgpt.com:443 or chatgpt.com:443,
// "93.184.216.34" for 93.184.216.34:443, "::1" for [::1]:443. An address is unmapped and keeps its zone: fe80::1%2 and
// fe80::1%3 are two links, so they can be two machines, and the Host facet and a filter tell them apart (A37). What
// compares an address against a live block does not: the kernel ignores the scope id on all but a link-local address and
// a block holds none (liveblock.Normalize, decide.Unmapped), so a block on 2001:db8::1 refuses [2001:db8::1%1] as well, and
// BlockHostOf is the form that comparison reads. A line's Target still says what the agent wrote. A unix socket, a netlink
// family, a path and text that is not a host (spaces, slashes, markup) name none: "".
func HostOf(dst string) string {
	if i := strings.Index(dst, "://"); i > 0 {
		dst = dst[i+3:]
	}
	if dst == "" || strings.HasPrefix(dst, "unix:") || strings.ContainsAny(dst, " ()<>\"'/\\@~\t") {
		return ""
	}
	host := dst
	if h, port, err := net.SplitHostPort(dst); err == nil {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return "" // a word with a colon: not a destination
		}
		host = h
	} else if strings.HasPrefix(dst, "[") && strings.HasSuffix(dst, "]") {
		host = dst[1 : len(dst)-1]
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().String()
	}
	if strings.Contains(host, ":") {
		return "" // a word with a colon, or host:port with a bad port: not a destination
	}
	return strings.ToLower(host)
}

// BlockHostOf is HostOf's answer as a live block holds it: the same host with no zone. A block's enforcement is by
// address, whatever scope id a connect passed, so a reading that asks whether a block covers a host asks with this form;
// a block on fe80::1 covers fe80::1%2 and fe80::1%3 alike (fail closed), while the facet keeps them two.
func BlockHostOf(host string) string {
	if !strings.Contains(host, ":") && (host == "" || host[0] < '0' || host[0] > '9') {
		return host // no address starts with anything but a digit or has no colon: a name, and ParseAddr's error would cost an allocation
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.WithZone("").String()
	}
	return host
}

func fsOp(p payload) string {
	if p.Op != "open" {
		return p.Op
	}
	const accMode, wronly, rdwr, creat, trunc = 3, 1, 2, 0o100, 0o1000
	if p.Flags&accMode == wronly || p.Flags&accMode == rdwr || p.Flags&(creat|trunc) != 0 {
		return "write"
	}
	return "read"
}

// askNames is what an ask or an answer is about as a person reads it: the target, and a held fs mutation's second name
// (a rename's or a link's new name, a symlink's stored target; ADR 0047) after " → ", as an fs line names its second
// path, so an approval of a rename is never shown without where it goes and the dashboard's path shortener shows each
// name whole instead of cutting the pair in the middle.
func askNames(target, target2 string) string {
	if target2 == "" {
		return target
	}
	return target + " → " + target2
}

// refuseStart retains the decoder's reason and invalidates earlier baseline claims.
func (r *Run) refuseStart(err error) {
	r.StartError = err.Error()
	r.EffectiveHash, r.BaselineSHA256 = "", ""
}

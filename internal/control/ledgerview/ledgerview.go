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
	Seq       uint64
	TS        time.Time
	Run       string
	Agent     string
	Kind      string
	Source    string
	Rule      string
	Verdict   string
	Authority string
	Reason    string
	Op        string
	Target    string
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
	// off is the line's byte offset in its events file (Line reads it back from there).
	off int64
	// Mirror is a kind=refused line that mirrors a refused action of its run (pair.go): the same refusal as that
	// action's line, so no count counts it again.
	Mirror bool
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
	ID        string
	Agent     string
	Contract  string
	Tier      string
	Command   string
	Cwd       string
	Start     time.Time
	End       time.Time
	Last      time.Time // the newest line's time
	Ended     bool
	Live      bool // listed in <root>/.live, its lock held (Store.liveRuns), and no run_end read
	EndReason string
	ExitCode  int
	Signal    int
	Lines     int // lines read
	Refusals  int // refusals: refused actions and refused lines that mirror none (Event.Refusal)
	Asks      int // ask lines
	Kinds     map[string]int
	Events    []Event
	Pending   []Ask
	// Cut means Events covers only a bounded part of the run; summary counters are complete.
	Cut bool
	// PendingCut reports more simultaneous unanswered asks than the bounded display can retain.
	PendingCut bool
	// Bad counts malformed lines and unsupported record kinds.
	Bad int
	// Identity and policy, from run_start: who started the run, where, under which exact contract and build.
	User, Host, Kernel, TegoVersion, ContractHash, Harness, Capture string
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
	// st is the run's cache entry (nil for a Run built for the line bound); memo its per-version derived views.
	st   *runState
	memo *runMemo
	// lastID is the newest line's id (its hash) and file the events file as read, for this version: what the chain
	// verdict cache and Line's offset read take, so neither looks at a runState another request may be reading.
	lastID string
	file   fileID
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
// ended.
func (r *Run) State() string {
	switch {
	case r.Ended:
		return "ended"
	case r.Live:
		return "running"
	default:
		return "lost"
	}
}

// Duration is end-start for an ended run, now-start for a running one, and for a lost run, which recorded no end, the
// time from its start to its newest line: all the record can say, and it stops growing as a lost run does.
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
	Run    string
	Agent  string
	AskID  string
	Hold   string
	TS     time.Time
	Seq    uint64
	Op     string
	Target string
	Rule   string
}

// Snapshot is one bounded scan of a ledger root.
type Snapshot struct {
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
func liveSet(root string) map[string]bool {
	out := map[string]bool{}
	ents, err := os.ReadDir(filepath.Join(root, ".live"))
	if err != nil {
		return out
	}
	for _, e := range ents {
		out[e.Name()] = true
	}
	return out
}

// add counts one line into the summary. ev.Mirror is already set (runState.markMirror), so a refused action and the
// line that mirrors it count as one refusal (Event.Refusal).
func (r *Run) add(ev Event) {
	if ev.Refusal() {
		r.Refusals++
		if ev.SystemLookup {
			r.SysRefusals++
		}
	}
	r.Lines++
	kind := ev.Kind
	if !record.Kind(kind).Valid() {
		kind = "unknown"
		r.Bad++
	}
	r.Kinds[kind]++
	if r.Agent == "" {
		r.Agent = ev.Agent
	}
	switch ev.Kind {
	case string(record.KindRunStart):
		r.Start = ev.TS
		var p struct {
			Tier           string   `json:"tier"`
			Command        []string `json:"command"`
			Cwd            string   `json:"cwd"`
			ContractSource struct {
				Path string `json:"path"`
			} `json:"contract_source"`
			User         string `json:"launcher_user"`
			UID          int    `json:"launcher_uid"`
			Host         string `json:"host"`
			Kernel       string `json:"kernel"`
			TegoVersion  string `json:"tego_version"`
			ContractHash string `json:"contract_hash"`
			Capture      string `json:"capture"`
			Harness      struct {
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
		// ev.Target is the command too, read back from its blob when the writer moved it to one (resolveBlob).
		r.Tier, r.Command, r.Cwd, r.Contract = p.Tier, ev.Target, p.Cwd, p.ContractSource.Path
		r.User, r.UID, r.Host, r.Kernel, r.TegoVersion = p.User, p.UID, p.Host, p.Kernel, p.TegoVersion
		r.ContractHash, r.Capture, r.Harness = p.ContractHash, p.Capture, p.Harness.Name
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
		r.Asks++
	}
	if r.Start.IsZero() {
		r.Start = ev.TS
	}
	if ev.TS.After(r.Last) {
		r.Last = ev.TS
	}
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
	Op       string   `json:"op"`
	Path     string   `json:"path"`
	Path2    string   `json:"path2"`
	Flags    int      `json:"flags"`
	Created  bool     `json:"created"`
	Errno    int      `json:"errno"`
	Dst      string   `json:"dst"`
	Host     string   `json:"host"`
	Proto    string   `json:"proto"`
	Method   string   `json:"method"`
	Argv     []string `json:"argv"`
	Target   string   `json:"target"`
	Target2  string   `json:"target2"` // a held fs mutation's second name (ADR 0047): shown after " → "
	AskID    string   `json:"ask_id"`
	AskRule  string   `json:"ask_rule"`
	Hold     string   `json:"hold"`
	By       string   `json:"by"`
	Approved *bool    `json:"approved"`
	Name     string   `json:"name"`
	Tool     string   `json:"tool"`
	What     string   `json:"what"`
	Why      string   `json:"why"`
	Which    string   `json:"which"`
	Value    float64  `json:"value"`
	Ceiling  float64  `json:"ceiling"`
	Reason   string   `json:"reason"`
	ExitCode int      `json:"exit_code"`
	Command  []string `json:"command"`
	Tier     string   `json:"tier"`
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
	var p payload
	if len(e.Payload) > 0 {
		_ = json.Unmarshal(e.Payload, &p)
	}
	switch e.Kind {
	case record.KindFS:
		ev.Op, ev.Target = fsOp(p), p.Path
		ev.readNothing = !secretpath.ReadOpen(p.Op, p.Flags, p.Errno, p.Created)
		if p.Path2 != "" {
			ev.Target += " → " + p.Path2
		}
	case record.KindNet:
		ev.Op, ev.Proto = "connect", p.Proto
		if p.Op != "" {
			ev.Op = p.Op
		}
		ev.Target = DisplayDst(p.Dst)
		if p.Host != "" {
			ev.Target = p.Host + " (" + ev.Target + ")"
		}
		ev.Host = strings.ToLower(p.Host)
		if ev.Host == "" {
			ev.Host = HostOf(p.Dst)
		}
		ev.SystemLookup = IsSystemLookup(p.Dst)
	case record.KindExec:
		ev.Op, ev.Target, ev.path = "exec", strings.Join(p.Argv, " "), p.Path
		if ev.Target == "" {
			ev.Target, ev.blob = p.Path, p.ArgvBlob
		}
	case record.KindRefused:
		ev.Op, ev.Target = p.Op, DisplayDst(p.Target)
		if strings.HasPrefix(string(e.Reason), "net-") { // a refused connection; other refusals name paths and programs
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

// HostOf is the host a destination names, lower-cased: "chatgpt.com" for tcp://chatgpt.com:443 or chatgpt.com:443,
// "93.184.216.34" for 93.184.216.34:443, "::1" for [::1]:443. An address reads as a live block holds it and every
// matcher compares it (liveblock.Normalize, decide.Unmapped), unmapped and with no zone: a line keeps the scope id its
// connect passed, the agent's to choose and ignored by the kernel on all but a link-local address, and a block on
// 2001:db8::1 refuses [2001:db8::1%1] as well. A line's Target still says what the agent wrote. A unix socket, a netlink
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
		return a.Unmap().WithZone("").String()
	}
	if strings.Contains(host, ":") {
		return "" // a word with a colon, or host:port with a bad port: not a destination
	}
	return strings.ToLower(host)
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

// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"sort"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/secretpath"
	"github.com/attention-span-ai/tego/internal/check/syslookup"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The receipt's activity sections: where the run connected, the programs it ran and the secret-looking files
// it read. A watched run refuses nothing, so without them its receipt said only "Nothing was refused" about a run
// that read ~/.ssh/id_rsa and connected to an attacker three times.

func addVerdict(v *Verdicts, verdict record.Verdict) {
	switch verdict {
	case record.VerdictObserved:
		v.Observed++
	case record.VerdictRefused:
		v.Refused++
	default:
		v.Allowed++
	}
}

// activity is one pass's state for the activity sections. Each map holds at most MaxPaths keys: a key past the cap
// is counted in its over count, never named, so memory stays bounded whatever the run did.
type activity struct {
	conns     map[string]*Verdicts
	connOver  int
	tries     int            // every connection counted, listed or past the cap
	sends     int            // of tries, the UDP datagram sends (record.NetOpSend)
	destSends map[string]int // dst -> its sends, for the destinations conns retained
	lookups   int            // the routine system lookups, counted apart from conns
	sockets   int            // the socket calls that name no place (syslookup.NoPlace), counted apart from conns
	progs     map[string]int
	progOver  int
	sens      map[string]int  // path -> index in Receipt.SensitiveReads
	fresh     map[string]bool // the paths this run created (foldTempRenames)
}

func newActivity() activity {
	return activity{conns: map[string]*Verdicts{}, destSends: map[string]int{}, progs: map[string]int{}, sens: map[string]int{}, fresh: map[string]bool{}}
}

// destination is the place a net line names: name:port when the line carries a host name other than the address
// itself, else the destination as recorded (ip:port, unix:<path>).
func destination(p *payload) string {
	if p.Host == "" || strings.HasPrefix(p.Dst, "unix:") {
		return p.Dst
	}
	i := strings.LastIndexByte(p.Dst, ':')
	if i < 0 {
		return p.Host
	}
	host, port := strings.Trim(p.Dst[:i], "[]"), p.Dst[i+1:]
	if host == p.Host {
		return p.Dst
	}
	return p.Host + ":" + port
}

// connection counts one net line. Only a connect is a connection: an HTTP request line repeats a connection the
// forwarder already made, a bind opens no connection, and the tego DNS broker's socket is tego's own. An ask line is
// skipped: the line after the answer carries the verdict. A routine system lookup is counted apart (countConn).
func (b *builder) connection(e *record.Event, p *payload) {
	if e.Verdict == record.VerdictAsk || (p.Op != "" && p.Op != "connect" && p.Op != record.NetOpSend) || p.Mechanism == "dns-broker" || p.Dst == "" {
		return
	}
	b.countConn(destination(p), e.Rule, e.Verdict, p.Op == record.NetOpSend)
}

// countConn counts one connection to dst under rule. A routine system lookup (syslookup.Routine: the nscd socket a real
// Codex asks for every name it resolves, userdb, D-Bus, a DNS lookup) carries none of the run's data: it is counted in
// SystemLookups, never as a place, so the receipt, tego watch's "seen:" line and the dashboard's verdict (which
// folds the same destinations by the same classifier) never name it as where the run connected. A socket call that
// names no place (syslookup.NoPlace: glibc's connect(AF_UNSPEC) resets, the kernel's netlink socket) is no place
// either: the first watch of a Python fetch named "unspec" its most used place. One that was not refused is counted in
// RoutineSockets. A refused one is no routine call: the supervisor refuses a send whose address is AF_UNSPEC (R4,
// whose interpretation depends on the socket's domain) and a netlink send that is no route query (ADR 0128).
// Refusals counts and lists it, and, as on the dashboard, it is neither a place nor a routine socket call. An
// observe run continues that send instead (GAPS C61): an attempted send whose destination and result were not
// established. It is listed under syslookup.UnreadSendPlace, observed, and never as a disconnect.
//
// send says the line is a UDP datagram the run sent (record.NetOpSend), not a connect: it is one more attempt at its
// destination, and is counted again in DatagramSends and the destination's Sends, so the receipt tells a socket that
// only connected from one that sent (GAPS C172). A ledger from before the op has none, and counts as a connect.
func (b *builder) countConn(dst, rule string, verdict record.Verdict, send bool) {
	a := &b.act
	dst = syslookup.PlaceOf(dst, rule) // an AF_UNSPEC send attempt stays visible even though its destination is unknown
	if syslookup.NoPlace(dst, rule) {
		if verdict != record.VerdictRefused {
			a.sockets++
		}
		return
	}
	if syslookup.Routine(dst, rule) {
		a.lookups++
		return
	}
	a.tries++
	if send {
		a.sends++
	}
	v, ok := a.conns[dst]
	if !ok {
		if len(a.conns) >= MaxPaths {
			a.connOver++
			return
		}
		v = &Verdicts{}
		a.conns[dst] = v
	}
	addVerdict(v, verdict)
	if send {
		a.destSends[dst]++
	}
}

// program counts one exec that ran: a refused exec never ran (Refusals lists it), and a failed one ran nothing.
func (b *builder) program(e *record.Event, p *payload) {
	if e.Verdict == record.VerdictRefused || e.Verdict == record.VerdictAsk || p.Path == "" || p.SyscallRet < 0 {
		return
	}
	a := &b.act
	if _, ok := a.progs[p.Path]; !ok && len(a.progs) >= MaxPaths {
		a.progOver++
		return
	}
	a.progs[p.Path]++
}

// isSensitive applies one path classification to action and refused-only lines.
func (b *builder) isSensitive(path, rule string) bool {
	return secretpath.Is(path) || secretpath.GuardRule(rule) || b.sensitivePath != nil && b.sensitivePath(path)
}

// sensitive counts one open of a secret-looking, rule-guarded or context-protected file. An open for writing only
// reads nothing; an allowed open that failed (no such file) read nothing either. A refused try counts whatever its
// flags: the agent asked for the file.
func (b *builder) sensitive(e *record.Event, p *payload) {
	if p.Op != record.FSOpen || e.Verdict == record.VerdictAsk {
		return
	}
	if e.Verdict != record.VerdictRefused && (!secretpath.ReadOpen(p.Op, p.Flags, p.Errno, p.Created) || p.SyscallRet < 0) {
		return
	}
	if !b.isSensitive(p.Path, e.Rule) {
		return
	}
	b.countRead(p.Path, e.Verdict)
}

func (b *builder) countRead(path string, verdict record.Verdict) {
	rc, a := b.rc, &b.act
	i, ok := a.sens[path]
	if !ok {
		if len(rc.SensitiveReads) >= MaxPaths {
			rc.SensitiveReadsTruncated = true
			return
		}
		i = len(rc.SensitiveReads)
		a.sens[path] = i
		rc.SensitiveReads = append(rc.SensitiveReads, SensitiveRead{Path: path})
	}
	addVerdict(&rc.SensitiveReads[i].Verdicts, verdict)
}

// refusedAlone counts a kind=refused line written with no action line before it (a supervisor's net refusal, a
// held open a person denied) as the connection or the read it refused.
func (b *builder) refusedAlone(e *record.Event, p *payload) {
	switch p.Op {
	case "net", "connect":
		if p.Target != "" {
			b.countConn(p.Target, e.Rule, record.VerdictRefused, false)
		}
	case record.FSOpen:
		if b.isSensitive(p.Target, e.Rule) {
			b.countRead(p.Target, record.VerdictRefused)
		}
	}
}

// finishActivity sorts the counts into the receipt's lists (most first, then by name), keeps the top MaxTop and says
// what a tier that does not record the allowed actions leaves out.
func (b *builder) finishActivity() {
	rc, a := b.rc, &b.act
	conns := make([]Connection, 0, len(a.conns))
	for d, v := range a.conns {
		conns = append(conns, Connection{Destination: d, Count: v.Total(), Verdicts: *v, Sends: a.destSends[d]})
	}
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].Count != conns[j].Count {
			return conns[i].Count > conns[j].Count
		}
		return conns[i].Destination < conns[j].Destination
	})
	if len(conns) > MaxTop {
		rc.ConnectionsMore = len(conns) - MaxTop
		conns = conns[:MaxTop]
	}
	rc.ConnectionsOverflowAttempts = a.connOver
	rc.Connections, rc.ConnectionTries, rc.SystemLookups, rc.RoutineSockets = conns, a.tries, a.lookups, a.sockets
	rc.DatagramSends = a.sends

	progs := make([]Program, 0, len(a.progs))
	for p, n := range a.progs {
		progs = append(progs, Program{Path: p, Count: n})
	}
	sort.Slice(progs, func(i, j int) bool {
		if progs[i].Count != progs[j].Count {
			return progs[i].Count > progs[j].Count
		}
		return progs[i].Path < progs[j].Path
	})
	if len(progs) > MaxTop {
		rc.ProgramsMore = len(progs) - MaxTop
		progs = progs[:MaxTop]
	}
	rc.ProgramsOverflowAttempts = a.progOver
	rc.Programs = progs

	// A ledger written before the capability line cannot say what was recorded: no note, as for files, and an empty
	// list of sensitive reads proves nothing.
	caps := b.runStart.Capabilities
	rc.SensitiveReadsUnknown = !caps[string(backend.CapRecordReads)]
	rc.ReadsNotified = b.runStart.ReadsNotified
	if caps == nil {
		return
	}
	if !caps[string(backend.CapRecordExecOpenNet)] {
		rc.ConnectionsNote = "tier " + rc.Tier + " records refused connections and programs only, not the ones it allowed"
	}
	if !caps[string(backend.CapRecordReads)] {
		rc.SensitiveReadsNote = readsNote(b.runStart.ReadsNotified)
	}
}

// readsNote says what the sensitive files list of a run that keeps no allowed read cannot hold. A refused read has a
// line only where the supervisor is told of read opens (run_start.reads_notified, ADR 0077). At tier landlock that is
// not the default: Landlock refuses inside a syscall the filter never notified, so such a run's list holds neither
// kind (SEMANTICS §7). A root tier's refused read is in its kernel record, which this list cannot prove was read, and a
// ledger older than reads_notified does not say, so those two promise nothing either way.
func readsNote(rn *record.ReadsNotified) string {
	const allowed = "this run did not record the files it was allowed to read (record: full records them)"
	switch {
	case rn == nil || rn.Why == record.ReadsNotifiedWhyKernel:
		return allowed + "; a refused read may be missing too"
	case rn.Notified:
		return allowed + "; only refused reads are listed"
	}
	return "this run did not record the files it read, allowed or refused (record: full records them)"
}

// RefusedReadsUnrecorded reports whether run_start says a read this run refused left no line (reads_notified false, at
// an enforcing tier: reason.reads off, or no supervisor), so Refusals cannot count it: a tier-landlock run whose
// deny_read refused a read said "Nothing was refused." A root tier's refused read is in its kernel record, a run that
// enforces nothing refuses nothing, and a record older than reads_notified does not say; an unknown reason counts as
// unrecorded, as readsNote reads it.
func (rc *Receipt) RefusedReadsUnrecorded() bool { return ReadsUnrecordedBy(rc.ReadsNotified) }

// ReadsUnrecordedBy is RefusedReadsUnrecorded for run_start's reads_notified rn: the one rule, which the dashboard
// reads from a run's run_start without building its receipt.
func ReadsUnrecordedBy(rn *record.ReadsNotified) bool {
	return rn != nil && !rn.Notified && rn.Why != record.ReadsNotifiedWhyKernel && rn.Why != record.ReadsNotifiedWhyRecordsOnly
}

// foldTempRenames folds the write-then-rename that saves a file in one step (Python's .pyc cache, editors, git):
// a write to X.<suffix> followed by a rename of X.<suffix> to X reads as one "wrote X". It folds only a temporary
// file this run created itself (O_CREAT|O_EXCL, or created: true), so a rename of a file that existed before the run
// (a real rename by the agent) is always listed.
func (b *builder) foldTempRenames() {
	f, fresh := &b.rc.Files, b.act.fresh
	if len(f.Renamed) == 0 || len(fresh) == 0 {
		return
	}
	folded := map[string]bool{}
	kept := f.Renamed[:0]
	for _, r := range f.Renamed {
		suffix, ok := strings.CutPrefix(r.From, r.To+".")
		if !ok || suffix == "" || strings.Contains(suffix, "/") || !fresh[r.From] {
			kept = append(kept, r)
			continue
		}
		folded[r.From] = true
		if !b.seen["w\x00"+r.To] {
			b.add(&f.Written, "w", r.To)
		}
	}
	if len(folded) == 0 {
		return
	}
	f.Renamed = kept
	drop := func(l []string) []string {
		out := l[:0]
		for _, p := range l {
			if !folded[p] {
				out = append(out, p)
			}
		}
		return out
	}
	f.Written, f.Created = drop(f.Written), drop(f.Created)
}

// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"path"
	"slices"
	"sort"
	"strings"
	"time"
)

// A watched run (tego watch) records no contract, so its Signal cannot tell the project's own API from the attacker's
// address: both are a send next to a secret that got through. The demo runs the same agent twice, watched and
// enforced, and the enforced run's contract says which destinations the job needs. A Reference is that allow list,
// and Against reads a watched run's Signal against it, so a destination the enforced run allows is never "Next to a
// secret" and never part of a leak. Nothing here changes what the ledger says; it only says which list a watched
// run's sends were measured against (RunSignal.AllowedFrom), and the pages name that run.

// Reference is the allow list a watched run is read against: an enforced run's contract net entries and the
// destinations its own lines show allowed by a net[...] entry.
type Reference struct {
	// Run is the enforced run's ID.
	Run string
	// Net is its contract's net.allow entries as written ("127.0.0.1:8803", "tcp://chatgpt.com:443").
	Net []string
	// Dests are the destination keys its Signal marks InContract (DNS left out: it is always allowed anyway).
	Dests map[string]bool
}

// ReferenceRun is the run whose contract a watched run r is read against: its PairOf, the run in runs that enforced
// (not tier observe) the same recorded workspace and nonempty agent identity, harness and program, and started closest to it. It is
// nil when r is not a watched run or no reliably matching enforced run is listed.
func ReferenceRun(runs []*Run, r *Run) *Run {
	if r == nil || r.Tier != "observe" {
		return nil
	}
	return PairOf(runs, r)
}

// PairOf is the run of the other kind (enforced for a watched run, watched for an enforced one) in runs (newest
// first) with the same workspace, agent, harness and program, starting closest to r; the newest wins a tie. The demo starts its two takes
// together, so a later enforced run of the same program (a Block now take, a rehearsal) is not the watched take's
// pair: the run page's reference, its Compare button and the Overview's pair all name the same run.
func PairOf(runs []*Run, r *Run) *Run {
	if r == nil || r.Tier == "" {
		return nil
	}
	watched := r.Tier == "observe"
	gap := func(o *Run) time.Duration { return max(o.Start.Sub(r.Start), r.Start.Sub(o.Start)) }
	var best *Run
	for _, o := range runs {
		if o == nil || o.ID == r.ID || o.Tier == "" || (o.Tier == "observe") == watched || !sameIdentity(o, r) {
			continue
		}
		if best == nil || gap(o) < gap(best) {
			best = o
		}
	}
	return best
}

// sameIdentity requires recorded workspace and agent identities. A program name and
// a nearby start time alone cannot authorize borrowing another run's contract.
func sameIdentity(a, b *Run) bool {
	return SameProgram(a, b) && path.IsAbs(a.Cwd) && a.Cwd == b.Cwd && a.Agent != "" && a.Agent == b.Agent && a.Harness == b.Harness
}

// SameProgram reports whether two runs ran the same program (the base name of each command's first word).
func SameProgram(a, b *Run) bool {
	return a != nil && b != nil && program(a.Command) != "" && program(a.Command) == program(b.Command)
}

// program is the base name of a command line's first word: "codex" for "/usr/bin/codex --no-daemon".
func program(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	return path.Base(f[0])
}

// NewReference is the Reference of enforced run id: its contract's net entries and what its Signal says it allowed.
func NewReference(id string, net []string, sig *RunSignal) Reference {
	ref := Reference{Run: id, Net: net, Dests: map[string]bool{}}
	if sig != nil {
		for _, d := range sig.Outbound {
			if d.InContract && !lookupDst(&d) {
				ref.Dests[d.Key] = true
			}
		}
	}
	return ref
}

// allows reports whether the reference allows destination d: its lines allowed d's key, or a net entry names it
// (scheme left out; an exact host:port, a bare host for any port, or "*.domain" for its subdomains). Address ranges
// are not matched: a watched run's send to one stays marked, which errs on the side of showing it.
func (ref Reference) allows(d *Dest) bool {
	if ref.Dests[d.Key] {
		return true
	}
	host, port := hostPort(d.Key)
	for _, e := range ref.Net {
		e = strings.TrimSpace(e)
		if i := strings.Index(e, "://"); i >= 0 {
			e = e[i+3:]
		}
		eh, ep := hostPort(e)
		if ep != "" && ep != port {
			continue
		}
		switch {
		case e == d.Key, eh == host:
			return true
		case strings.HasPrefix(eh, "*.") && strings.HasSuffix(host, eh[1:]):
			return true
		}
	}
	return false
}

// Against is s read against ref for watched run r: a destination ref allows is in the contract (and so never next to
// a secret), each secret's "next to a send" is measured again without those, and AllowedFrom names ref's run. s is
// not changed (Signal shares its slices with a cache); the result has its own copy of every slice sortSignal sorts.
func (s *RunSignal) Against(ref Reference) *RunSignal {
	if s == nil || ref.Run == "" {
		return s
	}
	out := *s
	out.Outbound, out.Secrets = slices.Clone(s.Outbound), slices.Clone(s.Secrets)
	out.Groups, out.Programs = slices.Clone(s.Groups), slices.Clone(s.Programs)
	out.AllowedFrom = ref.Run
	for i := range out.Outbound {
		d := &out.Outbound[i]
		if !d.InContract && ref.allows(d) {
			d.InContract, d.NearSecret = true, false
		}
	}
	for i := range out.Secrets {
		st := &out.Secrets[i]
		st.NearSend, st.ReadNearSend = nearSend(st, out.Outbound)
	}
	sortSignal(&out)
	return &out
}

// nearSend is whether a destination off the contract (not background, not DNS) was first contacted within
// NearSecretWindow and NearSecretLines of st's first touch or of a read of it (near), and of a read of it (read).
func nearSend(st *SecretTouch, outbound []Dest) (near, read bool) {
	first := []touchAt{{st.FirstSeq, st.First}}
	for i := range outbound {
		d := &outbound[i]
		if d.Background || d.InContract || ResolverDst(d.Key) {
			continue
		}
		if pairDistance(st.reads, d.sends) != ^uint64(0) {
			return true, true
		}
		near = near || nearOne(st.reads, d.FirstSeq, d.First)
		near = near || nearOne(first, d.FirstSeq, d.First)
	}
	return near, false
}

// pairDistance measures only successful read/send pairs inside both windows.
// Sequence order bounds the candidates even when a destination was contacted
// thousands of times before its first secret read.
func pairDistance(reads, sends []touchAt) uint64 {
	best := ^uint64(0)
	for _, send := range sends {
		i := sort.Search(len(reads), func(i int) bool { return reads[i].seq >= send.seq || send.seq-reads[i].seq <= NearSecretLines })
		for ; i < len(reads); i++ {
			r := reads[i]
			if r.seq > send.seq && r.seq-send.seq > NearSecretLines {
				break
			}
			if delta := r.ts.Sub(send.ts); delta >= -NearSecretWindow && delta <= NearSecretWindow {
				best = min(best, nearest(send.seq, []uint64{r.seq}))
			}
		}
	}
	return best
}
